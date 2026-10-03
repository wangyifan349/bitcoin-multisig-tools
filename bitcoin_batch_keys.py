#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =================================================================
# Script function
# Bulk tool for Bitcoin private keys (WIF) and addresses.
#
# Directly double-click this file (or run it without parameters) to get the interactive menu. All functions can be completed in the menu.
# It will wait for a carriage return before exiting, and the window will not flash by.
#
# Command line mode (optional):
# gen generates random private keys in batches. Each secret is generated independently and falls in the secp256k1 scalar domain [1, n-1]
# import Import private key files in batches (the files end with END) and restore all addresses
# info View address information (type / network / version / witness program / lock script)
# selftest Self-test, it is most reliable to run it first after the program starts running. Add -v to print item by item.
# -----------------------------------------------------------------
# Implementation instructions: Prioritize using the installed library (coincurve/ecdsa/bech32m/bech32/base58),
# Whichever one is not installed will automatically return to the equivalent implementation built into this file, so it can be run even if a single file is copied.
# Do not use wallet-level packaging such as bip-utils / bitcoinlib, hash160, WIF packaging,
# Taproot tweaked key, address derivation and parsing are all implemented by this file.
# =================================================================
import argparse
import hashlib
import json
import os
import secrets
import sys
import time

if os.name == "nt":                               # Console encoding adjustment is only required on Windows
    import ctypes
else:
    ctypes = None

#================= Optional encoding library: base58 =================
try:                                             # Prefer using pip install base58
    import base58
    HAVE_BASE58 = True
except ImportError:                              # Fallback to built-in implementation when missing
    HAVE_BASE58 = False

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"  # Remove the easily mixed 0 O I l


def b58_encode_builtin(data):
    """Built-in Base58 encoding (only used if base58 library is not installed)."""
    number = int.from_bytes(data, "big")
    encoded = ""
    while number:
        number, rest = divmod(number, 58)
        encoded = BASE58_ALPHABET[rest] + encoded
    for byte in data:
        if byte != 0:
            break
        encoded = "1" + encoded
    return encoded


def b58_decode_builtin(text):
    """Built-in Base58 decoding (only used if base58 library is not installed)."""
    number = 0
    for char in text:
        if char not in BASE58_ALPHABET:
            raise ValueError("Illegal Base58 character %r" % char)
        number = number * 58 + BASE58_ALPHABET.index(char)
    decoded = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    for char in text:
        if char != "1":
            break
        decoded = b"\x00" + decoded
    return decoded


def b58_encode(data):
    """Base58 encoding: Use the base58 library. If the library is missing, use the built-in implementation."""
    if HAVE_BASE58:
        return base58.b58encode(data).decode("ascii")
    return b58_encode_builtin(data)


def b58_decode(text):
    """Base58 decoding: Use the base58 library. If the library is missing, use the built-in implementation."""
    if HAVE_BASE58:
        return base58.b58decode(text)
    return b58_decode_builtin(text)


#================= Optional encoding library: bech32m / bech32 =================
try:                                             # Preferred bech32m: The same API covers both bech32 and bech32m
    import bech32m
    HAVE_BECH32M = True
except ImportError:                              # If it is missing, it will fall back to the bech32 library. If it is missing, it will use the built-in implementation.
    HAVE_BECH32M = False

try:                                             # bech32 1.2.0 only implements BIP-173, bech32m constants need to be filled in by yourself
    import bech32
    HAVE_BECH32 = True
except ImportError:
    HAVE_BECH32 = False

BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"  #5-bit value to character mapping table
BECH32_CONST = 1                                     # BIP-173 (witness v0) validation constants
BECH32M_CONST = 0x2BC830A3                           # BIP-350 (witness v1+) validation constants
BECH32_GENERATORS = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]  # Generate polynomial coefficients


def bech32_polymod(values):
    """Built-in BCH checksum calculation (used when both libraries are missing)."""
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = ((checksum & 0x1FFFFFF) << 5) ^ value
        for index in range(5):
            if (top >> index) & 1:
                checksum ^= BECH32_GENERATORS[index]
    return checksum


def bech32_hrp_expand(hrp):
    """Built-in HRP expansion: high-order 5-bit sequence + delimited 0 + low-order 5-bit sequence."""
    return [ord(char) >> 5 for char in hrp] + [0] + [ord(char) & 31 for char in hrp]


def convert_bits(data, from_bits, to_bits, pad=True):
    """Bit width conversion: 8 bit byte <-> 5 bit grouping, bech32m decoding requires pad=False."""
    if HAVE_BECH32:
        return bech32.convertbits(data, from_bits, to_bits, pad)
    accumulator = 0
    bits = 0
    result = []
    max_value = (1 << to_bits) - 1
    max_accumulator = (1 << (from_bits + to_bits - 1)) - 1
    for value in data:
        if value < 0 or (value >> from_bits):
            return None
        accumulator = ((accumulator << from_bits) | value) & max_accumulator
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            result.append((accumulator >> bits) & max_value)
    if pad:
        if bits:
            result.append((accumulator << (to_bits - bits)) & max_value)
    elif bits >= from_bits or ((accumulator << (to_bits - bits)) & max_value):
        return None
    return result


def bech32_checksum(hrp, data, const):
    """Generate 6 5-bit check characters, const determines whether it is bech32 or bech32m."""
    if HAVE_BECH32 and const == BECH32_CONST:
        return bech32.bech32_create_checksum(hrp, data)
    polymod = bech32_polymod(bech32_hrp_expand(hrp) + list(data) + [0] * 6) ^ const
    return [(polymod >> 5 * (5 - index)) & 31 for index in range(6)]


def bech32_checksum_spec(hrp, data):
    """Determine whether the checksum belongs to bech32 or bech32m, and return a constant or None (check failed)."""
    if HAVE_BECH32:
        if bech32.bech32_verify_checksum(hrp, data):
            return BECH32_CONST
    elif bech32_polymod(bech32_hrp_expand(hrp) + list(data)) == BECH32_CONST:
        return BECH32_CONST
    polymod = bech32_polymod(bech32_hrp_expand(hrp) + list(data))
    if polymod == BECH32M_CONST:
        return BECH32M_CONST
    return None


def bech32_hrp_of_address(address):
    """Take the part before the last '1' of the address as the HRP candidate."""
    lowered = address.lower()
    position = lowered.rfind("1")
    return lowered[:position] if position > 0 else ""


def segwit_encode(hrp, witness_version, witness_program):
    """SegWit address encoding: v0 uses bech32, v1 and above use bech32m (automatically selected by the library according to version)."""
    if HAVE_BECH32M:
        return bech32m.encode(hrp, witness_version, witness_program)
    data = [witness_version] + convert_bits(list(witness_program), 8, 5)
    const = BECH32_CONST if witness_version == 0 else BECH32M_CONST
    checksum = bech32_checksum(hrp, data, const)
    return hrp + "1" + "".join(BECH32_CHARSET[value] for value in data + checksum)


def segwit_decode(address):
    """SegWit address decoding, returns (hrp, witness_version, witness_program) or None."""
    if HAVE_BECH32M:                                # The bech32m library comes with all legality checks
        hrp = bech32_hrp_of_address(address)
        if not hrp:
            return None
        try:
            decoded = bech32m.decode(hrp, address.lower())
        except (bech32m.DecodeError, bech32m.HrpDoesNotMatch, ValueError, IndexError):
            return None
        return hrp, decoded.witver, bytes(decoded.witprog)

    if any(ord(char) < 33 or ord(char) > 126 for char in address):
        return None
    if address.lower() != address and address.upper() != address:
        return None
    address = address.lower()
    position = address.rfind("1")
    if position < 1 or position + 7 > len(address) or len(address) > 90:
        return None
    hrp = address[:position]
    try:
        data = [BECH32_CHARSET.index(char) for char in address[position + 1:]]
    except ValueError:
        return None
    spec = bech32_checksum_spec(hrp, data)
    if spec is None:
        return None
    program = convert_bits(data[1:-6], 5, 8, False)
    if not program or data[0] > 16:
        return None
    if data[0] == 0 and len(program) not in (20, 32):
        return None
    if data[0] == 0 and program and spec != BECH32_CONST:
        return None
    if data[0] != 0 and spec != BECH32M_CONST:
        return None
    return hrp, data[0], bytes(program)


#================= Hash =================
def sha256(data):
    """Single SHA-256."""
    return hashlib.sha256(data).digest()


def double_sha256(data):
    """Double SHA-256, checksum source for Base58Check."""
    return sha256(sha256(data))


def hash160(data):
    """RIPEMD160(SHA256(data)), Bitcoin's 160-bit hash."""
    return hashlib.new("ripemd160", sha256(data)).digest()


def tagged_hash(tag, data):
    """BIP340 domain-separated hash: SHA256(SHA256(tag) || SHA256(tag) || data)."""
    prefix = sha256(tag.encode("ascii"))
    return sha256(prefix + prefix + data)


#================= secp256k1 curve parameters =================
PRIME = 2 ** 256 - 2 ** 32 - 977  # Domain p
ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # Basic point order n
CURVE_B = 7                                    # Curve coefficient b
BASE_X = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
BASE_Y = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def check_secret(secret):
    """The verification private key falls in the secp256k1 scalar field [1, n-1]."""
    if not isinstance(secret, int):
        raise ValueError("Private key must be an integer")
    if not 1 <= secret < ORDER:
        raise ValueError("Private key exceeds secp256k1 valid range [1, n-1]")
    return secret


#================= Optional curve library: coincurve/ecdsa =================
try:                                             # coincurve binds libsecp256k1, the fastest
    import coincurve
    HAVE_COINCURVE = True
except ImportError:
    HAVE_COINCURVE = False

try:                                             # ecdsa: A standard ECDSA implementation in pure Python
    import ecdsa
    import ecdsa.ellipticcurve
    HAVE_ECDSA = True
except ImportError:
    HAVE_ECDSA = False

if HAVE_COINCURVE:
    CURVE_BACKEND = "coincurve"
elif HAVE_ECDSA:
    CURVE_BACKEND = "ecdsa"
else:
    CURVE_BACKEND = "built-in"


#================= Built-in elliptic curve group operations (a catch-up when both libraries are missing) =================
def jacobian_double(point):
    """Double the Jacobian coordinates to avoid finding the modular inversion every time."""
    x, y, z = point
    if y == 0 or z == 0:
        return (0, 0, 0)
    a = (x * x) % PRIME
    b = (y * y) % PRIME
    c = (b * b) % PRIME
    d = (2 * ((x + b) * (x + b) - a - c)) % PRIME
    e = (3 * a) % PRIME
    f = (e * e) % PRIME
    x3 = (f - 2 * d) % PRIME
    y3 = (e * (d - x3) - 8 * c) % PRIME
    z3 = (2 * y * z) % PRIME
    return (x3, y3, z3)


def jacobian_add(point1, point2):
    """Jacobian coordinate point plus."""
    x1, y1, z1 = point1
    x2, y2, z2 = point2
    if z1 == 0:
        return point2
    if z2 == 0:
        return point1
    z1z1 = z1 * z1 % PRIME
    z2z2 = z2 * z2 % PRIME
    u1 = x1 * z2z2 % PRIME
    u2 = x2 * z1z1 % PRIME
    s1 = y1 * z2 * z2z2 % PRIME
    s2 = y2 * z1 * z1z1 % PRIME
    if u1 == u2:
        if s1 != s2:
            return (0, 0, 0)
        return jacobian_double(point1)
    h = (u2 - u1) % PRIME
    i = (2 * h) % PRIME
    i = i * i % PRIME
    j = h * i % PRIME
    r = 2 * (s2 - s1) % PRIME
    v = u1 * i % PRIME
    x3 = (r * r - j - 2 * v) % PRIME
    y3 = (r * (v - x3) - 2 * s1 * j) % PRIME
    z3 = ((z1 + z2) * (z1 + z2) - z1z1 - z2z2) * h % PRIME
    return (x3, y3, z3)


def jacobian_to_affine(point):
    """Convert Jacobian coordinates to affine coordinates; return None for infinity points."""
    x, y, z = point
    if z == 0:
        return None
    inverse = pow(z, PRIME - 2, PRIME)
    inverse2 = inverse * inverse % PRIME
    return (x * inverse2 % PRIME, y * inverse2 * inverse % PRIME)


def builtin_scalar_multiply(scalar):
    """Built-in scalar multiplication: double-and-add, Jacobian coordinates."""
    result = (0, 0, 0)
    addend = (BASE_X, BASE_Y, 1)
    while scalar:
        if scalar & 1:
            result = jacobian_add(result, addend)
        addend = jacobian_double(addend)
        scalar >>= 1
    return jacobian_to_affine(result)


def builtin_point_add(first, second):
    """Built-in affine coordinate point addition."""
    if first is None:
        return second
    if second is None:
        return first
    x1, y1 = first
    x2, y2 = second
    if x1 == x2:
        if (y1 + y2) % PRIME == 0:
            return None
        slope = (3 * x1 * x1) * pow(2 * y1 % PRIME, PRIME - 2, PRIME) % PRIME
    else:
        slope = (y2 - y1) * pow((x2 - x1) % PRIME, PRIME - 2, PRIME) % PRIME
    x3 = (slope * slope - x1 - x2) % PRIME
    return (x3, (slope * (x1 - x3) - y1) % PRIME)


#================= Elliptic curve operation entry (dispatched by backend) =================
def secret_to_point(secret):
    """Private key -> affine coordinate curve point (x, y), that is, public key point Q = secret * G."""
    check_secret(secret)
    if HAVE_COINCURVE:
        return coincurve.PublicKey.from_valid_secret(secret.to_bytes(32, "big")).point()
    if HAVE_ECDSA:
        point = ecdsa.SECP256k1.generator * secret
        return (point.x(), point.y())
    return builtin_scalar_multiply(secret)


def point_add(first, second):
    """Add affine coordinate points; returns None (point at infinity) when the two points are opposites of each other."""
    if first is None:
        return second
    if second is None:
        return first
    if HAVE_COINCURVE:
        try:
            merged = coincurve.PublicKey.from_point(first[0], first[1]).combine(
                [coincurve.PublicKey.from_point(second[0], second[1])])
        except ValueError:                    # P + (-P) = point at infinity
            return None
        return merged.point()
    if HAVE_ECDSA:
        curve = ecdsa.SECP256k1.curve
        left = ecdsa.ellipticcurve.PointJacobi.from_affine(
            ecdsa.ellipticcurve.Point(curve, first[0], first[1]))
        right = ecdsa.ellipticcurve.PointJacobi.from_affine(
            ecdsa.ellipticcurve.Point(curve, second[0], second[1]))
        total = left + right
        # When P + (-P) ecdsa returns INFINITY (normal Point, coordinates are None), no to_affine()
        if total.x() is None or total.y() is None:
            return None
        if hasattr(total, "to_affine"):
            total = total.to_affine()
        return (total.x(), total.y())
    return builtin_point_add(first, second)


#================= Public key serialization =================
def public_key_bytes(point, compressed=True):
    """Public key point to bytes: compressed 33 bytes (02/03 + x), uncompressed 65 bytes (04 + x + y)."""
    x, y = point
    if compressed:
        return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def x_only_public_key(point):
    """BIP340 x-only public key, only retains the x coordinate (32 bytes)."""
    return point[0].to_bytes(32, "big")


def lift_x(x_bytes):
    """BIP340 lift_x: Restore even y curve points from 32-byte x coordinates."""
    x = int.from_bytes(x_bytes, "big")
    if not 0 <= x < PRIME:
        raise ValueError("x-coordinate is outside domain range")
    y_square = (pow(x, 3, PRIME) + CURVE_B) % PRIME
    y = pow(y_square, (PRIME + 1) // 4, PRIME)
    if y * y % PRIME != y_square:
        raise ValueError("x-coordinate is not on secp256k1 curve")
    return (x, y if y % 2 == 0 else PRIME - y)


def taproot_output_key(point):
    """BIP86: Q = P + int(tagged_hash(\"TapTweak\", x(P))) * G, taking an even number of y if necessary."""
    internal = x_only_public_key(point)
    tweak = int.from_bytes(tagged_hash("TapTweak", internal), "big")
    if tweak >= ORDER:
        raise ValueError("TapTweak beyond curve level")
    result = point_add(point, secret_to_point(tweak))
    if result is None:
        raise ValueError("Taproot output point is infinity point")
    if result[1] & 1:                      # Even y normalization: x remains unchanged after negation
        result = (result[0], PRIME - result[1])
    return result[0].to_bytes(32, "big")


# ================= Base58Check =================
def base58check_encode(payload):
    """Base58Check: The payload is encoded after appending a 4-byte double SHA-256 checksum."""
    return b58_encode(payload + double_sha256(payload)[:4])


def base58check_decode(text):
    """Base58Check Decode and checksum."""
    raw = b58_decode(text.strip())
    if len(raw) < 5:
        raise ValueError("Base58Check data is too short")
    payload, checksum = raw[:-4], raw[-4:]
    if double_sha256(payload)[:4] != checksum:
        raise ValueError("Base58Check checksum does not match")
    return payload


#================= Network and Script Constants =================
WIF_VERSION = 0x80   # WIF private key version byte
NETWORKS = {                                   # Network prefix: Base58 version bytes + Bech32 HRP
    "bc":  {"name": "Bitcoin mainnet", "p2pkh": 0x00, "p2sh": 0x05, "hrp": "bc"},
    "tb":  {"name": "Bitcoin testnet", "p2pkh": 0x6F, "p2sh": 0xC4, "hrp": "tb"},
    "btc": {"name": "Bitcoin Regtest", "p2pkh": 0x6F, "p2sh": 0xC4, "hrp": "bcrt"},
}
SCRIPT_LABELS = [                            # Output order and labels
    ("p2pkh", "P2PKH", "1..."),
    ("p2sh-p2wpkh", "P2SH-P2WPKH", "3..."),
    ("p2wpkh", "P2WPKH (BIP84)", "bc1q..."),
    ("p2tr", "P2TR (BIP86)", "bc1p..."),
]
SHORT_LABELS = {                            # The short name used for block display, removing the suffix such as BIP number
    "p2pkh": "P2PKH",
    "p2sh-p2wpkh": "P2SH-P2WPKH",
    "p2wpkh": "P2WPKH",
    "p2tr": "P2TR",
}
KNOWN_VERSIONS = {                                          # Base58 address version byte meaning
    0x00: "P2PKH Mainnet", 0x05: "P2SH mainnet",
    0x6F: "P2PKH testnet/Regtest", 0xC4: "P2SH testnet/Regtest",
}


def network_params(network):
    """Get the network parameters, and the unknown network defaults to the main network."""
    return NETWORKS.get(network, NETWORKS["bc"])


def all_script_kinds():
    """All script types are output by default."""
    return [item[0] for item in SCRIPT_LABELS]


def split_script_kinds(text):
    """Split the --kinds argument; return None in case of unknown types."""
    kinds = [item.strip() for item in text.split(",") if item.strip()]
    valid = set(all_script_kinds())
    unknown = [item for item in kinds if item not in valid]
    if unknown:
        print("Unrecognized type: %s (optional %s)" % (",".join(unknown), ",".join(sorted(valid))),
              file=sys.stderr)
        return None
    return kinds


#================= Private Key: Generate/WIF/Parse =================
def generate_secret():
    """Each key is independently selected as a random scalar in the range [1, n-1] using secrets (rejection sampling, no modulo bias)."""
    return secrets.randbelow(ORDER - 1) + 1


def secret_to_wif(secret, compressed=True):
    """Private Key -> WIF. A 0x01 flag is appended to the end of the compressed private key."""
    check_secret(secret)
    payload = bytes([WIF_VERSION]) + secret.to_bytes(32, "big")
    if compressed:
        payload += b"\x01"
    return base58check_encode(payload)


def wif_to_secret(wif):
    """WIF -> (private key, whether to compress or not), while verifying the version bytes and length."""
    payload = base58check_decode(wif)
    if not payload or payload[0] != WIF_VERSION:
        raise ValueError("Not a mainnet WIF private key (version byte should be 0x80)")
    if len(payload) == 34 and payload[-1] == 0x01:
        return check_secret(int.from_bytes(payload[1:33], "big")), True
    if len(payload) == 33:
        return check_secret(int.from_bytes(payload[1:33], "big")), False
    raise ValueError("Illegal WIF length (expected 33 or 34 bytes)")


def parse_secret(text):
    """Parse private key: WIF / 64-bit hex / decimal."""
    cleaned = text.strip()
    if not cleaned:
        raise ValueError("Input is empty")
    if cleaned[0] in "5KL9c" and len(cleaned) >= 50:
        return wif_to_secret(cleaned)
    lowered = cleaned.lower()
    if lowered.startswith("0x"):
        return check_secret(int(lowered[2:], 16)), True
    if len(cleaned) == 64 and all(char in "0123456789abcdefABCDEF" for char in cleaned):
        return check_secret(int(cleaned, 16)), True
    if cleaned.isdigit():
        return check_secret(int(cleaned)), True
    raise ValueError("Unrecognized private key format (supports WIF / 64-bit hex / decimal)")


#================= Address derivation =================
def derive_addresses(secret, compressed=True, network="bc", kinds=None):
    """Derive the address from the private key and return [(kind, label, prefix hint, address, lock script hex), ...]."""
    check_secret(secret)
    params = network_params(network)
    kinds = set(kinds or all_script_kinds())
    point = secret_to_point(secret)
    pub = public_key_bytes(point, compressed)
    pub_hash = hash160(pub)
    output = []

    if "p2pkh" in kinds:
        script = bytes.fromhex("76a914") + pub_hash + bytes.fromhex("88ac")
        output.append(("p2pkh", "P2PKH", "1...",
                       base58check_encode(bytes([params["p2pkh"]]) + pub_hash), script.hex()))
    if "p2sh-p2wpkh" in kinds:
        redeem = bytes.fromhex("0014") + pub_hash
        redeem_hash = hash160(redeem)
        output.append(("p2sh-p2wpkh", "P2SH-P2WPKH", "3...",
                       base58check_encode(bytes([params["p2sh"]]) + redeem_hash),
                       (bytes.fromhex("a914") + redeem_hash + bytes.fromhex("87")).hex()))
    if "p2wpkh" in kinds:
        output.append(("p2wpkh", "P2WPKH (BIP84)", params["hrp"] + "1q...",
                       segwit_encode(params["hrp"], 0, pub_hash),
                       (bytes.fromhex("0014") + pub_hash).hex()))
    if "p2tr" in kinds:
        taproot_key = taproot_output_key(point)
        output.append(("p2tr", "P2TR (BIP86)", params["hrp"] + "1p...",
                       segwit_encode(params["hrp"], 1, taproot_key),
                       (bytes.fromhex("5120") + taproot_key).hex()))
    return output


def build_record(secret, compressed, network="bc", index=None, kinds=None):
    """Collate a private key into a complete output record."""
    point = secret_to_point(secret)
    pub = public_key_bytes(point, compressed)
    return {
        "index": index,
        "secret": secret,
        "hex": format(secret, "064x"),
        "decimal": str(secret),
        "wif": secret_to_wif(secret, compressed),
        "compressed": compressed,
        "pubkey": pub.hex(),
        "pubkey_hash": hash160(pub).hex(),
        "x_only_pubkey": x_only_public_key(point).hex(),
        "addresses": derive_addresses(secret, compressed, network, kinds),
    }


#================= Batch business logic (common to command line and interactive menu) =================
def generate_records(count, compressed=True, network="bc", kinds=None):
    """Generate random private key records in batches and return (record list, seconds taken)."""
    started = time.perf_counter()
    records = []
    for index in range(1, count + 1):
        secret = generate_secret()                # Each secret is generated independently
        records.append(build_record(secret, compressed, network, index, kinds))
        if count > 200 and index % 200 == 0:
            print("...generated %d/%d" % (index, count), file=sys.stderr)
    return records, time.perf_counter() - started


def import_records(lines, network="bc", kinds=None, force_compression=False, force_uncompressed=False):
    """Convert [(line number, private key text), ...] into records and return (record list, failure list)."""
    records = []
    failures = []
    for number, line in lines:
        try:
            secret, compressed = parse_secret(line)
        except ValueError as error:
            failures.append((number, line, str(error)))
            continue
        if force_compression:
            compressed = True
        elif force_uncompressed:
            compressed = False
        records.append(build_record(secret, compressed, network, len(records) + 1, kinds))
    return records, failures


def inspect_addresses(items):
    """Parse addresses in batches, return (success list, failure list); stop when encountering END."""
    entries = []
    failures = []
    for item in items:
        if item.strip().upper().startswith("END"):
            break
        try:
            entries.append(inspect_address(item))
        except Exception as error:
            failures.append((item, str(error)))
    return entries, failures


#================= Address resolution =================
def script_from_program(witness_version, program):
    """Spell out SegWit locking script by witness v / program."""
    if witness_version == 0:
        return ("00" if len(program) == 20 else "0020") + program.hex()
    return "%02x%02x%s" % (0x50 + witness_version, len(program), program.hex())


def inspect_address(address):
    """Parse the address and return a dictionary of structured information."""
    text = address.strip()
    if not text:
        raise ValueError("Address is empty")

    decoded = segwit_decode(text)                       # Try SegWit first
    if decoded:
        hrp, version, program = decoded
        spec = "bech32" if version == 0 else "bech32m"
        network = "bc" if hrp == "bc" else ("tb" if hrp == "tb" else ("btc" if hrp == "bcrt" else "unknown"))
        return {
            "address": text,
            "kind": "segwit",
            "type": "P2WPKH (BIP84)" if version == 0 and len(program) == 20 else
                    "P2WSH (BIP141)" if version == 0 else
                    "P2TR (BIP86)" if version == 1 and len(program) == 32 else
                    "P2WPKH (BIP341 v%d)" % version if version == 1 and len(program) == 20 else
                    "Witness v%d" % version,
            "network": network,
            "hrp": hrp,
            "encoding": spec,
            "version": "witness v%d" % version,
            "witness_version": version,
            "program": program.hex(),
            "program_bytes": len(program),
            "script": script_from_program(version, program),
            "note": ("Starting with %s1p, latest format" % hrp) if version == 1 and len(program) == 32 else
                    ("Starting with %s1q, the handling fee is lower than the old address starting with 1" % hrp) if len(program) == 20 else
                    "Multi-sign or script address, a script determines how to spend it",
        }

    try:
        payload = base58check_decode(text)              # Then press Base58Check to parse
    except Exception as error:
        raise ValueError("Not a legal SegWit(bech32/bech32m) address, Base58Check decoding also failed: %s" % error)
    version, digest = payload[0], payload[1:]
    if len(digest) != 20:
        raise ValueError("Address of version byte 0x%02x is not a 20-byte hash" % version)
    if version in (0x00, 0x6F):
        script = bytes.fromhex("76a914") + digest + bytes.fromhex("88ac")
        kind, label = "p2pkh", "P2PKH"
    elif version in (0x05, 0xC4):
        script = bytes.fromhex("a914") + digest + bytes.fromhex("87")
        kind, label = "p2sh", "P2SH"
    else:
        raise ValueError("Unknown address version byte 0x%02x" % version)
    if kind == "p2sh":
        note = "The address the other party sent you. You can transfer money in; if you want to transfer money out again, you must have a redemption script from the other party."
    else:
        note = "The general receiving address of the payee's public key (the most common one starting with 1)"
    return {
        "address": text,
        "kind": kind,
        "type": label,
        "network": "bc" if version in (0x00, 0x05) else "tb",
        "hrp": "",
        "encoding": "base58check",
        "version": "0x%02x (%s)" % (version, KNOWN_VERSIONS.get(version, "Unknown version")),
        "witness_version": None,
        "program": digest.hex(),
        "program_bytes": len(digest),
        "script": script.hex(),
        "note": note,
    }


#================= Output Rendering =================
def display_width(text):
    """There are 2 columns based on East Asian full-width characters to ensure that Chinese and English are mixed and aligned."""
    total = 0
    for char in text:
        total += 2 if "\u1100" <= char <= "\u115f" or "\u2e80" <= char <= "\ua4cf" \
            or "\uac00" <= char <= "\ud7a3" or "\uf900" <= char <= "\ufaff" \
            or "\ufe30" <= char <= "\ufe6f" or "\uff00" <= char <= "\uff60" \
            or "\uffe0" <= char <= "\uffe6" else 1
    return total


def pad_display(text, size):
    """Fill in spaces to the right of the display width."""
    return text + " " * max(0, size - display_width(text))


def records_to_rows(records):
    """Flatten records into a row dictionary of equal-width tables."""
    rows = []
    for record in records:
        row = {"#": "" if record["index"] is None else str(record["index"]),
               "WIF": record["wif"], "priv_hex": record["hex"]}
        for _kind, label, _prefix, address, _script in record["addresses"]:
            row[label] = address
        rows.append(row)
    return rows


def render(records, fmt):
    """Output records in the specified format (block/line/csv/json)."""
    rows = records_to_rows(records)
    if not rows:
        return "(no record)"
    columns = list(rows[0].keys())

    if fmt == "json":
        payload = []
        for record in records:
            payload.append({
                "index": record["index"],
                "wif": record["wif"],
                "privkey_hex": record["hex"],
                "privkey_decimal": record["decimal"],
                "compressed": record["compressed"],
                "pubkey": record["pubkey"],
                "pubkey_hash160": record["pubkey_hash"],
                "x_only_pubkey": record["x_only_pubkey"],
                "addresses": [{"kind": kind, "type": label, "address": address, "script": script}
                              for kind, label, _prefix, address, script in record["addresses"]],
            })
        return json.dumps(payload, ensure_ascii=False, indent=2)

    if fmt == "csv":
        lines = [",".join(columns)]
        for row in rows:
            lines.append(",".join(str(row[column]) for column in columns))
        return "\n".join(lines)

    if fmt == "line":                                 # One key per line for easy reprocessing
        widths = [max([display_width(column)] + [display_width(str(row[column])) for row in rows])
                  for column in columns]
        lines = ["  ".join(pad_display(name, widths[index])
                           for index, name in enumerate(columns)).rstrip()]
        for row in rows:
            lines.append("  ".join(pad_display(str(row[column]), widths[index])
                                   for index, column in enumerate(columns)).rstrip())
        return "\n".join(lines)

    blocks = []                # block: Display keys one by one in blocks. By default, only the private key and address are displayed.
    for record in records:
        number = "" if record["index"] is None else "%d. " % record["index"]
        body = [number + "private key" + record["wif"]]
        for kind, label, _prefix, address, _script in record["addresses"]:
            body.append("     %-11s %s" % (SHORT_LABELS.get(kind, label), address))
        blocks.append("\n".join(body))
    return "\n\n".join(blocks)


def render_detail(records):
    """Detailed view: Private key, private key hexadecimal, public key, and script are fully expanded for verification and troubleshooting."""
    blocks = []
    for record in records:
        number = "" if record["index"] is None else "%d. " % record["index"]
        body = [number + "private key" + record["wif"],
                "Private key hex" + record["hex"],
                "public key" + record["pubkey"]]
        for kind, label, _prefix, address, script in record["addresses"]:
            body.append("   %-9s %s" % (SHORT_LABELS.get(kind, label), address))
            body.append("   %-9s %s" % ("", script))
        blocks.append("\n".join(body))
    return "\n\n".join(blocks)


def render_inspect(entries, fmt):
    """Output the geocoding results in the specified format (block/csv/json)."""
    if fmt == "json":
        return json.dumps(entries, ensure_ascii=False, indent=2)
    if fmt == "csv":
        keys = ["address", "kind", "type", "network", "hrp", "encoding", "version",
                "witness_version", "program", "program_bytes", "script", "note"]
        lines = [",".join(keys)]
        for entry in entries:
            lines.append(",".join("" if entry.get(key) is None else str(entry[key]) for key in keys))
        return "\n".join(lines)
    if len(entries) == 1:                      # Single address: focus on what it is and how to use it
        entry = entries[0]
        lines = ["address" + entry["address"],
                 "type" + entry["type"],
                 "network" + entry["network"]]
        if entry["kind"] == "p2sh":
            lines.append("Purpose The address sent to you by the other party. You can transfer money in; if you want to transfer money out again, you must have a redemption script from the other party.")
        else:
            lines.append("Purpose: Transfer money to this address and the other party will receive the money.")
            if entry["note"]:
                lines.append("illustrate" + entry["note"])
        lines.append("Details" + entry["script"])
        return "\n".join(lines)

    blocks = []                                # Multiple addresses: compact list
    for entry in entries:
        lines = ["address" + entry["address"],
                 "       %s  %s  %s" % (entry["type"], entry["network"], entry["encoding"])]
        if entry["note"]:
            lines.append("       " + entry["note"])
        blocks.append("\n".join(lines))
    return "\n\n".join(blocks)


#================= Files and Console =================
def read_key_file(path):
    """Read the private key file: fetch the key line by line and end when encountering END; blank lines and # comments are ignored."""
    if path == "-":
        lines = sys.stdin.read().splitlines()
    else:
        with open(path, "r", encoding="utf-8-sig", errors="replace") as handle:
            lines = handle.read().splitlines()
    keys = []
    stopped = False
    for number, raw in enumerate(lines, 1):
        line = raw.strip()
        if stopped:
            continue
        if not line or line.startswith("#"):
            continue
        if line.upper().startswith("END"):            # Ignore everything after END
            stopped = True
            continue
        keys.append((number, line))
    return keys, stopped


def write_output(text, path):
    """Write to file or print to standard output."""
    if not path or path == "-":
        print(text)
        return
    with open(path, "w", encoding="utf-8", newline="") as handle:
        handle.write(text + "\n")


def enable_utf8_console():
    """Switch the Windows console to UTF-8 to avoid Chinese garbled characters or UnicodeEncodeError when double-clicking to run."""
    if ctypes is not None:
        try:
            ctypes.windll.kernel32.SetConsoleOutputCP(65001)
            ctypes.windll.kernel32.SetConsoleCP(65001)
        except Exception:
            pass
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def pause_before_exit(message="\nPress Enter to close the window..."):
    """Wait for a carriage return before ending the interactive mode, and the runtime window will not flash by when double-clicking."""
    try:
        input(message)
    except (EOFError, KeyboardInterrupt):
        pass


def backend_note():
    """Prompts the currently used library to facilitate confirmation of the operating environment."""
    if HAVE_BECH32M:
        segwit = "bech32m library"
    elif HAVE_BECH32:
        segwit = "bech32 library (only BIP-173, bech32m self-complementing)"
    else:
        segwit = "built-in"
    return "Curve=%s SegWit=%s Base58=%s Random=secrets" % (
        CURVE_BACKEND, segwit, "base58 library" if HAVE_BASE58 else "built-in")


#================= Command line subcommands =================
def render_keys(records):
    """Pure private key text: one WIF per line, for saving to disk, and can be read back as is using import."""
    return "\n".join(record["wif"] for record in records)


def output_records(records, args):
    """Output record: When writing to a file, only write the private key (one per line), and when writing to the screen, display it according to the format."""
    if args.out != "-":
        write_output(render_keys(records) + "\n", args.out)
    else:
        write_output(render(records, args.format), args.out)
    if getattr(args, "detail", False) and args.format == "block" and args.out == "-":
        write_output(render_detail(records), args.out)


def command_gen(args):
    """Subcommand gen: Generate random private keys and addresses in batches."""
    records, elapsed = generate_records(args.count, not args.no_compression, args.network, args.kinds)
    output_records(records, args)
    print("Generated %d keys (%s, took %.2f seconds)%s"
          % (len(records), network_params(args.network)["name"], elapsed,
             ", private keys written to " + args.out if args.out != "-" else ""), file=sys.stderr)
    return 0


def command_import(args):
    """Subcommand import: Import private keys in batches (the file ends with END) and restore the address."""
    if args.file:
        try:
            keys, stopped = read_key_file(args.file)
        except OSError as error:
            print("Failed to read %s: %s" % (args.file, error), file=sys.stderr)
            return 1
    elif args.keys:
        keys = list(enumerate(args.keys, 1))
        stopped = any(item.strip().upper().startswith("END") for item in args.keys)
    else:
        keys, stopped = read_key_file("-")

    records, failures = import_records(keys, args.network, args.kinds,
                                       args.force_compression, args.force_uncompressed)
    output_records(records, args) if records else write_output("(No private key available)\n", args.out)
    for number, line, reason in failures:
        print("Skip line %d: %s (%s)" % (number, line, reason), file=sys.stderr)
    print("Read %d, recognized %d, unrecognized %d%s"
          % (len(keys), len(records), len(failures),
             ", truncated by END" if stopped else ""), file=sys.stderr)
    return 1 if failures and args.strict else 0


def command_info(args):
    """Subcommand info: View address information."""
    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8-sig", errors="replace") as handle:
                items = handle.read().split()
        except OSError as error:
            print("Failed to read %s: %s" % (args.file, error), file=sys.stderr)
            return 1
    else:
        items = args.addresses
    if not items:
        print("Please give an address, or use -i to specify the address file", file=sys.stderr)
        return 1

    entries, failures = inspect_addresses(items)
    if entries:
        write_output(render_inspect(entries, args.format), args.out)
    for item, reason in failures:
        print("Cannot parse address: %s (%s)" % (item, reason), file=sys.stderr)
    return 1 if failures and args.strict else 0


def command_selftest(args):
    """Subcommand selftest: Use public test vectors to verify curve operations, encoding and derivation logic."""
    if getattr(args, "verbose", False):
        global VERBOSE
        VERBOSE = True
    point = secret_to_point(1)
    bip86_internal = "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115"
    checks = [
        ("secp256k1 public key (secret=1)",
         public_key_bytes(point, True).hex(),
         "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
        ("Uncompressed public key (secret=1)",
         public_key_bytes(point, False).hex(),
         "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
         "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"),
        ("WIF compression (secret=1)", secret_to_wif(1, True),
         "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"),
        ("WIF uncompressed (secret=1)", secret_to_wif(1, False),
         "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf"),
        ("P2PKH (secret=1)", derive_addresses(1, True, "bc", ["p2pkh"])[0][3],
         "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"),
        ("P2SH-P2WPKH (secret=1)", derive_addresses(1, True, "bc", ["p2sh-p2wpkh"])[0][3],
         "3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN"),
        ("BIP84 P2WPKH (secret=1)", derive_addresses(1, True, "bc", ["p2wpkh"])[0][3],
         "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"),
        ("BIP86 P2TR output_key (xprv m/86'/0'/0'/0/0)",
         taproot_output_key(lift_x(bytes.fromhex(bip86_internal))).hex(),
         "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c"),
        ("BIP86 P2TR address (xprv m/86'/0'/0'/0/0)",
         segwit_encode("bc", 1, taproot_output_key(lift_x(bytes.fromhex(bip86_internal)))),
         "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"),
        ("BIP173 bech32 v0", segwit_decode("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4")[2].hex(),
         "751e76e8199196d454941c45d1b3a323f1433bd6"),
        ("BIP350 bech32m v1",
         segwit_decode("bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y")[2].hex(),
         "751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6"),
    ]
    passed = True
    for name, actual, expected in checks:
        good = actual.lower() == expected.lower()
        passed = passed and good
        if not good:
            print("Failed: %s" % name)
            print("Calculate: %s" % actual)
            print("Should be: %s" % expected)
    for bad in (0, ORDER):                           # Private key range boundary check
        try:
            check_secret(bad)
            print("Failed: Private key %d is out of range and should be rejected" % bad)
            passed = False
        except ValueError:
            pass
    total = len(checks) + 2
    print("Total %d checks, %s" % (total, "All checks passed; the program is working correctly." if passed else "Some checks failed."))
    if passed and VERBOSE:
        print(backend_note())
        for name, actual, _expected in checks:
            print("  [OK] %s -> %s" % (name, actual))
    return 0 if passed else 1


#================= Interactive menu (entered when running without parameters, double-click to use) =================
MENU_TEXT = """
============================================================
Bitcoin Private Key/Address Tool
------------------------------------------------------------
1 Generate 10 private keys and addresses
2 Import the private key and restore the address
3 Check the details of an address
4 Check the address corresponding to a private key
5 Self-test (check whether the program is normal)
0 exit
============================================================
"""

WARNING_TEXT = "The private key is generated locally, please do not send it to any website."

MENU_BATCH_SIZE = 10          # The menu is fixedly generated 10 times at a time

VERBOSE = False               # Print item by item during self-test, turned on by -v


def ask_network():
    """Ask about the network and press Enter to default to the main network."""
    answer = input("Network [bc mainnet / tb testnet / btc regtest, press Enter=bc]:").strip().lower()
    if not answer:
        return "bc"
    if answer not in NETWORKS:
        print("Unknown network %s, use mainnet bc instead." % answer)
        return "bc"
    return answer


def prompt_key_lines():
    """Paste private keys interactively: one per line, ending when encountering END."""
    print("One private key per line, ignore empty lines, enter END to end:")
    keys = []
    while True:
        try:
            line = input("> ")
        except (EOFError, KeyboardInterrupt):
            print()
            break
        cleaned = line.strip()
        if not cleaned:
            continue
        if cleaned.upper().startswith("END"):
            break
        keys.append((len(keys) + 1, cleaned))
    return keys


def menu_generate():
    """Menu 1: Fixed generation of 10 private keys, just ask if you want to save them to a file."""
    records, elapsed = generate_records(MENU_BATCH_SIZE, True, "bc", None)
    path = input("Save to file? Fill in the path to save, press Enter directly without saving:").strip()
    print()
    if path:
        write_output(render_keys(records) + "\n", path)
        print("Generated %d, private keys written to %s (took %.2f seconds). The file contains one private key per line and can be read back using option 2. \n"
              % (len(records), path, elapsed))
    print(render(records, "block"))


def menu_import():
    """Menu 2: Import private keys in batches."""
    print("Fill in the private key file path; just press Enter and paste it manually (one per line, enter END to end)")
    path = input("File path:").strip()
    if path:
        try:
            keys, stopped = read_key_file(path)
        except OSError as error:
            print("Failed to read file: %s" % error)
            return
    else:
        keys = prompt_key_lines()
        stopped = True
    records, failures = import_records(keys, "bc", None)
    for number, line, reason in failures:
        print("Skip: %s (%s)" % (line, reason))
    print("Read %d, recognized %d, unrecognized %d\n" % (len(keys), len(records), len(failures)))
    if records:
        print(render(records, "block"))


def menu_info():
    """Menu 3: View address information."""
    print("Enter the address and press Enter. You can enter multiple consecutively; enter END or press Enter to end:")
    items = []
    while True:
        try:
            item = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not item or item.upper().startswith("END"):
            break
        items.append(item)
    if not items:
        print("No address entered.")
        return
    entries, failures = inspect_addresses(items)
    if entries:
        print(render_inspect(entries, "block"))
    for item, reason in failures:
        print("Cannot parse address: %s (%s)" % (item, reason))


def menu_lookup():
    """Menu 4: Query all addresses corresponding to a single private key."""
    print("You can fill in WIF, 64-bit hexadecimal, or decimal numbers")
    text = input("Private key:").strip()
    if not text:
        return
    secret, compressed = parse_secret(text)
    print(render([build_record(secret, compressed, "bc", None, None)], "block"))


def menu_selftest():
    """Menu 5: Run self-test."""
    command_selftest(None)


MENU_ACTIONS = {
    "1": menu_generate,
    "2": menu_import,
    "3": menu_info,
    "4": menu_lookup,
    "5": menu_selftest,
}


def show_menu():
    """Print interactive menu."""
    print(MENU_TEXT)


def run_interactive():
    """Interactive mode main loop; double-click to run this file and go here."""
    try:
        print(WARNING_TEXT)
        while True:
            show_menu()
            try:
                choice = input("Please select [0-5]:").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                return 0
            if choice == "0":
                print("Goodbye.")
                return 0
            action = MENU_ACTIONS.get(choice)
            if action is None:
                print("Invalid selection, please enter 0-5.")
                continue
            try:
                action()
            except (ValueError, OSError) as error:
                print("Error: %s" % error)
            except (EOFError, KeyboardInterrupt):
                print()
            print()
    finally:
        pause_before_exit()


#================= Command line parsing =================
def add_common_arguments(parser):
    """Give gen / import subcommands common parameters."""
    parser.add_argument("-n", "--network", default="bc", choices=sorted(NETWORKS),
                        help="Network prefix (default bc mainnet)")
    parser.add_argument("--kinds", default=",".join(all_script_kinds()),
                        help="Types of scripts to output, comma separated")
    parser.add_argument("-f", "--format", dest="format", default="block",
                        choices=["block", "line", "csv", "json"], help="Output format (default block)")
    parser.add_argument("-d", "--detail", action="store_true",
                        help="Switch to detailed view in block format to display private key hexadecimal, public key and lock script.")
    parser.add_argument("-o", "--out", default="-",
                        help="Output file; when writing a file, only write the private key (one per line, which can be read back with import), - means standard output")


def build_parser():
    """Build the argparse parser."""
    parser = argparse.ArgumentParser(
        prog="bitcoin_batch_keys.py",
        description="Bitcoin private key (WIF)/address batch tool; run it directly without parameters (or double-click) to enter the interactive menu",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example:\n"
               "Double-click this file, or run it directly to enter the interactive menu\n"
               "  python bitcoin_batch_keys.py gen -c 20 -o keys.txt\n"
               "  python bitcoin_batch_keys.py gen -c 3 -d\n"
               "  python bitcoin_batch_keys.py import -i keys.txt\n"
               "  python bitcoin_batch_keys.py info bc1q... 1Abc...\n")
    parser.add_argument("--version", action="version", version="bitcoin_batch_keys 1.1")
    subs = parser.add_subparsers(dest="command", required=True)

    gen = subs.add_parser("gen", help="Generate random private keys and addresses in batches")
    gen.add_argument("-c", "--count", type=int, default=10, help="Number of spawns (default 10)")
    gen.add_argument("--no-compression", action="store_true", help="WIF does not have the 0x01 compression flag bit")
    add_common_arguments(gen)
    gen.set_defaults(func=command_gen)

    imp = subs.add_parser("import", help="Import private keys in batches (file ends with END)")
    imp.add_argument("-i", "--in", dest="file", help="Private key file path, - indicates standard input")
    imp.add_argument("keys", nargs="*", help="You can also directly give several WIF/hex private keys")
    imp.add_argument("--force-compression", action="store_true", help="Ignore the original flag and derive it uniformly according to the compressed public key")
    imp.add_argument("--force-uncompressed", action="store_true", help="Uniformly derived from uncompressed public keys")
    imp.add_argument("--strict", action="store_true", help="Returns a non-zero exit code when there is a line that failed to parse")
    add_common_arguments(imp)
    imp.set_defaults(func=command_import)

    info = subs.add_parser("info", help="View address information")
    info.add_argument("addresses", nargs="*", help="one or more addresses")
    info.add_argument("-i", "--in", dest="file", help="Address file path (split by white space)")
    info.add_argument("-f", "--format", dest="format", default="block",
                      choices=["block", "csv", "json"], help="Output format (default block)")
    info.add_argument("-o", "--out", default="-", help="Output file, - means standard output")
    info.add_argument("--strict", action="store_true", help="Returns a non-zero exit code when there is an unresolvable address")
    info.set_defaults(func=command_info)

    test = subs.add_parser("selftest", help="self-test")
    test.add_argument("-v", "--verbose", action="store_true", help="Item-by-item print inspection process")
    test.set_defaults(func=command_selftest)
    return parser


def run_command(arguments):
    """Command line mode: parse parameters and execute corresponding subcommands."""
    args = build_parser().parse_args(arguments)
    if hasattr(args, "kinds"):
        args.kinds = split_script_kinds(args.kinds)
        if args.kinds is None:
            return 2
    try:
        return args.func(args)
    except (KeyboardInterrupt, EOFError):
        print("\nInterrupted.", file=sys.stderr)
        return 130


def main():
    """Entry: Enter the interactive menu without command line parameters, otherwise use sub-commands."""
    enable_utf8_console()
    arguments = sys.argv[1:]
    if arguments:
        return run_command(arguments)
    return run_interactive()


if __name__ == "__main__":
    sys.exit(main())
