#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =================================================================
# Bitcoin Multisig Address Generation and Verification Tool — V2
#
# Double-click this file (or run it without arguments) to open the interactive menu;
# the CLI subcommands work from the command line too.
#
# Two multisig mechanisms are supported. They are different, so do not mix them:
#
# 1) Native SegWit multisig (P2WSH), addresses start with bc1q, m-of-n
#    Script: OP_m <pubkey 1> ... <pubkey n> OP_n OP_CHECKMULTISIG
#    Address: bech32(witness v0, hash160(witnessScript))
#    Properties: any m members can sign to spend; changing the member set changes the address.
#
# 2) Taproot multisig, addresses start with bc1p (P2TR script path), N-of-N full signing
#    One tapscript leaf per member: <32-byte x-only pubkey> OP_CHECKSIG
#    The leaves form a TapTree to get the merkle root, which tweaks the NUMS internal key.
#    Address: bech32m(witness v1, output_key)
#    Properties: all members must sign; none may be missing. Taproot has no OP_CHECKMULTISIG,
#    so m-of-n is impossible in script; the common alternative is MuSig2 key aggregation,
#    or the script-path + full-signing approach used by this file.
#    Security: the internal key is the BIP341 NUMS point, whose discrete log is unknown,
#    so the key path cannot be spent; funds can move only via the script path with every
#    member signing. The internal key must NOT be the base point G — G's discrete log is 1,
#    so anyone could compute the tweaked private key and bypass the multisig entirely.
#
# Member input: WIF private key / 64-hex private key / decimal private key /
# 33-byte compressed pubkey / 65-byte uncompressed pubkey / 32-byte x-only pubkey (Taproot only)
#
# -----------------------------------------------------------------
# Implementation notes: prefer installed libraries (coincurve/ecdsa/bech32m/bech32/base58);
# any that are missing fall back to the equivalent built-in implementations in this file,
# so a single copied file still runs. No wallet-level or third-party multisig wrapper is used;
# signature hashes are implemented directly from the BIP specifications.
# =================================================================
import argparse
import hashlib
import hmac
import json
import os
import secrets
import sys
import time

if os.name == "nt":                               # Console encoding fix is only needed on Windows
    import ctypes
else:
    ctypes = None
#================= Optional encoding library: base58 =================
try:                                             # Prefer: pip install base58
    import base58
    HAVE_BASE58 = True
except ImportError:                              # Fall back to the built-in implementation
    HAVE_BASE58 = False

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"  # Omits easily confused characters 0 O I l


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
MAINNET = {                                    # This tool only works on the mainnet: Base58 version byte + Bech32 HRP
    "name": "Bitcoin mainnet", "p2pkh": 0x00, "p2sh": 0x05, "hrp": "bc",
}
HRP_NAMES = {"bc": "Mainnet", "tb": "testnet", "bcrt": "Regtest"}   # Only used to label external addresses
KNOWN_VERSIONS = {                                          # Base58 address version byte meaning
    0x00: "P2PKH Mainnet", 0x05: "P2SH mainnet",
    0x6F: "P2PKH testnet/Regtest", 0xC4: "P2SH testnet/Regtest",
}




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

#================= Script construction primitives =================
OP_CHECKSIG = 0xAC
OP_CHECKSIGVERIFY = 0xAD
OP_CHECKMULTISIG = 0xAE

LEAF_TAPSCRIPT = 0xC0             # BIP341 leaf version 0xc0
TAPSCRIPT_MAX_SIZE = 10_000       # Tapscript length limit
MAX_MULTISIG_KEYS = 16            # OP_CHECKMULTISIG up to 16 public keys


def compact_size(number):
    """Bitcoin variable-length integer (compact_size) encoding."""
    if number < 0:
        raise ValueError("compact_size cannot be negative")
    if number < 0xFD:
        return bytes([number])
    if number <= 0xFFFF:
        return b"\xfd" + number.to_bytes(2, "little")
    if number <= 0xFFFFFFFF:
        return b"\xfe" + number.to_bytes(4, "little")
    if number <= 0xFFFFFFFFFFFFFFFF:
        return b"\xff" + number.to_bytes(8, "little")
    raise ValueError("compact_size is outside the 64-bit range")


def push_data(data):
    """Push data into the script stack: compact_size(length) + data."""
    return compact_size(len(data)) + data


def push_opcode(number):
    """Push a number from 0 to 16.

OP_0 is 0x00, OP_1..OP_16 is 0x51..0x60.
Never write bytes([number]) directly - that will get 0x01..0x10, which is not a legal opcode.
    """
    if not 0 <= number <= MAX_MULTISIG_KEYS:
        raise ValueError("Only OP_0 to OP_16 are supported. The m/n of multi-signature cannot exceed this range.")
    return b"" if number == 0 else bytes([0x50 + number])


#================= Public key processing =================
def is_valid_pubkey(data):
    """Verify that the public key bytes actually fall on the secp256k1 curve."""
    try:
        if len(data) == 33 and data[0] in (2, 3):
            # Compressed public key: lift_x success means that x³+7 is a quadratic remainder, and both prefixes are legal
            return lift_x(data[1:]) is not None
        if len(data) == 65 and data[0] == 4:
            x = int.from_bytes(data[1:33], "big")
            y = int.from_bytes(data[33:], "big")
            if not 0 <= x < PRIME or not 0 <= y < PRIME:
                return False
            return (y * y - x * x * x - CURVE_B) % PRIME == 0
        if len(data) == 32:
            return lift_x(data) is not None
    except ValueError:
        return False
    return False


def compressed_pubkey(secret):
    """Private key -> 33-byte compressed public key (multi-signature scripts must use compressed format)."""
    return public_key_bytes(secret_to_point(secret), True)


def parse_pubkey(text):
    """Unify the public key text entered by the user into bytes (33 / 65 / 32 bytes)."""
    cleaned = text.strip()
    if not cleaned:
        raise ValueError("Public key is empty")
    try:
        data = bytes.fromhex(cleaned)
    except ValueError:
        raise ValueError("Public key must be in hexadecimal")
    if not is_valid_pubkey(data):
        raise ValueError("This is not a valid secp256k1 public key")
    return data


def pubkey_to_xonly(data):
    """Public key -> 32 bytes x-only (BIP340 Taproot only recognizes x-coordinates)."""
    if len(data) == 32:
        return data
    if len(data) == 33:
        return data[1:]
    if len(data) == 65 and data[0] == 4:
        return data[1:33]
    raise ValueError("The public key length is wrong, it should be 32 / 33 / 65 bytes")


def pubkey_to_compressed(data):
    """Public key -> 33 bytes compressed public key; x-only prefixed according to even y convention (EIP-340 rules)."""
    if len(data) == 33:
        return data
    if len(data) == 32:
        return bytes([0x02]) + data
    if len(data) == 65 and data[0] == 4:
        return bytes([0x02 + (int.from_bytes(data[33:], "big") & 1)]) + data[1:33]
    raise ValueError("The public key length is wrong, it should be 32 / 33 / 65 bytes")


def key_fingerprint(pubkey):
    """BIP32 fingerprint = the first 4 bytes of hash160 (compressed public key), used to number members during multi-signature coordination."""
    return hash160(pubkey_to_compressed(pubkey))[:4].hex()


def sort_keys_bip67(pubkeys):
    """BIP67: Sort by public key bytes in ascending order.

For multi-signatures, everyone must use the same order, otherwise the addresses calculated by each will be different and the money will go to the wrong address.
    """
    return sorted(pubkeys)


def sort_keys_by_fingerprint(pubkeys):
    """Sort by fingerprint (old practice before BIP67), only used to compare old wallets."""
    return sorted(pubkeys, key=lambda item: (hash160(item)[:4], item))


#================= P2WSH multi-sign (bc1q, m-of-n) =================
def multisig_witness_script(threshold, pubkeys):
    """Construct OP_m <pubkeys...> OP_n OP_CHECKMULTISIG.

threshold = several member signatures required (m), pubkeys = public keys of all members (n).
    """
    if not pubkeys:
        raise ValueError("There must be at least one member public key")
    count = len(pubkeys)
    if not 1 <= threshold <= count:
        raise ValueError("Requires signatures from %d individuals, but only %d members total" % (threshold, count))
    if count > MAX_MULTISIG_KEYS:
        raise ValueError("Bitcoin's OP_CHECKMULTISIG only supports up to 16 public keys")
    body = b"".join(push_data(pubkey) for pubkey in pubkeys)
    return push_opcode(threshold) + body + push_opcode(count) + bytes([OP_CHECKMULTISIG])


def p2wsh_script_pubkey(witness_script):
    """P2WSH's scriptPubKey: OP_0 <20 bytes hash160(witnessScript)>."""
    return b"\x00\x14" + hash160(witness_script)


def p2sh_p2wsh_script_pubkey(witness_script):
    """P2SH-P2WSH's scriptPubKey (compatible with old wallets)."""
    return b"\xa9\x14" + hash160(b"\x00\x14" + hash160(witness_script)) + b"\x87"


def p2sh_script_pubkey(redeem_script):
    """scriptPubKey for old P2SH."""
    return b"\xa9\x14" + hash160(redeem_script) + b"\x87"


def address_from_script_pubkey(script_pubkey):
    """scriptPubKey -> address (including SegWit / P2SH-P2WSH / P2SH)."""
    if len(script_pubkey) == 22 and script_pubkey[0] == 0x00 and script_pubkey[1] == 0x14:
        witness_script = None                 # Only hash, script cannot be restored
        return segwit_encode(MAINNET["hrp"], 0, script_pubkey[2:22]), witness_script
    if (len(script_pubkey) == 23 and script_pubkey[0] == 0xA9 and script_pubkey[1] == 0x14
            and script_pubkey[-1] == 0x87):
        return base58check_encode(bytes([MAINNET["p2sh"]]) + script_pubkey[2:22]), None
    raise ValueError("scriptPubKey is not supported by this tool")


def p2wsh_address(witness_script):
    """Native SegWit multi-signature address bc1q... (witness v0 + hash160)."""
    return segwit_encode(MAINNET["hrp"], 0, hash160(witness_script))


def p2sh_p2wsh_address(witness_script):
    """P2SH package P2WSH compatible address 3...."""
    nested = b"\x00\x14" + hash160(witness_script)
    return base58check_encode(bytes([MAINNET["p2sh"]]) + hash160(nested))


def p2sh_multisig_address(redeem_script):
    """Old P2SH multi-signature address 3... (not recommended, all new wallets use P2WSH)."""
    return base58check_encode(bytes([MAINNET["p2sh"]]) + hash160(redeem_script))


#================= Taproot (bc1p, script path, N-of-N full signature) =================
# The NUMS point of BIP341: No one knows its discrete logarithm, so the key path cannot be spent, and money can only be spent on the script path.
# The internal public key must not be replaced by the base point G - the discrete logarithm of G is 1, anyone can figure out the tweak and private key it themselves,
# This is equivalent to completely bypassing multi-signature. NUMS is always used here.
NUMS_X = bytes.fromhex("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")


def tapleaf_hash(script, leaf_version=LEAF_TAPSCRIPT):
    """BIP341 leaf hash = tagged_hash(\"TapLeaf\", leaf version || script length || script)."""
    if not 0xC0 <= leaf_version <= 0xFE:
        raise ValueError("Currently only tapscript leaf version 0xc0 is supported")
    if len(script) > TAPSCRIPT_MAX_SIZE:
        raise ValueError("tapscript exceeds 10KB limit")
    return tagged_hash("TapLeaf", bytes([leaf_version]) + compact_size(len(script)) + script)


def tapbranch_hash(first, second):
    """BIP341 branch hashing: the two sub-hashes are arranged in ascending byte order and then hashed (the order cannot be reversed)."""
    low, high = sorted([first, second])
    return tagged_hash("TapBranch", low + high)


def build_taptree(leaf_hashes):
    """A TapTree is constructed from a list of leaf hashes.

Returns (merkle_root, paths), paths[i] is the side hash list of the i-th leaf (from bottom to top).
When there are an odd number of leaves, cut into \"left = first floor(n/2), right = remaining\", so n=3 is obtained
[l0, [l1, l2]], consistent with the BIP341 official vector.
Note that BIP341 itself does not specify a tree shape: changing the same set of public keys to a different tree shape means changing the bc1p address.
Therefore, the participating parties must agree on the tree shape (which must also be reflected in PSBT).
    """
    if not leaf_hashes:
        raise ValueError("TapTree must have at least one leaf")

    def build(items):
        """items = [(index, leaf hash)] -> (root hash, {index: [side branch...]})"""
        if len(items) == 1:
            index, digest = items[0]
            return digest, {index: []}
        split = len(items) // 2
        left_root, left_paths = build(items[:split])
        right_root, right_paths = build(items[split:])
        paths = {}
        for index, siblings in left_paths.items():
            paths[index] = siblings + [right_root]
        for index, siblings in right_paths.items():
            paths[index] = siblings + [left_root]
        return tapbranch_hash(left_root, right_root), paths

    root, paths = build(list(enumerate(leaf_hashes)))
    return root, [paths[index] for index in range(len(leaf_hashes))]


def tapscript_leaf_for_key(pubkey_x32):
    """Single-member tapscript leaf script: <32-byte x-only public key> OP_CHECKSIG."""
    if len(pubkey_x32) != 32:
        raise ValueError("Taproot leaf public key must be 32 bytes x-only")
    return push_data(pubkey_x32) + bytes([OP_CHECKSIG])


def tapscript_chain_for_keys(pubkeys_x32):
    """String N public keys into a tapscript: CHECKSIGVERIFY at the front and CHECKSIG at the end.

This is the correct structure for bc1p to implement \"full signature\". Taproot does not have OP_CHECKMULTISIG,
If you want N people to sign, you have to write a signature chain by hand; if one signature chain is missing, the chain will be broken and the script will inevitably fail.
    """
    if not pubkeys_x32:
        raise ValueError("There must be at least one member public key")
    parts = []
    last = len(pubkeys_x32) - 1
    for position, pubkey in enumerate(pubkeys_x32):
        parts.append(push_data(pubkey))
        parts.append(bytes([OP_CHECKSIG if position == last else OP_CHECKSIGVERIFY]))
    return b"".join(parts)


def build_taproot_plan(pubkeys_x32, layout="chain", internal_x=NUMS_X):
    """Turn a set of member public keys into a complete bc1p scheme.

layout=\"chain\" (default, and the only structure that can truly force everyone to sign):
A single leaf, script is a chain of N CHECKSIGs.

layout=\"tree\":
Each member has a leaf, forming a TapTree. In this way, the address can also be calculated, but the script path of BIP341
Spending one time can only prove one leaf, so it cannot express \"multiple people signing at the same time\".
It is only suitable for locking mutually exclusive alternative scripts into the same address. This document retains it for alignment
BIP341 official vector, and provides tree options for users familiar with PSBT.

The return value includes leaf script, merkle root, control block, output public key and witness stack template.
    """
    keys = sorted(pubkeys_x32)
    if not keys:
        raise ValueError("There must be at least one member public key")
    if len(set(keys)) != len(keys):
        raise ValueError("There are duplicate member public keys")

    if layout == "chain":
        script = tapscript_chain_for_keys(keys)
        root = tapleaf_hash(script)
        output_point = taproot_output_point(internal_x, root)
        output_key = output_point[0].to_bytes(32, "big")
        return {
            "layout": "chain",
            "keys": keys,
            "leaf_scripts": [script],
            "merkle_root": root,
            "merkle_paths": [[]],
            "control_blocks": [taproot_control_block([], output_point)],
            "output_point": output_point,
            "output_key": output_key,
            "script_pubkey": b"\x51\x20" + output_key,
            "signature_count": len(keys),
        }

    scripts = [tapscript_leaf_for_key(key) for key in keys]
    root, paths = build_taptree([tapleaf_hash(script) for script in scripts])
    output_point = taproot_output_point(internal_x, root)
    output_key = output_point[0].to_bytes(32, "big")
    return {
        "layout": "tree",
        "keys": keys,
        "leaf_scripts": scripts,
        "merkle_root": root,
        "merkle_paths": paths,
        "control_blocks": [taproot_control_block(paths[index], output_point)
                           for index in range(len(scripts))],
        "output_point": output_point,
        "output_key": output_key,
        "script_pubkey": b"\x51\x20" + output_key,
        "signature_count": len(scripts),
    }


def taproot_tweak(internal_x, merkle_root=None):
    """t = tagged_hash(\"TapTweak\", internal public key x || merkle root).

Note that there is no 0x00 prefix here (the final version of BIP341 is directly spliced).
The early draft was written as 0x00 || p || merkleRoot. If you copy the draft, the calculated address will be wrong.
    """
    return tagged_hash("TapTweak", internal_x + (merkle_root or b""))


def taproot_output_point(internal_x, merkle_root=None):
    """Q = lift_x(internal public key) + t*G, returns the output point (x, y).

According to BIP341, the curve order t >= is invalid (fails directly instead of taking modulo the order).
    """
    tweak = int.from_bytes(taproot_tweak(internal_x, merkle_root), "big")
    if tweak >= ORDER:
        raise ValueError("TapTweak beyond curve level")
    output = point_add(lift_x(internal_x), secret_to_point(tweak))
    if output is None:
        raise ValueError("The output point is an infinite point")
    return output


def taproot_output_key(internal_x, merkle_root=None):
    """Taproot outputs the public key (32 bytes x coordinate)."""
    return taproot_output_point(internal_x, merkle_root)[0].to_bytes(32, "big")


def taproot_script_pubkey(internal_x, merkle_root=None):
    """P2TR's scriptPubKey: OP_1 <32 bytes output_key>."""
    return b"\x51\x20" + taproot_output_key(internal_x, merkle_root)


def taproot_address(merkle_root, internal_x=NUMS_X):
    """bc1p... address = bech32m(witness v1, output_key)."""
    return segwit_encode(MAINNET["hrp"], 1,
                         taproot_output_key(internal_x, merkle_root))


def taproot_control_block(merkle_path, output_point, internal_x=NUMS_X,
                          leaf_version=LEAF_TAPSCRIPT):
    """Control block = (leaf version | output point parity bits) || internal public key || side hash sequence.

The verifier can use the side branch to recalculate the merkle root and then recalculate the tweak to confirm that the leaf indeed belongs to the address.
There is no way to shoehorn other scripts in.
    """
    parity = output_point[1] & 1
    return bytes([(leaf_version & 0xFE) | parity]) + internal_x + b"".join(merkle_path)
#================= Transaction analysis (used to calculate signature hash) =================
class TxInput(object):
    """A transaction input. Outpoint directly stores 36 bytes (txid little endian + index little endian)."""

    def __init__(self, outpoint, script_sig=b"", sequence=0xFFFFFFFF, witness=None):
        self.outpoint = outpoint
        self.script_sig = script_sig
        self.sequence = sequence
        self.witness = list(witness or [])


def make_outpoint(txid_hex, index):
    """Transaction hash hex (positive order) + index -> 36 bytes outpoint (internal little endian)."""
    raw = bytes.fromhex(txid_hex)[::-1]
    return raw + index.to_bytes(4, "little")


class TxOutput(object):
    def __init__(self, value, script_pubkey):
        self.value = value
        self.script_pubkey = script_pubkey

    def serialize(self):
        return self.value.to_bytes(8, "little") + compact_size(len(self.script_pubkey)) + self.script_pubkey


class Transaction(object):
    def __init__(self, version=2, inputs=None, outputs=None, locktime=0):
        self.version = version
        self.inputs = list(inputs or [])
        self.outputs = list(outputs or [])
        self.locktime = locktime

    def serialize(self, with_witness=False):
        """Output SegWit format (0x00 0x01 + witness data) when with_witness=True.

Pay attention to the field order (BIP144):
            version | marker | flag | txins | txouts | witnesses | locktime
The witness data is sandwiched between the output and the locktime, not behind the locktime.
        """
        has_witness = any(item.witness for item in self.inputs)
        use_witness = bool(with_witness and has_witness)
        body = self.version.to_bytes(4, "little")
        if use_witness:
            body += b"\x00\x01"
        body += compact_size(len(self.inputs))
        for item in self.inputs:
            body += item.outpoint + compact_size(len(item.script_sig)) + item.script_sig
            body += item.sequence.to_bytes(4, "little")
        body += compact_size(len(self.outputs))
        for item in self.outputs:
            body += item.serialize()
        if use_witness:
            for item in self.inputs:
                body += compact_size(len(item.witness))
                for element in item.witness:
                    body += compact_size(len(element)) + element
        body += self.locktime.to_bytes(4, "little")
        return body


def read_compact_size(data, offset):
    """Read compact_size from data[offset:], return (number, new offset)."""
    if offset >= len(data):
        raise ValueError("Data ends early when reading length")
    first = data[offset]
    offset += 1
    if first < 0xFD:
        return first, offset
    sizes = {0xFD: 2, 0xFE: 4, 0xFF: 8}
    if first not in sizes:
        raise ValueError("The first byte of compact_size is illegal: 0x%02x" % first)
    width = sizes[first]
    if offset + width > len(data):
        raise ValueError("Data ends early when reading length")
    return int.from_bytes(data[offset:offset + width], "little"), offset + width


def read_compact_size_item(data, offset):
    """Read compact_size + the subsequent data and return (data, new offset)."""
    length, offset = read_compact_size(data, offset)
    if offset + length > len(data):
        raise ValueError("Data ends early while reading content")
    return data[offset:offset + length], offset + length


def parse_transaction(raw):
    """Parse the original transaction bytes and return Transaction."""
    if len(raw) < 10:
        raise ValueError("Transaction data is too short")
    offset = 0
    version = int.from_bytes(raw[offset:offset + 4], "little")
    offset += 4
    marker = None
    if raw[offset:offset + 2] == b"\x00\x01":
        marker = raw[offset:offset + 2]
        offset += 2
    count, offset = read_compact_size(raw, offset)
    inputs = []
    for _ in range(count):
        outpoint = raw[offset:offset + 36]
        if len(outpoint) != 36:
            raise ValueError("Transaction input was truncated")
        offset += 36
        script_sig, offset = read_compact_size_item(raw, offset)
        sequence = int.from_bytes(raw[offset:offset + 4], "little")
        offset += 4
        inputs.append(TxInput(outpoint, script_sig, sequence))
    count, offset = read_compact_size(raw, offset)
    outputs = []
    for _ in range(count):
        value = int.from_bytes(raw[offset:offset + 8], "little")
        offset += 8
        script_pubkey, offset = read_compact_size_item(raw, offset)
        outputs.append(TxOutput(value, script_pubkey))
    # Witness data after output but before locktime (BIP144)
    if marker is not None:
        for item in inputs:
            element_count, offset = read_compact_size(raw, offset)
            witness = []
            for _ in range(element_count):
                element, offset = read_compact_size_item(raw, offset)
                witness.append(element)
            item.witness = witness
    locktime = int.from_bytes(raw[offset:offset + 4], "little")
    offset += 4
    if offset != len(raw):
        raise ValueError("There are extra bytes at the end of the transaction data")
    return Transaction(version, inputs, outputs, locktime)


#================= Signature Hash Type =================
SIGHASH_ALL = 0x01
SIGHASH_NONE = 0x02
SIGHASH_SINGLE = 0x03
SIGHASH_ANYONECANPAY = 0x80
SIGHASH_DEFAULT = 0x00


def sighash_base_type(hash_type):
    return hash_type & 0x1F


def sighash_is_anyonecanpay(hash_type):
    return bool(hash_type & SIGHASH_ANYONECANPAY)


#================= BIP143: Native SegWit (P2WSH / P2WPKH) signed hashes =================
def bip143_sighash(tx, input_index, script_code, amount, hash_type=SIGHASH_ALL):
    """BIP143 Compute signature hashes for native SegWit inputs.

script_code for P2WSH is witnessScript itself (without length prefix,
compact_size is added when serialized into preimage), which is different from P2SH-P2WSH.
    """
    base_type = sighash_base_type(hash_type)
    anyone_can_pay = sighash_is_anyonecanpay(hash_type)
    anyone_or_none = anyone_can_pay or base_type in (SIGHASH_NONE, SIGHASH_SINGLE)

    # Note: Do not use the sentinel value of the old algorithm \"0x01 is returned when the input sequence number exceeds the output number\".
    # BIP143 explicitly requires hashOutputs to be set to 32 zeros at this time, the semantics remain the same but the hashes are different.
    if anyone_can_pay:
        hash_prevouts = b"\x00" * 32
    else:
        hash_prevouts = double_sha256(b"".join(item.outpoint for item in tx.inputs))
    hash_sequence = (b"\x00" * 32 if anyone_or_none
                     else double_sha256(b"".join(item.sequence.to_bytes(4, "little")
                                                 for item in tx.inputs)))

    # hashOutputs is determined only by base_type and has nothing to do with ANYONECANPAY:
    # Neither SINGLE nor NONE -> output all; SINGLE and the sequence number is within the range -> output the same sequence number; the rest are 0.
    if base_type == SIGHASH_SINGLE:
        hash_outputs = (double_sha256(tx.outputs[input_index].serialize())
                        if input_index < len(tx.outputs) else b"\x00" * 32)
    elif base_type == SIGHASH_NONE:
        hash_outputs = b"\x00" * 32
    else:
        hash_outputs = double_sha256(b"".join(item.serialize() for item in tx.outputs))

    preimage = tx.version.to_bytes(4, "little")
    preimage += hash_prevouts + hash_sequence
    preimage += tx.inputs[input_index].outpoint
    preimage += compact_size(len(script_code)) + script_code
    preimage += amount.to_bytes(8, "little")
    preimage += tx.inputs[input_index].sequence.to_bytes(4, "little")
    preimage += hash_outputs
    preimage += tx.locktime.to_bytes(4, "little")
    preimage += hash_type.to_bytes(4, "little")
    return double_sha256(preimage)


#================= BIP341: Taproot Signature Hash =================
def taproot_sighash(tx, input_index, prevout_scripts, prevout_amounts, hash_type=SIGHASH_DEFAULT,
                    ext_flag=0, annex=None, script=None, leaf_version=LEAF_TAPSCRIPT,
                    codeseparator_pos=0xFFFFFFFF):
    """BIP341 SigMsg -> TapSighash.

prevout_scripts / prevout_amounts must be all input scriptPubKey and amounts,
Because even with ANYONECANPAY, Taproot hashes all of this information entered together.
    """
    if len(prevout_scripts) != len(tx.inputs) or len(prevout_amounts) != len(tx.inputs):
        raise ValueError("A scriptPubKey and amount must be provided for each input")
    base_type = hash_type & 0x03
    anyone_can_pay = sighash_is_anyonecanpay(hash_type)

    zero32 = b"\x00" * 32
    if anyone_can_pay:
        sha_prevouts = sha_amounts = sha_scriptpubkeys = sha_sequences = zero32
    else:
        sha_prevouts = sha256(b"".join(item.outpoint for item in tx.inputs))
        sha_amounts = sha256(b"".join(value.to_bytes(8, "little") for value in prevout_amounts))
        sha_scriptpubkeys = sha256(b"".join(compact_size(len(item)) + item
                                             for item in prevout_scripts))
        sha_sequences = sha256(b"".join(item.sequence.to_bytes(4, "little")
                                        for item in tx.inputs))

    message = bytes([hash_type & 0xFF])
    message += tx.version.to_bytes(4, "little")
    message += tx.locktime.to_bytes(4, "little")
    # When not ANYONECANPAY, these four hashes immediately follow nLockTime (BIP341 SigMsg order)
    if not anyone_can_pay:
        message += sha_prevouts + sha_amounts + sha_scriptpubkeys + sha_sequences

    # BIP341: When hash_type & 3 is NONE or SINGLE, sha_outputs is **entirely omitted**,
    # Instead of filling in 32 zeros. Padding with zeros results in a completely different hash.
    if base_type not in (SIGHASH_NONE, SIGHASH_SINGLE):
        message += sha256(b"".join(item.serialize() for item in tx.outputs))

    spend_type = ext_flag * 2 + (1 if annex is not None else 0)
    message += bytes([spend_type])
    if anyone_can_pay:
        item = tx.inputs[input_index]
        message += item.outpoint
        message += prevout_amounts[input_index].to_bytes(8, "little")
        message += compact_size(len(prevout_scripts[input_index])) + prevout_scripts[input_index]
        message += item.sequence.to_bytes(4, "little")
    else:
        message += input_index.to_bytes(4, "little")
    if annex is not None:
        message += sha256(compact_size(len(annex)) + annex)
    if base_type == SIGHASH_SINGLE:
        if input_index >= len(tx.outputs):
            raise ValueError("SIGHASH_SINGLE When the input sequence number exceeds the output quantity")
        message += sha256(tx.outputs[input_index].serialize())
    # BIP342 script-path extension: if script is given, it must be connected
    # tapleaf_hash(32) || key_version(1) || codesep_pos(4, little endian).
    # Note that codesep_pos is **fixed 4 bytes** and will be written as 0xffffffff when OP_CODESEPARATOR has not been executed.
    # Not omitted - leaving out those 37 bytes would result in a completely different hash.
    if script is not None:
        message += tapleaf_hash(script, leaf_version)
        message += b"\x00"
        message += codeseparator_pos.to_bytes(4, "little")
    return tagged_hash("TapSighash", b"\x00" + message)


#================= ECDSA (for bc1q multi-signature) =================
def parse_der_signature(der):
    """Parses a DER-encoded signature, returning (r, s). Format: 30 <len> 02 <len> r 02 <len> s."""
    if len(der) < 8 or der[0] != 0x30:
        raise ValueError("Not a DER signature (first byte should be 0x30)")
    if der[1] != len(der) - 2:
        raise ValueError("The total length of DER does not match")
    if der[2] != 0x02:
        raise ValueError("Missing r tag in DER")
    r_length = der[3]
    r_start = 4
    r_end = r_start + r_length
    if der[r_end] != 0x02:
        raise ValueError("Missing s tag in DER")
    s_length = der[r_end + 1]
    s_value = der[r_end + 2:r_end + 2 + s_length]
    if r_end + 2 + s_length != len(der):
        raise ValueError("DER has extra data at the end")
    return int.from_bytes(der[r_start:r_end], "big"), int.from_bytes(s_value, "big")


def point_negate(point):
    """The curve point is inverted (x, -y)."""
    return point[0], (PRIME - point[1]) % PRIME


def scalar_multiply(point, scalar):
    """Universal scalar multiplication, point is None to indicate a point at infinity."""
    scalar %= ORDER
    result = None
    addend = point
    while scalar:
        if scalar & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        scalar >>= 1
    return result


def ecdsa_verify(message_hash, der_signature, pubkey):
    """Built-in ECDSA signature verification, returns True / False."""
    try:
        r, s = parse_der_signature(der_signature)
    except ValueError:
        return False
    if not 1 <= r < ORDER or not 1 <= s < ORDER:
        return False
    compressed = pubkey_to_compressed(pubkey)
    if not is_valid_pubkey(compressed):
        return False
    # lift_x only gives points with even numbers y; if the odd or even prefix is wrong, it will be inverted to get the real y
    target = lift_x(compressed[1:])
    if (2 + (target[1] & 1)) != compressed[0]:
        target = point_negate(target)
    value = int.from_bytes(message_hash, "big") % ORDER
    inverse = pow(s, ORDER - 2, ORDER)
    combined = point_add(_base_multiply(value * inverse % ORDER),
                         scalar_multiply(target, r * inverse % ORDER))
    if combined is None:
        return False
    return combined[0] % ORDER == r


def _base_multiply(scalar):
    """Scalar times base point G."""
    return secret_to_point(scalar)


#================= Schnorr / BIP340 (for bc1p) =================
BASE_POINT = (BASE_X, BASE_Y)


def schnorr_sign(message32, secret, aux_rand32=None):
    """BIP340 Schnorr signature, for self-checking and testing purposes only."""
    if len(message32) != 32:
        raise ValueError("Message hash must be 32 bytes")
    if aux_rand32 is not None and len(aux_rand32) != 32:
        raise ValueError("aux_rand must be 32 bytes")
    point = secret_to_point(secret)
    xonly = point[0].to_bytes(32, "big")
    # If y is an odd number, invert the private key to ensure that the d used corresponds to an even number y.
    adjusted = secret if not point[1] & 1 else ORDER - secret
    padded = adjusted.to_bytes(32, "big")
    for _ in range(64):
        aux = aux_rand32 if aux_rand32 is not None else secrets.token_bytes(32)
        mask = int.from_bytes(tagged_hash("BIP0340/aux", aux), "big")
        nonce_input = (int.from_bytes(padded, "big") ^ mask).to_bytes(32, "big")
        candidate = int.from_bytes(tagged_hash("BIP0340/nonce", nonce_input + xonly + message32),
                                   "big") % ORDER
        if candidate == 0:
            continue
        nonce_point = secret_to_point(candidate)
        nonce = candidate if not nonce_point[1] & 1 else ORDER - candidate
        challenge = int.from_bytes(tagged_hash("BIP0340/challenge",
                                               nonce_point[0].to_bytes(32, "big") + xonly + message32),
                                   "big") % ORDER
        signature = nonce_point[0].to_bytes(32, "big") + ((nonce + challenge * adjusted)
                                                          % ORDER).to_bytes(32, "big")
        if schnorr_verify(message32, xonly, signature):
            return signature
    raise ValueError("Schnorr signing failed, retried 64 times")


def schnorr_verify(message32, pubkey_x32, signature64):
    """BIP340 Schnorr signature verification, returns True / False."""
    if len(message32) != 32 or len(pubkey_x32) != 32 or len(signature64) != 64:
        return False
    try:
        target = lift_x(pubkey_x32)
    except ValueError:
        return False
    r = int.from_bytes(signature64[:32], "big")
    s = int.from_bytes(signature64[32:], "big")
    if r >= PRIME or s >= ORDER:
        return False
    challenge = int.from_bytes(tagged_hash("BIP0340/challenge",
                                           signature64[:32] + pubkey_x32 + message32),
                               "big") % ORDER
    recovered = point_add(secret_to_point(s), point_negate(scalar_multiply(target, challenge)))
    if recovered is None:
        return False
    if recovered[1] & 1:
        return False
    return recovered[0] == r


#================= BIP32: Get member public keys from xpub (real multi-signatures are coordinated with xpub) =================
XPUB_VERSIONS = {
    0x0488B21E: "xpub", 0x043587CF: "tpub",
    0x043587D3: "ypub", 0x043583FF: "upub",
    0x044A5262: "zpub", 0x044A4E28: "vpub",
}


class ExtendedKey(object):
    def __init__(self, chain_code, pubkey, depth=0, fingerprint=b"\x00\x00\x00\x00", child_index=0):
        self.chain_code = chain_code
        self.pubkey = pubkey
        self.depth = depth
        self.fingerprint = fingerprint
        self.child_index = child_index


def parse_extended_key(text):
    """Parse xpub/tpub."""
    payload = base58check_decode(text.strip())
    if len(payload) != 78:
        raise ValueError("Extended public key length is wrong, should be 78 bytes")
    version = int.from_bytes(payload[0:4], "big")
    depth = payload[4]
    fingerprint = payload[5:9]
    child_index = int.from_bytes(payload[9:13], "big")
    chain_code = payload[13:45]
    pubkey = payload[45:78]
    if not is_valid_pubkey(pubkey):
        raise ValueError("The public key in the extended public key is illegal")
    return version, ExtendedKey(chain_code, pubkey, depth, fingerprint, child_index)


def serialize_extended_key(key, version=0x0488B21E):
    """Recode ExtendedKey to xpub (required for descriptor and fingerprint display)."""
    payload = version.to_bytes(4, "big") + bytes([key.depth]) + key.fingerprint
    payload += key.child_index.to_bytes(4, "big") + key.chain_code + key.pubkey
    return base58check_encode(payload)


def derive_pubkey(parent, index):
    """BIP32 public key derivation (only non-reinforced derivation is supported, multi-sign member paths are all 0/0/*)."""
    if index >= 0x80000000:
        raise ValueError("This tool only supports non-hardened derived paths (/0/0/* and the like)")
    digest = hmac.new(parent.chain_code, parent.pubkey + index.to_bytes(4, "big"), hashlib.sha512).digest()
    left = int.from_bytes(digest[:32], "big")
    if left == 0 or left >= ORDER:
        raise ValueError("The derived key is invalid")
    parent_point = lift_x(parent.pubkey[1:])
    if (2 + (parent_point[1] & 1)) != parent.pubkey[0]:
        parent_point = point_negate(parent_point)
    child_point = point_add(secret_to_point(left), parent_point)
    if child_point is None:
        raise ValueError("The derived public key is the point at infinity")
    return ExtendedKey(digest[32:], bytes([2 + (child_point[1] & 1)]) + child_point[0].to_bytes(32, "big"),
                       parent.depth + 1, hash160(parent.pubkey)[:4], index)


def pubkey_from_descriptor_path(text):
    """Supports the writing method \"xpub.../0/0/0\".

Returns (derived public key, root xpub, derived xpub).
    """
    parts = [item.strip() for item in text.strip().split("/")]
    base = parts[0]
    if not base.lower().startswith(("xpub", "tpub")):
        return None
    version, key = parse_extended_key(base)
    root_xpub = serialize_extended_key(key, version)
    for item in parts[1:]:
        if item in ("", "*", "'", "*'"):
            raise ValueError("The derived path must be hard-coded here, wildcards cannot be used.")
        key = derive_pubkey(key, int(item))
    return key.pubkey, root_xpub, serialize_extended_key(key, version)
#================= Script executor (really run the script during Self-test) =================
OP_0 = 0x00
OP_PUSHDATA1 = 0x4C
OP_PUSHDATA2 = 0x4D
OP_PUSHDATA4 = 0x4E
OP_1 = 0x51
OP_16 = 0x60
OP_CHECKSIG = 0xAC
OP_CHECKSIGVERIFY = 0xAD
OP_CHECKMULTISIG = 0xAE
OP_CODESEPARATOR = 0xAB


def parse_script_ops(script):
    """Split the script into [(type, value)], with type being \"data\" or \"op\"."""
    ops = []
    offset = 0
    while offset < len(script):
        opcode = script[offset]
        offset += 1
        if 1 <= opcode <= 75:
            ops.append(("data", script[offset:offset + opcode]))
            offset += opcode
        elif opcode in (OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4):
            width = {OP_PUSHDATA1: 1, OP_PUSHDATA2: 2, OP_PUSHDATA4: 4}[opcode]
            length = int.from_bytes(script[offset:offset + width], "little")
            offset += width
            ops.append(("data", script[offset:offset + length]))
            offset += length
        else:
            ops.append(("op", opcode))
    return ops


def push_script_number(stack, number):
    """OP_0..OP_16 is pushed onto the stack: 0 pushes a null byte, 1~16 pushes a single byte."""
    if number == 0:
        stack.append(b"")
    elif 1 <= number <= 16:
        stack.append(bytes([number]))
    else:
        raise ValueError("Script number %d exceeds OP_0..OP_16" % number)


def push_opcode_number(stack, opcode):
    """Translate the **opcode** of OP_0 / OP_1..OP_16 into the number it represents and then push it onto the stack.

Opcodes and numbers are not the same thing: the opcode for OP_2 is 0x52, but the number it represents is 2.
Directly pushing the opcode byte onto the stack as a number will cause the subsequent pop_script_number to read 82.
Then all OP_CHECKMULTISIG scripts will fail to execute.
    """
    if opcode == OP_0:
        push_script_number(stack, 0)
    elif OP_1 <= opcode <= OP_16:
        push_script_number(stack, opcode - OP_1 + 1)
    else:
        raise ValueError("Opcode 0x%02x is not OP_0..OP_16" % opcode)


def pop_script_number(stack):
    """Take out the script number at the top of the stack."""
    if not stack:
        raise ValueError("The stack is empty and no number can be retrieved.")
    raw = stack.pop()
    return 0 if not raw else int.from_bytes(raw, "little")


def run_checkmultisig(stack, verify_signature):
    """The core matching logic of OP_CHECKMULTISIG copies the semantics of Bitcoin Core.

Two consensus rules that are easy to violate:
* Fails directly when the number of signatures is 0;
* Signatures must appear in public key order, and each signature can only be paired with a public key \"no earlier than the current position\".
You cannot skip the previous public key to sign the later one.
    """
    key_count = pop_script_number(stack)
    if key_count < 1 or key_count > MAX_MULTISIG_KEYS:
        return False
    if len(stack) < key_count:
        return False
    keys = [stack.pop() for _ in range(key_count)]
    sig_count = pop_script_number(stack)
    if sig_count < 1 or sig_count > key_count:
        return False
    if len(stack) < sig_count:
        return False
    signatures = [stack.pop() for _ in range(sig_count)]
    keys.reverse()                     # The stack is last in, first out, and conversely is the writing order in the script.
    signatures.reverse()
    position = 0
    for signature in signatures:
        matched = False
        while position < len(keys):
            pubkey = keys[position]
            position += 1
            if verify_signature(signature, pubkey):
                matched = True
                break
        if not matched:
            return False
    return True


def run_checksig(stack, verify_signature, require_nonempty):
    """OP_CHECKSIG: The top of the stack is the public key, and the bottom is the signature. Return the signature verification result (the caller decides whether to push it onto the stack)."""
    if len(stack) < 2:
        return False
    pubkey = stack.pop()
    signature = stack.pop()
    if not signature:
        # Empty signatures are only accepted by CHECKSIGVERIFY (anyone can spend it); ordinary CHECKSIG is not accepted.
        return not require_nonempty
    return bool(verify_signature(signature, pubkey))


def execute_multisig_script(script, stack, verify_signature):
    """Execute OP_m <keys> OP_n OP_CHECKMULTISIG this subset."""
    if not stack:
        return False
    stack.pop(0)                       # OP_CHECKMULTISIG requires an empty placeholder element at the bottom of the stack
    for kind, value in parse_script_ops(script):
        if kind == "data":
            stack.append(value)
        elif OP_0 <= value <= OP_16:
            push_opcode_number(stack, value)
        elif value == OP_CHECKMULTISIG:
            if not run_checkmultisig(stack, verify_signature):
                return False
            # The operation result of CHECKMULTISIG should be left on the top of the stack, and then it should be the only one left on the verification stack.
            #\"It's the only one left\" is a consensus requirement: if there are not enough signatures (there are things left in the stack) or too many signatures, it will fail.
            stack.append(b"\x01")
            if len(stack) != 1 or not stack[0]:
                return False
        elif value == OP_CODESEPARATOR:
            continue
        else:
            return False               # No other opcodes should appear in the script generated by this tool
    return len(stack) == 1 and bool(stack[0])


def execute_tapscript(script, stack, verify_signature):
    """Execute the subset of tapscript generated by this tool: CHECKSIGVERIFY chain + end CHECKSIG."""
    for kind, value in parse_script_ops(script):
        if kind == "data":
            stack.append(value)
        elif OP_0 <= value <= OP_16:
            push_opcode_number(stack, value)
        elif value in (OP_CHECKSIG, OP_CHECKSIGVERIFY):
            passed = run_checksig(stack, verify_signature, require_nonempty=True)
            if value == OP_CHECKSIGVERIFY:
                # The operation result of the VERIFY version is not left on the stack.
                if not passed:
                    return False
            else:
                # The result of the normal CHECKSIG operation must be left on the top of the stack
                stack.append(b"\x01" if passed else b"")
        elif value == OP_CODESEPARATOR:
            continue
        else:
            return False
    return len(stack) == 1 and bool(stack[0])


#================= Built-in ECDSA signature (for Self-test only) =================
def encode_der_signature(r, s):
    """Encode (r, s) as DER: 30 <len> 02 <len> r 02 <len> s."""
    def part(value):
        raw = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
        if raw[0] & 0x80:
            raw = b"\x00" + raw
        return b"\x02" + bytes([len(raw)]) + raw
    body = part(r) + part(s)
    return b"\x30" + bytes([len(body)]) + body


def ecdsa_sign(message_hash, secret):
    """Built-in ECDSA signature, dedicated for Self-test (please use a mature wallet or HWI for production environment)."""
    value = int.from_bytes(message_hash, "big") % ORDER
    while True:
        nonce = secrets.randbelow(ORDER - 1) + 1
        r = secret_to_point(nonce)[0] % ORDER
        if r == 0:
            continue
        s = pow(nonce, ORDER - 2, ORDER) * (value + r * secret) % ORDER
        if s == 0:
            continue
        if s > ORDER // 2:             # Low S (BIP62), consistent with mainstream wallets
            s = ORDER - s
        return encode_der_signature(r, s)


#================= End-to-end verification =================
def build_test_transaction():
    """Create a transaction for self-checking: 1 input, 1 output."""
    tx = Transaction(version=2, locktime=0)
    tx.inputs.append(TxInput(make_outpoint("00" * 32, 0), b"", 0xFFFFFFFD))
    tx.outputs.append(TxOutput(90_000, bytes.fromhex("0014") + hash160(b"\x00" * 20)))
    return tx


def verify_p2wsh_multisig(witness_script, ordered_keys, secrets_by_key, signer_count,
                          amount=100_000):
    """Construct an m-of-n witness stack and actually execute witnessScript once.

signer_count determines how many people sign, and is used to confirm that \"one less signature will inevitably fail\".
    """
    if not 1 <= signer_count <= len(ordered_keys):
        raise ValueError("The number of signatures is illegal")
    script_pubkey = p2wsh_script_pubkey(witness_script)
    tx = build_test_transaction()
    message = bip143_sighash(tx, 0, witness_script, amount, SIGHASH_ALL)
    signatures = [ecdsa_sign(message, secrets_by_key[key]) for key in ordered_keys[:signer_count]]
    for signature, key in zip(signatures, ordered_keys[:signer_count]):
        if not ecdsa_verify(message, signature, key):
            return False, "The %d signature cannot be verified" % (signer_count)
    ok = execute_multisig_script(witness_script, [b""] + signatures,
                                 lambda sig, pk: ecdsa_verify(message, sig, pk))
    label = "%d/%d member signatures" % (signer_count, len(ordered_keys))
    return ok, (label + ": Script judgment passed" if ok else label + ": Script judgment failed")


def verify_taproot_script_path(leaf_script, signatures, amount=100_000,
                                hash_type=SIGHASH_DEFAULT):
    """The script path to verify bc1p costs: control block -> merkle proof -> output public key -> signature one by one.

Only single leaf + CHECKSIG chains are supported, which is the N-of-N structure that BIP341 can really enforce:
The script path can only prove one leaf at a time, and multiple leaves can only be used to lock \"mutually exclusive alternative scripts\".
It cannot be used to require multiple people to sign at the same time.
    """
    script_pubkey = taproot_script_pubkey(NUMS_X, tapleaf_hash(leaf_script))
    control = taproot_control_block([], taproot_output_point(NUMS_X, tapleaf_hash(leaf_script)))
    tx = build_test_transaction()
    prevout_scripts = [script_pubkey]
    prevout_amounts = [amount]

    #1) From the verifier's perspective, only scriptPubKey, control block and merkle path are known.
    # Recalculate the merkle root, output public key and parity bit, which must be exactly the same as scriptPubKey.
    leaf_version = control[0] & 0xFE
    parity = control[0] & 1          # The parity bit is in the lowest bit of byte 0, not in control[1]
    merkle_path = [control[33 + 32 * i:65 + 32 * i] for i in range((len(control) - 33) // 32)]
    rebuilt_root = tapleaf_hash(leaf_script, leaf_version)
    for sibling in merkle_path:
        rebuilt_root = tapbranch_hash(rebuilt_root, sibling)
    if rebuilt_root != tapleaf_hash(leaf_script, leaf_version):
        return False, "merkle proved wrong"
    rebuilt_point = taproot_output_point(NUMS_X, rebuilt_root)
    if rebuilt_point[1] & 1 != parity:
        return False, "The parity bits of the output public key recorded in the control block do not match."
    if rebuilt_point[0].to_bytes(32, "big") != script_pubkey[2:]:
        return False, "The recalculated output public key is inconsistent with scriptPubKey"

    #2) Sign one by one. The witness stack is in reverse order: the top of the stack is the signature of the last member.
    def check(signature, pubkey_x32):
        message = taproot_sighash(tx, 0, prevout_scripts, prevout_amounts, hash_type,
                                  ext_flag=1, script=leaf_script, leaf_version=leaf_version)
        return schnorr_verify(message, pubkey_x32, signature)

    ok = execute_tapscript(leaf_script, list(signatures), check)
    label = "%d member signatures" % len(signatures)
    return ok, (label + ": tapscript passed" if ok else label + ":tapscript judgment failed")
#================= Member Analysis =================
def is_hex_text(text):
    if not text or len(text) % 2:
        return False
    try:
        bytes.fromhex(text)
    except ValueError:
        return False
    return True


def make_member(pubkey, secret=None, xpub=None, source="", descriptor_key=None):
    """Unify membership records. pubkey must be a 33-byte compressed public key."""
    return {
        "pubkey": pubkey,
        "secret": secret,
        "xpub": xpub,
        "source": source,
        "descriptor_key": descriptor_key or pubkey.hex(),
        "fingerprint": key_fingerprint(pubkey),
    }


def parse_member(text):
    """Parse a line of member input.

Support: WIF private key / 64-bit hexadecimal private key / decimal private key /
33-byte compressed public key / 65-byte uncompressed public key /
x: prefixed 32-byte x-only public key /
xpub derived path (xpub.../0/0/0)
    """
    cleaned = text.strip()
    if not cleaned:
        raise ValueError("This line is empty")
    lowered = cleaned.lower()

    if lowered.startswith("x:") or lowered.startswith("xonly:"):
        body = cleaned.split(":", 1)[1].strip()
        if not is_hex_text(body) or len(body) != 64:
            raise ValueError("x: must be followed by 64-digit hexadecimal (x-only public key)")
        data = bytes.fromhex(body)
        if not is_valid_pubkey(data):
            raise ValueError("This is not a valid x-only public key")
        return make_member(pubkey_to_compressed(data), None, None, cleaned)

    if "/" in cleaned and cleaned[:4].lower() in ("xpub", "tpub"):
        derived = pubkey_from_descriptor_path(cleaned)
        if derived is None:
            raise ValueError("The extended public key path is written incorrectly")
        pubkey, root_xpub, _ = derived
        head, _, _ = cleaned.rpartition("/")
        return make_member(pubkey, None, root_xpub, cleaned, head + "/*")

    if is_hex_text(cleaned) and len(cleaned) in (66, 130):
        data = bytes.fromhex(cleaned)
        if is_valid_pubkey(data):
            return make_member(pubkey_to_compressed(data), None, None, cleaned)

    # Reuse V1's parse_secret, which returns (private key integer, whether to compress) tuple
    secret, _compressed = parse_secret(cleaned)
    return make_member(compressed_pubkey(secret), secret, None, cleaned)


def parse_members(text, allow_blank=False):
    """Multi-line input -> member list. Empty lines will be skipped (convenient for pasting lists with empty lines directly)."""
    members = []
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip() and allow_blank:
            continue
        if not line.strip():
            continue
        try:
            members.append(parse_member(line))
        except ValueError as error:
            raise ValueError("Problem at line %d: %s" % (number, error))
    if not members:
        raise ValueError("No members read")
    fingerprints = [item["fingerprint"] for item in members]
    if len(set(fingerprints)) != len(fingerprints):
        raise ValueError("There are duplicate members (same fingerprints), please check the list")
    return members


def random_members(count):
    """Randomly generate count members (for trial runs and demos)."""
    members = []
    while len(members) < count:
        secret = generate_secret()
        member = make_member(compressed_pubkey(secret), secret, None, secret_to_wif(secret))
        if member["fingerprint"] not in [item["fingerprint"] for item in members]:
            members.append(member)
    return members


#================= Solution construction =================
def build_p2wsh_scheme(members, threshold, order="bip67"):
    """Building an m-of-n multi-signature scheme for bc1q."""
    pubkeys = [item["pubkey"] for item in members]
    if len(set(pubkeys)) != len(pubkeys):
        raise ValueError("There are duplicate member public keys")
    if order == "fingerprint":
        ordered = sort_keys_by_fingerprint(pubkeys)
    else:
        ordered = sort_keys_bip67(pubkeys)
    witness_script = multisig_witness_script(threshold, ordered)
    keys_by_pubkey = {item["pubkey"]: item for item in members}
    descriptor = "wsh(sortedmulti(%d,%s))" % (
        threshold, ",".join(keys_by_pubkey[key]["descriptor_key"] for key in ordered))
    return {
        "type": "p2wsh",
        "label": "Native SegWit multi-signature",
        "threshold": threshold,
        "members": len(ordered),
        "keys": ordered,
        "order": order,
        "witness_script": witness_script,
        "script_pubkey": p2wsh_script_pubkey(witness_script),
        "address": p2wsh_address(witness_script),
        "descriptor": descriptor,
        "note": "Once the member set is changed, the address will change, and the payment address must be re-appointed.",
    }


def build_taproot_scheme(members, layout="chain"):
    """Construct bc1p's full signature scheme."""
    xonly = [pubkey_to_xonly(item["pubkey"]) for item in members]
    plan = build_taproot_plan(xonly, layout)
    keys_by_xonly = {pubkey_to_xonly(item["pubkey"]): item for item in members}
    if layout == "chain":
        # and_v(v:pk(k1),and_v(v:pk(k2),...)) —— One-to-one correspondence with the CHECKSIGVERIFY chain
        parts = ["v:pk(%s)" % keys_by_xonly[key]["descriptor_key"] for key in plan["keys"]]
        tree = parts[-1]
        for item in reversed(parts[:-1]):
            tree = "and_v(%s,%s)" % (item, tree)
    else:
        tree = "{%s}" % ",".join("pk(%s)" % keys_by_xonly[key]["descriptor_key"]
                                 for key in plan["keys"])
    descriptor = "tr(%s,%s)" % (NUMS_X.hex(), tree)
    return {
        "type": "p2tr",
        "label": "Signed by all members of Taproot",
        "threshold": len(plan["keys"]),
        "members": len(plan["keys"]),
        "keys": plan["keys"],
        "layout": layout,
        "signature_count": plan["signature_count"],
        "leaf_scripts": plan["leaf_scripts"],
        "merkle_root": plan["merkle_root"],
        "merkle_paths": plan["merkle_paths"],
        "control_blocks": plan["control_blocks"],
        "output_key": plan["output_key"],
        "output_point": plan["output_point"],
        "script_pubkey": plan["script_pubkey"],
        "address": segwit_encode(MAINNET["hrp"], 1, plan["output_key"]),
        "descriptor": descriptor,
        "note": "Taproot does not have OP_CHECKMULTISIG. The signature of all members relies on a CHECKSIG chain, even if one is missing.",
    }


#================= Descriptor Checksum (# xxxxxxxx for BIP380) =================
DESCRIPTOR_INPUT_CHARSET = ("0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~"
                            "ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ")
DESCRIPTOR_CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
DESCRIPTOR_GENERATORS = [0xF5DEE51989, 0xA9FDCA3312, 0x1BAB10E32D,
                         0x3706B1677A, 0x644D626FFD]


def descriptor_polymod(symbols):
    checksum = 1
    for value in symbols:
        top = checksum >> 35
        checksum = ((checksum & 0x7FFFFFFFF) << 5) ^ value
        for index in range(5):
            if (top >> index) & 1:
                checksum ^= DESCRIPTOR_GENERATORS[index]
    return checksum


def descriptor_expand(text):
    """Expand descriptor text into 5-bit groups."""
    groups = []
    symbols = []
    for character in text:
        if character not in DESCRIPTOR_INPUT_CHARSET:
            raise ValueError("Illegal characters in descriptor: %r" % character)
        value = DESCRIPTOR_INPUT_CHARSET.index(character)
        symbols.append(value & 31)
        groups.append(value >> 5)
        if len(groups) == 3:
            symbols.append(groups[0] * 9 + groups[1] * 3 + groups[2])
            groups = []
    if len(groups) == 1:
        symbols.append(groups[0])
    elif len(groups) == 2:
        symbols.append(groups[0] * 3 + groups[1])
    return symbols


def descriptor_checksum(text):
    """Calculates the BIP380 descriptor checksum and returns 8 characters (excluding #).

Note that 8 0s should be added at the end and then XORed with 1. This is the practice of BIP380 reference implementation;
Just padding with 1 zero will give you an incorrect checksum (the correct value of the official vector raw(deadbeef) is 89f8spxm).
    """
    symbols = descriptor_expand(text) + [0, 0, 0, 0, 0, 0, 0, 0]
    value = descriptor_polymod(symbols) ^ 1
    return "".join(DESCRIPTOR_CHECKSUM_CHARSET[(value >> (5 * (7 - i))) & 31] for i in range(8))


def descriptor_checksum_valid(text):
    """Check in turn: the descriptor's own checksum is correct."""
    if text[-9:] != "#" + text[-8:] or "#" not in text:
        return False
    body, given = text[:-9], text[-8:]
    if len(given) != 8 or any(char not in DESCRIPTOR_CHECKSUM_CHARSET for char in given):
        return False
    symbols = descriptor_expand(body) + [DESCRIPTOR_CHECKSUM_CHARSET.index(char) for char in given]
    return descriptor_polymod(symbols) == 1


def descriptor_with_checksum(text):
    if "#" in text:
        text = text.split("#", 1)[0]
    return text + "#" + descriptor_checksum(text)
#================= Console and underlying gadgets =================
def enable_utf8_console():
    """The Windows console outputs in UTF-8 to prevent Chinese characters from turning into question marks."""
    if os.name == "nt" and ctypes is not None:
        try:
            ctypes.windll.kernel32.SetConsoleOutputCP(65001)
            ctypes.windll.kernel32.SetConsoleCP(65001)
        except Exception:                           # A few environments do not support it, so just ignore it.
            pass


#================= Self-check =================
# The expected value is taken from the public official vector, not calculated by me:
# BIP32 xpub fields and roundtrips
# BIP140/341 TapLeaf / TapBranch / merkle root / tweak / control block / output public key / address
# BIP173 bech32 address
# BIP340 Schnorr signature
#   BIP350  bech32m
# BIP380 descriptor checksum
def expect_equal(name, actual, expected):
    if actual != expected:
        raise AssertionError("%s: expected %s, actual %s" % (name, expected, actual))
    return name


#---------- Official vector (BIP340 Schnorr) ----------
# Top 15 official BIP340 vectors (bip-0340/test-vectors.csv).
# Fields: serial number, private key, public key, aux_rand, message, signature, whether the signature is verified.
# Items 15~18 are variable-length message vectors, and schnorr of this tool only processes 32-byte messages.
#(Taproot signature hash is always 32 bytes), so it is not included. The private key \"-\" is a vector that only verifies signatures.
BIP340_VECTORS = [
    ("0", "0000000000000000000000000000000000000000000000000000000000000003", "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9", "0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000", "e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0", True),
    ("1", "b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef", "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659", "0000000000000000000000000000000000000000000000000000000000000001", "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89", "6896bd60eeae296db48a229ff71dfe071bde413e6d43f917dc8dcf8c78de33418906d11ac976abccb20b091292bff4ea897efcb639ea871cfa95f6de339e4b0a", True),
    ("2", "c90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b14e5c9", "dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8", "c87aa53824b4d7ae2eb035a2b5bbbccc080e76cdc6d1692c4b0b62d798e6d906", "7e2d58d8b3bcdf1abadec7829054f90dda9805aab56c77333024b9d0a508b75c", "5831aaeed7b44bb74e5eab94ba9d4294c49bcf2a60728d8b4c200f50dd313c1bab745879a5ad954a72c45a91c3a51d3c7adea98d82f8481e0e1e03674a6f3fb7", True),
    ("3", "0b432b2677937381aef05bb02a66ecd012773062cf3fa2549e44f58ed2401710", "25d1dff95105f5253c4022f628a996ad3a0d95fbf21d468a1b33f8c160d8f517", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "7eb0509757e246f19449885651611cb965ecc1a187dd51b64fda1edc9637d5ec97582b9cb13db3933705b32ba982af5af25fd78881ebb32771fc5922efc66ea3", True),
    ("4", "-", "d69c3509bb99e412e68b0fe8544e72837dfa30746d8be2aa65975f29d22dc7b9", "-", "4df3c3f68fcc83b27e9d42c90431a72499f17875c81a599b566c9889b9696703", "00000000000000000000003b78ce563f89a0ed9414f5aa28ad0d96d6795f9c6376afb1548af603b3eb45c9f8207dee1060cb71c04e80f593060b07d28308d7f4", True),
    ("5", "-", "eefdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a34", "-", "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89", "6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e17776969e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b", False),
    ("6", "-", "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659", "-", "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89", "fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a14602975563cc27944640ac607cd107ae10923d9ef7a73c643e166be5ebeafa34b1ac553e2", False),
    ("7", "-", "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659", "-", "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89", "1fa62e331edbc21c394792d2ab1100a7b432b013df3f6ff4f99fcb33e0e1515f28890b3edb6e7189b630448b515ce4f8622a954cfe545735aaea5134fccdb2bd", False),
    ("8", "-", "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659", "-", "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89", "6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e177769961764b3aa9b2ffcb6ef947b6887a226e8d7c93e00c5ed0c1834ff0d0c2e6da6", False),
    ("9", "-", "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659", "-", "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89", "0000000000000000000000000000000000000000000000000000000000000000123dda8328af9c23a94c1feecfd123ba4fb73476f0d594dcb65c6425bd186051", False),
    ("10", "-", "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659", "-", "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89", "00000000000000000000000000000000000000000000000000000000000000017615fbaf5ae28864013c099742deadb4dba87f11ac6754f93780d5a1837cf197", False),
    ("11", "-", "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659", "-", "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89", "4a298dacae57395a15d0795ddbfd1dcb564da82b0f269bc70a74f8220429ba1d69e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b", False),
    ("12", "-", "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659", "-", "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89", "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f69e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b", False),
    ("13", "-", "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659", "-", "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89", "6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e177769fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", False),
    ("14", "-", "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30", "-", "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89", "6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e17776969e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b", False),
]


def register_checks(check):
    register_primitive_checks(check)
    register_vector_checks(check)
    register_multisig_checks(check)
    register_official_sighash_checks(check)


#---------- Low-level primitives ----------
def register_primitive_checks(check):
    def bech32_p2wpkh():
        # BIP173 official vector
        key = bytes.fromhex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
        address = segwit_encode("bc", 0, hash160(key))
        expect_equal("BIP173 P2WPKH address", address,
                     "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
        return address

    def bech32m_p2tr():
        # Witness version 1 must use bech32m; the program is taken from the BIP341 official vector, and the address is also official
        program = bytes.fromhex("53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343")
        address = segwit_encode("bc", 1, program)
        expect_equal("BIP350 Taproot address", address,
                     "bc1p2wsldez5mud2yam29q22wgfh9439spgduvct83k3pm50fcxa5dps59h4z5")
        return address

    def bech32_version_binding():
        """The witness version and checksum algorithm must be bound: v0 can only bech32, v1~v16 can only bech32m.

Note that BIP350 explicitly recommends that the **decoder** try two checksums at the same time (the wallet must be compatible),
So \"the decoder rejects the corresponding version\" is not a correct behavior; what is checked here is the binding of the encoding side,
In addition, the decoding end must be able to identify the version and witness program, and must report an error when the checksum is changed.
        """
        v1_program = bytes.fromhex("53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343")
        v0_program = bytes.fromhex("751e76e8199196d454941c45d1b3a323f1433bd6")
        good = segwit_encode("bc", 1, v1_program)
        # Encoding side: v0 -> bech32(q), v1 -> bech32m(p)
        expect_equal("v0 encoding prefix", segwit_encode("bc", 0, v0_program)[:4], "bc1q")
        expect_equal("v1 encoding prefix", segwit_encode("bc", 1, v1_program)[:4], "bc1p")
        # Decoding end: The version and witness program must be restored correctly
        hrp, version, program = segwit_decode(segwit_encode("bc", 1, v1_program))
        expect_equal("Decode hrp", hrp, "bc")
        expect_equal("Decode witness version", version, 1)
        expect_equal("decoding witness program", program.hex(), v1_program.hex())
        # The checksum has been changed -> must not be solved (the convention is to return None, not throw an exception)
        broken = "bc1p2wsldez5mud2yam29q22wgfh9439spgduvct83k3pm50fcxa5dps59h4z6"
        if segwit_decode(broken) is not None:
            raise AssertionError("Even after changing the checksum, I can still figure it out.")
        # Addresses with incorrect length must also be rejected
        if segwit_decode(good[:40]) is not None:
            raise AssertionError("The truncated address can still be solved")
        return "The encoder binds the version correctly; the decoder rejects malformed checksums."

    def tagged_hash_domain():
        expect_equal("tagged_hash with field separation",
                     tagged_hash("TapLeaf", b"").hex(),
                     sha256(sha256(b"TapLeaf") + sha256(b"TapLeaf")).hex())
        expect_equal("Different tags have different results",
                     tagged_hash("TapLeaf", b"") == tagged_hash("TapBranch", b""), False)
        return "Domain separation is correct"

    def schnorr_roundtrip():
        secret = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF
        xonly = pubkey_to_xonly(compressed_pubkey(secret))
        message = sha256(b"bitcoin multisig selftest")
        signature = schnorr_sign(message, secret, b"\x00" * 32)
        if not schnorr_verify(message, xonly, signature):
            raise AssertionError("I can't even verify the signature I signed.")
        broken = signature[:-1] + bytes([signature[-1] ^ 1])
        if schnorr_verify(message, xonly, broken):
            raise AssertionError("Even if I change one byte, it still passes.")
        wrong_key = pubkey_to_xonly(compressed_pubkey(secret + 1))
        if schnorr_verify(message, wrong_key, signature):
            raise AssertionError("I can still get through changing the public key")
        return "Signing and verification pass; tampered signatures and wrong keys are rejected."

    def bip340_vectors():
        """Check the BIP340 official vector: if it can be signed, re-sign and compare it one by one, and if it can only be signed, it will be judged one by one to pass/reject."""
        signed = verified = 0
        for index, secret_hex, pubkey_hex, aux_hex, msg_hex, sig_hex, should_pass in BIP340_VECTORS:
            label = "BIP340 vector %s" % index
            message = bytes.fromhex(msg_hex)
            signature = bytes.fromhex(sig_hex)
            xonly = bytes.fromhex(pubkey_hex)

            got = schnorr_verify(message, xonly, signature)
            expect_equal("%s signature verification result" % label, got, should_pass)
            verified += 1

            if secret_hex == "-":
                continue
            secret = int(secret_hex, 16)
            expect_equal("%s public key" % label,
                         pubkey_to_xonly(compressed_pubkey(secret)).hex(), pubkey_hex)
            produced = schnorr_sign(message, secret, bytes.fromhex(aux_hex))
            expect_equal("%s signature" % label, produced.hex(), sig_hex)
            signed += 1
        return "Re-signed %d cases and verified %d; all match the official vectors." % (signed, verified)

    def ecdsa_roundtrip():
        secret = 0x0BADC0DE00000000000000000000000000000000000000000000000000000001
        message = sha256(b"ecdsa selftest")
        signature = ecdsa_sign(message, secret)
        pubkey = compressed_pubkey(secret)
        if not ecdsa_verify(message, signature, pubkey):
            raise AssertionError("Self-signing and self-inspection failed")
        if ecdsa_verify(message, signature, compressed_pubkey(secret + 1)):
            raise AssertionError("I can still get through changing the public key")
        if ecdsa_verify(sha256(b"another message"), signature, pubkey):
            raise AssertionError("I can still survive by changing the news")
        return "Signing and verification pass; wrong keys and changed messages are rejected."

    def bip32_fields():
        # Mainnet xpub of BIP32 official vector 1, field-by-field verification
        text = ("xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJ"
                "oCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8")
        version, key = parse_extended_key(text)
        expect_equal("xpub version bytes", version, 0x0488B21E)
        expect_equal("xpub depth", key.depth, 0)
        expect_equal("xpub fingerprint", key.fingerprint.hex(), "00000000")
        expect_equal("xpub subindex", key.child_index, 0)
        expect_equal("xpub chaincode", key.chain_code.hex(),
                     "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508")
        expect_equal("xpub public key", key.pubkey.hex(),
                     "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2")
        expect_equal("xpub round trip consistent", serialize_extended_key(key, version), text)
        return "All fields and round-trips match the official vectors."

    def bip32_derives():
        # Only non-reinforced derivation is supported, so the mainnet xpub of the official vector 1 is used as the parent.
        # The expected value is calculated independently by libsecp256k1: the master public key prefix is 03 (Y is an odd number),
        # It just covers the pitfall of \"the parent point cannot simply use lift_x (always an even number Y)\".
        version, key = parse_extended_key(
            "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJ"
            "oCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8")
        expect_equal("m/0x0/0 sub-public key", derive_pubkey(key, 0).pubkey.hex(),
                     "027c4b09ffb985c298afe7e5813266cbfcb7780b480ac294b0b43dc21f2be3d13c")
        expect_equal("m/0x0/0 sub-chain code", derive_pubkey(key, 0).chain_code.hex(),
                     "d323f1be5af39a2d2f08f5e8f664633849653dbe329802e9847cfc85f8d7b52a")
        expect_equal("m/0x1 sub-public key", derive_pubkey(key, 1).pubkey.hex(),
                     "037c2098fd2235660734667ff8821dbbe0e6592d43cfd86b5dde9ea7c839b93a50")

        # Three levels are derived continuously, and the parent-child parity is flipped back and forth to prevent errors such as \"forcing negative values based on parent parity\".
        node = key
        for index in (0, 0, 2):
            node = derive_pubkey(node, index)
        expect_equal("Continuously derive m/0x0/0x0/2 public keys", node.pubkey.hex(),
                     "02b252b9a5c5a31f07d52ef5308e4845b21b15e367abf00e8e47bcb48cbcfad2d0")
        expect_equal("Continuously derived chaincode", node.chain_code.hex(),
                     "0f676defcc0789bd9951f55e4d0687051ceae44f2dd0c32981da25befb05180a")
        expect_equal("Continuously derived depth", node.depth, 3)

        child = derive_pubkey(key, 0)
        if child.fingerprint != hash160(key.pubkey)[:4]:
            raise AssertionError("The child key fingerprint should be the first 4 bytes of hash160 of the parent public key")
        if not is_valid_pubkey(child.pubkey):
            raise AssertionError("Derive an illegal public key")
        if serialize_extended_key(child, version).startswith("xpub") is False:
            raise AssertionError("Wrong prefix after recoding")
        return "Byte-for-byte consistent with libsecp256k1, including parity flips."

    def bip32_hardened_rejected():
        _, key = parse_extended_key(
            "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJ"
            "oCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8")
        try:
            derive_pubkey(key, 0x80000000)
        except ValueError:
            return "Hardened derivations are rejected (xpubs contain public keys only)."
        raise AssertionError("The hardening path was not rejected")

    def descriptor_checksum_vector():
        # BIP380 official vector
        expect_equal("BIP380 raw(deadbeef)",
                     descriptor_with_checksum("raw(deadbeef)"), "raw(deadbeef)#89f8spxm")
        for text in ("raw(deadbeef)#89f8spxm",
                     "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)",
                     "wsh(sortedmulti(2,xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/0/0/*))"):
            built = descriptor_with_checksum(text)
            if not descriptor_checksum_valid(built):
                raise AssertionError("Generated by yourself but failed to verify by yourself: %s" % built)
        if descriptor_checksum_valid("raw(deedbeef)#89f8spxm"):
            raise AssertionError("The descriptor with modified content actually passed the verification")
        return "The official vector is consistent and tampered descriptors can be detected"

    def pubkey_validation():
        good = "0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352"
        expect_equal("Compressed public key is valid", is_valid_pubkey(bytes.fromhex(good)), True)
        expect_equal("x=0 is judged as invalid", is_valid_pubkey(bytes.fromhex("02" + "00" * 32)), False)
        expect_equal("The wrong prefix is judged to be invalid.", is_valid_pubkey(bytes.fromhex("05" + "11" * 32)), False)
        uncompressed = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" \
                       "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
        expect_equal("Uncompressed public keys are valid", is_valid_pubkey(bytes.fromhex(uncompressed)), True)
        return "Valid and invalid keys are classified correctly."

    check("BIP173 bech32 address", bech32_p2wpkh)
    check("BIP350 bech32m address", bech32m_p2tr)
    check("Witness version and checksum are bound", bech32_version_binding)
    check("tagged_hash domain separation", tagged_hash_domain)
    check("Schnorr signature verification", schnorr_roundtrip)
    check("BIP340 test vectors", bip340_vectors)
    check("ECDSA signing and verification", ecdsa_roundtrip)
    check("BIP32 xpub field", bip32_fields)
    check("BIP32 non-hardened derivation", bip32_derives)
    check("Hardened derivations are rejected", bip32_hardened_rejected)
    check("BIP380 descriptor checksum", descriptor_checksum_vector)
    check("Public key validity", pubkey_validation)


#---------- Official vector (BIP341 TapTree) ----------
# Directly embed the BIP341 official vector (the scriptPubKey part of bip-0341/wallet-test-vectors.json),
# This way the delivered file does not depend on any external data files.
# tree maintains the official original tree shape with nested tuples: leaves are (\"l\", leaf version, script hex),
# The branches are (\"b\", left, right). The official merkle root for [a, [b, c]] is
# TapBranch(a, TapBranch(b, c)), after being flattened and divided according to floor, the result is another root, which does not match.
BIP341_WALLET_VECTORS = [
    {
        "internal": "d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d",
        "tree": None,
        "tweak": "b86e7be8f39bab32a6f2c0443abbc210f0edac0e2c53d501b36b64437d9c6c70",
        "tweaked": "53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343",
        "spk": "512053a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343",
        "addr": "bc1p2wsldez5mud2yam29q22wgfh9439spgduvct83k3pm50fcxa5dps59h4z5",
    },
    {
        "internal": "187791b6f712a8ea41c8ecdd0ee77fab3e85263b37e1ec18a3651926b3a6cf27",
        "tree": ('l', 192, '20d85a959b0290bf19bb89ed43c916be835475d013da4b362117393e25a48229b8ac'),
        "leaf_hashes": ['5b75adecf53548f3ec6ad7d78383bf84cc57b55a3127c72b9a2481752dd88b21'],
        "root": "5b75adecf53548f3ec6ad7d78383bf84cc57b55a3127c72b9a2481752dd88b21",
        "tweak": "cbd8679ba636c1110ea247542cfbd964131a6be84f873f7f3b62a777528ed001",
        "tweaked": "147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3",
        "blocks": ['c1187791b6f712a8ea41c8ecdd0ee77fab3e85263b37e1ec18a3651926b3a6cf27'],
        "spk": "5120147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3",
        "addr": "bc1pz37fc4cn9ah8anwm4xqqhvxygjf9rjf2resrw8h8w4tmvcs0863sa2e586",
    },
    {
        "internal": "93478e9488f956df2396be2ce6c5cced75f900dfa18e7dabd2428aae78451820",
        "tree": ('l', 192, '20b617298552a72ade070667e86ca63b8f5789a9fe8731ef91202a91c9f3459007ac'),
        "leaf_hashes": ['c525714a7f49c28aedbbba78c005931a81c234b2f6c99a73e4d06082adc8bf2b'],
        "root": "c525714a7f49c28aedbbba78c005931a81c234b2f6c99a73e4d06082adc8bf2b",
        "tweak": "6af9e28dbf9d6aaf027696e2598a5b3d056f5fd2355a7fd5a37a0e5008132d30",
        "tweaked": "e4d810fd50586274face62b8a807eb9719cef49c04177cc6b76a9a4251d5450e",
        "blocks": ['c093478e9488f956df2396be2ce6c5cced75f900dfa18e7dabd2428aae78451820'],
        "spk": "5120e4d810fd50586274face62b8a807eb9719cef49c04177cc6b76a9a4251d5450e",
        "addr": "bc1punvppl2stp38f7kwv2u2spltjuvuaayuqsthe34hd2dyy5w4g58qqfuag5",
    },
    {
        "internal": "ee4fe085983462a184015d1f782d6a5f8b9c2b60130aff050ce221ecf3786592",
        "tree": ('b', ('l', 192, '20387671353e273264c495656e27e39ba899ea8fee3bb69fb2a680e22093447d48ac'), ('l', 250, '06424950333431')),
        "leaf_hashes": ['8ad69ec7cf41c2a4001fd1f738bf1e505ce2277acdcaa63fe4765192497f47a7', 'f224a923cd0021ab202ab139cc56802ddb92dcfc172b9212261a539df79a112a'],
        "root": "6c2dc106ab816b73f9d07e3cd1ef2c8c1256f519748e0813e4edd2405d277bef",
        "tweak": "9e0517edc8259bb3359255400b23ca9507f2a91cd1e4250ba068b4eafceba4a9",
        "tweaked": "712447206d7a5238acc7ff53fbe94a3b64539ad291c7cdbc490b7577e4b17df5",
        "blocks": ['c0ee4fe085983462a184015d1f782d6a5f8b9c2b60130aff050ce221ecf3786592f224a923cd0021ab202ab139cc56802ddb92dcfc172b9212261a539df79a112a', 'faee4fe085983462a184015d1f782d6a5f8b9c2b60130aff050ce221ecf37865928ad69ec7cf41c2a4001fd1f738bf1e505ce2277acdcaa63fe4765192497f47a7'],
        "spk": "5120712447206d7a5238acc7ff53fbe94a3b64539ad291c7cdbc490b7577e4b17df5",
        "addr": "bc1pwyjywgrd0ffr3tx8laflh6228dj98xkjj8rum0zfpd6h0e930h6saqxrrm",
    },
    {
        "internal": "f9f400803e683727b14f463836e1e78e1c64417638aa066919291a225f0e8dd8",
        "tree": ('b', ('l', 192, '2044b178d64c32c4a05cc4f4d1407268f764c940d20ce97abfd44db5c3592b72fdac'), ('l', 192, '07546170726f6f74')),
        "leaf_hashes": ['64512fecdb5afa04f98839b50e6f0cb7b1e539bf6f205f67934083cdcc3c8d89', '2cb2b90daa543b544161530c925f285b06196940d6085ca9474d41dc3822c5cb'],
        "root": "ab179431c28d3b68fb798957faf5497d69c883c6fb1e1cd9f81483d87bac90cc",
        "tweak": "639f0281b7ac49e742cd25b7f188657626da1ad169209078e2761cefd91fd65e",
        "tweaked": "77e30a5522dd9f894c3f8b8bd4c4b2cf82ca7da8a3ea6a239655c39c050ab220",
        "blocks": ['c1f9f400803e683727b14f463836e1e78e1c64417638aa066919291a225f0e8dd82cb2b90daa543b544161530c925f285b06196940d6085ca9474d41dc3822c5cb', 'c1f9f400803e683727b14f463836e1e78e1c64417638aa066919291a225f0e8dd864512fecdb5afa04f98839b50e6f0cb7b1e539bf6f205f67934083cdcc3c8d89'],
        "spk": "512077e30a5522dd9f894c3f8b8bd4c4b2cf82ca7da8a3ea6a239655c39c050ab220",
        "addr": "bc1pwl3s54fzmk0cjnpl3w9af39je7pv5ldg504x5guk2hpecpg2kgsqaqstjq",
    },
    {
        "internal": "e0dfe2300b0dd746a3f8674dfd4525623639042569d829c7f0eed9602d263e6f",
        "tree": ('b', ('l', 192, '2072ea6adcf1d371dea8fba1035a09f3d24ed5a059799bae114084130ee5898e69ac'), ('b', ('l', 192, '202352d137f2f3ab38d1eaa976758873377fa5ebb817372c71e2c542313d4abda8ac'), ('l', 192, '207337c0dd4253cb86f2c43a2351aadd82cccb12a172cd120452b9bb8324f2186aac'))),
        "leaf_hashes": ['2645a02e0aac1fe69d69755733a9b7621b694bb5b5cde2bbfc94066ed62b9817', 'ba982a91d4fc552163cb1c0da03676102d5b7a014304c01f0c77b2b8e888de1c', '9e31407bffa15fefbf5090b149d53959ecdf3f62b1246780238c24501d5ceaf6'],
        "root": "ccbd66c6f7e8fdab47b3a486f59d28262be857f30d4773f2d5ea47f7761ce0e2",
        "tweak": "b57bfa183d28eeb6ad688ddaabb265b4a41fbf68e5fed2c72c74de70d5a786f4",
        "tweaked": "91b64d5324723a985170e4dc5a0f84c041804f2cd12660fa5dec09fc21783605",
        "blocks": ['c0e0dfe2300b0dd746a3f8674dfd4525623639042569d829c7f0eed9602d263e6fffe578e9ea769027e4f5a3de40732f75a88a6353a09d767ddeb66accef85e553', 'c0e0dfe2300b0dd746a3f8674dfd4525623639042569d829c7f0eed9602d263e6f9e31407bffa15fefbf5090b149d53959ecdf3f62b1246780238c24501d5ceaf62645a02e0aac1fe69d69755733a9b7621b694bb5b5cde2bbfc94066ed62b9817', 'c0e0dfe2300b0dd746a3f8674dfd4525623639042569d829c7f0eed9602d263e6fba982a91d4fc552163cb1c0da03676102d5b7a014304c01f0c77b2b8e888de1c2645a02e0aac1fe69d69755733a9b7621b694bb5b5cde2bbfc94066ed62b9817'],
        "spk": "512091b64d5324723a985170e4dc5a0f84c041804f2cd12660fa5dec09fc21783605",
        "addr": "bc1pjxmy65eywgafs5tsunw95ruycpqcqnev6ynxp7jaasylcgtcxczs6n332e",
    },
    {
        "internal": "55adf4e8967fbd2e29f20ac896e60c3b0f1d5b0efa9d34941b5958c7b0a0312d",
        "tree": ('b', ('l', 192, '2071981521ad9fc9036687364118fb6ccd2035b96a423c59c5430e98310a11abe2ac'), ('b', ('l', 192, '20d5094d2dbe9b76e2c245a2b89b6006888952e2faa6a149ae318d69e520617748ac'), ('l', 192, '20c440b462ad48c7a77f94cd4532d8f2119dcebbd7c9764557e62726419b08ad4cac'))),
        "leaf_hashes": ['f154e8e8e17c31d3462d7132589ed29353c6fafdb884c5a6e04ea938834f0d9d', '737ed1fe30bc42b8022d717b44f0d93516617af64a64753b7a06bf16b26cd711', 'd7485025fceb78b9ed667db36ed8b8dc7b1f0b307ac167fa516fe4352b9f4ef7'],
        "root": "2f6b2c5397b6d68ca18e09a3f05161668ffe93a988582d55c6f07bd5b3329def",
        "tweak": "6579138e7976dc13b6a92f7bfd5a2fc7684f5ea42419d43368301470f3b74ed9",
        "tweaked": "75169f4001aa68f15bbed28b218df1d0a62cbbcf1188c6665110c293c907b831",
        "blocks": ['c155adf4e8967fbd2e29f20ac896e60c3b0f1d5b0efa9d34941b5958c7b0a0312d3cd369a528b326bc9d2133cbd2ac21451acb31681a410434672c8e34fe757e91', 'c155adf4e8967fbd2e29f20ac896e60c3b0f1d5b0efa9d34941b5958c7b0a0312dd7485025fceb78b9ed667db36ed8b8dc7b1f0b307ac167fa516fe4352b9f4ef7f154e8e8e17c31d3462d7132589ed29353c6fafdb884c5a6e04ea938834f0d9d', 'c155adf4e8967fbd2e29f20ac896e60c3b0f1d5b0efa9d34941b5958c7b0a0312d737ed1fe30bc42b8022d717b44f0d93516617af64a64753b7a06bf16b26cd711f154e8e8e17c31d3462d7132589ed29353c6fafdb884c5a6e04ea938834f0d9d'],
        "spk": "512075169f4001aa68f15bbed28b218df1d0a62cbbcf1188c6665110c293c907b831",
        "addr": "bc1pw5tf7sqp4f50zka7629jrr036znzew70zxyvvej3zrpf8jg8hqcssyuewe",
    },
]

def vector_leaves(node):
    """List leaves (leaf version, script bytes) in depth-first order, in the same order as official leafHashes."""
    if node[0] == "l":
        return [(node[1], bytes.fromhex(node[2]))]
    return vector_leaves(node[1]) + vector_leaves(node[2])


def vector_tree_root(node):
    if node[0] == "l":
        return tapleaf_hash(bytes.fromhex(node[2]), node[1])
    return tapbranch_hash(vector_tree_root(node[1]), vector_tree_root(node[2]))


def vector_paths(node):
    """Returns a list of side hashes from each leaf leading to the root in leaf order (from bottom to top)."""
    if node[0] == "l":
        return [[]]
    left_root = vector_tree_root(node[1])
    right_root = vector_tree_root(node[2])
    result = []
    for path in vector_paths(node[1]):
        result.append(path + [right_root])
    for path in vector_paths(node[2]):
        result.append(path + [left_root])
    return result


def register_vector_checks(check):
    def tapleaf_hash_matches_spec():
        script = bytes.fromhex("20" + "11" * 32 + "ac")
        expect_equal("TapLeaf hash", tapleaf_hash(script),
                     tagged_hash("TapLeaf", b"\xc0" + b"\x22" + script))
        return "Matches the BIP341 definition byte for byte."

    def tapbranch_is_order_independent():
        first, second = sha256(b"a"), sha256(b"b")
        expect_equal("Branch hashing is order independent", tapbranch_hash(first, second),
                     tapbranch_hash(second, first))
        return "Result is identical regardless of leaf order."

    def taptree_convention():
        # The tree shape of the three leaves in the official vector is [l0, [l1, l2]], and the floor segmentation of this tool must be reproducible.
        # Note that the leaf public key must be 32 bytes x-only, and using hash160 (20 bytes) will be rejected.
        scripts = [tapscript_leaf_for_key(sha256(b"member%d" % index))
                   for index in range(3)]
        leaves = [tapleaf_hash(script) for script in scripts]
        root, paths = build_taptree(leaves)
        manual = tapbranch_hash(leaves[0], tapbranch_hash(leaves[1], leaves[2]))
        expect_equal("3 leaf tree shape", root.hex(), manual.hex())
        expect_equal("The number of side branches of leaf 0", len(paths[0]), 1)
        expect_equal("The number of side branches of leaf 1", len(paths[1]), 2)
        return "[l0,[l1,l2]], same shape as the official vectors."

    def wallet_vectors():
        """Check the embedded BIP341 official vectors item by item."""
        counts = dict.fromkeys(["leaf", "root", "tweak", "output", "control", "spk", "address"], 0)
        for entry in BIP341_WALLET_VECTORS:
            internal_x = bytes.fromhex(entry["internal"])
            tree = entry["tree"]
            if tree is None:
                # Pure key path: merkle root is empty, tweak only hashes the internal public key itself
                expect_equal("Official vector key path tweak",
                             taproot_tweak(internal_x, None).hex(), entry["tweak"])
                output_point = taproot_output_point(internal_x, None)
                expect_equal("Official vector key path tweakedPubkey",
                             output_point[0].to_bytes(32, "big").hex(), entry["tweaked"])
            else:
                leaves = vector_leaves(tree)
                root = vector_tree_root(tree)
                for position, (version, script) in enumerate(leaves):
                    expect_equal("Official vector leafHashes",
                                 tapleaf_hash(script, version).hex(),
                                 entry["leaf_hashes"][position])
                    counts["leaf"] += 1
                expect_equal("Official vector merkleRoot", root.hex(), entry["root"])
                counts["root"] += 1
                expect_equal("Official vector tweak", taproot_tweak(internal_x, root).hex(),
                             entry["tweak"])
                counts["tweak"] += 1

                output_point = taproot_output_point(internal_x, root)
                expect_equal("Official vector tweakedPubkey",
                             output_point[0].to_bytes(32, "big").hex(), entry["tweaked"])
                counts["output"] += 1

                blocks = entry.get("blocks") or []
                paths = vector_paths(tree)
                for position, (version, _script) in enumerate(leaves):
                    if position >= len(blocks):
                        break
                    control = taproot_control_block(paths[position], output_point,
                                                    internal_x, version)
                    expect_equal("Official vector control block", control.hex(), blocks[position])
                    counts["control"] += 1

            program = output_point[0].to_bytes(32, "big")
            expect_equal("Official vector scriptPubKey", (b"\x51\x20" + program).hex(),
                         entry["spk"])
            counts["spk"] += 1
            expect_equal("Official vector bech32m address", segwit_encode("bc", 1, program),
                         entry["addr"])
            counts["address"] += 1
        return "%d leaves, %d roots, %d tweaks, %d outputs, %d control blocks, %d scripts, %d addresses - all matched." % (
            counts["leaf"], counts["root"], counts["tweak"], counts["output"],
            counts["control"], counts["spk"], counts["address"])

    check("TapLeaf hash algorithm", tapleaf_hash_matches_spec)
    check("TapBranch order-independence", tapbranch_is_order_independent)
    check("TapTree branch layout", taptree_convention)
    check("BIP341 test vectors", wallet_vectors)


#----------Multi-signature plan ----------
def register_multisig_checks(check):
    def witness_script_structure():
        key1 = bytes.fromhex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
        key2 = bytes.fromhex("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")
        script = multisig_witness_script(1, [key1, key2])
        # OP_1(0x51) <push33+key1> <push33+key2> OP_2(0x52) OP_CHECKMULTISIG(0xae)
        expect_equal("witnessScript structure", script.hex(),
                     "51" + "21" + key1.hex() + "21" + key2.hex() + "52ae")
        expect_equal("3-of-3 threshold bytes", multisig_witness_script(3, [key1, key2, key1]).hex()[:2],
                     "53")
        return "OP_m ... OP_n OP_CHECKMULTISIG"

    def threshold_enforced():
        members = random_members(3)
        scheme = build_p2wsh_scheme(members, 2)
        secrets_by_key = {item["pubkey"]: item["secret"] for item in members}
        ordered = scheme["keys"]
        if verify_p2wsh_multisig(scheme["witness_script"], ordered, secrets_by_key, 1)[0]:
            raise AssertionError("1 signature actually passed 2-of-3")
        if not verify_p2wsh_multisig(scheme["witness_script"], ordered, secrets_by_key, 2)[0]:
            raise AssertionError("2 signatures that should have passed but didn't")
        if verify_p2wsh_multisig(scheme["witness_script"], ordered, secrets_by_key, 3)[0]:
            raise AssertionError("3 signatures were rejected by 2-of-3")
        return "2-of-3: 1 signature is rejected, 2 pass, and extra signatures are rejected."

    def three_of_five():
        members = random_members(5)
        scheme = build_p2wsh_scheme(members, 3)
        secrets_by_key = {item["pubkey"]: item["secret"] for item in members}
        if verify_p2wsh_multisig(scheme["witness_script"], scheme["keys"],
                                 secrets_by_key, 2)[0]:
            raise AssertionError("2 signatures actually passed 3-of-5")
        if not verify_p2wsh_multisig(scheme["witness_script"], scheme["keys"],
                                     secrets_by_key, 3)[0]:
            raise AssertionError("3-of-5 should pass")
        return "3-of-5: 2 signatures are rejected, 3 pass."

    def wrong_signer_rejected():
        # Three people are on the list, but signing with a private key outside the list should not pass.
        members = random_members(3)
        outsider = random_members(1)[0]
        scheme = build_p2wsh_scheme(members, 2)
        message = bip143_sighash(build_test_transaction(), 0,
                                 scheme["witness_script"], 100_000, SIGHASH_ALL)
        signatures = [ecdsa_sign(message, outsider["secret"]) for _ in range(2)]
        stack = [b""] + signatures
        ok = execute_multisig_script(
            scheme["witness_script"], stack,
            lambda sig, pk: ecdsa_verify(message, sig, pk))
        if ok:
            raise AssertionError("People who were not on the list actually signed successfully.")
        return "Signatures from non-member keys are rejected."

    def sorting_matters():
        # There is about a 1/6 probability that \"byte ascending order\" and \"fingerprint order\" under a random public key are exactly the same.
        # Directly asserting that the two addresses are different will occasionally fail, so change a few groups first until the sorting is really different.
        by67 = byfinger = None
        for _ in range(50):
            members = random_members(3)
            by67 = build_p2wsh_scheme(members, 2, order="bip67")
            byfinger = build_p2wsh_scheme(members, 2, order="fingerprint")
            if by67["keys"] != byfinger["keys"]:
                break
        else:
            raise AssertionError("50 consecutive sets of public keys failed to distinguish between the two orderings, and the test itself failed.")
        if by67["keys"] != sorted(by67["keys"]):
            raise AssertionError("BIP67 result is not in byte ascending order")
        if by67["address"] == byfinger["address"]:
            raise AssertionError("The two sortings give the same address, but the sorting does not take effect.")
        if by67["witness_script"] == byfinger["witness_script"]:
            raise AssertionError("Two sortings give the same witnessScript, but the sorting does not take effect.")
        return "Ordering changes the address (BIP67 lexicographic order)."

    def taproot_all_sign():
        # Run a few more rounds: the y parity bits of the output public key are approximately random. If you run only one round, there is about half a probability of not touching a certain side.
        rounds = 12
        for _ in range(rounds):
            members = random_members(3)
            scheme = build_taproot_scheme(members, "chain")
            rows = run_scheme_checks(scheme, members)
            if len(rows) < 2:
                raise AssertionError("Too few use cases: %s" % (rows,))
            for label, expect_pass, actual_pass, detail in rows:
                # Key: Determine \"whether the behavior meets expectations\" rather than \"whether the signature verification passes.\"
                # When there is one less person to sign, the script should reject it. In this case, actual_pass is False.
                if actual_pass != expect_pass:
                    raise AssertionError("%s behaves opposite of expected: %s" % (label, detail))
            if not any(expect and actual for _l, expect, actual, _d in rows):
                raise AssertionError("There is no use case that has been signed by all employees.")
            if not any((not expect) and (not actual) for _l, expect, actual, _d in rows):
                raise AssertionError("There is no use case where one person signed less and was rejected.")
        return "bc1p: over %d trials, the required signature count passes and fewer signers fail." % rounds

    def taproot_internal_key_matters():
        members = random_members(2)
        scheme = build_taproot_scheme(members, "chain")
        if NUMS_X == BASE_X.to_bytes(32, "big"):
            raise AssertionError("The internal public key should not be the base point G")
        if taproot_output_key(BASE_X.to_bytes(32, "big"),
                              scheme["merkle_root"]) == scheme["output_key"]:
            raise AssertionError("The output public key is not affected by the internal public key")
        return "The output key depends on the internal key, which is the NUMS key rather than the generator."

    def taproot_tree_layout_differs():
        members = random_members(3)
        chain = build_taproot_scheme(members, "chain")
        tree = build_taproot_scheme(members, "tree")
        if chain["address"] == tree["address"]:
            raise AssertionError("The chain and tree layouts have the same address")
        if chain["signature_count"] != tree["signature_count"]:
            raise AssertionError("The number of signatures should be the same for both layouts")
        return '"chain" and "tree" produce two different addresses.'

    def address_prefixes():
        members = random_members(3)
        p2wsh = build_p2wsh_scheme(members, 2)
        p2tr = build_taproot_scheme(members, "chain")
        expect_equal("bc1q prefix", p2wsh["address"][:4], "bc1q")
        expect_equal("bc1p prefix", p2tr["address"][:4], "bc1p")
        expect_equal("Compatible address has been removed",
                     "p2sh_p2wsh_address" in p2wsh or "p2sh_legacy_address" in p2wsh,
                     False)
        return "bc1q / bc1p prefixes are correct and old P2SH is no longer generated"

    def mainnet_only():
        # This tool only works on the mainnet, and no testnet address should appear on any entrance.
        members = random_members(3)
        produced = []
        for threshold in (1, 2, 3):
            scheme = build_p2wsh_scheme(members, threshold)
            produced += [scheme["address"]]
        produced.append(build_taproot_scheme(members)["address"])
        produced.append(build_taproot_scheme(members, "tree")["address"])
        for address in produced:
            if address.startswith(("tb1", "bcrt1")):
                raise AssertionError("A non-mainnet address popped up:" + address)
        if not produced[0].startswith("bc1q") or not produced[-1].startswith("bc1p"):
            raise AssertionError("Mainnet prefix is wrong")
        return "%d addresses are mainnet only; no tb1/bcrt1." % len(produced)

    def member_input_forms():
        secret = 0x2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A
        wif = secret_to_wif(secret)
        pubkey = compressed_pubkey(secret)
        forms = [wif, "%064x" % secret, str(secret), pubkey.hex(),
                 "x:" + pubkey_to_xonly(pubkey).hex()]
        seen = set()
        for form in forms:
            seen.add(parse_member(form)["pubkey"])
        if len(seen) != 1:
            raise AssertionError("The five ways of writing the same private key parsed out %d different public keys." % len(seen))
        return "WIF / hex / decimal / compressed pubkey / x-only forms all yield the same result."

    def inspect_addresses():
        members = random_members(3)
        p2wsh = build_p2wsh_scheme(members, 2)
        p2tr = build_taproot_scheme(members, "chain")
        cases = [
            (p2wsh["address"], "SegWit v0", "bc1q multi-signature address"),
            (p2tr["address"], "Taproot", "bc1p address"),
        ]
        for address, expected, label in cases:
            report = inspect_address(address)
            if "Can't understand" in report:
                raise AssertionError("%s was misjudged as incomprehensible: %s" % (label, report.strip()))
            if expected not in report:
                raise AssertionError("The parsing result of %s is incorrect: %s" % (label, report.strip()))
        # Garbage input must give a prompt instead of throwing an exception
        for junk in ("not-an-address", "bc1q", "", "0OIl"):
            report = inspect_address(junk)
            if "Can't understand" not in report:
                raise AssertionError("The garbage input %r was parsed successfully: %s" % (junk, report.strip()))
        return "bc1q / bc1p / P2SH parse correctly, and malformed input is reported without crashing."

    check("Witness script structure", witness_script_structure)
    check("2-of-3 threshold enforced", threshold_enforced)
    check("3-of-5 threshold enforced", three_of_five)
    check("Signatures from non-member keys are rejected", wrong_signer_rejected)
    check("Public key ordering changes the address", sorting_matters)
    check("bc1p requires all signers", taproot_all_sign)
    check("Taproot internal key", taproot_internal_key_matters)
    check("Taproot chain vs tree", taproot_tree_layout_differs)
    check("Address prefixes", address_prefixes)
    check("Mainnet-only addresses", mainnet_only)
    check("Member input formats", member_input_forms)
    check("Address inspection", inspect_addresses)


#---------- Official vector (BIP143 native SegWit signature hash) ----------
# Article by article copied from the official example in the BIP143 specification text.
# Note that the scriptCode line comes with the compact_size length prefix in the original text, which has been stripped off when copied.
# Covers native P2WPKH, P2SH-P2WPKH, and native P2WSH (including SINGLE out-of-bounds),
# And P2SH-P2WSH 6-of-6 is signed once with each of the 6 hash types.
BIP143_VECTORS = [
    {
        "name": "Native P2WPKH",
        "tx": "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000",
        "vin": 1,
        "amount": 600000000,
        "script": "76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac",
        "expect": {
            "0x01": "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670",
        },
    },
    {
        "name": "P2SH-P2WPKH",
        "tx": "0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a54770100000000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000",
        "vin": 0,
        "amount": 1000000000,
        "script": "76a91479091972186c449eb1ded22b78e40d009bdf008988ac",
        "expect": {
            "0x01": "64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6",
        },
    },
    {
        "name": "Native P2WSH (SINGLE out of bounds)",
        "tx": "0100000002fe3dc9208094f3ffd12645477b3dc56f60ec4fa8e6f5d67c565d1c6b9216b36e0000000000ffffffff0815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee0a6925f80000000000ffffffff0100f2052a010000001976a914a30741f8145e5acadf23f751864167f32e0963f788ac00000000",
        "vin": 1,
        "amount": 4900000000,
        "script": "21026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac",
        "expect": {
            "0x03": "82dde6e4f1e94d02c2b7ad03d2115d691f48d064e9d52f58194a6637e4194391",
        },
    },
    {
        "name": "P2SH-P2WSH 6-of-6",
        "tx": "010000000136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000000ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac00000000",
        "vin": 0,
        "amount": 987654321,
        "script": "56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae",
        "expect": {
            "0x01": "185c0be5263dce5b4bb50a047973c1b6272bfbd0103a89444597dc40b248ee7c",
            "0x02": "e9733bc60ea13c95c6527066bb975a2ff29a925e80aa14c213f686cbae5d2f36",
            "0x03": "1e1f1c303dc025bd664acb72e583e933fae4cff9148bf78c157d1e8f78530aea",
            "0x81": "2a67f03e63a6a422125878b40b82da593be8d4efaafe88ee528af6e5a9955c6e",
            "0x82": "781ba15f3779d5542ce8ecb5c18716733a5ee42a6f51488ec96154934e2c890a",
            "0x83": "511e8e52ed574121fc1b654970395502128263f62662e076dc6baf05c2e6a99b",
        },
    },
]


#---------- Official vector (BIP341 Taproot signature hash) ----------
# Automatically generated by gen_taproot_sighash_table.py from BIP341 official vectors.
# Override keyPathSpending for all 7 inputs: ALL / NONE / SINGLE / DEFAULT
# and three ANYONECANPAY combinations; merkle_root of some entries is not empty,
# Used to check taproot_tweak at the same time and commit the merkle root together.
# Automatically generated by gen_taproot_sighash_table.py from BIP341 official vectors
TAPROOT_SIGHASH_VECTOR = {
    "unsigned": "02000000097de20cbff686da83a54981d2b9bab3586f4ca7e48f57f5b55963115f3b334e9c010000000000000000d7b7cab57b1393ace2d064f4d4a2cb8af6def61273e127517d44759b6dafdd990000000000fffffffff8e1f583384333689228c5d28eac13366be082dc57441760d957275419a418420000000000fffffffff0689180aa63b30cb162a73c6d2a38b7eeda2a83ece74310fda0843ad604853b0100000000feffffffaa5202bdf6d8ccd2ee0f0202afbbb7461d9264a25e5bfd3c5a52ee1239e0ba6c0000000000feffffff956149bdc66faa968eb2be2d2faa29718acbfe3941215893a2a3446d32acd050000000000000000000e664b9773b88c09c32cb70a2a3e4da0ced63b7ba3b22f848531bbb1d5d5f4c94010000000000000000e9aa6b8e6c9de67619e6a3924ae25696bb7b694bb677a632a74ef7eadfd4eabf0000000000ffffffffa778eb6a263dc090464cd125c466b5a99667720b1c110468831d058aa1b82af10100000000ffffffff0200ca9a3b000000001976a91406afd46bcdfd22ef94ac122aa11f241244a37ecc88ac807840cb0000000020ac9a87f5594be208f8532db38cff670c450ed2fea8fcdefcc9a663f78bab962b0065cd1d",
    "scripts": [
        "512053a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343",
        "5120147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3",
        "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac",
        "5120e4d810fd50586274face62b8a807eb9719cef49c04177cc6b76a9a4251d5450e",
        "512091b64d5324723a985170e4dc5a0f84c041804f2cd12660fa5dec09fc21783605",
        "00147dd65592d0ab2fe0d0257d571abf032cd9db93dc",
        "512075169f4001aa68f15bbed28b218df1d0a62cbbcf1188c6665110c293c907b831",
        "5120712447206d7a5238acc7ff53fbe94a3b64539ad291c7cdbc490b7577e4b17df5",
        "512077e30a5522dd9f894c3f8b8bd4c4b2cf82ca7da8a3ea6a239655c39c050ab220",
    ],
    "amounts": [
        420000000,
        462000000,
        294000000,
        504000000,
        630000000,
        378000000,
        672000000,
        546000000,
        588000000,
    ],
    "signed": "020000000001097de20cbff686da83a54981d2b9bab3586f4ca7e48f57f5b55963115f3b334e9c010000000000000000d7b7cab57b1393ace2d064f4d4a2cb8af6def61273e127517d44759b6dafdd990000000000fffffffff8e1f583384333689228c5d28eac13366be082dc57441760d957275419a41842000000006b4830450221008f3b8f8f0537c420654d2283673a761b7ee2ea3c130753103e08ce79201cf32a022079e7ab904a1980ef1c5890b648c8783f4d10103dd62f740d13daa79e298d50c201210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798fffffffff0689180aa63b30cb162a73c6d2a38b7eeda2a83ece74310fda0843ad604853b0100000000feffffffaa5202bdf6d8ccd2ee0f0202afbbb7461d9264a25e5bfd3c5a52ee1239e0ba6c0000000000feffffff956149bdc66faa968eb2be2d2faa29718acbfe3941215893a2a3446d32acd050000000000000000000e664b9773b88c09c32cb70a2a3e4da0ced63b7ba3b22f848531bbb1d5d5f4c94010000000000000000e9aa6b8e6c9de67619e6a3924ae25696bb7b694bb677a632a74ef7eadfd4eabf0000000000ffffffffa778eb6a263dc090464cd125c466b5a99667720b1c110468831d058aa1b82af10100000000ffffffff0200ca9a3b000000001976a91406afd46bcdfd22ef94ac122aa11f241244a37ecc88ac807840cb0000000020ac9a87f5594be208f8532db38cff670c450ed2fea8fcdefcc9a663f78bab962b0141ed7c1647cb97379e76892be0cacff57ec4a7102aa24296ca39af7541246d8ff14d38958d4cc1e2e478e4d4a764bbfd835b16d4e314b72937b29833060b87276c030141052aedffc554b41f52b521071793a6b88d6dbca9dba94cf34c83696de0c1ec35ca9c5ed4ab28059bd606a4f3a657eec0bb96661d42921b5f50a95ad33675b54f83000141ff45f742a876139946a149ab4d9185574b98dc919d2eb6754f8abaa59d18b025637a3aa043b91817739554f4ed2026cf8022dbd83e351ce1fabc272841d2510a010140b4010dd48a617db09926f729e79c33ae0b4e94b79f04a1ae93ede6315eb3669de185a17d2b0ac9ee09fd4c64b678a0b61a0a86fa888a273c8511be83bfd6810f0247304402202b795e4de72646d76eab3f0ab27dfa30b810e856ff3a46c9a702df53bb0d8cc302203ccc4d822edab5f35caddb10af1be93583526ccfbade4b4ead350781e2f8adcd012102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f90141a3785919a2ce3c4ce26f298c3d51619bc474ae24014bcdd31328cd8cfbab2eff3395fa0a16fe5f486d12f22a9cedded5ae74feb4bbe5351346508c5405bcfee0020141ea0c6ba90763c2d3a296ad82ba45881abb4f426b3f87af162dd24d5109edc1cdd11915095ba47c3a9963dc1e6c432939872bc49212fe34c632cd3ab9fed429c4820141bbc9584a11074e83bc8c6759ec55401f0ae7b03ef290c3139814f545b58a9f8127258000874f44bc46db7646322107d4d86aec8e73b8719a61fff761d75b5dd9810065cd1d",
    "spending": [
        {
            "index": 0,
            "hashType": 3,
            "internalPubkey": "d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d",
            "merkleRoot": None,
            "tweak": "b86e7be8f39bab32a6f2c0443abbc210f0edac0e2c53d501b36b64437d9c6c70",
            "sighash": "2514a6272f85cfa0f45eb907fcb0d121b808ed37c6ea160a5a9046ed5526d555",
        },
        {
            "index": 1,
            "hashType": 131,
            "internalPubkey": "187791b6f712a8ea41c8ecdd0ee77fab3e85263b37e1ec18a3651926b3a6cf27",
            "merkleRoot": "5b75adecf53548f3ec6ad7d78383bf84cc57b55a3127c72b9a2481752dd88b21",
            "tweak": "cbd8679ba636c1110ea247542cfbd964131a6be84f873f7f3b62a777528ed001",
            "sighash": "325a644af47e8a5a2591cda0ab0723978537318f10e6a63d4eed783b96a71a4d",
        },
        {
            "index": 3,
            "hashType": 1,
            "internalPubkey": "93478e9488f956df2396be2ce6c5cced75f900dfa18e7dabd2428aae78451820",
            "merkleRoot": "c525714a7f49c28aedbbba78c005931a81c234b2f6c99a73e4d06082adc8bf2b",
            "tweak": "6af9e28dbf9d6aaf027696e2598a5b3d056f5fd2355a7fd5a37a0e5008132d30",
            "sighash": "bf013ea93474aa67815b1b6cc441d23b64fa310911d991e713cd34c7f5d46669",
        },
        {
            "index": 4,
            "hashType": 0,
            "internalPubkey": "e0dfe2300b0dd746a3f8674dfd4525623639042569d829c7f0eed9602d263e6f",
            "merkleRoot": "ccbd66c6f7e8fdab47b3a486f59d28262be857f30d4773f2d5ea47f7761ce0e2",
            "tweak": "b57bfa183d28eeb6ad688ddaabb265b4a41fbf68e5fed2c72c74de70d5a786f4",
            "sighash": "4f900a0bae3f1446fd48490c2958b5a023228f01661cda3496a11da502a7f7ef",
        },
        {
            "index": 6,
            "hashType": 2,
            "internalPubkey": "55adf4e8967fbd2e29f20ac896e60c3b0f1d5b0efa9d34941b5958c7b0a0312d",
            "merkleRoot": "2f6b2c5397b6d68ca18e09a3f05161668ffe93a988582d55c6f07bd5b3329def",
            "tweak": "6579138e7976dc13b6a92f7bfd5a2fc7684f5ea42419d43368301470f3b74ed9",
            "sighash": "15f25c298eb5cdc7eb1d638dd2d45c97c4c59dcaec6679cfc16ad84f30876b85",
        },
        {
            "index": 7,
            "hashType": 130,
            "internalPubkey": "ee4fe085983462a184015d1f782d6a5f8b9c2b60130aff050ce221ecf3786592",
            "merkleRoot": "6c2dc106ab816b73f9d07e3cd1ef2c8c1256f519748e0813e4edd2405d277bef",
            "tweak": "9e0517edc8259bb3359255400b23ca9507f2a91cd1e4250ba068b4eafceba4a9",
            "sighash": "cd292de50313804dabe4685e83f923d2969577191a3e1d2882220dca88cbeb10",
        },
        {
            "index": 8,
            "hashType": 129,
            "internalPubkey": "f9f400803e683727b14f463836e1e78e1c64417638aa066919291a225f0e8dd8",
            "merkleRoot": "ab179431c28d3b68fb798957faf5497d69c883c6fb1e1cd9f81483d87bac90cc",
            "tweak": "639f0281b7ac49e742cd25b7f188657626da1ad169209078e2761cefd91fd65e",
            "sighash": "cccb739eca6c13a8a89e6e5cd317ffe55669bbda23f2fd37b0f18755e008edd2",
        },
    ],
}


def register_official_sighash_checks(check):
    def bip143_official():
        passed = 0
        for case in BIP143_VECTORS:
            tx = parse_transaction(bytes.fromhex(case["tx"]))
            script = bytes.fromhex(case["script"])
            for key, expected in case["expect"].items():
                got = bip143_sighash(tx, case["vin"], script,
                                     case["amount"], int(key, 16))
                expect_equal("BIP143 %s hashType=%s" % (case["name"], key),
                             got.hex(), expected)
                passed += 1
        return "All %d official vectors match (across hash types)." % passed

    def taproot_sighash_official():
        vector = TAPROOT_SIGHASH_VECTOR
        tx = parse_transaction(bytes.fromhex(vector["unsigned"]))
        scripts = [bytes.fromhex(item) for item in vector["scripts"]]
        amounts = vector["amounts"]
        expect_equal("The number of prevout is consistent with the number of inputs", len(scripts), len(tx.inputs))

        signed = parse_transaction(bytes.fromhex(vector["signed"]))
        # BIP144: version | marker | flag | txins | txouts | witnesses | locktime
        expect_equal("Official signed transaction serialization round trip",
                     signed.serialize(with_witness=True).hex(), vector["signed"])

        passed = 0
        for case in vector["spending"]:
            index = case["index"]
            internal_x = bytes.fromhex(case["internalPubkey"])
            merkle_root = bytes.fromhex(case["merkleRoot"]) if case["merkleRoot"] else None

            expect_equal("TapTweak hashType=%#04x" % case["hashType"],
                         taproot_tweak(internal_x, merkle_root).hex(), case["tweak"])

            message = taproot_sighash(tx, index, scripts, amounts,
                                      case["hashType"], ext_flag=0)
            expect_equal("TapSighash input %d hashType=%#04x" % (index, case["hashType"]),
                         message.hex(), case["sighash"])

            # The last item in the official witness is the Schnorr signature (the last digit is the hash type when it is 65 bytes)
            raw = signed.inputs[index].witness[-1]
            signature = raw[:64]
            output_x = taproot_output_key(internal_x, merkle_root)
            if not schnorr_verify(message, output_x, signature):
                raise AssertionError("Official Schnorr signature failed signature verification under derived output public key: enter %d"
                                     % index)
            passed += 1
        return "All %d vectors match (tweak, output key, Schnorr verification included)." % passed

    def bip342_script_path_extension():
        """The BIP342 script path extension must follow the BIP341 generic SigMsg.

The official vectors are not copied here (there is no scriptPathSpending in wallet-test-vectors.json of BIP341).
Instead, manually spell out the expected value according to the original text of BIP342: sigMsg should be appended at the end.
tapleaf_hash(32) || key_version(0x00) || codesep_pos(4 bytes little endian).
Everything works fine with the 37 bytes less key path, only the script path computes a completely different hash.
        """
        tx = Transaction(
            version=2,
            inputs=[TxInput(bytes(range(32)) + (0).to_bytes(4, "little"), b"", 0xFFFFFFFE),
                    TxInput(bytes(range(32, 64)) + (1).to_bytes(4, "little"), b"", 0xFFFFFFFF)],
            outputs=[TxOutput(100_000, bytes.fromhex("0014" + "11" * 20)),
                     TxOutput(90_000, bytes.fromhex("5120" + "22" * 32))],
            locktime=17,
        )
        prevout_scripts = [bytes.fromhex("5120" + "aa" * 32), bytes.fromhex("0014" + "bb" * 20)]
        amounts = [150_000, 140_000]
        leaf_script = bytes.fromhex("20" + "cc" * 32 + "ac")

        # Manually spell the public part of BIP341 general SigMsg according to the specification (hashType=0x00, which is SIGHASH_DEFAULT,
        # The hash range is the same as ALL). spend_type and input_index are placed later and are spelled according to the spending method.
        common = bytes([0x00])
        common += (2).to_bytes(4, "little")
        common += (17).to_bytes(4, "little")
        common += sha256(b"".join(item.outpoint for item in tx.inputs))
        common += sha256(b"".join(value.to_bytes(8, "little") for value in amounts))
        common += sha256(b"".join(compact_size(len(item)) + item
                                  for item in prevout_scripts))
        common += sha256(b"".join(item.sequence.to_bytes(4, "little") for item in tx.inputs))
        common += sha256(b"".join(item.serialize() for item in tx.outputs))
        index_bytes = (0).to_bytes(4, "little")

        key_path = taproot_sighash(tx, 0, prevout_scripts, amounts, 0x00, ext_flag=0)
        expect_equal("BIP341 Generic SigMsg", key_path.hex(),
                     tagged_hash("TapSighash", b"\x00" + common
                                 + bytes([0x00]) + index_bytes).hex())

        # Script path: spend_type becomes 0x02, followed by the 37-byte BIP342 extension
        extension = tapleaf_hash(leaf_script, LEAF_TAPSCRIPT)
        extension += b"\x00"                            # key_version
        extension += (0xFFFFFFFF).to_bytes(4, "little")  # Not executed OP_CODESEPARATOR
        script_path = taproot_sighash(tx, 0, prevout_scripts, amounts, 0x00,
                                      ext_flag=1, script=leaf_script)
        expect_equal("BIP342 script-path extension", script_path.hex(),
                     tagged_hash("TapSighash", b"\x00" + common
                                 + bytes([0x02]) + index_bytes + extension).hex())

        if key_path == script_path:
            raise AssertionError("The script path and key path calculate the same hash, indicating that the extension is ignored")

        # When OP_CODESEPARATOR is executed, codesep_pos is replaced with the real position, and the rest remains unchanged.
        with_sep = taproot_sighash(tx, 0, prevout_scripts, amounts, 0x00,
                                   ext_flag=1, script=leaf_script, codeseparator_pos=3)
        expect_equal("BIP342 codesep_pos=3", with_sep.hex(),
                     tagged_hash("TapSighash", b"\x00" + common
                                 + bytes([0x02]) + index_bytes + extension[:-4]
                                 + (3).to_bytes(4, "little")).hex())
        if with_sep == script_path:
            raise AssertionError("codeseparator_pos does not go into the hash")

        # Extensions and signatures must be compatible: signature -> signature verification and go through the real process
        secret = 0x0111111111111111111111111111111111111111111111111111111111111111
        xonly = pubkey_to_xonly(compressed_pubkey(secret))
        signature = schnorr_sign(script_path, secret)
        if not schnorr_verify(script_path, xonly, signature):
            raise AssertionError("Script path signature self-verification failed")
        return "Key path, script path, and codesep_pos all correct; the extension is 37 bytes."

    check("BIP143 official signature hashes", bip143_official)
    check("BIP341 official signature hashes", taproot_sighash_official)
    check("BIP342 script-path extension", bip342_script_path_extension)

#================= Output format =================
def cell(value):
    """Unify the display of None."""
    return "—" if value is None else str(value)


def hex_or_none(data):
    return None if data is None else data.hex()


def scheme_to_json(scheme):
    """Convert the scheme into a JSON serializable structure."""
    result = {}
    for key, value in scheme.items():
        if isinstance(value, bytes):
            result[key] = value.hex()
        elif isinstance(value, (list, tuple)):
            result[key] = [item.hex() if isinstance(item, bytes) else item for item in value]
        elif isinstance(value, tuple):
            result[key] = value
        else:
            result[key] = value
    result.pop("output_point", None)
    result.pop("merkle_paths", None)
    return result


def render_scheme(scheme):
    """The default is concise chunked output."""
    if scheme["type"] == "p2wsh":
        header = "%d-of-%d multi-signature (bc1q, requires the signature of %d people)" % (
            scheme["threshold"], scheme["members"], scheme["threshold"])
        rows = [
            ("Primary address bc1q", scheme["address"]),
            ("descriptor", descriptor_with_checksum(scheme["descriptor"])),
        ]
    else:
        header = "%d-of-%d signed by all members (bc1p, no one of %d can be missing)" % (
            scheme["threshold"], scheme["members"], scheme["threshold"])
        rows = [
            ("Primary address bc1p", scheme["address"]),
            ("Output public key", scheme["output_key"].hex()),
            ("descriptor", descriptor_with_checksum(scheme["descriptor"])),
        ]
    lines = ["=" * 64, header, "=" * 64]
    lines += ["  %-12s %s" % (label, value) for label, value in rows]
    lines.append("")
    lines.append("Members (by %s):" % ("BIP67 sorting" if scheme["type"] == "p2wsh" else "x coordinate ascending order"))
    if scheme["type"] != "p2wsh":
        lines.append("Note: The following is an x-only public key (the compressed public key removes the first 02/03 bytes).")
    for index, key in enumerate(scheme["keys"], 1):
        lines.append("   %2d. %s" % (index, key.hex()))
    lines.append("=" * 64)
    return "\n".join(lines)


def render_scheme_detail(scheme):
    """Complete information when adding -d: scripts, paths, and control blocks are fully expanded."""
    lines = [render_scheme(scheme), ""]
    if scheme["type"] == "p2wsh":
        lines += [
            "  witnessScript  ", scheme["witness_script"].hex(),
            "  scriptPubKey   ", scheme["script_pubkey"].hex(),
            "redeemScript(old)", scheme["witness_script"].hex(),
            "",
        ]
    else:
        lines += [
            "leaf script", scheme["leaf_scripts"][0].hex(),
            "  merkle root    ", scheme["merkle_root"].hex(),
            "control block", scheme["control_blocks"][0].hex(),
            "  scriptPubKey   ", scheme["script_pubkey"].hex(),
            "",
            "Witness stack template (signed by all members):",
        ]
        for index in range(len(scheme["keys"])):
            lines.append("[%d] <Schnorr signature of member %d>" % (index, index + 1))
        lines.append("[%d] <control block>" % len(scheme["keys"]))
        lines.append("")
    lines.append("illustrate:" + scheme["note"])
    return "\n".join(lines)


def render_members(members):
    lines = ["=" * 64, "member key", "=" * 64]
    all_secret_keys = all(item.get("secret") for item in members)
    for index, item in enumerate(members, 1):
        lines.append("%2d. Private key (WIF) %s" % (index, item["source"]))
        lines.append("↑ Keep it confidential! This is your signing authority. Don't save it online or tell anyone.")
        lines.append("Public key %s" % item["pubkey"].hex())
        lines.append("↑ This one may be public; it is used to assemble the multisig address with counterparties.")
        secret = item.get("secret")
        if secret:
            ok = compressed_pubkey(secret) == item["pubkey"]
            lines.append("Check %s" % ("Pass - the public key in the above line was indeed generated from that private key" if ok
                                                 else "Exception - The public key does not match the private key!"))
        lines.append("")
    if all_secret_keys:
        lines.append("It has been verified item by item: the \"public key\" of each row is indeed derived from the corresponding \"private key\".")
    lines.append("=" * 64)
    return "\n".join(lines)


def render_verify_report(title, rows):
    """Plan verification report. Each item in rows is (description, whether expected to pass, whether actually passed, details)."""
    lines = ["=" * 64, "  " + title, "=" * 64]
    for label, expect_pass, actual_pass, detail in rows:
        mark = "pass" if actual_pass == expect_pass else "fail"
        lines.append("  [%s] %-34s %s" % (mark, label, detail))
    lines.append("=" * 64)
    return "\n".join(lines)


def render_selftest_report(title, checks):
    """Self-test report. Each check item is (name, passed or not, details)."""
    lines = ["=" * 64, "  " + title, "=" * 64]
    for name, ok, detail in checks:
        lines.append("  [%s] %-34s %s" % ("pass" if ok else "fail", name, detail))
    lines.append("=" * 64)
    return "\n".join(lines)


def write_output(text, path):
    """Output to a file or standard output."""
    if path in (None, "", "-"):
        print(text)
        return
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text + "\n")
    print("Saved to %s" % path)


def display_width(text):
    """The length is calculated according to the terminal display width (Chinese is calculated as two spaces)."""
    import unicodedata
    return sum(2 if unicodedata.east_asian_width(char) in "WF" else 1 for char in text)


def pause_before_exit(message="\nPress Enter to close the window..."):
    if sys.stdin.isatty():
        try:
            input(message)
        except (EOFError, KeyboardInterrupt):
            pass


def backend_note():
    """Backend instructions for -v."""
    parts = ["curve" + CURVE_BACKEND]
    parts.append("SegWit address encoding" + ("bech32m library" if HAVE_BECH32M else "built-in"))
    parts.append("Base58 encoding" + ("base58 library" if HAVE_BASE58 else "built-in"))
    return ",".join(parts)


#================= Plan verification demonstration =================
def run_scheme_checks(scheme, members, verbose=False):
    """Perform end-to-end verification of the built solution to prove that the script actually works as expected.

One less person will be deliberately signed, and the verification script will indeed reject it - just checking \"if you sign enough to pass\" does not explain the threshold.

Returns (description, expected pass, actual pass, details) for each row.
By returning \"expected\" and \"actual\" separately, the caller can judge whether the behavior meets expectations;
If only Boolean values are returned, \"correctly rejected\" and \"erroneously passed\" will be mixed together.
    """
    rows = []

    if scheme["type"] == "p2wsh":
        secrets_by_key = {item["pubkey"]: item["secret"] for item in members if item["secret"]}
        ordered = [key for key in scheme["keys"] if key in secrets_by_key]
        if len(ordered) < scheme["threshold"]:
            return [("Insufficient member private key, skip", True, True,
                     "Only got %d/%d private keys" % (len(ordered), scheme["threshold"]))]
        # When the threshold is 1, there is no testable scenario with \"one less person\" (0 people cannot construct the witness stack), and only the compliance situation is measured.
        counts = [scheme["threshold"]]
        if scheme["threshold"] - 1 >= 1:
            counts.insert(0, scheme["threshold"] - 1)
        for count in counts:
            expect_pass = (count == scheme["threshold"])
            actual, detail = verify_p2wsh_multisig(scheme["witness_script"], ordered,
                                                 secrets_by_key, count)
            label = "%d/%d person signature (%s)" % (count, len(ordered),
                                           "should pass" if expect_pass else "should fail")
            rows.append((label, expect_pass, actual, detail))
        return rows

    secrets_by_xonly = {pubkey_to_xonly(item["pubkey"]): item["secret"]
                        for item in members if item["secret"]}
    ordered = [key for key in scheme["keys"] if key in secrets_by_xonly]
    if not ordered:
        return [("Insufficient member private key, skip", True, True, "Didn't get any member private key")]
    leaf_script = scheme["leaf_scripts"][0]
    transaction = build_test_transaction()
    signatures = []
    for key in ordered:
        message = taproot_sighash(transaction, 0, [scheme["script_pubkey"]], [100_000],
                                  SIGHASH_DEFAULT, ext_flag=1, script=leaf_script)
        signatures.append(schnorr_sign(message, secrets_by_xonly[key]))
    for count in (len(signatures) - 1, len(signatures)):
        expect_pass = (count == len(signatures))
        # The witness stack is in reverse order: the top of the stack is the signature of the last member, so it must be passed backwards.
        actual, detail = verify_taproot_script_path(leaf_script, list(reversed(signatures[:count])))
        label = "%d/%d person signature (%s)" % (count, len(signatures),
                                       "should pass" if expect_pass else "should fail")
        rows.append((label, expect_pass, actual, detail))
    return rows


#================= Command line =================
def read_members_file(path):
    if path in (None, "", "-"):
        return sys.stdin.read()
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def default_threshold(count):
    """Give a decent default threshold: 3 people -> 2, 5 people -> 3, at least 1 when there are few people."""
    return min(count, max(2, count // 2 + 1))


def command_build(args):
    members = parse_members(read_members_file(args.members))
    schemes = []
    if args.type in ("p2wsh", "both"):
        threshold = args.threshold or default_threshold(len(members))
        schemes.append(build_p2wsh_scheme(members, threshold, args.order))
    if args.type in ("p2tr", "both"):
        schemes.append(build_taproot_scheme(members, args.layout))
    outputs = []
    for scheme in schemes:
        if args.detail:
            outputs.append(render_scheme_detail(scheme))
        else:
            outputs.append(render_scheme(scheme))
        if args.verify:
            rows = run_scheme_checks(scheme, members, args.verbose)
            outputs.append(render_verify_report("End-to-end signature verification", rows))
    if args.format == "json":
        write_output(json.dumps([scheme_to_json(item) for item in schemes],
                                ensure_ascii=False, indent=2), args.out)
    else:
        write_output("\n\n".join(outputs), args.out)
    return 0


def command_keys(args):
    members = random_members(args.count)
    if args.format == "json":
        write_output(json.dumps([
{"wif": item["source"], "pubkey": item["pubkey"].hex()} for item in members],
            ensure_ascii=False, indent=2), args.out)
    else:
        write_output(render_members(members), args.out)
    return 0


def inspect_address(address):
    """What can you tell by looking at the address. It is not clear whether scriptPubKey is P2WPKH or P2WSH."""
    lines = []
    # segwit_decode returns (hrp, version, witness program), returns None if it is not a SegWit address
    decoded = segwit_decode(address)
    if decoded is not None:
        hrp, version, program = decoded
        lines.append("Type: SegWit v%d%s" % (version, "(Taproot)" if version == 1 else ""))
        lines.append("Prefix: %s..." % address[:8])
        lines.append("Network: %s" % HRP_NAMES.get(hrp, hrp))
        lines.append("Witness program: %s (%d bytes)" % (program.hex(), len(program)))
        if version == 0 and len(program) == 20:
            lines.append("Note: P2WPKH and P2WSH are both 20 bytes and cannot be distinguished by just looking at the address.")
            lines.append("You have to look at UTXO's scriptPubKey to know.")
        elif version == 0 and len(program) == 32:
            lines.append("Description: P2WSH, multi-signature address is this.")
        elif version == 1:
            lines.append("Description: Taproot outputs the public key (bc1p).")
        else:
            lines.append("Description: Unknown witness version, please confirm whether the address is correct.")
        return "\n".join(lines)
    try:
        payload = base58check_decode(address)
        if not payload:
            raise ValueError("Wrong length or checksum")
        lines.append("Type: Base58Check (P2PKH or P2SH)")
        lines.append("Content: %s" % payload.hex())
        if payload[0] == 0x00:
            lines.append("Description: P2PKH, scriptPubKey starts with 76a914.")
        elif payload[0] in (0x05, 0xC4):
            lines.append("Note: P2SH, scriptPubKey starting with a9 is an old-fashioned multi-signature.")
        else:
            lines.append("Explanation: The prefix %02x is not a common P2PKH/P2SH." % payload[0])
        return "\n".join(lines)
    except ValueError as error:
        return "Can't understand this address: %s" % error


def command_inspect(args):
    report = inspect_address(args.address)
    write_output(report, args.out)
    # For addresses that are incomprehensible, the caller (script, pipeline) must be able to determine success or failure.
    return 1 if "Can't understand" in report else 0


def command_selftest(args):
    """Built-in Self-test. By default, only one line of conclusions is reported, and -v is used to list each item."""
    checks = []
    register_checks(lambda name, function: collect_check(checks, name, function))
    if args.verbose:
        write_output(render_selftest_report("Self-test", checks), args.out)
        return 0 if all(item[1] for item in checks) else 1
    failed = [item for item in checks if not item[1]]
    write_output("Total %d checks, %d failed." % (len(checks), len(failed)) if failed
                 else "Program OK: %d checks, all passed." % len(checks), args.out)
    return 1 if failed else 0


def collect_check(checks, name, function):
    """Run a Self-test and note any abnormalities as results."""
    try:
        checks.append((name, True, function() or ""))
    except Exception as error:                    # Self-test should count any exception as a failure
        checks.append((name, False, "%s: %s" % (type(error).__name__, error)))


MENU_TEXT = """
================== Bitcoin Multi-signature Tool V2 ==================
1 One-click multisig plan
     (the program creates the keys for you)
2 Use your own member list  Paste xpub / public keys / private keys
3 Inspect address
4 Self-test
0 Exit
======================================================
""".strip("\n")

WARNING_TEXT = "The keys above are confidential. Keep any private keys offline and out of source control.tory."


def prompt_members():
    """Paste the member list.ter to end."""
    print("WIF private key / 64-bit hex private key / decimal private key are all accepted.")
    print("33-byte compressed public key / x: plus 64-bit x-only public key / xpub derivation path")
    print("One per line, or comma-separated; press Enter on an empty line to finish:")
    lines = []
    while True:
        try:
            line = input("  > ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not line:
            break
        lines.extend(part.strip() for part in line.split(",") if part.strip())
    return "\n".join(lines)


def ask_threshold(members):
    """bc1q requires several signatures. Just ask this sentence, press Enter to use the default value; if you make a mistake, ask again without reporting an error."""
    fallback = default_threshold(len(members))
    while True:
        raw = input("Signatures required for bc1q (1-%d, press Enter for %d):" % (
            len(members), fallback)).strip()
        if not raw:
            return fallback
        try:
            value = int(raw)
        except ValueError:
            print("Enter an integer between 1 and %d." % len(members))
            continue
        if 1 <= value <= len(members):
            return value
        print("The threshold must be between 1 and %d; this plan has %d members." % (len(members), len(members)))


def show_schemes(members, threshold):
    """Show both bc1q and bc1p plans. If all keys exist locally, verify signatures before asking to save. file."""
    pairs = [("bc1q lets any m-of-n signers spend", build_p2wsh_scheme(members, threshold)),
             ("bc1p requires every member to sign", build_taproot_scheme(members))]
    blocks = []
    for title, scheme in pairs:
        text = render_scheme(scheme)
        blocks.append("---- %s ----\n%s" % (title, text))
        print()
        print("  ---- %s ----" % title)
        print(text)
        if all(item["secret"] for item in members):
            print()
            print(render_verify_report("End-to-end signature verification", run_scheme_checks(scheme, members)))
    path = input("\n Save to file (press enter without saving):").strip()
    if path:
        write_output("\n\n".join(blocks), path)
        print("Saved to %s" % path)
    return 0


def menu_build():
    print()
    members = parse_members(prompt_members())
    if not members:
        print("No members read, back to menu.")
        return 0
    print("Read %d members." % len(members))
    return show_schemes(members, ask_threshold(members))


def menu_quick():
    """Shortest path: Say \"how many people v how many can sign\", the program creates the key and directly gives the address."""
    print()
    print("How many people do you want and how many of them can sign? Write directly, for example:")
    print("3v2 = signatures of any 2 of 3 members; 5v3 = 3 of 5.")
    print("Just write a number (such as 4) to give only the number of people, and use the default value for the threshold.")
    raw = input("  > ").strip().lower()
    if not raw:
        return 0
    for sep in ("of", "v", "/", "-", ",", ",", " "):
        raw = raw.replace(sep, " ")
    numbers = [int(part) for part in raw.split() if part.isdigit()]
    if not numbers:
        print("Couldn't parse that, back to the main menu.")
        return 0
    total = numbers[0]
    threshold = numbers[1] if len(numbers) >= 2 else default_threshold(total)
    if threshold > total:              # If the order is reversed, it will be automatically reversed.
        total, threshold = threshold, total
    if not (1 <= total <= 20 and 1 <= threshold <= total):
        print("The number of people is limited to 1-20, and the threshold must be 1-%d." % total)
        return 0
    members = random_members(total)
    print()
    print(render_members(members))
    print("Warning: " + WARNING_TEXT)
    print("Tip: If you want to do multi-party multi-signature, each participant should keep their own private key.")
    print("Only send the \"public key\" above to others, and then use menu 2 to build the combined address.")
    return show_schemes(members, threshold)


def menu_inspect():
    print()
    text = input("Enter the address (press Enter to return):").strip()
    if not text:
        return 0
    print()
    print(inspect_address(text))
    return 0


def menu_selftest():
    checks = []
    register_checks(lambda name, function: collect_check(checks, name, function))
    print()
    print(render_selftest_report("Self-test", checks))
    failed = [item for item in checks if not item[1]]
    print()
    print("Total %d checks, %d failed." % (len(checks), len(failed)) if failed
          else "Program OK: %d checks, all passed." % len(checks))
    return 0


MENU_ACTIONS = {
    "1": menu_quick, "2": menu_build, "3": menu_inspect, "4": menu_selftest,
}


def show_menu():
    print()
    print(MENU_TEXT)


def run_interactive():
    enable_utf8_console()
    print()
    print("Bitcoin multisig address tool V2 (mainnet only)")
    print("  " + "-" * 46)
    print("bc1q = m-of-n: any m signatures are enough")
    print("bc1p = n-of-n: every member must sign")
    print("These mechanisms are different; do not confuse them.")
    while True:
        show_menu()
        try:
            choice = input("Please select (press enter to exit):").strip() or "0"
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if choice == "0":
            return 0
        action = MENU_ACTIONS.get(choice)
        if action is None:
            print("There is no such option.")
            continue
        try:
            action()
        except (ValueError, OSError) as error:
            print("\n Error: %s" % error)
        except KeyboardInterrupt:
            print("\nCancelled.")


def add_common_arguments(parser):
    parser.add_argument("-f", "--format", default="block", choices=["block", "json"],
                        help="Output format, default block")
    parser.add_argument("-o", "--out", default="-", help="Output file, - means print to screen")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show details like backend, itemized results, and more")


def build_parser():
    parser = argparse.ArgumentParser(
        prog="bitcoin_multisig_v2",
        description="Bitcoin multisig address generation and verification (mainnet): bc1q m-of-n, bc1p n-of-n")
    subparsers = parser.add_subparsers(dest="command")

    build = subparsers.add_parser("build", help="Generate multi-signature plan based on member list")
    build.add_argument("members", nargs="?", default="-", help="Member list file, - means reading from standard input")
    build.add_argument("-t", "--type", default="p2wsh", choices=["p2wsh", "p2tr", "both"],
                       help="Scheme type, default p2wsh (m-of-n for bc1q)")
    build.add_argument("-m", "--threshold", type=int, default=None, help="Several signatures are required (for bc1q)")
    build.add_argument("--order", default="bip67", choices=["bip67", "fingerprint"],
                       help="Public key sorting method, default bip67")
    build.add_argument("--layout", default="chain", choices=["chain", "tree"],
                       help="Taproot structure, default chain (can really force everyone to sign)")
    build.add_argument("-d", "--detail", action="store_true", help="Display complete information such as scripts, control blocks, etc.")
    build.add_argument("--verify", action="store_true", help="By the way, do end-to-end signature verification")
    add_common_arguments(build)

    keys = subparsers.add_parser("keys", help="Generate random member keys")
    keys.add_argument("-c", "--count", type=int, default=10, help="Generate several, default 10")
    add_common_arguments(keys)

    inspect = subparsers.add_parser("inspect", help="Inspect address")
    inspect.add_argument("address", help="The address to resolve")
    add_common_arguments(inspect)

    selftest = subparsers.add_parser("selftest", help="Built-in Self-test")
    selftest.add_argument("-o", "--out", default="-", help="Output file, - means print to screen")
    selftest.add_argument("-v", "--verbose", action="store_true", help="Show results item by item")
    return parser


def main():
    enable_utf8_console()
    parser = build_parser()
    arguments = parser.parse_args()
    if arguments.command is None:
        return run_interactive()
    if arguments.command == "build":
        return command_build(arguments)
    if arguments.command == "keys":
        return command_keys(arguments)
    if arguments.command == "inspect":
        return command_inspect(arguments)
    if arguments.command == "selftest":
        return command_selftest(arguments)
    parser.print_help()
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError) as error:
        print("Something went wrong: %s" % error, file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print()
        sys.exit(130)