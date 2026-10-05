#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
# Bitcoin Multisig Address Generation and Verification Tool --- V2
#
# [About this script]
# A single file, fully offline, with no dependency on any wallet-level or
# third-party multisig wrapper. It generates two kinds of mainnet multisig
# addresses and then actually runs the spending transaction through its own
# script interpreter, proving that the address and the threshold behave as
# expected instead of merely computing a string and showing it to you.
#
# Double-click this file (or run it with no arguments) to enter the English
# menu; the command line can be used directly as well:
#
#   python bitcoin_multisig_v2_en.py                             enter the English menu
#   python bitcoin_multisig_v2_en.py build keys.txt -t both -d --verify
#   python bitcoin_multisig_v2_en.py keys -c 10                 make 10 test keys
#   python bitcoin_multisig_v2_en.py inspect bc1q...            parse one address
#   python bitcoin_multisig_v2_en.py selftest -v                run the official vectors
#
# Member input formats (mix freely, one per line):
#   WIF private key / 64-hex-digit private key / decimal private key /
#   33-byte compressed pubkey / 65-byte uncompressed pubkey / 32-byte x-only pubkey
#   (Taproot only)
#
# Two kinds of multisig are supported. The mechanisms differ, do not mix them:
#
#   1) bc1q prefix - native SegWit multisig (P2WSH) - m-of-n
#      Any m members' signatures can spend. Members may be added or removed
#      without changing the address structure, but once the member set changes
#      the address must change, so all participants have to agree in advance on
#      the same public keys and the same ordering.
#
#   2) bc1p prefix - Taproot script-path multisig (P2TR) - N-of-N
#      The member public keys are chained into one CHECKSIG chain and every
#      member has to sign; not one can be missing. Taproot has no
#      OP_CHECKMULTISIG, so m-of-n cannot be done inside a single script (MuSig2
#      key aggregation is a different scheme and out of scope for this file).
#      Security: the internal key is fixed to BIP341's NUMS point, nobody knows
#      its discrete logarithm, so the key path cannot spend and the funds can
#      only be moved by a script path where everybody signs. Never use the base
#      point G as the internal key here - G's discrete logarithm is 1, so
#      anybody can compute the tweak and privatize it alone, which bypasses the
#      multisig completely.
#
# [Core logic and formulas]
#
#   0. Curve basics
#      secp256k1: y^2 = x^3 + 7 (mod p)
#      p = 2^256 - 2^32 - 977, b = 7, base point order n
#      (PRIME, CURVE_B, ORDER in the code)
#      public key point Q = d * G
#      compressed pubkey = (0x02 | 0x03) || x(32B), first byte = 2 + (y mod 2)
#      lift_x(x): y = (x^3 + 7)^((p+1)/4) mod p, take the even y
#
#   1. Hashes
#      hash160(d)         = RIPEMD160(SHA256(d))            20-byte digest
#      double_sha256(d)   = SHA256(SHA256(d))               Base58Check checksum
#      tagged_hash(tag,d) = SHA256(SHA256(tag) || SHA256(tag) || d)
#                          the domain-separated hash of BIP340/341/342
#
#   2. bc1q address (P2WSH, m-of-n)
#      witnessScript = OP_m <pk1> ... <pk_n> OP_n OP_CHECKMULTISIG
#        OP_k is encoded as 0x50 + k (k = 1...16), and OP_0 is 0x00;
#        you must not write bytes([k]) directly, that yields invalid 0x01...0x10
#        the public keys are sorted ascending by bytes (BIP67; everyone must
#        agree, otherwise the addresses all differ)
#      scriptPubKey  = 0x00 0x14 || hash160(witnessScript)      34 bytes in total
#      address = bech32("bc", witness version 0 || convertbits(program, 8->5))
#        the checksum uses the BCH polynomial (BIP173, constant 1; witness version
#        >= 1 uses bech32m, BIP350, constant 0x2BC830A3):
#          chk = ((chk & 0x1FFFFFF) << 5) ^ v
#          each step also XORs the generators selected by the 5 bits of chk >> 25
#
#   3. bc1p address (P2TR, N-of-N all signatures)
#      leaf script = push(x-only 32B) || OP_CHECKSIG, the form used by the tree
#                   layout with "one leaf per member"; the default chain layout
#                   strings N public keys into one CHECKSIGVERIFY chain (with a
#                   single trailing CHECKSIG), and the whole chain counts as one leaf
#      leaf hash = tagged_hash("TapLeaf", 0xC0 || compact_size(len) || script)
#      branch hash = tagged_hash("TapBranch", min(a,b) || max(a,b))   ascending
#      Merkle root = pairwise merges bottom-up; with an odd number of leaves the
#                   left side takes the first floor(n/2), so 3 leaves give
#                   [l0, [l1, l2]], the same shape as the BIP341 official vectors
#                   (the chain layout has a single leaf, so the Merkle root is
#                   exactly that leaf hash)
#      tweak  = tagged_hash("TapTweak", internal key x || merkle root)
#               note there is no 0x00 prefix: an early draft had
#               0x00 || p || merkleRoot, and copying that draft gives a wrong address
#      output point Q = lift_x(internal key) + tweak * G, and tweak >= n is invalid
#      scriptPubKey = 0x51 0x20 || Q.x(32B)
#      address = bech32m("bc", witness version 1, Q.x)
#      control block = (leaf version | Q.y parity) || internal key x ||
#                      the sequence of sibling hashes; the verifier recomputes the
#                      Merkle root from the siblings and then the tweak, so no other
#                      script can be smuggled in
#      internal key = BIP341's NUMS point H (x = 50929b74...03ac0), see NUMS_X
#
#   4. Signature hashes
#      P2WSH follows BIP143, the final result is double_sha256(preimage):
#        preimage = version || hashPrevouts || hashSequence || outpoint ||
#                   compact_size(len) || witnessScript || amount (8B LE) ||
#                   sequence || hashOutputs || locktime || hash_type
#        the three hashes are decided by hash_type; when the input index exceeds
#        the number of outputs, hashOutputs is 32 zero bytes instead of the old
#        algorithm's 0x01 sentinel value
#      Taproot follows BIP341: SigMsg starts with 0x00, then
#      tagged_hash("TapSighash", ...):
#        without ANYONECANPAY, what follows nLockTime is sha_prevouts,
#        sha_amounts, sha_scriptpubkeys, sha_sequences
#        when the low 2 bits of hash_type are NONE/SINGLE, sha_outputs is
#        omitted entirely, not filled with 32 zero bytes
#        the script path additionally appends
#        tapleaf_hash(32B) || 0x00 || codesep_pos(4B LE), and if OP_CODESEPARATOR
#        never ran, write 0xffffffff - those 37 bytes cannot be skipped
#
#   5. Threshold verification (the scripts really run during the self-test)
#      P2WSH: execute OP_CHECKMULTISIG with Bitcoin Core semantics - a signature
#             count of zero fails immediately; signatures must appear in public
#             key order and cannot skip ahead to sign a later key
#      bc1p:  a CHECKSIGVERIFY chain plus a trailing CHECKSIG; one missing
#             signature breaks the chain, so it must fail
#
#   6. BIP32 non-hardened derivation (multisig member paths are all 0/0/*)
#      I = HMAC-SHA512(chain_code, pubkey || index_be32), the left half is the
#      private key and the right half the chain code
#      the left half must satisfy 0 < I_L < n, otherwise that index is invalid
#      child point = lift_x(I_L) * G + parent point
#
#   7. Descriptor checksum (BIP380)
#      after mapping the characters into 5-bit groups, run the polymod:
#        chk = ((chk & 0x7FFFFFFFF) << 5) ^ v
#        each step XORs the generators selected by the 5 bits of chk >> 35; then
#        8 zeros are appended and XORed with 1 so the final result is 0.
#        Appending only one zero yields a wrong checksum
#
# [Naming conventions]
#   Functions and variables: lower snake_case (push_data, taproot_tweak,
#     wrap_value)
#   Constants: UPPER_CASE (PRIME, ORDER, LINE_WIDTH, BECH32M_CONST)
#   Data fields: lower snake_case, kept identical to the JSON output keys
#     (address, descriptor, witness_script, merkle_root, ...)
#   Two spots are deliberately left as they are; do not "tidy them up":
#     (1) a...v, x/y/z, u1/u2 in the elliptic curve addition/multiplication
#         formulas keep the standard notation, so they can be compared term by
#         term against the EFD and the formulas in the literature;
#     (2) field names such as internalPubkey, merkleRoot and hashType in the
#         official vectors are copied verbatim from the BIP texts, so they can
#         be diffed against the official documents.
#
# [Implementation and dependencies]
#   Installed libraries are used when available (coincurve / ecdsa / bech32m /
#   bech32 / base58); whichever one is missing falls back automatically to the
#   equivalent built-in implementation in this file, so the single file still
#   runs when it is copied elsewhere.
#   All signature hashes are implemented from the BIP specifications. The
#   bundled Schnorr/ECDSA signatures exist only for the self-test; in production
#   use a mature wallet or HWI.
# =============================================================================
import argparse
import hashlib
import hmac
import json
import os
import secrets
import sys
import time
import unicodedata

if os.name == "nt":                               # Console encoding tweak is only needed on Windows
    import ctypes
else:
    ctypes = None
# ================= Optional encoding library: base58 =================
try:                                             # prefer `pip install base58`
    import base58
    HAVE_BASE58 = True
except ImportError:                              # fall back to the built-in implementation when missing
    HAVE_BASE58 = False

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"  # the easily confused 0 O I l are removed


def base58_encode_builtin(data):
    """Built-in Base58 encoding (only used when the base58 library is missing)."""
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


def base58_decode_builtin(text):
    """Built-in Base58 decoding (only used when the base58 library is missing)."""
    number = 0
    for char in text:
        if char not in BASE58_ALPHABET:
            raise ValueError("invalid Base58 character %r" % char)
        number = number * 58 + BASE58_ALPHABET.index(char)
    decoded = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    for char in text:
        if char != "1":
            break
        decoded = b"\x00" + decoded
    return decoded


def base58_encode(data):
    """Base58 encoding: use the base58 library, or the built-in implementation if it is missing."""
    if HAVE_BASE58:
        return base58.b58encode(data).decode("ascii")
    return base58_encode_builtin(data)


def base58_decode(text):
    """Base58 decoding: use the base58 library, or the built-in implementation if it is missing."""
    if HAVE_BASE58:
        return base58.b58decode(text)
    return base58_decode_builtin(text)


# ================= Optional encoding libraries: bech32m / bech32 =================
try:                                             # bech32m comes first: one API covers both bech32 and bech32m
    import bech32m
    HAVE_BECH32M = True
except ImportError:                              # on ImportError fall back to the bech32 library, then to the built-in code
    HAVE_BECH32M = False

try:                                             # bech32 1.2.0 only implements BIP-173, so the bech32m constant has to be added by hand
    import bech32
    HAVE_BECH32 = True
except ImportError:
    HAVE_BECH32 = False

BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"  # map from 5-bit values to characters
BECH32_CONST = 1                                     # BIP-173 (witness v0) checksum constant
BECH32M_CONST = 0x2BC830A3                           # BIP-350 (witness v1+) checksum constant
BECH32_GENERATORS = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]  # generator polynomial coefficients


def bech32_polymod(values):
    """Built-in BCH checksum computation (used when both libraries are missing)."""
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = ((checksum & 0x1FFFFFF) << 5) ^ value
        for index in range(5):
            if (top >> index) & 1:
                checksum ^= BECH32_GENERATORS[index]
    return checksum


def bech32_hrp_expand(hrp):
    """Built-in HRP expansion: the high 5-bit sequence + separator 0 + the low 5-bit sequence."""
    return [ord(char) >> 5 for char in hrp] + [0] + [ord(char) & 31 for char in hrp]


def convert_bits(data, from_bits, to_bits, pad=True):
    """Bit width conversion: 8-bit bytes <-> 5-bit groups; bech32m decoding needs pad=False."""
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
    """Build the 6 five-bit checksum characters; const decides bech32 vs bech32m."""
    if HAVE_BECH32 and const == BECH32_CONST:
        return bech32.bech32_create_checksum(hrp, data)
    polymod = bech32_polymod(bech32_hrp_expand(hrp) + list(data) + [0] * 6) ^ const
    return [(polymod >> 5 * (5 - index)) & 31 for index in range(6)]


def bech32_checksum_spec(hrp, data):
    """Decide whether a checksum is bech32 or bech32m; return the constant or None (verification failed)."""
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
    """SegWit address encoding: v0 uses bech32, v1 and above use bech32m (the library picks by version)."""
    if HAVE_BECH32M:
        return bech32m.encode(hrp, witness_version, witness_program)
    data = [witness_version] + convert_bits(list(witness_program), 8, 5)
    const = BECH32_CONST if witness_version == 0 else BECH32M_CONST
    checksum = bech32_checksum(hrp, data, const)
    return hrp + "1" + "".join(BECH32_CHARSET[value] for value in data + checksum)


def segwit_decode(address):
    """SegWit address decoding; returns (hrp, witness_version, witness_program) or None."""
    if HAVE_BECH32M:                                # the bech32m library performs every validity check itself
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


# ================= Hashes =================
def sha256(data):
    """A single SHA-256."""
    return hashlib.sha256(data).digest()


def double_sha256(data):
    """Double SHA-256, the source of the Base58Check checksum."""
    return sha256(sha256(data))


def hash160(data):
    """RIPEMD160(SHA256(data)), Bitcoin's 160-bit hash."""
    return hashlib.new("ripemd160", sha256(data)).digest()


def tagged_hash(tag, data):
    """BIP340 domain-separated hash: SHA256(SHA256(tag) || SHA256(tag) || data)."""
    prefix = sha256(tag.encode("ascii"))
    return sha256(prefix + prefix + data)


# ================= secp256k1 curve parameters =================
PRIME = 2 ** 256 - 2 ** 32 - 977  # field p
ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # base point order n
CURVE_B = 7                                    # curve coefficient b
BASE_X = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
BASE_Y = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def check_secret(secret):
    """Check that the private key lies in the secp256k1 scalar field [1, n-1]."""
    if not isinstance(secret, int):
        raise ValueError("the private key must be an integer")
    if not 1 <= secret < ORDER:
        raise ValueError("private key outside the valid secp256k1 range [1, n-1]")
    return secret


# ================= Optional curve libraries: coincurve / ecdsa =================
try:                                             # coincurve wraps libsecp256k1 and is the fastest
    import coincurve
    HAVE_COINCURVE = True
except ImportError:
    HAVE_COINCURVE = False

try:                                             # ecdsa: a standard ECDSA implementation in pure Python
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
    CURVE_BACKEND = "builtin"


# ================= Built-in elliptic curve group operations (fallback when both libraries are missing) =================
def jacobian_double(point):
    """Doubling in Jacobian coordinates, so no modular inverse is needed every time."""
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
    """Point addition in Jacobian coordinates."""
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
    """Convert Jacobian coordinates to affine; None for the point at infinity."""
    x, y, z = point
    if z == 0:
        return None
    inverse = pow(z, PRIME - 2, PRIME)
    inverse2 = inverse * inverse % PRIME
    return (x * inverse2 % PRIME, y * inverse2 * inverse % PRIME)


def builtin_scalar_multiply(scalar):
    """Built-in scalar multiplication: double-and-add in Jacobian coordinates."""
    result = (0, 0, 0)
    addend = (BASE_X, BASE_Y, 1)
    while scalar:
        if scalar & 1:
            result = jacobian_add(result, addend)
        addend = jacobian_double(addend)
        scalar >>= 1
    return jacobian_to_affine(result)


def builtin_point_add(first, second):
    """Built-in point addition in affine coordinates."""
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


# ================= Elliptic curve entry points (dispatched by backend) =================
def secret_to_point(secret):
    """Private key -> curve point (x, y) in affine coordinates, i.e. the public key point Q = secret * G."""
    check_secret(secret)
    if HAVE_COINCURVE:
        return coincurve.PublicKey.from_valid_secret(secret.to_bytes(32, "big")).point()
    if HAVE_ECDSA:
        point = ecdsa.SECP256k1.generator * secret
        return (point.x(), point.y())
    return builtin_scalar_multiply(secret)


def point_add(first, second):
    """Point addition in affine coordinates; None when the two points are inverses (point at infinity)."""
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
        # for P + (-P) ecdsa returns INFINITY (a plain Point whose coords are None); it has no to_affine()
        if total.x() is None or total.y() is None:
            return None
        if hasattr(total, "to_affine"):
            total = total.to_affine()
        return (total.x(), total.y())
    return builtin_point_add(first, second)


# ================= Public key serialization =================
def public_key_bytes(point, compressed=True):
    """Curve point to bytes: 33 bytes compressed (02/03 + x), 65 bytes uncompressed (04 + x + y)."""
    x, y = point
    if compressed:
        return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def x_only_public_key(point):
    """BIP340 x-only public key, keeping only the x coordinate (32 bytes)."""
    return point[0].to_bytes(32, "big")


def lift_x(x_bytes):
    """BIP340 lift_x: recover the curve point with even y from a 32-byte x coordinate."""
    x = int.from_bytes(x_bytes, "big")
    if not 0 <= x < PRIME:
        raise ValueError("x coordinate is outside the field range")
    y_square = (pow(x, 3, PRIME) + CURVE_B) % PRIME
    y = pow(y_square, (PRIME + 1) // 4, PRIME)
    if y * y % PRIME != y_square:
        raise ValueError("x coordinate is not on the secp256k1 curve")
    return (x, y if y % 2 == 0 else PRIME - y)



# ================= Base58Check =================
def base58check_encode(payload):
    """Base58Check: append a 4-byte double SHA-256 checksum to the payload, then encode."""
    return base58_encode(payload + double_sha256(payload)[:4])


def base58check_decode(text):
    """Decode Base58Check and verify the checksum."""
    raw = base58_decode(text.strip())
    if len(raw) < 5:
        raise ValueError("the Base58Check payload is too short")
    payload, checksum = raw[:-4], raw[-4:]
    if double_sha256(payload)[:4] != checksum:
        raise ValueError("the Base58Check checksum does not match")
    return payload


# ================= Network and script constants =================
WIF_VERSION = 0x80   # WIF private key version byte
MAINNET = {                                    # this tool only does mainnet: Base58 version byte + Bech32 HRP
    "name": "Bitcoin mainnet", "p2pkh": 0x00, "p2sh": 0x05, "hrp": "bc",
}
HRP_NAMES = {"bc": "mainnet", "tb": "testnet", "bcrt": "regtest"}   # only used to label addresses that come from elsewhere
KNOWN_VERSIONS = {                                          # meaning of the Base58 address version bytes
    0x00: "P2PKH mainnet", 0x05: "P2SH mainnet",
    0x6F: "P2PKH testnet/regtest", 0xC4: "P2SH testnet/regtest",
}




# ================= Private keys: generation / WIF / parsing =================
def generate_secret():
    """Every key draws an independent random scalar with secrets over [1, n-1] (rejection sampling, no modulo bias)."""
    return secrets.randbelow(ORDER - 1) + 1


def secret_to_wif(secret, compressed=True):
    """Private key -> WIF. A compressed private key gets a trailing 0x01 marker."""
    check_secret(secret)
    payload = bytes([WIF_VERSION]) + secret.to_bytes(32, "big")
    if compressed:
        payload += b"\x01"
    return base58check_encode(payload)


def wif_to_secret(wif):
    """WIF -> (private key, is_compressed); the version byte and the length are validated too."""
    payload = base58check_decode(wif)
    if not payload or payload[0] != WIF_VERSION:
        raise ValueError("not a mainnet WIF private key (the version byte should be 0x80)")
    if len(payload) == 34 and payload[-1] == 0x01:
        return check_secret(int.from_bytes(payload[1:33], "big")), True
    if len(payload) == 33:
        return check_secret(int.from_bytes(payload[1:33], "big")), False
    raise ValueError("illegal WIF length (it must be 33 or 34 bytes)")


def parse_secret(text):
    """Parse a private key: WIF / 64 hex digits / decimal."""
    cleaned = text.strip()
    if not cleaned:
        raise ValueError("the input is empty")
    if cleaned[0] in "5KL9c" and len(cleaned) >= 50:
        return wif_to_secret(cleaned)
    lowered = cleaned.lower()
    if lowered.startswith("0x"):
        return check_secret(int(lowered[2:], 16)), True
    if len(cleaned) == 64 and all(char in "0123456789abcdefABCDEF" for char in cleaned):
        return check_secret(int(cleaned, 16)), True
    if cleaned.isdigit():
        return check_secret(int(cleaned)), True
    raise ValueError("unrecognized private key format (WIF / 64-hex-digit / decimal are supported)")

# ================= Script construction primitives =================
OP_CHECKSIG = 0xAC
OP_CHECKSIGVERIFY = 0xAD
OP_CHECKMULTISIG = 0xAE

LEAF_TAPSCRIPT = 0xC0             # BIP341 leaf version 0xc0
TAPSCRIPT_MAX_SIZE = 10_000       # tapscript size limit
MAX_MULTISIG_KEYS = 16            # OP_CHECKMULTISIG takes at most 16 public keys


def compact_size(number):
    """Encoding of Bitcoin's variable-length integer (compact_size)."""
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
    raise ValueError("compact_size exceeds the 64-bit range")


def push_data(data):
    """Push data onto the script stack: compact_size(len) + data."""
    return compact_size(len(data)) + data


def push_opcode(number):
    """Push a number from 0 to 16.

    OP_0 is 0x00 and OP_1..OP_16 are 0x51..0x60.
    Never write bytes([number]) directly -- that gives 0x01..0x10, which are
    not valid opcodes.
    """
    if not 0 <= number <= MAX_MULTISIG_KEYS:
        raise ValueError("only OP_0 through OP_16 are supported; the multisig m/n cannot exceed that range")
    return b"" if number == 0 else bytes([0x50 + number])


# ================= Public key handling =================
def is_valid_pubkey(data):
    """Check whether the public key bytes really lie on the secp256k1 curve."""
    try:
        if len(data) == 33 and data[0] in (2, 3):
            # compressed pubkey: if lift_x succeeds then x^3+7 is a quadratic residue, so both prefixes are legal
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
    """Private key -> 33-byte compressed public key (multisig scripts must use the compressed form)."""
    return public_key_bytes(secret_to_point(secret), True)


def parse_pubkey(text):
    """Normalize user-supplied public key text into bytes (33 / 65 / 32 bytes)."""
    cleaned = text.strip()
    if not cleaned:
        raise ValueError("the public key is empty")
    try:
        data = bytes.fromhex(cleaned)
    except ValueError:
        raise ValueError("the public key must be hexadecimal")
    if not is_valid_pubkey(data):
        raise ValueError("this is not a valid secp256k1 public key")
    return data


def pubkey_to_xonly(data):
    """Public key -> 32-byte x-only (BIP340 Taproot only looks at the x coordinate)."""
    if len(data) == 32:
        return data
    if len(data) == 33:
        return data[1:]
    if len(data) == 65 and data[0] == 4:
        return data[1:33]
    raise ValueError("wrong public key length; it must be 32 / 33 / 65 bytes")


def pubkey_to_compressed(data):
    """Public key -> 33-byte compressed public key; x-only gets a prefix by the even-y convention (the EIP-340 rule)."""
    if len(data) == 33:
        return data
    if len(data) == 32:
        return bytes([0x02]) + data
    if len(data) == 65 and data[0] == 4:
        return bytes([0x02 + (int.from_bytes(data[33:], "big") & 1)]) + data[1:33]
    raise ValueError("wrong public key length; it must be 32 / 33 / 65 bytes")


def key_fingerprint(pubkey):
    """BIP32 fingerprint = the first 4 bytes of hash160(compressed pubkey), used to number the members while coordinating."""
    return hash160(pubkey_to_compressed(pubkey))[:4].hex()


def sort_keys_bip67(pubkeys):
    """BIP67: sort the public keys ascending by their bytes.

    Everyone doing a multisig must use the same order; otherwise each side
    ends up with a different address and the money goes to the wrong one.
    """
    return sorted(pubkeys)


def sort_keys_by_fingerprint(pubkeys):
    """Sort by fingerprint (the old practice from before BIP67), only for comparison with old wallets."""
    return sorted(pubkeys, key=lambda item: (hash160(item)[:4], item))


# ================= P2WSH multisig (bc1q, m-of-n) =================
def multisig_witness_script(threshold, pubkeys):
    """Build OP_m <pubkeys...> OP_n OP_CHECKMULTISIG.

    threshold = how many members must sign (m), pubkeys = every member public key (n).
    """
    if not pubkeys:
        raise ValueError("at least one member public key is required")
    count = len(pubkeys)
    if not 1 <= threshold <= count:
        raise ValueError("%d signatures are needed but there are only %d members" % (threshold, count))
    if count > MAX_MULTISIG_KEYS:
        raise ValueError("Bitcoin's OP_CHECKMULTISIG supports at most 16 public keys")
    body = b"".join(push_data(pubkey) for pubkey in pubkeys)
    return push_opcode(threshold) + body + push_opcode(count) + bytes([OP_CHECKMULTISIG])


def p2wsh_script_pubkey(witness_script):
    """The scriptPubKey of P2WSH: OP_0 <20-byte hash160(witnessScript)>."""
    return b"\x00\x14" + hash160(witness_script)


def p2sh_p2wsh_script_pubkey(witness_script):
    """The scriptPubKey of P2SH-P2WSH (for old wallet compatibility)."""
    return b"\xa9\x14" + hash160(b"\x00\x14" + hash160(witness_script)) + b"\x87"


def p2sh_script_pubkey(redeem_script):
    """The scriptPubKey of legacy P2SH."""
    return b"\xa9\x14" + hash160(redeem_script) + b"\x87"


def address_from_script_pubkey(script_pubkey):
    """scriptPubKey -> address (SegWit / P2SH-P2WSH / P2SH)."""
    if len(script_pubkey) == 22 and script_pubkey[0] == 0x00 and script_pubkey[1] == 0x14:
        witness_script = None                 # only a hash is available; the script cannot be recovered
        return segwit_encode(MAINNET["hrp"], 0, script_pubkey[2:22]), witness_script
    if (len(script_pubkey) == 23 and script_pubkey[0] == 0xA9 and script_pubkey[1] == 0x14
            and script_pubkey[-1] == 0x87):
        return base58check_encode(bytes([MAINNET["p2sh"]]) + script_pubkey[2:22]), None
    raise ValueError("this scriptPubKey is not supported by this tool")


def p2wsh_address(witness_script):
    """Native SegWit multisig address bc1q... (witness v0 + hash160)."""
    return segwit_encode(MAINNET["hrp"], 0, hash160(witness_script))


def p2sh_p2wsh_address(witness_script):
    """The compatibility address 3... of P2SH wrapping P2WSH."""
    nested = b"\x00\x14" + hash160(witness_script)
    return base58check_encode(bytes([MAINNET["p2sh"]]) + hash160(nested))


def p2sh_multisig_address(redeem_script):
    """Legacy P2SH multisig address 3... (not recommended; new wallets all use P2WSH)."""
    return base58check_encode(bytes([MAINNET["p2sh"]]) + hash160(redeem_script))


# ================= Taproot (bc1p, script path, N-of-N everyone signs) =================
# BIP341's NUMS point: nobody knows its discrete logarithm, so the key path cannot spend; the money can only move along the script path.
# Never swap the internal public key for the base point G -- G's discrete logarithm is 1, so anybody can compute the tweak and turn it into a private key,
# which bypasses the multisig completely. NUMS is fixed here.
NUMS_X = bytes.fromhex("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")


def tapleaf_hash(script, leaf_version=LEAF_TAPSCRIPT):
    """BIP341 leaf hash = tagged_hash("TapLeaf", leaf version || script length || script)."""
    if not 0xC0 <= leaf_version <= 0xFE:
        raise ValueError("only tapscript leaf version 0xc0 is supported at the moment")
    if len(script) > TAPSCRIPT_MAX_SIZE:
        raise ValueError("the tapscript exceeds the 10KB limit")
    return tagged_hash("TapLeaf", bytes([leaf_version]) + compact_size(len(script)) + script)


def tapbranch_hash(first, second):
    """BIP341 branch hash: sort the two child hashes ascending by bytes and hash them (the order must not be reversed)."""
    low, high = sorted([first, second])
    return tagged_hash("TapBranch", low + high)


def build_taptree(leaf_hashes):
    """Build a TapTree from a list of leaf hashes.

    Returns (merkle_root, paths); paths[i] is the sibling hash list of leaf number i (bottom-up).
    With an odd number of leaves the split is "left = the first floor(n/2), right = the rest", so n=3 gives
    [l0, [l1, l2]], which matches the official BIP341 vectors.
    Note that BIP341 itself does not fix the tree shape: the same public keys with another shape give another bc1p address,
    so all the parties must agree on the shape in advance (and record it in the PSBT).
    """
    if not leaf_hashes:
        raise ValueError("the TapTree needs at least one leaf")

    def build(items):
        """items = [(index, leaf hash)] -> (root hash, {index: [siblings...]})"""
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
    """The tapscript leaf script of a single member: <32-byte x-only pubkey> OP_CHECKSIG."""
    if len(pubkey_x32) != 32:
        raise ValueError("a Taproot leaf pubkey must be a 32-byte x-only key")
    return push_data(pubkey_x32) + bytes([OP_CHECKSIG])


def tapscript_chain_for_keys(pubkeys_x32):
    """Chain N public keys into one tapscript: CHECKSIGVERIFY up front, CHECKSIG at the end.

    This is the right structure for "everyone signs" with bc1p. Taproot has no OP_CHECKMULTISIG,
    so making all N people sign means hand-writing a signature chain; one missing signature breaks the chain and the script must fail.
    """
    if not pubkeys_x32:
        raise ValueError("at least one member public key is required")
    parts = []
    last = len(pubkeys_x32) - 1
    for position, pubkey in enumerate(pubkeys_x32):
        parts.append(push_data(pubkey))
        parts.append(bytes([OP_CHECKSIG if position == last else OP_CHECKSIGVERIFY]))
    return b"".join(parts)


def build_taproot_plan(pubkeys_x32, layout="chain", internal_x=NUMS_X):
    """Turn a set of member public keys into a complete bc1p scheme.

    layout="chain"(the default, and the only shape that really enforces everyone signing):
        a single leaf whose script is a chain of N CHECKSIGs.

    layout="tree":
        one leaf per member, forming a TapTree. The address can be computed, but a BIP341 script-path
        spend can only prove one leaf at a time, so it cannot express "several people signing together",
        it only fits locking mutually exclusive alternative scripts into one address. This file keeps it in order to line up with
        BIP341 the official vectors and to give PSBT-savvy users the choice of a tree shape.

    The return value holds the leaf scripts, the merkle root, the control blocks, the output key and the witness stack template.
    """
    keys = sorted(pubkeys_x32)
    if not keys:
        raise ValueError("at least one member public key is required")
    if len(set(keys)) != len(keys):
        raise ValueError("duplicate member public keys")

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
    """t = tagged_hash("TapTweak", internal key x || merkle root).

    Note there is no 0x00 prefix here (the final BIP341 just concatenates).
    An early draft wrote 0x00 || p || merkleRoot; copying that draft yields the wrong address.
    """
    return tagged_hash("TapTweak", internal_x + (merkle_root or b""))


def taproot_output_point(internal_x, merkle_root=None):
    """Q = lift_x(internal key) + t*G; returns the output point (x, y).

    As BIP341 specifies, t >= the curve order is invalid (fail outright instead of reducing modulo the order).
    """
    tweak = int.from_bytes(taproot_tweak(internal_x, merkle_root), "big")
    if tweak >= ORDER:
        raise ValueError("the TapTweak is beyond the curve order")
    output = point_add(lift_x(internal_x), secret_to_point(tweak))
    if output is None:
        raise ValueError("the output point is the point at infinity")
    return output


def taproot_output_key(internal_x, merkle_root=None):
    """The Taproot output public key (32-byte x coordinate)."""
    return taproot_output_point(internal_x, merkle_root)[0].to_bytes(32, "big")


def taproot_script_pubkey(internal_x, merkle_root=None):
    """The scriptPubKey of P2TR: OP_1 <32-byte output_key>."""
    return b"\x51\x20" + taproot_output_key(internal_x, merkle_root)


def taproot_address(merkle_root, internal_x=NUMS_X):
    """The address bc1p... = bech32m(witness v1, output_key)."""
    return segwit_encode(MAINNET["hrp"], 1,
                         taproot_output_key(internal_x, merkle_root))


def taproot_control_block(merkle_path, output_point, internal_x=NUMS_X,
                          leaf_version=LEAF_TAPSCRIPT):
    """The control block = (leaf version | output point parity) || internal key || sibling hash sequence.

    The verifier recomputes the merkle root from the siblings and then the tweak, which proves this leaf really belongs to the address,
    so no other script can be forced in.
    """
    parity = output_point[1] & 1
    return bytes([(leaf_version & 0xFE) | parity]) + internal_x + b"".join(merkle_path)
# ================= Transaction parsing (needed to compute the signature hashes) =================
class TxInput(object):
    """One transaction input. The outpoint stores 36 bytes directly (txid little-endian + index little-endian)."""

    def __init__(self, outpoint, script_sig=b"", sequence=0xFFFFFFFF, witness=None):
        self.outpoint = outpoint
        self.script_sig = script_sig
        self.sequence = sequence
        self.witness = list(witness or [])


def make_outpoint(txid_hex, index):
    """Transaction hash in hex (forward order) + index -> the 36-byte outpoint (little-endian inside)."""
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
        """With with_witness=True, output the SegWit format (0x00 0x01 + witness data).

        Mind the field order (BIP144):
            version | marker | flag | txins | txouts | witnesses | locktime
        the witness data sits **between** the outputs and the locktime, not after the locktime.
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
    """Read a compact_size from data[offset:]; returns (value, new offset)."""
    if offset >= len(data):
        raise ValueError("the data ends while reading a length")
    first = data[offset]
    offset += 1
    if first < 0xFD:
        return first, offset
    sizes = {0xFD: 2, 0xFE: 4, 0xFF: 8}
    if first not in sizes:
        raise ValueError("illegal compact_size first byte: 0x%02x" % first)
    width = sizes[first]
    if offset + width > len(data):
        raise ValueError("the data ends while reading a length")
    return int.from_bytes(data[offset:offset + width], "little"), offset + width


def read_compact_size_item(data, offset):
    """Read a compact_size plus the data after it; returns (data, new offset)."""
    length, offset = read_compact_size(data, offset)
    if offset + length > len(data):
        raise ValueError("the data ends while reading the contents")
    return data[offset:offset + length], offset + length


def parse_transaction(raw):
    """Parse raw transaction bytes; returns a Transaction."""
    if len(raw) < 10:
        raise ValueError("the transaction data is too short")
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
            raise ValueError("the transaction inputs are truncated")
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
    # the witness data goes after the outputs and before the locktime (BIP144)
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
        raise ValueError("there are extra bytes at the end of the transaction data")
    return Transaction(version, inputs, outputs, locktime)


# ================= Signature hash types =================
SIGHASH_ALL = 0x01
SIGHASH_NONE = 0x02
SIGHASH_SINGLE = 0x03
SIGHASH_ANYONECANPAY = 0x80
SIGHASH_DEFAULT = 0x00


def sighash_base_type(hash_type):
    return hash_type & 0x1F


def sighash_is_anyonecanpay(hash_type):
    return bool(hash_type & SIGHASH_ANYONECANPAY)


# ================= BIP143: native SegWit (P2WSH / P2WPKH) signature hash =================
def bip143_sighash(tx, input_index, script_code, amount, hash_type=SIGHASH_ALL):
    """BIP143 computes the signature hash of a native SegWit input.

    For P2WSH the script_code is the witnessScript itself (no length prefix in front,
    the compact_size is only added when serializing it into the preimage); that differs from P2SH-P2WSH.
    """
    base_type = sighash_base_type(hash_type)
    anyone_can_pay = sighash_is_anyonecanpay(hash_type)
    anyone_or_none = anyone_can_pay or base_type in (SIGHASH_NONE, SIGHASH_SINGLE)

    # Mind this: do not keep the old algorithm's 0x01 sentinel for "input index beyond the number of outputs".
    # BIP143 explicitly requires hashOutputs to be 32 zero bytes then; the meaning is unchanged but the hash differs.
    if anyone_can_pay:
        hash_prevouts = b"\x00" * 32
    else:
        hash_prevouts = double_sha256(b"".join(item.outpoint for item in tx.inputs))
    hash_sequence = (b"\x00" * 32 if anyone_or_none
                     else double_sha256(b"".join(item.sequence.to_bytes(4, "little")
                                                 for item in tx.inputs)))

    # hashOutputs is decided by base_type alone and has nothing to do with ANYONECANPAY:
    # neither SINGLE nor NONE -> all outputs; SINGLE with the index in range -> the output with the same index; otherwise 0.
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


# ================= BIP341: Taproot signature hash =================
def taproot_sighash(tx, input_index, prevout_scripts, prevout_amounts, hash_type=SIGHASH_DEFAULT,
                    ext_flag=0, annex=None, script=None, leaf_version=LEAF_TAPSCRIPT,
                    codeseparator_pos=0xFFFFFFFF):
    """BIP341 SigMsg -> TapSighash.

    prevout_scripts / prevout_amounts must hold the scriptPubKey and amount of every input,
    because even with ANYONECANPAY, Taproot hashes that information for all inputs together.
    """
    if len(prevout_scripts) != len(tx.inputs) or len(prevout_amounts) != len(tx.inputs):
        raise ValueError("the scriptPubKey and amount of every input are required")
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
    # without ANYONECANPAY these four hashes follow nLockTime immediately (BIP341 SigMsg order)
    if not anyone_can_pay:
        message += sha_prevouts + sha_amounts + sha_scriptpubkeys + sha_sequences

    # BIP341: when hash_type & 3 is NONE or SINGLE, sha_outputs is **omitted entirely**,
    # not filled with 32 zero bytes. Filling in zeros yields a completely different hash.
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
            raise ValueError("with SIGHASH_SINGLE the input index is beyond the number of outputs")
        message += sha256(tx.outputs[input_index].serialize())
    # the BIP342 script-path extension: when a script is given it must be appended
    # tapleaf_hash(32) || key_version(1) || codesep_pos(4, little-endian).
    # Note codesep_pos is a **fixed 4 bytes**; when OP_CODESEPARATOR never ran it is 0xffffffff,
    # not omitted -- dropping these 37 bytes yields a completely different hash.
    if script is not None:
        message += tapleaf_hash(script, leaf_version)
        message += b"\x00"
        message += codeseparator_pos.to_bytes(4, "little")
    return tagged_hash("TapSighash", b"\x00" + message)


# ================= ECDSA (used by bc1q multisig) =================
def parse_der_signature(der):
    """Parse a DER-encoded signature; returns (r, s). Format: 30 <len> 02 <len> r 02 <len> s."""
    if len(der) < 8 or der[0] != 0x30:
        raise ValueError("not a DER signature (the first byte should be 0x30)")
    if der[1] != len(der) - 2:
        raise ValueError("the DER total length does not match")
    if der[2] != 0x02:
        raise ValueError("the r marker is missing from the DER")
    r_length = der[3]
    r_start = 4
    r_end = r_start + r_length
    if der[r_end] != 0x02:
        raise ValueError("the s marker is missing from the DER")
    s_length = der[r_end + 1]
    s_value = der[r_end + 2:r_end + 2 + s_length]
    if r_end + 2 + s_length != len(der):
        raise ValueError("there is extra data at the end of the DER")
    return int.from_bytes(der[r_start:r_end], "big"), int.from_bytes(s_value, "big")


def point_negate(point):
    """Negate a curve point (x, -y)."""
    return point[0], (PRIME - point[1]) % PRIME


def scalar_multiply(point, scalar):
    """Generic scalar multiplication; point = None means the point at infinity."""
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
    """Built-in ECDSA verification; returns True / False."""
    try:
        r, s = parse_der_signature(der_signature)
    except ValueError:
        return False
    if not 1 <= r < ORDER or not 1 <= s < ORDER:
        return False
    compressed = pubkey_to_compressed(pubkey)
    if not is_valid_pubkey(compressed):
        return False
    # lift_x only returns the point with even y; when the parity prefix does not match, negate to get the real y
    target = lift_x(compressed[1:])
    if (2 + (target[1] & 1)) != compressed[0]:
        target = point_negate(target)
    value = int.from_bytes(message_hash, "big") % ORDER
    inverse = pow(s, ORDER - 2, ORDER)
    combined = point_add(scalar_multiply_base_point(value * inverse % ORDER),
                         scalar_multiply(target, r * inverse % ORDER))
    if combined is None:
        return False
    return combined[0] % ORDER == r


def scalar_multiply_base_point(scalar):
    """Scalar multiplication of the base point G."""
    return secret_to_point(scalar)


# ================= Schnorr / BIP340 (used by bc1p) =================
BASE_POINT = (BASE_X, BASE_Y)


def schnorr_sign(message32, secret, aux_rand32=None):
    """BIP340 Schnorr signing, for the self-test and for testing only."""
    if len(message32) != 32:
        raise ValueError("the message hash must be 32 bytes")
    if aux_rand32 is not None and len(aux_rand32) != 32:
        raise ValueError("aux_rand must be 32 bytes")
    point = secret_to_point(secret)
    xonly = point[0].to_bytes(32, "big")
    # if y is odd, negate the private key so the d used corresponds to an even y
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
    raise ValueError("Schnorr signing failed after 64 retries")


def schnorr_verify(message32, pubkey_x32, signature64):
    """BIP340 Schnorr verification; returns True / False."""
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


# ================= BIP32: derive the member public keys from an xpub (real multisig setups coordinate over xpubs) =================
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
    """Parse an xpub / tpub."""
    payload = base58check_decode(text.strip())
    if len(payload) != 78:
        raise ValueError("wrong extended public key length; it should be 78 bytes")
    version = int.from_bytes(payload[0:4], "big")
    depth = payload[4]
    fingerprint = payload[5:9]
    child_index = int.from_bytes(payload[9:13], "big")
    chain_code = payload[13:45]
    pubkey = payload[45:78]
    if not is_valid_pubkey(pubkey):
        raise ValueError("the public key inside the extended public key is invalid")
    return version, ExtendedKey(chain_code, pubkey, depth, fingerprint, child_index)


def serialize_extended_key(key, version=0x0488B21E):
    """Re-encode an ExtendedKey into an xpub (needed for descriptors and for showing fingerprints)."""
    payload = version.to_bytes(4, "big") + bytes([key.depth]) + key.fingerprint
    payload += key.child_index.to_bytes(4, "big") + key.chain_code + key.pubkey
    return base58check_encode(payload)


def derive_pubkey(parent, index):
    """BIP32 public key derivation (only non-hardened derivation; multisig member paths are all 0/0/*)."""
    if index >= 0x80000000:
        raise ValueError("this tool only supports non-hardened derivation paths (like /0/0/*)")
    digest = hmac.new(parent.chain_code, parent.pubkey + index.to_bytes(4, "big"), hashlib.sha512).digest()
    left = int.from_bytes(digest[:32], "big")
    if left == 0 or left >= ORDER:
        raise ValueError("the derived key is invalid")
    parent_point = lift_x(parent.pubkey[1:])
    if (2 + (parent_point[1] & 1)) != parent.pubkey[0]:
        parent_point = point_negate(parent_point)
    child_point = point_add(secret_to_point(left), parent_point)
    if child_point is None:
        raise ValueError("the derived public key is the point at infinity")
    return ExtendedKey(digest[32:], bytes([2 + (child_point[1] & 1)]) + child_point[0].to_bytes(32, "big"),
                       parent.depth + 1, hash160(parent.pubkey)[:4], index)


def pubkey_from_descriptor_path(text):
    """Supports the "xpub.../0/0/0" form.

    Returns (the derived public key, the root xpub, the derived xpub).
    """
    parts = [item.strip() for item in text.strip().split("/")]
    base = parts[0]
    if not base.lower().startswith(("xpub", "tpub")):
        return None
    version, key = parse_extended_key(base)
    root_xpub = serialize_extended_key(key, version)
    for item in parts[1:]:
        if item in ("", "*", "'", "*'"):
            raise ValueError("the derivation path has to be spelled out here; wildcards are not allowed")
        key = derive_pubkey(key, int(item))
    return key.pubkey, root_xpub, serialize_extended_key(key, version)
# ================= Script executor (the self-test really runs the scripts) =================
# OP_CHECKSIG / OP_CHECKSIGVERIFY / OP_CHECKMULTISIG are already defined with the script primitives above
OP_0 = 0x00
OP_PUSHDATA1 = 0x4C
OP_PUSHDATA2 = 0x4D
OP_PUSHDATA4 = 0x4E
OP_1 = 0x51
OP_16 = 0x60
OP_CODESEPARATOR = 0xAB


def parse_script_ops(script):
    """Split a script into [(kind, value)]; kind is "data" or "op"."""
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
    """Push OP_0..OP_16: 0 pushes empty bytes, 1 to 16 push a single byte."""
    if number == 0:
        stack.append(b"")
    elif 1 <= number <= 16:
        stack.append(bytes([number]))
    else:
        raise ValueError("script number %d is outside OP_0..OP_16" % number)


def push_opcode_number(stack, opcode):
    """Translate the **opcode** OP_0 / OP_1..OP_16 into the number it stands for, then push it.

    An opcode and a number are not the same thing: the opcode of OP_2 is 0x52, but the number it stands for is 2.
    Pushing the opcode byte as if it were the number makes pop_script_number read 82 later,
    so every OP_CHECKMULTISIG script ends up failing.
    """
    if opcode == OP_0:
        push_script_number(stack, 0)
    elif OP_1 <= opcode <= OP_16:
        push_script_number(stack, opcode - OP_1 + 1)
    else:
        raise ValueError("opcode 0x%02x is not OP_0..OP_16" % opcode)


def pop_script_number(stack):
    """Pop the script number off the top of the stack."""
    if not stack:
        raise ValueError("the stack is empty, no number to pop")
    raw = stack.pop()
    return 0 if not raw else int.from_bytes(raw, "little")


def run_checkmultisig(stack, verify_signature):
    """The core matching logic of OP_CHECKMULTISIG, following Bitcoin Core semantics.

    Two consensus rules that are easy to get wrong:
      * * a signature count of zero fails immediately;
      * * signatures must appear in public key order, and each one may only pair with a public key
        that is not earlier than the current position; it cannot skip a key to sign a later one.
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
    keys.reverse()                     # the stack is LIFO, so reversing gives the script order
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
    """OP_CHECKSIG: the public key is on top, the signature below it. Returns the verification result (the caller decides whether to push it)."""
    if len(stack) < 2:
        return False
    pubkey = stack.pop()
    signature = stack.pop()
    if not signature:
        # an empty signature is only accepted by CHECKSIGVERIFY (anyone-can-spend); plain CHECKSIG rejects it.
        return not require_nonempty
    return bool(verify_signature(signature, pubkey))


def execute_multisig_script(script, stack, verify_signature):
    """Execute the OP_m <keys> OP_n OP_CHECKMULTISIG subset."""
    if not stack:
        return False
    stack.pop(0)                       # OP_CHECKMULTISIG requires a dummy element at the bottom of the stack
    for kind, value in parse_script_ops(script):
        if kind == "data":
            stack.append(value)
        elif OP_0 <= value <= OP_16:
            push_opcode_number(stack, value)
        elif value == OP_CHECKMULTISIG:
            if not run_checkmultisig(stack, verify_signature):
                return False
            # the result of CHECKMULTISIG must be left on top of the stack, then the stack must hold nothing else.
            # "nothing else" is a consensus requirement: too few signatures (something is left) or too many both fail.
            stack.append(b"\x01")
            if len(stack) != 1 or not stack[0]:
                return False
        elif value == OP_CODESEPARATOR:
            continue
        else:
            return False               # no other opcode should show up in the scripts this tool generates
    return len(stack) == 1 and bool(stack[0])


def execute_tapscript(script, stack, verify_signature):
    """Execute the tapscript subset this tool generates: a CHECKSIGVERIFY chain plus a trailing CHECKSIG."""
    for kind, value in parse_script_ops(script):
        if kind == "data":
            stack.append(value)
        elif OP_0 <= value <= OP_16:
            push_opcode_number(stack, value)
        elif value in (OP_CHECKSIG, OP_CHECKSIGVERIFY):
            passed = run_checksig(stack, verify_signature, require_nonempty=True)
            if value == OP_CHECKSIGVERIFY:
                # the VERIFY variant leaves no result on the stack
                if not passed:
                    return False
            else:
                # the result of plain CHECKSIG must be left on top of the stack
                stack.append(b"\x01" if passed else b"")
        elif value == OP_CODESEPARATOR:
            continue
        else:
            return False
    return len(stack) == 1 and bool(stack[0])


# ================= Built-in ECDSA signing (self-test only) =================
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
    """Built-in ECDSA signing, for the self-test only (use a mature wallet or HWI in production)."""
    value = int.from_bytes(message_hash, "big") % ORDER
    while True:
        nonce = secrets.randbelow(ORDER - 1) + 1
        r = secret_to_point(nonce)[0] % ORDER
        if r == 0:
            continue
        s = pow(nonce, ORDER - 2, ORDER) * (value + r * secret) % ORDER
        if s == 0:
            continue
        if s > ORDER // 2:             # low S (BIP62), consistent with mainstream wallets
            s = ORDER - s
        return encode_der_signature(r, s)


# ================= End-to-end verification =================
def build_test_transaction():
    """Build a transaction for the self-test: 1 input, 1 output."""
    tx = Transaction(version=2, locktime=0)
    tx.inputs.append(TxInput(make_outpoint("00" * 32, 0), b"", 0xFFFFFFFD))
    tx.outputs.append(TxOutput(90_000, bytes.fromhex("0014") + hash160(b"\x00" * 20)))
    return tx


def verify_p2wsh_multisig(witness_script, ordered_keys, secrets_by_key, signer_count,
                          amount=100_000):
    """Build an m-of-n witness stack and really execute the witnessScript.

    signer_count decides how many members sign, to confirm that "one signature short always fails".
    """
    if not 1 <= signer_count <= len(ordered_keys):
        raise ValueError("the signer count is invalid")
    script_pubkey = p2wsh_script_pubkey(witness_script)
    tx = build_test_transaction()
    message = bip143_sighash(tx, 0, witness_script, amount, SIGHASH_ALL)
    signatures = [ecdsa_sign(message, secrets_by_key[key]) for key in ordered_keys[:signer_count]]
    for signature, key in zip(signatures, ordered_keys[:signer_count]):
        if not ecdsa_verify(message, signature, key):
            return False, "signature number %d does not verify" % (signer_count)
    ok = execute_multisig_script(witness_script, [b""] + signatures,
                                 lambda sig, pk: ecdsa_verify(message, sig, pk))
    return ok, ("the script says pass" if ok else "the script says fail")


def verify_taproot_script_path(leaf_script, signatures, amount=100_000,
                                hash_type=SIGHASH_DEFAULT):
    """Verify a bc1p script-path spend: control block -> merkle proof -> output key -> signature by signature.

    Only the single-leaf + CHECKSIG chain form is supported; that is the N-of-N structure BIP341 can really enforce:
    a script-path spend can only prove one leaf at a time, and several leaves can only lock in "mutually exclusive alternative scripts",
    they cannot be used to require several people to sign together.
    """
    script_pubkey = taproot_script_pubkey(NUMS_X, tapleaf_hash(leaf_script))
    control = taproot_control_block([], taproot_output_point(NUMS_X, tapleaf_hash(leaf_script)))
    tx = build_test_transaction()
    prevout_scripts = [script_pubkey]
    prevout_amounts = [amount]

    # 1) From the verifier point of view all it knows is the scriptPubKey, the control block and the merkle path,
    #    it recomputes the merkle root, the output key and the parity, which must match the scriptPubKey exactly.
    leaf_version = control[0] & 0xFE
    parity = control[0] & 1          # the parity is the lowest bit of byte 0, not of control[1]
    merkle_path = [control[33 + 32 * i:65 + 32 * i] for i in range((len(control) - 33) // 32)]
    rebuilt_root = tapleaf_hash(leaf_script, leaf_version)
    for sibling in merkle_path:
        rebuilt_root = tapbranch_hash(rebuilt_root, sibling)
    if rebuilt_root != tapleaf_hash(leaf_script, leaf_version):
        return False, "the merkle proof does not match"
    rebuilt_point = taproot_output_point(NUMS_X, rebuilt_root)
    if rebuilt_point[1] & 1 != parity:
        return False, "the output key parity recorded in the control block does not match"
    if rebuilt_point[0].to_bytes(32, "big") != script_pubkey[2:]:
        return False, "the recomputed output key does not match the scriptPubKey"

    # 2) Verify the signatures one by one. The witness stack is reversed: the top holds the last member signature.
    def check(signature, pubkey_x32):
        message = taproot_sighash(tx, 0, prevout_scripts, prevout_amounts, hash_type,
                                  ext_flag=1, script=leaf_script, leaf_version=leaf_version)
        return schnorr_verify(message, pubkey_x32, signature)

    ok = execute_tapscript(leaf_script, list(signatures), check)
    return ok, ("the tapscript says pass" if ok else "the tapscript says fail")
# ================= Member parsing =================
def is_hex_text(text):
    if not text or len(text) % 2:
        return False
    try:
        bytes.fromhex(text)
    except ValueError:
        return False
    return True


def make_member(pubkey, secret=None, xpub=None, source="", descriptor_key=None):
    """Normalize a member record. pubkey is always a 33-byte compressed public key."""
    return {
        "pubkey": pubkey,
        "secret": secret,
        "xpub": xpub,
        "source": source,
        "descriptor_key": descriptor_key or pubkey.hex(),
        "fingerprint": key_fingerprint(pubkey),
    }


def parse_member(text):
    """Parse one line of member input.

    Supported: WIF private key / 64-hex-digit private key / decimal private key /
          33-byte compressed public key / 65-byte uncompressed public key /
          x:-prefixed 32-byte x-only public key /
          xpub derivation path (xpub.../0/0/0)
    """
    cleaned = text.strip()
    if not cleaned:
        raise ValueError("this line is empty")
    lowered = cleaned.lower()

    if lowered.startswith("x:") or lowered.startswith("xonly:"):
        body = cleaned.split(":", 1)[1].strip()
        if not is_hex_text(body) or len(body) != 64:
            raise ValueError("after x: there must be 64 hex digits (an x-only public key)")
        data = bytes.fromhex(body)
        if not is_valid_pubkey(data):
            raise ValueError("this is not a valid x-only public key")
        return make_member(pubkey_to_compressed(data), None, None, cleaned)

    if "/" in cleaned and cleaned[:4].lower() in ("xpub", "tpub"):
        derived = pubkey_from_descriptor_path(cleaned)
        if derived is None:
            raise ValueError("the extended public key path is malformed")
        pubkey, root_xpub, _ = derived
        head, _, _ = cleaned.rpartition("/")
        return make_member(pubkey, None, root_xpub, cleaned, head + "/*")

    if is_hex_text(cleaned) and len(cleaned) in (66, 130):
        data = bytes.fromhex(cleaned)
        if is_valid_pubkey(data):
            return make_member(pubkey_to_compressed(data), None, None, cleaned)

    # reuse parse_secret from V1; it returns the (private key integer, is_compressed) pair
    secret, _compressed = parse_secret(cleaned)
    return make_member(compressed_pubkey(secret), secret, None, cleaned)


def parse_members(text, allow_blank=False):
    """Multiple lines of input -> a list of members. Blank lines are skipped (handy when pasting a list that has blanks)."""
    members = []
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip() and allow_blank:
            continue
        if not line.strip():
            continue
        try:
            members.append(parse_member(line))
        except ValueError as error:
            raise ValueError("line %d has a problem: %s" % (number, error))
    if not members:
        raise ValueError("no members were read")
    fingerprints = [item["fingerprint"] for item in members]
    if len(set(fingerprints)) != len(fingerprints):
        raise ValueError("duplicate members (same fingerprint), please check the list")
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


# ================= Scheme construction =================
def build_p2wsh_scheme(members, threshold, order="bip67"):
    """Build the bc1q m-of-n multisig scheme."""
    pubkeys = [item["pubkey"] for item in members]
    if len(set(pubkeys)) != len(pubkeys):
        raise ValueError("duplicate member public keys")
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
        "label": "native SegWit multisig",
        "threshold": threshold,
        "members": len(ordered),
        "keys": ordered,
        "order": order,
        "witness_script": witness_script,
        "script_pubkey": p2wsh_script_pubkey(witness_script),
        "address": p2wsh_address(witness_script),
        "descriptor": descriptor,
        "note": "Once the member set changes the address changes, so the receiving address has to be agreed again.",
    }


def build_taproot_scheme(members, layout="chain"):
    """Build the bc1p everyone-signs scheme."""
    xonly = [pubkey_to_xonly(item["pubkey"]) for item in members]
    plan = build_taproot_plan(xonly, layout)
    keys_by_xonly = {pubkey_to_xonly(item["pubkey"]): item for item in members}
    if layout == "chain":
        # and_v(v:pk(k1),and_v(v:pk(k2),...)) -- one and_v per CHECKSIGVERIFY link
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
        "label": "Taproot everyone signs",
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
        "note": "Taproot has no OP_CHECKMULTISIG; everyone signing relies on one CHECKSIG chain, with no signature left out.",
    }


# ================= Descriptor checksum (the #xxxxxxxx of BIP380) =================
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
            raise ValueError("the descriptor contains an illegal character: %r" % character)
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
    """Compute the BIP380 descriptor checksum; returns 8 characters (without the #).

    note that 8 zeros are appended at the end and then XORed with 1, which is what the BIP380 reference implementation does;
    appending only one zero gives the wrong checksum (the correct value for the official vector raw(deadbeef) is 89f8spxm).
    """
    symbols = descriptor_expand(text) + [0, 0, 0, 0, 0, 0, 0, 0]
    value = descriptor_polymod(symbols) ^ 1
    return "".join(DESCRIPTOR_CHECKSUM_CHARSET[(value >> (5 * (7 - i))) & 31] for i in range(8))


def descriptor_checksum_valid(text):
    """Check the other way round: whether the checksum carried by a descriptor is correct."""
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
# ================= Console and low-level helpers =================
def enable_utf8_console():
    """Make the Windows console print UTF-8 so that Chinese text does not turn into question marks."""
    if os.name == "nt" and ctypes is not None:
        try:
            ctypes.windll.kernel32.SetConsoleOutputCP(65001)
            ctypes.windll.kernel32.SetConsoleCP(65001)
        except Exception:                           # a few environments do not support it, so just ignore failures
            pass


# ================= Self-test =================
# The expected values come from the published official vectors, not from my own computations:
#   BIP32   xpub fields and round trip
#   BIP140/341  TapLeaf / TapBranch / merkle root / tweak / control block / output key / address
#   BIP173  bech32 addresses
#   BIP340  Schnorr signatures
#   BIP350  bech32m
#   BIP380  descriptor checksums
def expect_equal(name, actual, expected):
    if actual != expected:
        raise AssertionError("%s: expected %s, got %s" % (name, expected, actual))
    return name


# ---------- Official vectors (BIP340 Schnorr) ----------
# The first 15 rows of the BIP340 official vectors (bip-0340/test-vectors.csv).
# Fields: index, secret key, public key, aux_rand, message, signature, whether it should verify.
# Rows 15 to 18 are the variable-length message vectors, while the schnorr here only handles 32-byte messages
# (a Taproot signature hash is always 32 bytes), so they are left out. The rows with "-" as the secret key are verify-only.
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


# ---------- Low-level primitives ----------
def register_primitive_checks(check):
    def bech32_p2wpkh():
        # BIP173 official vectors
        key = bytes.fromhex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
        address = segwit_encode("bc", 0, hash160(key))
        expect_equal("BIP173 P2WPKH address", address,
                     "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
        return address

    def bech32m_p2tr():
        # witness version 1 must use bech32m; the program comes from the official BIP341 vectors and so does the address
        program = bytes.fromhex("53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343")
        address = segwit_encode("bc", 1, program)
        expect_equal("BIP350 Taproot address", address,
                     "bc1p2wsldez5mud2yam29q22wgfh9439spgduvct83k3pm50fcxa5dps59h4z5")
        return address

    def bech32_version_binding():
        """The witness version and the checksum algorithm must be bound together: v0 can only be bech32, v1 to v16 only bech32m.

        Note that BIP350 explicitly recommends that the **decoding** side try both checksums (a wallet has to be compatible),
        so "the decoder rejects the matching version" is not the right behaviour; what is checked here is the binding on the **encoding** side,
        plus that the decoding side can recover the version and the witness program, and that a tampered checksum must be an error.
        """
        v1_program = bytes.fromhex("53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343")
        v0_program = bytes.fromhex("751e76e8199196d454941c45d1b3a323f1433bd6")
        good = segwit_encode("bc", 1, v1_program)
        # encoding side: v0 -> bech32 (q), v1 -> bech32m (p)
        expect_equal("v0 encoding prefix", segwit_encode("bc", 0, v0_program)[:4], "bc1q")
        expect_equal("v1 encoding prefix", segwit_encode("bc", 1, v1_program)[:4], "bc1p")
        # decoding side: the version and the witness program must come back correctly
        hrp, version, program = segwit_decode(segwit_encode("bc", 1, v1_program))
        expect_equal("decoded hrp", hrp, "bc")
        expect_equal("decoded witness version", version, 1)
        expect_equal("decoded witness program", program.hex(), v1_program.hex())
        # a tampered checksum -> it must not decode (by convention return None, do not raise)
        broken = "bc1p2wsldez5mud2yam29q22wgfh9439spgduvct83k3pm50fcxa5dps59h4z6"
        if segwit_decode(broken) is not None:
            raise AssertionError("a tampered checksum still decoded")
        # an address of the wrong length must also be rejected
        if segwit_decode(good[:40]) is not None:
            raise AssertionError("a truncated address still decoded")
        return "the encoding side binds the version correctly, the decoding side recovers it and rejects a bad checksum"

    def tagged_hash_domain():
        expect_equal("tagged_hash with a domain separator",
                     tagged_hash("TapLeaf", b"").hex(),
                     sha256(sha256(b"TapLeaf") + sha256(b"TapLeaf")).hex())
        expect_equal("a different tag gives a different result",
                     tagged_hash("TapLeaf", b"") == tagged_hash("TapBranch", b""), False)
        return "the domain separation is correct"

    def schnorr_roundtrip():
        secret = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF
        xonly = pubkey_to_xonly(compressed_pubkey(secret))
        message = sha256(b"bitcoin multisig selftest")
        signature = schnorr_sign(message, secret, b"\x00" * 32)
        if not schnorr_verify(message, xonly, signature):
            raise AssertionError("a signature we produced ourselves does not verify")
        broken = signature[:-1] + bytes([signature[-1] ^ 1])
        if schnorr_verify(message, xonly, broken):
            raise AssertionError("changing one byte still passed")
        wrong_key = pubkey_to_xonly(compressed_pubkey(secret + 1))
        if schnorr_verify(message, wrong_key, signature):
            raise AssertionError("swapping the public key still passed")
        return "verification passes; tampering and a swapped key are rejected"

    def bip340_vectors():
        """Check the BIP340 official vectors: re-sign every signable row and compare, and decide pass/fail on every verify-only row."""
        signed = verified = 0
        for index, secret_hex, pubkey_hex, aux_hex, msg_hex, sig_hex, should_pass in BIP340_VECTORS:
            label = "BIP340 vector %s" % index
            message = bytes.fromhex(msg_hex)
            signature = bytes.fromhex(sig_hex)
            xonly = bytes.fromhex(pubkey_hex)

            got = schnorr_verify(message, xonly, signature)
            expect_equal("%s verification result" % label, got, should_pass)
            verified += 1

            if secret_hex == "-":
                continue
            secret = int(secret_hex, 16)
            expect_equal("%s public key" % label,
                         pubkey_to_xonly(compressed_pubkey(secret)).hex(), pubkey_hex)
            produced = schnorr_sign(message, secret, bytes.fromhex(aux_hex))
            expect_equal("%s signature" % label, produced.hex(), sig_hex)
            signed += 1
        return "%d re-signed and %d verified rows all match the official ones" % (signed, verified)

    def ecdsa_roundtrip():
        secret = 0x0BADC0DE00000000000000000000000000000000000000000000000000000001
        message = sha256(b"ecdsa selftest")
        signature = ecdsa_sign(message, secret)
        pubkey = compressed_pubkey(secret)
        if not ecdsa_verify(message, signature, pubkey):
            raise AssertionError("our own signature failed our own verification")
        if ecdsa_verify(message, signature, compressed_pubkey(secret + 1)):
            raise AssertionError("swapping the public key still passed")
        if ecdsa_verify(sha256(b"another message"), signature, pubkey):
            raise AssertionError("swapping the message still passed")
        return "verification passes; a swapped key and a swapped message are rejected"

    def bip32_fields():
        # the mainnet xpub of official BIP32 vector 1, checked field by field
        text = ("xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJ"
                "oCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8")
        version, key = parse_extended_key(text)
        expect_equal("xpub version bytes", version, 0x0488B21E)
        expect_equal("xpub depth", key.depth, 0)
        expect_equal("xpub fingerprint", key.fingerprint.hex(), "00000000")
        expect_equal("xpub child index", key.child_index, 0)
        expect_equal("xpub chain code", key.chain_code.hex(),
                     "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508")
        expect_equal("xpub public key", key.pubkey.hex(),
                     "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2")
        expect_equal("xpub round trip", serialize_extended_key(key, version), text)
        return "the fields and the round trip both match the official vector"

    def bip32_derives():
        # Only non-hardened derivation is supported, so the mainnet xpub of official vector 1 is used as the parent.
        # The expected values are computed independently with libsecp256k1: the parent public key prefix is 03 (Y is odd),
        # which is exactly the case that catches the trap of "the parent point cannot simply use lift_x (always even Y)".
        version, key = parse_extended_key(
            "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJ"
            "oCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8")
        expect_equal("m/0x0/0 child public key", derive_pubkey(key, 0).pubkey.hex(),
                     "027c4b09ffb985c298afe7e5813266cbfcb7780b480ac294b0b43dc21f2be3d13c")
        expect_equal("m/0x0/0 child chain code", derive_pubkey(key, 0).chain_code.hex(),
                     "d323f1be5af39a2d2f08f5e8f664633849653dbe329802e9847cfc85f8d7b52a")
        expect_equal("m/0x1 child public key", derive_pubkey(key, 1).pubkey.hex(),
                     "037c2098fd2235660734667ff8821dbbe0e6592d43cfd86b5dde9ea7c839b93a50")

        # Derive three levels in a row; the parent/child parity flips back and forth, which catches errors like "just negate according to the parent parity".
        node = key
        for index in (0, 0, 2):
            node = derive_pubkey(node, index)
        expect_equal("chained derivation m/0x0/0x0/2 public key", node.pubkey.hex(),
                     "02b252b9a5c5a31f07d52ef5308e4845b21b15e367abf00e8e47bcb48cbcfad2d0")
        expect_equal("chained derivation chain code", node.chain_code.hex(),
                     "0f676defcc0789bd9951f55e4d0687051ceae44f2dd0c32981da25befb05180a")
        expect_equal("chained derivation depth", node.depth, 3)

        child = derive_pubkey(key, 0)
        if child.fingerprint != hash160(key.pubkey)[:4]:
            raise AssertionError("the child key fingerprint should be the first 4 bytes of hash160(parent pubkey)")
        if not is_valid_pubkey(child.pubkey):
            raise AssertionError("derivation produced an invalid public key")
        if serialize_extended_key(child, version).startswith("xpub") is False:
            raise AssertionError("the prefix is wrong after re-encoding")
        return "byte-for-byte identical to libsecp256k1, and parity flips are handled correctly"

    def bip32_hardened_rejected():
        _, key = parse_extended_key(
            "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJ"
            "oCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8")
        try:
            derive_pubkey(key, 0x80000000)
        except ValueError:
            return "a hardened path is correctly rejected (an xpub holds no private key, so it cannot derive)"
        raise AssertionError("a hardened path was not rejected")

    def descriptor_checksum_vector():
        # BIP380 official vectors
        expect_equal("BIP380 raw(deadbeef)",
                     descriptor_with_checksum("raw(deadbeef)"), "raw(deadbeef)#89f8spxm")
        for text in ("raw(deadbeef)#89f8spxm",
                     "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)",
                     "wsh(sortedmulti(2,xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/0/0/*))"):
            built = descriptor_with_checksum(text)
            if not descriptor_checksum_valid(built):
                raise AssertionError("we generated it and then it failed to verify: %s" % built)
        if descriptor_checksum_valid("raw(deedbeef)#89f8spxm"):
            raise AssertionError("a tampered descriptor passed the checksum")
        return "the official vector matches, and a tampered descriptor is detected"

    def pubkey_validation():
        good = "0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352"
        expect_equal("a compressed public key is valid", is_valid_pubkey(bytes.fromhex(good)), True)
        expect_equal("x=0 is judged invalid", is_valid_pubkey(bytes.fromhex("02" + "00" * 32)), False)
        expect_equal("a wrong prefix is judged invalid", is_valid_pubkey(bytes.fromhex("05" + "11" * 32)), False)
        uncompressed = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" \
                       "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
        expect_equal("an uncompressed public key is valid", is_valid_pubkey(bytes.fromhex(uncompressed)), True)
        return "valid and invalid are both judged correctly"

    check("BIP173 bech32 addresses", bech32_p2wpkh)
    check("BIP350 bech32m addresses", bech32m_p2tr)
    check("witness version bound to the checksum", bech32_version_binding)
    check("tagged_hash domain separation", tagged_hash_domain)
    check("Schnorr sign and verify", schnorr_roundtrip)
    check("BIP340 official vectors", bip340_vectors)
    check("ECDSA sign and verify", ecdsa_roundtrip)
    check("BIP32 xpub fields", bip32_fields)
    check("BIP32 non-hardened derivation", bip32_derives)
    check("hardened paths rejected", bip32_hardened_rejected)
    check("BIP380 descriptor checksum", descriptor_checksum_vector)
    check("public key validity check", pubkey_validation)


# ---------- Official vectors (BIP341 TapTree) ----------
# The official BIP341 vectors are embedded directly (the scriptPubKey part of bip-0341/wallet-test-vectors.json),
# so the delivered file depends on no external data file.
# The tree uses nested tuples to keep the official shape: a leaf is ("l", leaf version, script hex),
# a branch is ("b", left, right). The merkle root of the official [a, [b, c]] is
# TapBranch(a, TapBranch(b, c)); flattening it and splitting by floor gives another root, which does not match.
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
    """List the leaves (leaf version, script bytes) in depth-first order, matching the official leafHashes."""
    if node[0] == "l":
        return [(node[1], bytes.fromhex(node[2]))]
    return vector_leaves(node[1]) + vector_leaves(node[2])


def vector_tree_root(node):
    if node[0] == "l":
        return tapleaf_hash(bytes.fromhex(node[2]), node[1])
    return tapbranch_hash(vector_tree_root(node[1]), vector_tree_root(node[2]))


def vector_paths(node):
    """Return, in leaf order, the list of sibling hashes from each leaf up to the root (bottom-up)."""
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
        return "byte-for-byte identical to the BIP341 definition"

    def tapbranch_is_order_independent():
        first, second = sha256(b"a"), sha256(b"b")
        expect_equal("the branch hash is order independent", tapbranch_hash(first, second),
                     tapbranch_hash(second, first))
        return "reversing the order gives the same result"

    def taptree_convention():
        # In the official vector the three-leaf tree is [l0, [l1, l2]], which the floor split here has to reproduce.
        # Note the leaf public key must be a 32-byte x-only key; a hash160 (20 bytes) is rejected.
        scripts = [tapscript_leaf_for_key(sha256(b"member%d" % index))
                   for index in range(3)]
        leaves = [tapleaf_hash(script) for script in scripts]
        root, paths = build_taptree(leaves)
        manual = tapbranch_hash(leaves[0], tapbranch_hash(leaves[1], leaves[2]))
        expect_equal("3-leaf tree shape", root.hex(), manual.hex())
        expect_equal("sibling count of leaf 0", len(paths[0]), 1)
        expect_equal("sibling count of leaf 1", len(paths[1]), 2)
        return "[l0,[l1,l2]], the same shape as the official vector"

    def wallet_vectors():
        """Check every embedded official BIP341 vector."""
        counts = dict.fromkeys(["leaf", "root", "tweak", "output", "control", "spk", "address"], 0)
        for entry in BIP341_WALLET_VECTORS:
            internal_x = bytes.fromhex(entry["internal"])
            tree = entry["tree"]
            if tree is None:
                # pure key path: the merkle root is empty, the tweak hashes only the internal public key
                expect_equal("official vector key path tweak",
                             taproot_tweak(internal_x, None).hex(), entry["tweak"])
                output_point = taproot_output_point(internal_x, None)
                expect_equal("official vector key path tweakedPubkey",
                             output_point[0].to_bytes(32, "big").hex(), entry["tweaked"])
            else:
                leaves = vector_leaves(tree)
                root = vector_tree_root(tree)
                for position, (version, script) in enumerate(leaves):
                    expect_equal("official vector leafHashes",
                                 tapleaf_hash(script, version).hex(),
                                 entry["leaf_hashes"][position])
                    counts["leaf"] += 1
                expect_equal("official vector merkleRoot", root.hex(), entry["root"])
                counts["root"] += 1
                expect_equal("official vector tweak", taproot_tweak(internal_x, root).hex(),
                             entry["tweak"])
                counts["tweak"] += 1

                output_point = taproot_output_point(internal_x, root)
                expect_equal("official vector tweakedPubkey",
                             output_point[0].to_bytes(32, "big").hex(), entry["tweaked"])
                counts["output"] += 1

                blocks = entry.get("blocks") or []
                paths = vector_paths(tree)
                for position, (version, _script) in enumerate(leaves):
                    if position >= len(blocks):
                        break
                    control = taproot_control_block(paths[position], output_point,
                                                    internal_x, version)
                    expect_equal("official vector control block", control.hex(), blocks[position])
                    counts["control"] += 1

            program = output_point[0].to_bytes(32, "big")
            expect_equal("official vector scriptPubKey", (b"\x51\x20" + program).hex(),
                         entry["spk"])
            counts["spk"] += 1
            expect_equal("official vector bech32m address", segwit_encode("bc", 1, program),
                         entry["addr"])
            counts["address"] += 1
        return ("%d leaves, %d roots, %d tweaks, %d output keys, %d control blocks, %d scripts and %d addresses all match"
                % (counts["leaf"], counts["root"], counts["tweak"], counts["output"],
                   counts["control"], counts["spk"], counts["address"]))

    check("TapLeaf hash algorithm", tapleaf_hash_matches_spec)
    check("TapBranch order independence", tapbranch_is_order_independent)
    check("TapTree split convention", taptree_convention)
    check("BIP341 official vectors", wallet_vectors)


# ---------- Multisig schemes ----------
def register_multisig_checks(check):
    def witness_script_structure():
        key1 = bytes.fromhex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
        key2 = bytes.fromhex("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")
        script = multisig_witness_script(1, [key1, key2])
        # OP_1(0x51) <push33+key1> <push33+key2> OP_2(0x52) OP_CHECKMULTISIG(0xae)
        expect_equal("witnessScript structure", script.hex(),
                     "51" + "21" + key1.hex() + "21" + key2.hex() + "52ae")
        expect_equal("the threshold byte of 3-of-3", multisig_witness_script(3, [key1, key2, key1]).hex()[:2],
                     "53")
        return "OP_m ... OP_n OP_CHECKMULTISIG"

    def threshold_enforced():
        members = random_members(3)
        scheme = build_p2wsh_scheme(members, 2)
        secrets_by_key = {item["pubkey"]: item["secret"] for item in members}
        ordered = scheme["keys"]
        if verify_p2wsh_multisig(scheme["witness_script"], ordered, secrets_by_key, 1)[0]:
            raise AssertionError("1 signature passed 2-of-3")
        if not verify_p2wsh_multisig(scheme["witness_script"], ordered, secrets_by_key, 2)[0]:
            raise AssertionError("2 signatures should have passed but did not")
        if verify_p2wsh_multisig(scheme["witness_script"], ordered, secrets_by_key, 3)[0]:
            raise AssertionError("2-of-3 rejected 3 signatures")
        return "2-of-3: 1 signature rejected, 2 pass, and the script does not exceed its powers"

    def three_of_five():
        members = random_members(5)
        scheme = build_p2wsh_scheme(members, 3)
        secrets_by_key = {item["pubkey"]: item["secret"] for item in members}
        if verify_p2wsh_multisig(scheme["witness_script"], scheme["keys"],
                                 secrets_by_key, 2)[0]:
            raise AssertionError("2 signatures passed 3-of-5")
        if not verify_p2wsh_multisig(scheme["witness_script"], scheme["keys"],
                                     secrets_by_key, 3)[0]:
            raise AssertionError("3-of-5 should have passed")
        return "3-of-5: 2 rejected, 3 pass"

    def wrong_signer_rejected():
        # Three people are on the list, but signing with a private key from outside it must not pass
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
            raise AssertionError("somebody outside the list signed successfully")
        return "the signature of a member outside the list is rejected"

    def sorting_matters():
        # With random public keys, "ascending by bytes" and "fingerprint order" coincide with probability about 1/6,
        # so asserting that the two addresses differ outright would fail now and then; a few sets are tried until the orderings really differ.
        by67 = byfinger = None
        for _ in range(50):
            members = random_members(3)
            by67 = build_p2wsh_scheme(members, 2, order="bip67")
            byfinger = build_p2wsh_scheme(members, 2, order="fingerprint")
            if by67["keys"] != byfinger["keys"]:
                break
        else:
            raise AssertionError("50 consecutive sets of public keys did not distinguish the two orderings; the test itself is broken")
        if by67["keys"] != sorted(by67["keys"]):
            raise AssertionError("the BIP67 result is not sorted ascending by bytes")
        if by67["address"] == byfinger["address"]:
            raise AssertionError("both orderings give the same address, so the sorting had no effect")
        if by67["witness_script"] == byfinger["witness_script"]:
            raise AssertionError("both orderings give the same witnessScript, so the sorting had no effect")
        return "the ordering really changes the address (BIP67 ascending by bytes)"

    def taproot_all_sign():
        # Run several rounds: the parity of the output key y is nearly random, so a single round has about a 50% chance of never hitting one side
        rounds = 12
        for _ in range(rounds):
            members = random_members(3)
            scheme = build_taproot_scheme(members, "chain")
            rows = run_scheme_checks(scheme, members)
            if len(rows) < 2:
                raise AssertionError("too few cases: %s" % (rows,))
            for label, expect_pass, actual_pass, detail in rows:
                # The point is to judge whether the behaviour matches the expectation, not whether verification passes.
                # When one signature is short the script is supposed to reject, so actual_pass being False is correct here.
                if actual_pass != expect_pass:
                    raise AssertionError("%s behaves the opposite of what was expected: %s" % (label, detail))
            if not any(expect and actual for _l, expect, actual, _d in rows):
                raise AssertionError("no case where everyone signed was reached")
            if not any((not expect) and (not actual) for _l, expect, actual, _d in rows):
                raise AssertionError("no case where one missing signature was rejected was reached")
        return "bc1p: over %d rounds, 3 signatures always pass and 2 signatures are always rejected" % rounds

    def taproot_internal_key_matters():
        members = random_members(2)
        scheme = build_taproot_scheme(members, "chain")
        if NUMS_X == BASE_X.to_bytes(32, "big"):
            raise AssertionError("the internal public key should not be the base point G")
        if taproot_output_key(BASE_X.to_bytes(32, "big"),
                              scheme["merkle_root"]) == scheme["output_key"]:
            raise AssertionError("the output key is unaffected by the internal public key")
        return "the output key depends on the internal public key, and that key is NUMS, not G"

    def taproot_tree_layout_differs():
        members = random_members(3)
        chain = build_taproot_scheme(members, "chain")
        tree = build_taproot_scheme(members, "tree")
        if chain["address"] == tree["address"]:
            raise AssertionError("the chain and tree layouts unexpectedly give the same address")
        if chain["signature_count"] != tree["signature_count"]:
            raise AssertionError("the two layouts should need the same number of signatures")
        return "chain and tree are two different addresses"

    def address_prefixes():
        members = random_members(3)
        p2wsh = build_p2wsh_scheme(members, 2)
        p2tr = build_taproot_scheme(members, "chain")
        expect_equal("bc1q prefix", p2wsh["address"][:4], "bc1q")
        expect_equal("bc1p prefix", p2tr["address"][:4], "bc1p")
        expect_equal("the compatibility address is gone",
                     "p2sh_p2wsh_address" in p2wsh or "p2sh_legacy_address" in p2wsh,
                     False)
        return "the bc1q and bc1p prefixes are correct and legacy P2SH is no longer generated"

    def mainnet_only():
        # This tool only does mainnet, so no entry point may produce a testnet address anymore
        members = random_members(3)
        produced = []
        for threshold in (1, 2, 3):
            scheme = build_p2wsh_scheme(members, threshold)
            produced += [scheme["address"]]
        produced.append(build_taproot_scheme(members)["address"])
        produced.append(build_taproot_scheme(members, "tree")["address"])
        for address in produced:
            if address.startswith(("tb1", "bcrt1")):
                raise AssertionError("a non-mainnet address showed up: " + address)
        if not produced[0].startswith("bc1q") or not produced[-1].startswith("bc1p"):
            raise AssertionError("the mainnet prefix is wrong")
        return "all %d addresses are mainnet, with no tb1/bcrt1" % len(produced)

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
            raise AssertionError("the five ways of writing one private key parsed into %d different public keys" % len(seen))
        return "the five forms WIF/hex/decimal/public key/x-only all agree"

    def inspect_addresses():
        members = random_members(3)
        p2wsh = build_p2wsh_scheme(members, 2)
        p2tr = build_taproot_scheme(members, "chain")
        cases = [
            (p2wsh["address"], "SegWit v0", "bc1q multisig address"),
            (p2tr["address"], "Taproot", "bc1p address"),
        ]
        for address, expected, label in cases:
            report = inspect_address(address)
            if "Cannot make sense" in report:
                raise AssertionError("%s was wrongly judged unparseable: %s" % (label, report.strip()))
            if expected not in report:
                raise AssertionError("the parse result for %s is wrong: %s" % (label, report.strip()))
        # Garbage input must produce a message instead of raising
        for junk in ("not-an-address", "bc1q", "", "0OIl"):
            report = inspect_address(junk)
            if "Cannot make sense" not in report:
                raise AssertionError("garbage input %r was parsed successfully: %s" % (junk, report.strip()))
        return "bc1q, bc1p and P2SH all parse, and garbage input only gets a message without crashing"

    check("witnessScript structure", witness_script_structure)
    check("the 2-of-3 threshold holds", threshold_enforced)
    check("the 3-of-5 threshold holds", three_of_five)
    check("members outside the list are rejected", wrong_signer_rejected)
    check("public key ordering changes the address", sorting_matters)
    check("bc1p everyone signs", taproot_all_sign)
    check("the Taproot internal public key", taproot_internal_key_matters)
    check("the two Taproot layouts", taproot_tree_layout_differs)
    check("address prefixes", address_prefixes)
    check("only mainnet addresses", mainnet_only)
    check("member input formats", member_input_forms)
    check("address parsing with inspect", inspect_addresses)


# ---------- Official vectors (BIP143 native SegWit signature hash) ----------
# Copied one by one from the official examples in the BIP143 specification text.
# Note the scriptCode line in the original carries a compact_size length prefix, which has been stripped here.
# It covers native P2WPKH, P2SH-P2WPKH and native P2WSH (including SINGLE out of range),
# plus P2SH-P2WSH 6-of-6 signed once with each of the 6 hash types.
BIP143_VECTORS = [
    {
        "name": "native P2WPKH",
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
        "name": "native P2WSH (SINGLE out of range)",
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


# ---------- Official vectors (BIP341 Taproot signature hash) ----------
# Generated automatically from the official BIP341 vectors by gen_taproot_sighash_table.py.
# It covers all 7 inputs of keyPathSpending: ALL / NONE / SINGLE / DEFAULT
# as well as the three ANYONECANPAY combinations; some entries have a non-empty merkle_root,
# which also checks that taproot_tweak commits to the merkle root.
# Generated automatically from the official BIP341 vectors by gen_taproot_sighash_table.py
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
        return "all %d official vectors match (including the 6 hash types)" % passed

    def taproot_sighash_official():
        vector = TAPROOT_SIGHASH_VECTOR
        tx = parse_transaction(bytes.fromhex(vector["unsigned"]))
        scripts = [bytes.fromhex(item) for item in vector["scripts"]]
        amounts = vector["amounts"]
        expect_equal("the prevout count matches the input count", len(scripts), len(tx.inputs))

        signed = parse_transaction(bytes.fromhex(vector["signed"]))
        # BIP144: version | marker | flag | txins | txouts | witnesses | locktime
        expect_equal("the official signed transaction serializes and round trips",
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

            # the last item in the official witness is the Schnorr signature (for 65 bytes the last byte is the hash type)
            raw = signed.inputs[index].witness[-1]
            signature = raw[:64]
            output_x = taproot_output_key(internal_x, merkle_root)
            if not schnorr_verify(message, output_x, signature):
                raise AssertionError("the official Schnorr signature fails to verify under the derived output key: input %d"
                                     % index)
            passed += 1
        return "all %d official vectors match (including the tweak, the output key and Schnorr verification)" % passed

    def bip342_script_path_extension():
        """The BIP342 script-path extension must follow the common BIP341 SigMsg.

        The official vectors are not copied here (BIP341's wallet-test-vectors.json has no scriptPathSpending);
        instead the expected value is assembled by hand straight from BIP342: the end of sigMsg has to be extended with
        tapleaf_hash(32) || key_version(0x00) || codesep_pos(4 bytes little-endian).
        Without these 37 bytes the key path is perfectly fine; only the script path would end up with a completely different hash.
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

        # Assemble the common part of the BIP341 SigMsg by hand as the spec says (hashType=0x00, i.e. SIGHASH_DEFAULT,
        # which hashes the same range as ALL). spend_type and input_index are appended later, according to the spending type.
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
        expect_equal("the common BIP341 SigMsg", key_path.hex(),
                     tagged_hash("TapSighash", b"\x00" + common
                                 + bytes([0x00]) + index_bytes).hex())

        # script path: spend_type becomes 0x02, followed by the 37-byte BIP342 extension
        extension = tapleaf_hash(leaf_script, LEAF_TAPSCRIPT)
        extension += b"\x00"                            # key_version
        extension += (0xFFFFFFFF).to_bytes(4, "little")  # OP_CODESEPARATOR never ran
        script_path = taproot_sighash(tx, 0, prevout_scripts, amounts, 0x00,
                                      ext_flag=1, script=leaf_script)
        expect_equal("the BIP342 script-path extension", script_path.hex(),
                     tagged_hash("TapSighash", b"\x00" + common
                                 + bytes([0x02]) + index_bytes + extension).hex())

        if key_path == script_path:
            raise AssertionError("the script path and the key path give the same hash, so the extension was ignored")

        # When OP_CODESEPARATOR has run, codesep_pos becomes the real position and everything else stays the same
        with_sep = taproot_sighash(tx, 0, prevout_scripts, amounts, 0x00,
                                   ext_flag=1, script=leaf_script, codeseparator_pos=3)
        expect_equal("BIP342 codesep_pos=3", with_sep.hex(),
                     tagged_hash("TapSighash", b"\x00" + common
                                 + bytes([0x02]) + index_bytes + extension[:-4]
                                 + (3).to_bytes(4, "little")).hex())
        if with_sep == script_path:
            raise AssertionError("codeseparator_pos did not enter the hash")

        # The extension and the signature must work together: sign, then verify through the real flow
        secret = 0x0111111111111111111111111111111111111111111111111111111111111111
        xonly = pubkey_to_xonly(compressed_pubkey(secret))
        signature = schnorr_sign(script_path, secret)
        if not schnorr_verify(script_path, xonly, signature):
            raise AssertionError("the script-path signature failed its own verification")
        return "key path, script path and codesep_pos are all correct, with the 37-byte extension"

    check("BIP143 official signature hash", bip143_official)
    check("BIP341 official signature hash", taproot_sighash_official)
    check("BIP342 script-path extension", bip342_script_path_extension)

# ================= Output formatting =================
# Every render_* goes through the scheme below, otherwise the output ends up all over the place:
#   1) one block = the title embedded in the top border + the body + one bottom border, so only a single frame is drawn;
#   2) alignment is computed in display width (Chinese counts as two columns), never with the %-12s style that pads by character count;
#   3) overlong values (hex, descriptors) are wrapped instead of stretching into one line of hundreds of characters;
#   4) the same warning appears once instead of being repeated for every member.
LINE_WIDTH = 76                       # wide enough for a bc1p address or a compressed public key to sit on one line each
VALUE_GAP = 2                        # number of spaces between the label column and the value column
HEX_CHUNK = 64                       # at most 64 hex characters per line (32 bytes)
WARNING_TEXT = "The private keys stay on your side; do not post them online or commit them to a repository."


def display_width(text):
    """Measure a length in terminal display columns (Chinese counts as two)."""
    return sum(2 if unicodedata.east_asian_width(char) in "WF" else 1 for char in text)


def pad_display(text, width):
    """Pad on the right up to the given display width."""
    return text + " " * max(0, width - display_width(text))


def rule(title=None, char="="):
    """The border of a block. With a title the title is embedded in the top border, which saves it two lines of its own."""
    if not title:
        return char * LINE_WIDTH
    head = char * 2 + " " + title + " "
    return head + char * max(3, LINE_WIDTH - display_width(head))


def block(title, body):
    """Title + body lines -> one complete block."""
    return "\n".join([rule(title)] + list(body) + [rule()])


def split_columns(text, columns):
    """Split the text after display column columns; returns (the first half, the second half)."""
    used = 0
    for index, char in enumerate(text):
        used += display_width(char)
        if used > columns:
            return text[:index], text[index:]
    return text, ""


def wrap_value(value, width):
    """Wrap a long value: bytes break on whole bytes; str prefers to break after a comma, a space or a closing bracket, otherwise it breaks hard by display width.

    Wrapping must be lossless: joining the pieces back has to equal the original, so never rstrip at the end of a line,
    and when breaking after a space the space stays at the end of the line (invisible in the terminal).
    """
    if value is None:
        return ["—"]
    if isinstance(value, (bytes, bytearray)):
        text = bytes(value).hex()
        chunk = min(HEX_CHUNK, width // 2 * 2)         # an even number of characters, so a line is a whole number of bytes
        return [text[start:start + chunk] for start in range(0, len(text), chunk)] or [""]
    text = str(value)
    if display_width(text) <= width:
        return [text]
    lines = []
    rest = text
    while display_width(rest) > width:
        head, tail = split_columns(rest, width)
        cut = max(head.rfind(separator) for separator in (",", " ", ")"))
        if cut > width // 2:                          # the second half still has content, so break after the separator
            head, tail = rest[:cut + 1], rest[cut + 1:]
        lines.append(head)
        rest = tail
    if rest:
        lines.append(rest)
    return lines


def paragraph(text, indent="  ", hanging="    "):
    """Wrap a whole paragraph of explanatory text: the first line carries indent, the continuation lines are indented by hanging."""
    chunks = wrap_value(text, LINE_WIDTH - display_width(indent))
    return [indent + chunks[0]] + [hanging + chunk for chunk in chunks[1:]]


def kv_rows(rows, indent="  ", label_width=None):
    """A list of (label, value) -> aligned two-column text lines; when a value wraps it stays aligned with the value column."""
    column = label_width or max([display_width(label) for label, _value in rows] + [0])
    room = max(16, LINE_WIDTH - display_width(indent) - column - VALUE_GAP)
    lines = []
    for label, value in rows:
        chunks = wrap_value(value, room)
        lines.append(indent + pad_display(label, column) + " " * VALUE_GAP + chunks[0])
        continuation = indent + " " * (column + VALUE_GAP)
        lines.extend(continuation + chunk for chunk in chunks[1:])
    return lines


def check_lines(items, mark_width):
    """[mark] description + detail. If it fits they share a line, otherwise the detail is wrapped below."""
    indent = " " * (2 + mark_width + 4)
    lines = []
    for mark, label, detail in items:
        head = "  [%s]  %s" % (pad_display(mark, mark_width), label)
        if not detail:
            lines.append(head)
        elif display_width(head) + VALUE_GAP + display_width(detail) <= LINE_WIDTH:
            lines.append(head + " " * VALUE_GAP + detail)
        else:
            lines.append(head)
            lines.extend(indent + chunk
                         for chunk in wrap_value(detail, LINE_WIDTH - len(indent)))
    return lines


def scheme_to_json(scheme):
    """Turn a scheme into a JSON-serializable structure."""
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


def scheme_tag(scheme):
    """A short tag, used to tell two schemes apart within the same batch of output."""
    if scheme["type"] == "p2wsh":
        return "bc1q %d-of-%d" % (scheme["threshold"], scheme["members"])
    return "bc1p %d all sign" % scheme["members"]


def scheme_title(scheme):
    if scheme["type"] == "p2wsh":
        return "%s - any %d signatures can spend" % (scheme_tag(scheme), scheme["threshold"])
    return "%s - everyone must sign, not one may be missing" % scheme_tag(scheme)


def render_address(scheme):
    """The address gets its own paragraph with blank lines around it, right after the title.

    The address is the one thing this program really hands over, so it does not go into the two-column table as just another row:
    it takes a line of its own with blank lines above and below, so it is never missed even with several schemes.
    """
    return ["", "  Receiving address (%s)" % scheme_tag(scheme),
            "    " + scheme["address"], ""]


def render_address_summary(schemes):
    """The most convenient view of a batch of schemes: the addresses listed together so a whole block can be copied."""
    if len(schemes) < 2:
        return ""
    body = ["  Here are the receiving addresses; do not copy the leading or trailing spaces:", ""]
    for scheme in schemes:
        body += ["  %s" % scheme_tag(scheme), "    %s" % scheme["address"], ""]
    return block("Address list - %d in total" % len(schemes), body[:-1])


def render_key_list(title, keys):
    """The member public key list: index + public key, one per line."""
    lines = ["", "  " + title]
    for index, key in enumerate(keys, 1):
        lines.append("    %2d  %s" % (index, key.hex()))
    return lines


def scheme_body(scheme):
    """The scheme body: address, descriptor, members."""
    if scheme["type"] == "p2wsh":
        rows = [
            ("Descriptor", descriptor_with_checksum(scheme["descriptor"])),
            ("Ordering", "BIP67, public keys ascending by bytes" if scheme["order"] == "bip67"
                     else "sorted by public key fingerprint (the old practice from before BIP67)"),
        ]
        members = "Members (%d in total; these public keys below are what the address is computed from)" % scheme["members"]
    else:
        rows = [
            ("Output key", scheme["output_key"]),
            ("Descriptor", descriptor_with_checksum(scheme["descriptor"])),
            ("Structure", "chain: one CHECKSIG chain strings all the signatures together" if scheme["layout"] == "chain"
                     else "tree: one leaf per member, and a script-path spend only proves one leaf at a time"),
        ]
        members = "Members (%d in total; the 32-byte x-only public keys are listed below)" % scheme["members"]
    return render_address(scheme) + kv_rows(rows) + render_key_list(members, scheme["keys"]) \
        + [""] + paragraph("Note: " + scheme["note"])


def scheme_script_detail(scheme):
    """The script details that only -d gives."""
    if scheme["type"] == "p2wsh":
        rows = [("witnessScript", scheme["witness_script"]),
                ("scriptPubKey", scheme["script_pubkey"])]
        return [""] + kv_rows(rows)
    rows = [("Leaf script %d" % index, script)
            for index, script in enumerate(scheme["leaf_scripts"], 1)]
    rows += [("merkle root", scheme["merkle_root"]),
             ("Control block", scheme["control_blocks"][0]),
             ("scriptPubKey", scheme["script_pubkey"])]
    lines = [""] + kv_rows(rows) + ["", "  Witness stack template (top first):"]
    lines += ["    %d  the Schnorr signature of member number %d" % (index, index + 1)
              for index in range(len(scheme["keys"]))]
    lines.append("    %d  control block" % len(scheme["keys"]))
    return lines


def render_scheme(scheme):
    """The default output: address, descriptor, member list."""
    return block(scheme_title(scheme), scheme_body(scheme))


def render_scheme_detail(scheme):
    """The full information with -d: witnessScript, leaf scripts and control blocks all expanded."""
    return block(scheme_title(scheme) + " - details",
                 scheme_body(scheme) + scheme_script_detail(scheme))


def render_members(members):
    """The member list: the private keys and public keys each get a column aligned by index, and the warning is stated only once."""
    body = []
    holders = [item for item in members if item.get("secret")]
    if holders:
        body += paragraph("Private keys (WIF) - this is the signing right, keep them on your own machine only", "  ", "    ")
        body.append("")
        body += ["    %2d  %s" % (index, item["source"])
                 for index, item in enumerate(members, 1) if item.get("secret")]
        body.append("")
    body += paragraph("Public keys - use them together with other people public keys to build a multisig address; they may be public", "  ", "    ")
    body += ["    %2d  %s" % (index, item["pubkey"].hex())
             for index, item in enumerate(members, 1)]
    if len(holders) == len(members):
        matched = all(compressed_pubkey(item["secret"]) == item["pubkey"] for item in members)
        body += [""] + paragraph("Each item has been checked: every public key was derived from its private key %s"
                                 % ("." if matched else "(some do not match, check the input!)."))
    body += [""] + paragraph("Warning: " + WARNING_TEXT)
    return block("Member keys - %d in total" % len(members), body)


def render_verify_report(title, rows):
    """The verification report of a scheme. Each row of rows is (description, expected to pass, actually passed, detail)."""
    items = [("as expected" if actual == expect else "unexpected", label, detail)
             for label, expect, actual, detail in rows]
    return block(title, check_lines(items, display_width("as expected")))


def render_selftest_report(title, checks):
    """The self-test report. Each item of checks is (name, passed, detail)."""
    items = [("pass" if ok else "fail", name, detail) for name, ok, detail in checks]
    failed = len([item for item in checks if not item[1]])
    summary = ("%d checks in total, %d failed." % (len(checks), failed) if failed
               else "%d checks in total, all passed, the program is fine." % len(checks))
    return block(title, check_lines(items, display_width("pass")) + ["", "  " + summary])


def write_output(text, path):
    """Write to a file or to standard output."""
    if path in (None, "", "-"):
        print(text)
        return
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text + "\n")
    print("Saved to %s" % path)


def pause_before_exit(message="\nPress Enter to close the window..."):
    if sys.stdin.isatty():
        try:
            input(message)
        except (EOFError, KeyboardInterrupt):
            pass


def backend_note():
    """The backend description used by -v."""
    parts = ["curve " + CURVE_BACKEND]
    parts.append("SegWit address encoding " + ("bech32m library" if HAVE_BECH32M else "built in"))
    parts.append("Base58 encoding " + ("base58 library" if HAVE_BASE58 else "built in"))
    return ", ".join(parts)


# ================= End-to-end verification demo =================
def run_scheme_checks(scheme, members, verbose=False):
    """Run an end-to-end verification of the scheme that was built, proving that the script really behaves as expected.

    One signature is deliberately left out to confirm that the script does reject; only checking that enough signatures pass says nothing about the threshold.

    Each row returns (description, expected to pass, actually passed, detail).
    Returning "expected" and "actual" separately is what lets the caller judge whether the behaviour matches the expectation;
    a single boolean would mix "correctly rejected" and "wrongly passed" together.
    """
    rows = []

    if scheme["type"] == "p2wsh":
        secrets_by_key = {item["pubkey"]: item["secret"] for item in members if item["secret"]}
        ordered = [key for key in scheme["keys"] if key in secrets_by_key]
        if len(ordered) < scheme["threshold"]:
            return [("not enough member private keys, skipped", True, True,
                     "only %d of %d private keys were available" % (len(ordered), scheme["threshold"]))]
        # With a threshold of 1 there is no "one person short" case to measure (a witness stack cannot be built with 0 people), so only the satisfied case is tested
        counts = [scheme["threshold"]]
        if scheme["threshold"] - 1 >= 1:
            counts.insert(0, scheme["threshold"] - 1)
        for count in counts:
            expect_pass = (count == scheme["threshold"])
            actual, detail = verify_p2wsh_multisig(scheme["witness_script"], ordered,
                                                 secrets_by_key, count)
            rows.append((signature_scenario_label(count, len(ordered), expect_pass),
                         expect_pass, actual, detail))
        return rows

    secrets_by_xonly = {pubkey_to_xonly(item["pubkey"]): item["secret"]
                        for item in members if item["secret"]}
    ordered = [key for key in scheme["keys"] if key in secrets_by_xonly]
    if not ordered:
        return [("not enough member private keys, skipped", True, True, "no member private key was available")]
    leaf_script = scheme["leaf_scripts"][0]
    transaction = build_test_transaction()
    signatures = []
    for key in ordered:
        message = taproot_sighash(transaction, 0, [scheme["script_pubkey"]], [100_000],
                                  SIGHASH_DEFAULT, ext_flag=1, script=leaf_script)
        signatures.append(schnorr_sign(message, secrets_by_xonly[key]))
    for count in (len(signatures) - 1, len(signatures)):
        expect_pass = (count == len(signatures))
        # The witness stack is reversed: the top holds the last member signature, so it is passed back to front
        actual, detail = verify_taproot_script_path(leaf_script, list(reversed(signatures[:count])))
        rows.append((signature_scenario_label(count, len(signatures), expect_pass),
                     expect_pass, actual, detail))
    return rows


def signature_scenario_label(count, total, expect_pass):
    """The scenario name in the verification report: it states how many signed and whether a pass or a rejection is expected."""
    return "%d of %d signatures - should %s" % (count, total, "pass" if expect_pass else "be rejected")


# ================= Command line =================
def read_members_file(path):
    # utf-8-sig is used: Windows Notepad writes UTF-8 with a BOM, and without stripping it the first line fails to parse
    if path in (None, "", "-"):
        return sys.stdin.read()
    with open(path, encoding="utf-8-sig") as handle:
        return handle.read()


def default_threshold(count):
    """A sensible default threshold: 3 people -> 2, 5 people -> 3, and at least 1 when there are fewer."""
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
            outputs.append(render_verify_report("end-to-end verification - " + scheme_tag(scheme), rows))
    if args.format == "json":
        write_output(json.dumps([scheme_to_json(item) for item in schemes],
                                ensure_ascii=False, indent=2), args.out)
    else:
        summary = render_address_summary(schemes)
        if summary:                      # the address list goes first, so it is seen wherever you scroll to
            outputs.insert(0, summary)
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


def render_inspect_address(address, kind, extra=""):
    """The address being parsed also gets its own paragraph, so the parse result lines up with the address at a glance."""
    return ["", "  Address (%s)%s" % (kind, extra), "    " + address, ""]


def inspect_address(address):
    """What can be seen from an address. What cannot be seen is whether the scriptPubKey is P2WPKH or P2WSH."""
    address = (address or "").strip()
    # Non-ASCII input makes bech32 / base58 raise an encoding error, so it is caught first and answered in plain words
    if not address:
        return block("Address parsing", paragraph("Cannot make sense of this address: no address content was given."))
    if not address.isascii():
        return block("Address parsing", paragraph(
            "Cannot make sense of this address: it contains non-ASCII characters, most likely"
            "Chinese punctuation or full-width signs that came along when copying; please copy it again."))
    # segwit_decode returns (hrp, version, witness program), or None when it is not a SegWit address
    decoded = segwit_decode(address)
    if decoded is not None:
        hrp, version, program = decoded
        kind = "bc1p, Taproot" if version == 1 else "bc1q, %s" % HRP_NAMES.get(hrp, hrp)
        rows = [
            ("Type", "SegWit v%d%s" % (version, " (Taproot)" if version == 1 else "")),
            ("Network", HRP_NAMES.get(hrp, hrp)),
            ("Witness program", program),
            ("Program length", "%d bytes" % len(program)),
        ]
        if version == 0 and len(program) == 20:
            rows.append(("Note", "P2WPKH and P2WSH are both 20 bytes, so the address alone cannot tell them apart;"
                                 "you have to look at the scriptPubKey of the UTXO to know."))
        elif version == 0 and len(program) == 32:
            rows.append(("Note", "P2WSH, which is what multisig addresses are."))
        elif version == 1:
            rows.append(("Note", "a Taproot output key (bc1p)."))
        else:
            rows.append(("Note", "an unknown witness version; please confirm that the address is correct."))
        return block("Address parsing", render_inspect_address(address, kind) + kv_rows(rows))
    try:
        payload = base58check_decode(address)
        if not payload:
            raise ValueError("the length or the checksum is wrong")
        kind = "starting with 1" if payload[0] == 0x00 else "starting with 3" if payload[0] in (0x05, 0xC4) \
            else "a legacy address"
        rows = [("Type", "Base58Check (P2PKH or P2SH)"),
                ("Payload", payload)]
        if payload[0] == 0x00:
            rows.append(("Note", "P2PKH, whose scriptPubKey starts with 76a914."))
        elif payload[0] in (0x05, 0xC4):
            rows.append(("Note", "P2SH, where a scriptPubKey starting with a9 is a legacy multisig."))
        else:
            rows.append(("Note", "the prefix %02x is not a common P2PKH/P2SH." % payload[0]))
        return block("Address parsing", render_inspect_address(address, kind) + kv_rows(rows))
    except ValueError as error:
        return block("Address parsing", paragraph("Cannot make sense of this address: %s" % error))


def command_inspect(args):
    report = inspect_address(args.address)
    write_output(report, args.out)
    # An address that cannot be parsed has to let the caller (a script, a pipeline) tell success from failure
    return 1 if "Cannot make sense" in report else 0


def command_selftest(args):
    """The built-in self-test. By default it prints a one-line conclusion; -v lists every item."""
    checks = []
    register_checks(lambda name, function: collect_check(checks, name, function))
    if args.verbose:
        write_output(render_selftest_report("Self-test", checks), args.out)
        return 0 if all(item[1] for item in checks) else 1
    failed = [item for item in checks if not item[1]]
    write_output("%d checks in total, %d failed." % (len(checks), len(failed)) if failed
                 else "%d checks in total, all passed, the program is fine." % len(checks), args.out)
    return 1 if failed else 0


def collect_check(checks, name, function):
    """Run one self-test item and record any exception as its result."""
    try:
        checks.append((name, True, function() or ""))
    except Exception as error:                    # the self-test counts any exception as a failed item
        checks.append((name, False, "%s: %s" % (type(error).__name__, error)))


MENU_ITEMS = [
    ("1", "One-click multisig scheme", "the program creates the private keys and hands you the address"),
    ("2", "Build from your own list", "paste xpubs / public keys / private keys"),
    ("3", "Parse an address", "see what type the address is"),
    ("4", "Self-test", "run the built-in official vectors"),
    ("0", "Quit", ""),
]


def prompt_members():
    """Paste the members. One per line, and they can also be comma separated and pasted all at once; press Enter to finish."""
    print("  These can be mixed: WIF private key / 64-hex-digit private key / decimal private key")
    print("                     33-byte compressed public key / x: plus a 64-hex x-only public key / xpub derivation path")
    print("  One per line, commas work too; press Enter to finish:")
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
    """How many people bc1q needs. Only this one question; Enter uses the default, and a wrong entry is simply asked again without an error."""
    fallback = default_threshold(len(members))
    while True:
        raw = input("  How many signatures does bc1q need (1-%d, Enter for %d): " % (
            len(members), fallback)).strip()
        if not raw:
            return fallback
        try:
            value = int(raw)
        except ValueError:
            print("  It has to be an integer between 1 and %d." % len(members))
            continue
        if 1 <= value <= len(members):
            return value
        print("  The number has to be between 1 and %d, and you have %d members." % (len(members), len(members)))


def show_schemes(members, threshold):
    """Produce bc1q and bc1p together, verify once while the private keys are at hand, and finally ask whether to save to a file."""
    schemes = [build_p2wsh_scheme(members, threshold), build_taproot_scheme(members)]
    have_secrets = all(item["secret"] for item in members)
    texts = []
    summary = render_address_summary(schemes)
    if summary:                          # the address list first, then the details
        print()
        print(summary)
    for scheme in schemes:
        text = render_scheme(scheme)
        texts.append(text)
        print()
        print(text)
        if have_secrets:
            print()
            print(render_verify_report("end-to-end verification - " + scheme_tag(scheme),
                                       run_scheme_checks(scheme, members)))
    path = input("\n  Save to a file (press Enter to skip):").strip()
    if path:
        write_output("\n\n".join(([summary] if summary else []) + texts), path)
    return 0


def menu_build():
    print()
    members = parse_members(prompt_members())
    print("  Read %d members." % len(members))
    return show_schemes(members, ask_threshold(members))


def menu_quick():
    """The shortest path: say how many people in total and how many of them can sign (like 3v2), and the program creates the keys and gives the address right away."""
    print()
    print("  How many people in total, and how many of them can sign? The form is:")
    print("    3v2 = any 2 of the 3 members; 5v3 = 3 of the 5")
    print("    A single number (e.g. 4) is the member count, and the threshold takes its default")
    raw = input("  > ").strip().lower()
    if not raw:
        return 0
    for sep in ("of", "v", "/", "-", ",", "\uff0c", " "):
        raw = raw.replace(sep, " ")
    numbers = [int(part) for part in raw.split() if part.isdigit()]
    if not numbers:
        print("  That is not understood, returning to the main menu.")
        return 0
    total = numbers[0]
    threshold = numbers[1] if len(numbers) >= 2 else default_threshold(total)
    if threshold > total:              # the order was reversed, so swap it automatically
        total, threshold = threshold, total
    if not (1 <= total <= 20 and 1 <= threshold <= total):
        print("  The member count is limited to 1-20, and the threshold must be between 1 and %d." % total)
        return 0
    members = random_members(total)
    print()
    print(render_members(members))
    print("  Tip: for a real multi-party multisig, let every participant keep their own private key,")
    print("      exchange only the public keys above, and then use menu 2 to assemble the address.")
    return show_schemes(members, threshold)


def menu_inspect():
    print()
    text = input("  Enter an address (Enter to go back): ").strip()
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
    return 0


MENU_ACTIONS = {
    "1": menu_quick, "2": menu_build, "3": menu_inspect, "4": menu_selftest,
}


def show_banner():
    print()
    print(block("Bitcoin multisig address tool V2 - mainnet only", [
        "  bc1q   m-of-n multisig: any m signatures can spend",
        "  bc1p   everyone signs: not one of the N may be missing",
        "  The two mechanisms differ; do not mix them.",
    ]))


def show_menu():
    print()
    column = max(display_width(title) for _key, title, _hint in MENU_ITEMS)
    for key, title, hint in MENU_ITEMS:
        print(("  %s  %s" % (key, pad_display(title, column) + "   " + hint)).rstrip())


def run_interactive():
    enable_utf8_console()
    show_banner()
    while True:
        show_menu()
        try:
            choice = input("  Choose (Enter quits): ").strip() or "0"
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if choice == "0":
            return 0
        action = MENU_ACTIONS.get(choice)
        if action is None:
            print("  There is no such option.")
            continue
        try:
            action()
        except (ValueError, OSError) as error:
            print()
            print("\n".join(paragraph("Something went wrong: " + str(error))))
        except (EOFError, KeyboardInterrupt):
            print()
            print("  Cancelled.")
            return 0


def add_common_arguments(parser):
    parser.add_argument("-f", "--format", default="block", choices=["block", "json"],
                        help="output format, block by default")
    parser.add_argument("-o", "--out", default="-", help="output file, - means print to the screen")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="show the backend, the per-item results and other details")


def build_parser():
    parser = argparse.ArgumentParser(
        prog="bitcoin_multisig_v2",
        description="Bitcoin multisig address generation and verification (mainnet): m-of-n with bc1q, everyone signing with bc1p")
    subparsers = parser.add_subparsers(dest="command")

    build = subparsers.add_parser("build", help="build a multisig scheme from a member list")
    build.add_argument("members", nargs="?", default="-", help="member list file, - means read standard input")
    build.add_argument("-t", "--type", default="p2wsh", choices=["p2wsh", "p2tr", "both"],
                       help="scheme type, p2wsh by default (m-of-n with bc1q)")
    build.add_argument("-m", "--threshold", type=int, default=None, help="how many signatures are needed (bc1q)")
    build.add_argument("--order", default="bip67", choices=["bip67", "fingerprint"],
                       help="public key ordering, bip67 by default")
    build.add_argument("--layout", default="chain", choices=["chain", "tree"],
                       help="Taproot structure, chain by default (the one that really enforces everyone signing)")
    build.add_argument("-d", "--detail", action="store_true", help="show the full information: scripts, control blocks and so on")
    build.add_argument("--verify", action="store_true", help="also run an end-to-end verification")
    add_common_arguments(build)

    keys = subparsers.add_parser("keys", help="randomly generate member keys")
    keys.add_argument("-c", "--count", type=int, default=10, help="how many to generate, 10 by default")
    add_common_arguments(keys)

    inspect = subparsers.add_parser("inspect", help="parse an address")
    inspect.add_argument("address", help="the address to parse")
    add_common_arguments(inspect)

    selftest = subparsers.add_parser("selftest", help="the built-in self-test")
    selftest.add_argument("-o", "--out", default="-", help="output file, - means print to the screen")
    selftest.add_argument("-v", "--verbose", action="store_true", help="show the results item by item")
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
