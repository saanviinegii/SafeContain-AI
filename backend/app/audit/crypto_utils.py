"""SafeContain AI Pure-Python Cryptographic & EVM Web3 Utilities.

Provides zero-dependency EVM utilities compliant with Ethereum standards:
- Keccak-256 hash function (Ethereum sponge permutation)
- secp256k1 elliptic curve key derivation & EIP-155 transaction signing
- Recursive Length Prefix (RLP) serialization (Ethereum yellow paper)
- Contract ABI encoding & decoding for evidence anchoring view/write calls
"""

import hmac
import hashlib
import re
from typing import Any, Dict, List, Optional, Tuple, Union

# =============================================================================
# 1. KECCAK-256 HASH FUNCTION (Ethereum specification)
# =============================================================================

_KECCAK_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
]

_KECCAK_RHO = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14]
]


def keccak_256(data: bytes) -> bytes:
    """Computes standard Ethereum Keccak-256 hash (1088-bit rate, 0x01 pad)."""
    rate = 136  # 1088 bits / 8
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate != (rate - 1):
        padded.append(0x00)
    padded.append(0x80)

    state = [[0] * 5 for _ in range(5)]

    for block_idx in range(0, len(padded), rate):
        block = padded[block_idx:block_idx + rate]
        for i in range(rate // 8):
            state[i % 5][i // 5] ^= int.from_bytes(block[i * 8:(i + 1) * 8], "little")

        for round_idx in range(24):
            # Theta step
            C = [state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4] for x in range(5)]
            D = [C[(x - 1) % 5] ^ (((C[(x + 1) % 5] << 1) & 0xFFFFFFFFFFFFFFFF) | (C[(x + 1) % 5] >> 63)) for x in range(5)]
            for x in range(5):
                for y in range(5):
                    state[x][y] ^= D[x]

            # Rho and Pi steps
            B = [[0] * 5 for _ in range(5)]
            for x in range(5):
                for y in range(5):
                    rot = _KECCAK_RHO[x][y]
                    val = state[x][y]
                    B[y][(2 * x + 3 * y) % 5] = ((val << rot) & 0xFFFFFFFFFFFFFFFF) | (val >> (64 - rot)) if rot else val

            # Chi step
            for x in range(5):
                for y in range(5):
                    state[x][y] = B[x][y] ^ ((~B[(x + 1) % 5][y] & 0xFFFFFFFFFFFFFFFF) & B[(x + 2) % 5][y])

            # Iota step
            state[0][0] ^= _KECCAK_RC[round_idx]

    out = bytearray(32)
    for i in range(4):
        out[i * 8:(i + 1) * 8] = state[i % 5][i // 5].to_bytes(8, "little")
    return bytes(out)


# =============================================================================
# 2. SECP256K1 ELLIPTIC CURVE ARITHMETIC & ADDRESS DERIVATION
# =============================================================================

_SECP_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_SECP_A = 0
_SECP_B = 7
_SECP_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_SECP_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
_SECP_G = (_SECP_GX, _SECP_GY)
_SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def _mod_inv(k: int, p: int) -> int:
    return pow(k, p - 2, p)


def _point_add(p1: Optional[Tuple[int, int]], p2: Optional[Tuple[int, int]]) -> Optional[Tuple[int, int]]:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and y1 != y2:
        return None
    if x1 == x2:
        m = (3 * x1 * x1 + _SECP_A) * _mod_inv(2 * y1, _SECP_P) % _SECP_P
    else:
        m = (y2 - y1) * _mod_inv(x2 - x1, _SECP_P) % _SECP_P
    x3 = (m * m - x1 - x2) % _SECP_P
    y3 = (m * (x1 - x3) - y1) % _SECP_P
    return (x3, y3)


def _scalar_mult(k: int, point: Tuple[int, int] = _SECP_G) -> Tuple[int, int]:
    result = None
    addend = point
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    if result is None:
        raise ValueError("Scalar multiplication resulted in point at infinity")
    return result


def private_key_to_address(private_key_hex: str) -> str:
    """Derives standard checksummed/hex Ethereum address from 32-byte private key."""
    clean_hex = private_key_hex.strip().lower()
    if clean_hex.startswith("0x"):
        clean_hex = clean_hex[2:]
    if len(clean_hex) != 64:
        raise ValueError("Invalid private key: must be 32 bytes (64 hex characters)")

    priv_int = int(clean_hex, 16)
    if not (1 <= priv_int < _SECP_N):
        raise ValueError("Private key out of valid secp256k1 range")

    pub = _scalar_mult(priv_int, _SECP_G)
    pub_bytes = pub[0].to_bytes(32, "big") + pub[1].to_bytes(32, "big")
    addr_bytes = keccak_256(pub_bytes)[12:]
    return to_checksum_address("0x" + addr_bytes.hex())


def to_checksum_address(address_hex: str) -> str:
    """Implements EIP-55 mixed-case checksum encoding for Ethereum addresses."""
    clean = address_hex.lower().replace("0x", "")
    if len(clean) != 40:
        return address_hex
    h = keccak_256(clean.encode("utf-8")).hex()
    checksummed = "".join(
        c.upper() if int(h[i], 16) >= 8 else c.lower()
        for i, c in enumerate(clean)
    )
    return "0x" + checksummed


# =============================================================================
# 3. RECURSIVE LENGTH PREFIX (RLP) ENCODING
# =============================================================================

def rlp_encode(input_data: Any) -> bytes:
    """Encodes arbitrary Python structures (bytes, int, str, list) into canonical RLP."""
    if isinstance(input_data, bytes):
        if len(input_data) == 1 and input_data[0] < 0x80:
            return input_data
        elif len(input_data) < 56:
            return bytes([0x80 + len(input_data)]) + input_data
        else:
            length = len(input_data)
            len_bytes = length.to_bytes((length.bit_length() + 7) // 8, "big")
            return bytes([0xB7 + len(len_bytes)]) + len_bytes + input_data
    elif isinstance(input_data, int):
        if input_data == 0:
            return bytes([0x80])
        int_bytes = input_data.to_bytes((input_data.bit_length() + 7) // 8, "big")
        return rlp_encode(int_bytes)
    elif isinstance(input_data, str):
        if input_data.startswith("0x") and len(input_data) % 2 == 0:
            try:
                return rlp_encode(bytes.fromhex(input_data[2:]))
            except ValueError:
                pass
        return rlp_encode(input_data.encode("utf-8"))
    elif isinstance(input_data, (list, tuple)):
        encoded_items = b"".join(rlp_encode(item) for item in input_data)
        if len(encoded_items) < 56:
            return bytes([0xC0 + len(encoded_items)]) + encoded_items
        else:
            length = len(encoded_items)
            len_bytes = length.to_bytes((length.bit_length() + 7) // 8, "big")
            return bytes([0xF7 + len(len_bytes)]) + len_bytes + encoded_items
    raise TypeError(f"Unsupported type for RLP encoding: {type(input_data)}")


# =============================================================================
# 4. EIP-155 TRANSACTION SIGNING (Deterministic RFC 6979 Nonce)
# =============================================================================

def _rfc6979_nonce(msg_hash: bytes, priv_key_int: int) -> int:
    """Generates deterministic k-nonce per RFC 6979."""
    x = priv_key_int.to_bytes(32, "big")
    h1 = msg_hash
    V = b"\x01" * 32
    K = b"\x00" * 32
    K = hmac.new(K, V + b"\x00" + x + h1, hashlib.sha256).digest()
    V = hmac.new(K, V, hashlib.sha256).digest()
    K = hmac.new(K, V + b"\x01" + x + h1, hashlib.sha256).digest()
    V = hmac.new(K, V, hashlib.sha256).digest()
    while True:
        V = hmac.new(K, V, hashlib.sha256).digest()
        k = int.from_bytes(V, "big")
        if 1 <= k < _SECP_N:
            return k
        K = hmac.new(K, V + b"\x00", hashlib.sha256).digest()
        V = hmac.new(K, V, hashlib.sha256).digest()


def sign_transaction(
    nonce: int,
    gas_price: int,
    gas_limit: int,
    to: str,
    value: int,
    data: bytes,
    chain_id: int,
    private_key_hex: str,
) -> Tuple[str, str]:
    """Signs an Ethereum legacy / EIP-155 transaction and returns (raw_tx_hex, tx_hash_hex)."""
    clean_hex = private_key_hex.strip().lower()
    if clean_hex.startswith("0x"):
        clean_hex = clean_hex[2:]
    priv_int = int(clean_hex, 16)

    to_bytes = bytes.fromhex(to.lower().replace("0x", "")) if to else b""

    # EIP-155 pre-sign payload: [nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0]
    raw_for_signing = [nonce, gas_price, gas_limit, to_bytes, value, data, chain_id, 0, 0]
    msg_hash = keccak_256(rlp_encode(raw_for_signing))
    z = int.from_bytes(msg_hash, "big")

    k = _rfc6979_nonce(msg_hash, priv_int)
    R = _scalar_mult(k, _SECP_G)
    r = R[0] % _SECP_N
    if r == 0:
        raise ValueError("Signature r=0 generated, retry with different nonce")

    s = (_mod_inv(k, _SECP_N) * (z + r * priv_int)) % _SECP_N
    if s == 0:
        raise ValueError("Signature s=0 generated, retry with different nonce")

    recovery_id = (R[1] & 1)
    # Enforce low-s (BIP 62 / EIP-2)
    if s > (_SECP_N // 2):
        s = _SECP_N - s
        recovery_id ^= 1

    # EIP-155 v calculation: v = chain_id * 2 + 35 + recovery_id
    v = chain_id * 2 + 35 + recovery_id

    # Canonical signed raw transaction: [nonce, gasPrice, gasLimit, to, value, data, v, r, s]
    signed_payload = [nonce, gas_price, gas_limit, to_bytes, value, data, v, r, s]
    raw_tx = rlp_encode(signed_payload)
    tx_hash = "0x" + keccak_256(raw_tx).hex()
    return "0x" + raw_tx.hex(), tx_hash


# =============================================================================
# 5. SOLIDITY ABI ENCODER / DECODER
# =============================================================================

def encode_abi_call(func_signature: str, args: List[Any], types: List[str]) -> str:
    """Encodes a function call into standard EVM ABI hex string."""
    selector = keccak_256(func_signature.encode("utf-8"))[:4]
    parts: List[bytes] = []

    for arg, t in zip(args, types):
        if t == "bytes32":
            if isinstance(arg, str):
                clean = arg.replace("0x", "")
                raw = bytes.fromhex(clean)
            elif isinstance(arg, bytes):
                raw = arg
            else:
                raw = str(arg).encode("utf-8")
            if len(raw) < 32:
                raw = raw.ljust(32, b"\x00")
            elif len(raw) > 32:
                raw = raw[:32]
            parts.append(raw)
        elif t == "uint256" or t.startswith("uint"):
            val = int(arg)
            parts.append(val.to_bytes(32, "big"))
        elif t == "address":
            clean = arg.lower().replace("0x", "")
            raw = bytes.fromhex(clean).rjust(32, b"\x00")
            parts.append(raw)
        elif t == "string":
            # Dynamic string: for simplicity, if needed in legacy calls
            raw_s = arg.encode("utf-8")
            parts.append(raw_s.ljust(((len(raw_s) + 31) // 32) * 32, b"\x00"))
        else:
            raise ValueError(f"Unsupported ABI type: {t}")

    return "0x" + selector.hex() + "".join(p.hex() for p in parts)


def decode_abi_output(hex_data: str, types: List[str]) -> List[Any]:
    """Decodes standard EVM ABI output hex words."""
    clean = hex_data.replace("0x", "")
    words: List[str] = [clean[i:i + 64] for i in range(0, len(clean), 64)]
    results: List[Any] = []

    for i, t in enumerate(types):
        if i >= len(words):
            results.append(None)
            continue
        word = words[i]
        if t == "bytes32":
            results.append("0x" + word)
        elif t == "uint256" or t.startswith("uint"):
            results.append(int(word, 16))
        elif t == "bool":
            results.append(int(word, 16) != 0)
        elif t == "address":
            results.append(to_checksum_address("0x" + word[24:]))
        else:
            results.append("0x" + word)

    return results
