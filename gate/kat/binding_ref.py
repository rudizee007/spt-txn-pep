#!/usr/bin/env python3
"""
Independent reference implementation of the SPT-Txn x402 intent binding
(docs/SPEC-X402.md §4), used as the differential / known-answer oracle for the
Go gate. This file is intentionally a *separate* implementation: if the Go
canonicalizer and this Python one ever disagree on a byte, the KAT test fails —
which is exactly the canonicalization-mismatch bug class the threat model ranks
risk #1.

No third-party dependencies. base58 decode is plain radix conversion (an address
encoding, not cryptography).
"""
import hashlib

DOMAIN = b"spt-txn/x402-payment/v1"
VERSION = 1

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def decode_base58(s: str) -> bytes:
    n = 0
    for ch in s:
        i = _B58.find(ch)
        if i < 0:
            raise ValueError("invalid base58 char: %r" % ch)
        n = n * 58 + i
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    zeros = 0
    for ch in s:
        if ch == "1":
            zeros += 1
        else:
            break
    return b"\x00" * zeros + body


def decode_pubkey32(s: str) -> bytes:
    raw = decode_base58(s)
    if len(raw) != 32:
        raise ValueError("pubkey is not 32 bytes: got %d" % len(raw))
    return raw


def amount16le(a: int) -> bytes:
    if a < 0:
        raise ValueError("amount negative")
    if a >= (1 << 128):
        raise ValueError("amount exceeds u128")
    return a.to_bytes(16, "little")


def compute_binding_raw(scheme_tag: int, network_tag: int, asset32: bytes,
                        payto32: bytes, amount: int, resource: str,
                        nonce32: bytes) -> bytes:
    assert len(asset32) == 32 and len(payto32) == 32 and len(nonce32) == 32
    resource_hash = hashlib.sha256(resource.encode("utf-8")).digest()
    h = hashlib.sha256()
    h.update(DOMAIN)
    h.update(b"\x00")
    h.update(bytes([VERSION]))
    h.update(bytes([scheme_tag]))
    h.update(bytes([network_tag]))
    h.update(asset32)
    h.update(payto32)
    h.update(amount16le(amount))
    h.update(resource_hash)
    h.update(nonce32)
    return h.digest()


# ── Canonical KAT inputs (frozen; mirrored in binding_test.go) ──────────────
KAT_SCHEME_TAG = 1
KAT_NETWORK_TAG = 2
KAT_ASSET = bytes([0x11]) * 32
KAT_PAYTO = bytes([0x22]) * 32
KAT_AMOUNT = 1_000_000               # 1.000000 USDC (6 decimals)
KAT_RESOURCE = "https://api.example.com/resource"
KAT_NONCE = bytes([0x5A]) * 32

# A real mainnet USDC mint, to freeze the base58 → 32-byte decode vector.
USDC_MINT_B58 = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"


if __name__ == "__main__":
    b = compute_binding_raw(KAT_SCHEME_TAG, KAT_NETWORK_TAG, KAT_ASSET,
                            KAT_PAYTO, KAT_AMOUNT, KAT_RESOURCE, KAT_NONCE)
    print("KAT_BINDING          ", b.hex())

    # Field-flip vectors: every bound field must change the binding.
    flips = {
        "scheme_tag": (2, KAT_NETWORK_TAG, KAT_ASSET, KAT_PAYTO, KAT_AMOUNT, KAT_RESOURCE, KAT_NONCE),
        "network_tag": (KAT_SCHEME_TAG, 3, KAT_ASSET, KAT_PAYTO, KAT_AMOUNT, KAT_RESOURCE, KAT_NONCE),
        "asset": (KAT_SCHEME_TAG, KAT_NETWORK_TAG, bytes([0x12]) * 32, KAT_PAYTO, KAT_AMOUNT, KAT_RESOURCE, KAT_NONCE),
        "pay_to": (KAT_SCHEME_TAG, KAT_NETWORK_TAG, KAT_ASSET, bytes([0x23]) * 32, KAT_AMOUNT, KAT_RESOURCE, KAT_NONCE),
        "amount": (KAT_SCHEME_TAG, KAT_NETWORK_TAG, KAT_ASSET, KAT_PAYTO, KAT_AMOUNT + 1, KAT_RESOURCE, KAT_NONCE),
        "resource": (KAT_SCHEME_TAG, KAT_NETWORK_TAG, KAT_ASSET, KAT_PAYTO, KAT_AMOUNT, KAT_RESOURCE + "/", KAT_NONCE),
        "nonce": (KAT_SCHEME_TAG, KAT_NETWORK_TAG, KAT_ASSET, KAT_PAYTO, KAT_AMOUNT, KAT_RESOURCE, bytes([0x5B]) * 32),
    }
    for name, args in flips.items():
        fb = compute_binding_raw(*args)
        assert fb != b, "flip %s did not change binding" % name
        print("FLIP_%-12s %s" % (name, fb.hex()))

    # base58 decode vector.
    print("USDC_MINT_BYTES      ", decode_pubkey32(USDC_MINT_B58).hex())

    # u128 max amount must encode, one past must raise.
    print("AMOUNT_U128_MAX_LE   ", amount16le((1 << 128) - 1).hex())
    try:
        amount16le(1 << 128)
        print("OVERFLOW_CHECK        FAIL (did not raise)")
    except ValueError:
        print("OVERFLOW_CHECK        ok (raised)")
