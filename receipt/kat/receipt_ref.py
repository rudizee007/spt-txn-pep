#!/usr/bin/env python3
"""
Independent reference for the SPT-Txn receipt canonicalization + the RFC 6962
Merkle tree over receipts. Used as the differential / known-answer oracle for the
Go implementation. No third-party deps.

RFC 6962 (Certificate Transparency) leaf/node domain separation is used so a
node hash can never be reinterpreted as a leaf (second-preimage safety), and the
"largest power of two" split avoids the duplicate-leaf ambiguity (CVE-2012-2459).
"""
import hashlib

DOMAIN = b"spt-txn/receipt/v1"
VERSION = 1


def sha(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def canonical(seq: int, decision: int, binding: bytes, issued_at: int, prev: bytes) -> bytes:
    assert len(binding) == 32 and len(prev) == 32
    out = bytearray()
    out += DOMAIN
    out += b"\x00"
    out += bytes([VERSION])
    out += seq.to_bytes(8, "little")
    out += bytes([decision])
    out += binding
    out += issued_at.to_bytes(8, "little", signed=True)
    out += prev
    return bytes(out)


def receipt_hash(c: bytes) -> bytes:
    return sha(c)  # hash-chain link (prev_hash of the next receipt)


# RFC 6962 leaf and node hashing.
def leaf_hash(d: bytes) -> bytes:
    return sha(b"\x00" + d)


def node_hash(l: bytes, r: bytes) -> bytes:
    return sha(b"\x01" + l + r)


def largest_pow2_below(n: int) -> int:
    k = 1
    while k < n:
        k *= 2
    return k // 2


def mth(ds):
    n = len(ds)
    if n == 0:
        return sha(b"")
    if n == 1:
        return leaf_hash(ds[0])
    k = largest_pow2_below(n)
    return node_hash(mth(ds[:k]), mth(ds[k:]))


def path(m, ds):
    n = len(ds)
    if n == 1:
        return []
    k = largest_pow2_below(n)
    if m < k:
        return path(m, ds[:k]) + [mth(ds[k:])]
    return path(m - k, ds[k:]) + [mth(ds[:k])]


def root_from_path(m, n, leafh, pth):
    if n == 1:
        return leafh
    k = largest_pow2_below(n)
    if m < k:
        return node_hash(root_from_path(m, k, leafh, pth[:-1]), pth[-1])
    return node_hash(pth[-1], root_from_path(m - k, n - k, leafh, pth[:-1]))


if __name__ == "__main__":
    b0 = bytes([0x11]) * 32
    b1 = bytes([0x22]) * 32
    b2 = bytes([0x33]) * 32
    zero = bytes(32)

    c0 = canonical(0, 0, b0, 1_700_000_000, zero)
    h0 = receipt_hash(c0)
    c1 = canonical(1, 1, b1, 1_700_000_060, h0)
    h1 = receipt_hash(c1)
    c2 = canonical(2, 2, b2, 1_700_000_120, h1)
    h2 = receipt_hash(c2)

    ds = [c0, c1, c2]
    root = mth(ds)
    p1 = path(1, ds)
    verified = root_from_path(1, len(ds), leaf_hash(c1), p1) == root

    print("RECEIPT_H0", h0.hex())
    print("RECEIPT_H1", h1.hex())
    print("RECEIPT_H2", h2.hex())
    print("MERKLE_ROOT", root.hex())
    print("PROOF_IDX1", [x.hex() for x in p1])
    print("PROOF_VERIFIES", verified)

    # Tamper check: flipping one receipt changes the root.
    c1b = canonical(1, 1, bytes([0x23]) * 32, 1_700_000_060, h0)
    print("ROOT_AFTER_TAMPER_DIFFERS", mth([c0, c1b, c2]) != root)
