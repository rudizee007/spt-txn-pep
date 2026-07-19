// Package receipt implements SPT-Txn compliance receipts: a signed, canonical
// record emitted at each authorization decision, chained into an append-only log
// whose RFC 6962 Merkle root can be anchored on-chain. Evidence is a byproduct of
// enforcement, not something produced by a later audit.
//
// Only standard, audited primitives are used: crypto/ed25519 for signing and
// crypto/sha256 for hashing. No custom cryptography.
package receipt

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
)

const (
	// DomainTagReceipt domain-separates receipt bytes from every other SPT-Txn
	// construction.
	DomainTagReceipt = "spt-txn/receipt/v1"
	// LayoutVersion is hashed/signed into every receipt and bumped on any layout
	// change.
	LayoutVersion = 1
)

// Decision mirrors the gate's outcome as a stable wire value. It is its own type
// so this package does not import the gate.
type Decision uint8

const (
	Allow           Decision = 0
	DenyViolation   Decision = 1
	DenyUnavailable Decision = 2
)

// Receipt is one signed authorization decision. PrevHash chains it to the prior
// receipt (append-only tamper-evidence); Binding ties it to the exact payment
// considered (SPEC-X402 §4).
type Receipt struct {
	Seq      uint64
	Decision Decision
	Binding  [32]byte
	IssuedAt int64 // unix seconds
	PrevHash [32]byte
}

// CanonicalBytes is the fixed-width, domain-separated encoding that is hashed and
// signed. The layout is authoritative and matches receipt/kat/receipt_ref.py
// byte-for-byte.
func (r Receipt) CanonicalBytes() []byte {
	out := make([]byte, 0, len(DomainTagReceipt)+1+1+8+1+32+8+32)
	out = append(out, []byte(DomainTagReceipt)...)
	out = append(out, 0x00)
	out = append(out, LayoutVersion)
	var u8 [8]byte
	binary.LittleEndian.PutUint64(u8[:], r.Seq)
	out = append(out, u8[:]...)
	out = append(out, byte(r.Decision))
	out = append(out, r.Binding[:]...)
	binary.LittleEndian.PutUint64(u8[:], uint64(r.IssuedAt)) // two's-complement LE
	out = append(out, u8[:]...)
	out = append(out, r.PrevHash[:]...)
	return out
}

// Hash is SHA-256 of the canonical bytes — the hash-chain link used as the next
// receipt's PrevHash.
func (r Receipt) Hash() [32]byte {
	return sha256.Sum256(r.CanonicalBytes())
}

// Sign returns an Ed25519 signature over the canonical bytes. The receipt-signing
// key MUST be distinct from the token issuance key (separate rotation, separate
// blast radius) — a non-negotiable invariant.
func Sign(priv ed25519.PrivateKey, r Receipt) []byte {
	return ed25519.Sign(priv, r.CanonicalBytes())
}

// Verify checks the signature over the canonical bytes.
func Verify(pub ed25519.PublicKey, r Receipt, sig []byte) bool {
	return ed25519.Verify(pub, r.CanonicalBytes(), sig)
}
