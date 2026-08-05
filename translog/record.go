// Package translog implements the SPT-Txn TRANSPARENCY LOG: a signed,
// hash-chained, fixed-width record per authorization decision, appended to an
// append-only log whose RFC 6962 Merkle root can be anchored on-chain.
//
// # This is NOT the Transaction Receipt
//
// draft-coetzee-oauth-spt-txn-tokens-03 §Receipts defines a Transaction Receipt
// as a JSON object — PEP identity, PERMIT/DENY, class, rule path, token hash,
// policy hash, intent digest, jurisdiction, timestamp, nonce — signed over
// "spt-txn-receipt-v1" || 0x00 || JCS(receipt-without-sig).
//
// A translog Record is a different artifact answering a different question:
//
//	Transaction Receipt  what authority governed this decision, under which
//	                     policy and jurisdiction  (evidence)
//	translog.Record      where this decision sits in a tamper-evident,
//	                     inclusion-provable chain  (ordering + integrity)
//
// They compose; neither substitutes for the other. This package was previously
// named `receipt`, which was wrong twice over: it is not the spec's receipt, and
// its domain tag ("spt-txn/receipt/v1") differed from the spec's
// ("spt-txn-receipt-v1") only by punctuation — two tags asserting "receipt v1"
// over incompatible structures, which is precisely what domain separation exists
// to prevent. Renamed 2026-07-29; the tag is now "spt-txn/logentry/v1" and
// LayoutVersion is bumped to 2 so pre-rename records are distinguishable rather
// than merely incompatible.
//
// Only standard, audited primitives are used: crypto/ed25519 for signing and
// crypto/sha256 for hashing. No custom cryptography.
package translog

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
)

const (
	// DomainTagLogEntry domain-separates receipt bytes from every other SPT-Txn
	// construction.
	DomainTagLogEntry = "spt-txn/logentry/v1"
	// LayoutVersion is hashed/signed into every receipt and bumped on any layout
	// change.
	LayoutVersion = 2
)

// Decision mirrors the gate's outcome as a stable wire value. It is its own type
// so this package does not import the gate.
type Decision uint8

const (
	Allow           Decision = 0
	DenyViolation   Decision = 1
	DenyUnavailable Decision = 2
)

// Record is one signed authorization decision. PrevHash chains it to the prior
// receipt (append-only tamper-evidence); Binding ties it to the exact payment
// considered (SPEC-X402 §4).
type Record struct {
	Seq      uint64
	Decision Decision
	Binding  [32]byte
	IssuedAt int64 // unix seconds
	PrevHash [32]byte
}

// CanonicalBytes is the fixed-width, domain-separated encoding that is hashed and
// signed. The layout is authoritative and matches receipt/kat/receipt_ref.py
// byte-for-byte.
func (r Record) CanonicalBytes() []byte {
	out := make([]byte, 0, len(DomainTagLogEntry)+1+1+8+1+32+8+32)
	out = append(out, []byte(DomainTagLogEntry)...)
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
func (r Record) Hash() [32]byte {
	return sha256.Sum256(r.CanonicalBytes())
}

// Sign returns an Ed25519 signature over the canonical bytes. The receipt-signing
// key MUST be distinct from the token issuance key (separate rotation, separate
// blast radius) — a non-negotiable invariant.
func Sign(priv ed25519.PrivateKey, r Record) []byte {
	return ed25519.Sign(priv, r.CanonicalBytes())
}

// Verify checks the signature over the canonical bytes.
func Verify(pub ed25519.PublicKey, r Record, sig []byte) bool {
	return ed25519.Verify(pub, r.CanonicalBytes(), sig)
}
