// Package gate implements the SPT-Txn x402 payment gate: it decides ALLOW/DENY
// for an x402 payment BEFORE any transaction is signed.
//
// This file is the trust-boundary canonicalizer (docs/SPEC-X402.md §4). It turns
// an x402 PaymentRequirements + the token's single-use nonce into the 32-byte
// intent binding. A mismatch between how the issuer and the gate canonicalize is
// a full authorization bypass (threat model risk #1), so the layout is
// fixed-width, domain-separated, and never derived from raw JSON. The byte layout
// here is authoritative and MUST match the issuer and the Python KAT reference
// (gate/kat/binding_ref.py) byte-for-byte.
package gate

import (
	"crypto/sha256"
	"errors"
	"math/big"
)

const (
	// DomainTagX402 domain-separates this binding from every other SPT-Txn
	// construction. Never reuse a tag across constructions.
	DomainTagX402 = "spt-txn/x402-payment/v1"
	// LayoutVersion is hashed into the binding and bumped on any change to the
	// byte layout below, so an old token can never be replayed against a new
	// layout.
	LayoutVersion = 1
)

var (
	ErrUnknownScheme  = errors.New("gate: scheme not in allowlist")
	ErrUnknownNetwork = errors.New("gate: network not in allowlist")
	ErrAmountNegative = errors.New("gate: amount is negative")
	ErrAmountOverflow = errors.New("gate: amount exceeds u128")
	ErrBadAmount      = errors.New("gate: amount is not a base-10 integer")
	ErrBadPubkey      = errors.New("gate: pubkey is not 32 bytes")
)

// Allowlist maps the (scheme, network) strings a deployment accepts to their
// stable u8 tags. It is supplied by configuration, not hardcoded: an operator
// lists exactly the schemes and networks they support, and anything else is a
// hard DENY (SPEC-X402 §4). Tags, once assigned, are permanent (they are hashed
// into every binding).
type Allowlist struct {
	Schemes  map[string]byte
	Networks map[string]byte
}

// PaymentRequirements is the subset of the x402 402-response object the gate
// binds. Fields not listed here (extra.feePayer, maxTimeoutSeconds, description,
// mimeType) are deliberately unbound (SPEC-X402 §4). feePayer in particular is
// the facilitator's late-bound gas sponsor and is pinned instead by the
// settle-side pre-send assertion (§6.4), never by this binding.
type PaymentRequirements struct {
	Scheme            string // e.g. "exact"
	Network           string // CAIP-2, e.g. "solana:..."
	Asset             string // SPL mint, base58
	PayTo             string // recipient, base58
	MaxAmountRequired string // atomic units, base-10 string
	Resource          string // resource URL, bound byte-exact
}

// ComputeBinding resolves and normalizes a PaymentRequirements against the
// allowlist and returns the 32-byte intent binding for the given single-use
// nonce (the token jti). Any unknown scheme/network, malformed pubkey, or
// out-of-range amount is an error — the caller DENYs (fail closed).
func ComputeBinding(al Allowlist, pr PaymentRequirements, nonce [32]byte) ([32]byte, error) {
	var zero [32]byte
	schemeTag, ok := al.Schemes[pr.Scheme]
	if !ok {
		return zero, ErrUnknownScheme
	}
	networkTag, ok := al.Networks[pr.Network]
	if !ok {
		return zero, ErrUnknownNetwork
	}
	asset, err := decodePubkey32(pr.Asset)
	if err != nil {
		return zero, err
	}
	payTo, err := decodePubkey32(pr.PayTo)
	if err != nil {
		return zero, err
	}
	amount, ok := new(big.Int).SetString(pr.MaxAmountRequired, 10)
	if !ok {
		return zero, ErrBadAmount
	}
	return computeBindingRaw(schemeTag, networkTag, asset, payTo, amount, pr.Resource, nonce)
}

// computeBindingRaw is the fixed-width hash core. It takes already-decoded
// fields so a known-answer vector can exercise it directly, independent of
// base58 and allowlist parsing (SPEC-X402 §7). Field order and widths are
// authoritative.
func computeBindingRaw(schemeTag, networkTag byte, asset, payTo [32]byte, amount *big.Int, resource string, nonce [32]byte) ([32]byte, error) {
	var zero [32]byte
	amt, err := amount16LE(amount)
	if err != nil {
		return zero, err
	}
	resourceHash := sha256.Sum256([]byte(resource))

	h := sha256.New()
	h.Write([]byte(DomainTagX402))
	h.Write([]byte{0x00})
	h.Write([]byte{LayoutVersion})
	h.Write([]byte{schemeTag})
	h.Write([]byte{networkTag})
	h.Write(asset[:])
	h.Write(payTo[:])
	h.Write(amt[:])
	h.Write(resourceHash[:])
	h.Write(nonce[:])

	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

// amount16LE encodes a non-negative big.Int as 16 bytes little-endian (u128).
// Negative values or values exceeding 2^128-1 are rejected — the binding must
// never silently truncate an amount.
func amount16LE(a *big.Int) ([16]byte, error) {
	var out [16]byte
	if a.Sign() < 0 {
		return out, ErrAmountNegative
	}
	if a.BitLen() > 128 {
		return out, ErrAmountOverflow
	}
	be := a.Bytes() // big-endian, minimal length (empty for zero)
	for i := 0; i < len(be); i++ {
		out[i] = be[len(be)-1-i] // reverse into little-endian
	}
	return out, nil
}
