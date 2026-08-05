package translog

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

func b32(x byte) [32]byte {
	var a [32]byte
	for i := range a {
		a[i] = x
	}
	return a
}

// Differential KAT: record hashes must match the independent Python reference
// (translog/kat/logentry_ref.py).
func TestRecordCanonicalKAT(t *testing.T) {
	var zero [32]byte
	r0 := Record{Seq: 0, Decision: Allow, Binding: b32(0x11), IssuedAt: 1_700_000_000, PrevHash: zero}
	h0 := r0.Hash()
	if got := hex.EncodeToString(h0[:]); got != "0d898cc95373cf1c509cbb86d4af6451e0743a893311a6115f3c96286cbfd125" {
		t.Fatalf("H0 = %s", got)
	}
	r1 := Record{Seq: 1, Decision: DenyViolation, Binding: b32(0x22), IssuedAt: 1_700_000_060, PrevHash: h0}
	h1 := r1.Hash()
	if got := hex.EncodeToString(h1[:]); got != "27f032a4eca58f2b613389c219d162489c3dcf1754cb69592f199fd99936301b" {
		t.Fatalf("H1 = %s", got)
	}
	r2 := Record{Seq: 2, Decision: DenyUnavailable, Binding: b32(0x33), IssuedAt: 1_700_000_120, PrevHash: h1}
	h2 := r2.Hash()
	if got := hex.EncodeToString(h2[:]); got != "69b50bbcf6d2351bede9a6728cec549148c2c5a35513d651981c4e34a7d91bd4" {
		t.Fatalf("H2 = %s", got)
	}
}

func TestReceiptSignVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	r := Record{Seq: 7, Decision: Allow, Binding: b32(0xAB), IssuedAt: 1_700_000_000}
	sig := Sign(priv, r)
	if !Verify(pub, r, sig) {
		t.Fatal("valid signature must verify")
	}
	// Any tampered field must invalidate the signature.
	bad := r
	bad.Binding = b32(0xAC)
	if Verify(pub, bad, sig) {
		t.Fatal("tampered record must not verify")
	}
	// A different key must not verify.
	pub2, _, _ := ed25519.GenerateKey(nil)
	if Verify(pub2, r, sig) {
		t.Fatal("wrong key must not verify")
	}
}
