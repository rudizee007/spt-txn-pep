package receipt

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

// Differential KAT: receipt hashes must match the independent Python reference
// (receipt/kat/receipt_ref.py).
func TestReceiptCanonicalKAT(t *testing.T) {
	var zero [32]byte
	r0 := Receipt{Seq: 0, Decision: Allow, Binding: b32(0x11), IssuedAt: 1_700_000_000, PrevHash: zero}
	h0 := r0.Hash()
	if got := hex.EncodeToString(h0[:]); got != "8cf7a89878a64a02f306d4d8c20ef990cadb7c6118b9402cf2cdb4b91e14b1c0" {
		t.Fatalf("H0 = %s", got)
	}
	r1 := Receipt{Seq: 1, Decision: DenyViolation, Binding: b32(0x22), IssuedAt: 1_700_000_060, PrevHash: h0}
	h1 := r1.Hash()
	if got := hex.EncodeToString(h1[:]); got != "bf14cad3231542085277dce0b265d441ccfe3a7c6e7d74896f09c182cac360fd" {
		t.Fatalf("H1 = %s", got)
	}
	r2 := Receipt{Seq: 2, Decision: DenyUnavailable, Binding: b32(0x33), IssuedAt: 1_700_000_120, PrevHash: h1}
	h2 := r2.Hash()
	if got := hex.EncodeToString(h2[:]); got != "21ae9d8b9346be2d2a4c3f61e03692dfa1330cc1b51c90d3271497e8de00f183" {
		t.Fatalf("H2 = %s", got)
	}
}

func TestReceiptSignVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	r := Receipt{Seq: 7, Decision: Allow, Binding: b32(0xAB), IssuedAt: 1_700_000_000}
	sig := Sign(priv, r)
	if !Verify(pub, r, sig) {
		t.Fatal("valid signature must verify")
	}
	// Any tampered field must invalidate the signature.
	bad := r
	bad.Binding = b32(0xAC)
	if Verify(pub, bad, sig) {
		t.Fatal("tampered receipt must not verify")
	}
	// A different key must not verify.
	pub2, _, _ := ed25519.GenerateKey(nil)
	if Verify(pub2, r, sig) {
		t.Fatal("wrong key must not verify")
	}
}
