package receipt

import (
	"crypto/ed25519"
	"testing"
)

func TestLogAppendChainAndRoot(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	l := NewLog(pub)
	if _, err := l.Append(priv, Allow, b32(0x11), 1_700_000_000); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(priv, DenyViolation, b32(0x22), 1_700_000_060); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(priv, DenyUnavailable, b32(0x33), 1_700_000_120); err != nil {
		t.Fatal(err)
	}

	if l.Len() != 3 {
		t.Fatalf("len = %d", l.Len())
	}
	if err := l.Verify(); err != nil {
		t.Fatalf("log.Verify: %v", err)
	}

	// Same receipts as the KAT → same Merkle root.
	root := l.Root()
	if root != MerkleRoot(katLeaves()) {
		t.Fatal("log root does not match KAT root")
	}

	// Every receipt has a valid inclusion proof against the anchored root.
	for i := 0; i < l.Len(); i++ {
		p, err := l.Proof(i)
		if err != nil {
			t.Fatal(err)
		}
		if !VerifyInclusion(root, l.entries[i].Receipt.CanonicalBytes(), i, l.Len(), p) {
			t.Fatalf("inclusion proof %d failed", i)
		}
	}
}

// Mutating a committed receipt must be caught by Verify (signature + chain).
func TestLogTamperDetected(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	l := NewLog(pub)
	if _, err := l.Append(priv, Allow, b32(0x11), 1); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(priv, Allow, b32(0x22), 2); err != nil {
		t.Fatal(err)
	}
	l.entries[0].Receipt.Binding = b32(0x99) // tamper after the fact
	if err := l.Verify(); err == nil {
		t.Fatal("tampered log must fail Verify")
	}
}
