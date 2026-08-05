package translog

import (
	"encoding/hex"
	"testing"
)

// katLeaves rebuilds the three canonical receipts from the KAT.
func katLeaves() [][]byte {
	var zero [32]byte
	r0 := Record{Seq: 0, Decision: Allow, Binding: b32(0x11), IssuedAt: 1_700_000_000, PrevHash: zero}
	h0 := r0.Hash()
	r1 := Record{Seq: 1, Decision: DenyViolation, Binding: b32(0x22), IssuedAt: 1_700_000_060, PrevHash: h0}
	h1 := r1.Hash()
	r2 := Record{Seq: 2, Decision: DenyUnavailable, Binding: b32(0x33), IssuedAt: 1_700_000_120, PrevHash: h1}
	return [][]byte{r0.CanonicalBytes(), r1.CanonicalBytes(), r2.CanonicalBytes()}
}

func TestMerkleRootKAT(t *testing.T) {
	root := MerkleRoot(katLeaves())
	if got := hex.EncodeToString(root[:]); got != "5c520a777da3f47124aff92c7930e00d8ed4f58ae0e34dd88eee741912804625" {
		t.Fatalf("root = %s", got)
	}
}

func TestInclusionProofKAT(t *testing.T) {
	leaves := katLeaves()
	root := MerkleRoot(leaves)
	p, err := InclusionProof(leaves, 1)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"5387b131ab1a290b522d700c8e46535b415ddf2c28a3e0286b7d59c62a42dbe9",
		"9b0fe2dc0fac75c79be3cf7a0c27504e35816086e4b1b3cb8dc90cd07503a1b6",
	}
	if len(p) != len(want) {
		t.Fatalf("proof length = %d", len(p))
	}
	for i := range p {
		if got := hex.EncodeToString(p[i][:]); got != want[i] {
			t.Fatalf("proof[%d] = %s", i, got)
		}
	}
	if !VerifyInclusion(root, leaves[1], 1, len(leaves), p) {
		t.Fatal("KAT inclusion proof must verify")
	}
}

// For trees of every size 1..64, every leaf's generated proof verifies, and a
// flipped leaf does not.
func TestInclusionProofExhaustive(t *testing.T) {
	for n := 1; n <= 64; n++ {
		leaves := make([][]byte, n)
		for i := range leaves {
			leaves[i] = []byte{byte(i), byte(i >> 8), 0xEE}
		}
		root := MerkleRoot(leaves)
		for m := 0; m < n; m++ {
			p, err := InclusionProof(leaves, m)
			if err != nil {
				t.Fatalf("n=%d m=%d: %v", n, m, err)
			}
			if !VerifyInclusion(root, leaves[m], m, n, p) {
				t.Fatalf("n=%d m=%d: valid proof failed", n, m)
			}
			bad := append([]byte{}, leaves[m]...)
			bad[len(bad)-1] ^= 1
			if VerifyInclusion(root, bad, m, n, p) {
				t.Fatalf("n=%d m=%d: tampered leaf verified", n, m)
			}
		}
	}
}

// Leaf and node hashing must be domain-separated: a node hash must not collide
// with a leaf hash over the same bytes (second-preimage resistance).
func TestLeafNodeDomainSeparation(t *testing.T) {
	a := leafHash([]byte("a"))
	b := leafHash([]byte("b"))
	parent := nodeHash(a, b)
	forged := leafHash(append(append([]byte{}, a[:]...), b[:]...))
	if forged == parent {
		t.Fatal("leaf and node hashing are not domain-separated")
	}
}
