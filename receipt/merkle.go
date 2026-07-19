package receipt

import (
	"crypto/sha256"
	"errors"
)

// RFC 6962 (Certificate Transparency) Merkle tree. Leaf and node hashing are
// domain-separated (0x00 for leaves, 0x01 for internal nodes) so a node hash can
// never be reinterpreted as a leaf (second-preimage safety), and the tree splits
// on the largest power of two below n, which avoids the duplicate-leaf ambiguity
// (CVE-2012-2459). SHA-256 only — no custom cryptography.

var errIndexRange = errors.New("receipt: leaf index out of range")

func leafHash(data []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func nodeHash(l, r [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(l[:])
	h.Write(r[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// largestPow2Below returns the largest power of two strictly less than n (n >= 2).
func largestPow2Below(n int) int {
	k := 1
	for k < n {
		k <<= 1
	}
	return k >> 1
}

// MerkleRoot is the RFC 6962 Merkle Tree Hash over the leaf inputs.
func MerkleRoot(leaves [][]byte) [32]byte {
	n := len(leaves)
	if n == 0 {
		return sha256.Sum256(nil)
	}
	if n == 1 {
		return leafHash(leaves[0])
	}
	k := largestPow2Below(n)
	return nodeHash(MerkleRoot(leaves[:k]), MerkleRoot(leaves[k:]))
}

// InclusionProof returns the RFC 6962 audit path for the leaf at index m,
// ordered bottom-up (leaf-level sibling first, root-level sibling last).
func InclusionProof(leaves [][]byte, m int) ([][32]byte, error) {
	if m < 0 || m >= len(leaves) {
		return nil, errIndexRange
	}
	return auditPath(m, leaves), nil
}

func auditPath(m int, ds [][]byte) [][32]byte {
	if len(ds) == 1 {
		return nil
	}
	k := largestPow2Below(len(ds))
	if m < k {
		return append(auditPath(m, ds[:k]), MerkleRoot(ds[k:]))
	}
	return append(auditPath(m-k, ds[k:]), MerkleRoot(ds[:k]))
}

// VerifyInclusion recomputes the root from a leaf input, its index/size, and the
// audit path, and reports whether it equals root.
func VerifyInclusion(root [32]byte, leaf []byte, m, size int, path [][32]byte) bool {
	if m < 0 || m >= size {
		return false
	}
	got, ok := rootFromPath(m, size, leafHash(leaf), path)
	return ok && got == root
}

func rootFromPath(m, n int, leaf [32]byte, path [][32]byte) ([32]byte, bool) {
	if n == 1 {
		if len(path) != 0 {
			return [32]byte{}, false
		}
		return leaf, true
	}
	if len(path) == 0 {
		return [32]byte{}, false
	}
	k := largestPow2Below(n)
	sib := path[len(path)-1]
	rest := path[:len(path)-1]
	if m < k {
		left, ok := rootFromPath(m, k, leaf, rest)
		if !ok {
			return [32]byte{}, false
		}
		return nodeHash(left, sib), true
	}
	right, ok := rootFromPath(m-k, n-k, leaf, rest)
	if !ok {
		return [32]byte{}, false
	}
	return nodeHash(sib, right), true
}
