package receipt

import (
	"crypto/ed25519"
	"errors"
)

// Entry is a receipt together with its signature.
type Entry struct {
	Receipt   Receipt
	Signature []byte
}

// Log is an append-only, hash-chained receipt log. Its RFC 6962 Merkle root
// (Root) is the single value anchored on-chain — a periodic write, never read in
// the decision hot path.
type Log struct {
	pub     ed25519.PublicKey
	entries []Entry
}

// NewLog starts an empty log that verifies signatures against pub.
func NewLog(pub ed25519.PublicKey) *Log {
	return &Log{pub: pub}
}

// Append creates the next receipt (Seq = current length, PrevHash = the last
// receipt's hash), signs it with priv, self-verifies, and appends it.
func (l *Log) Append(priv ed25519.PrivateKey, decision Decision, binding [32]byte, issuedAt int64) (Entry, error) {
	var prev [32]byte
	if n := len(l.entries); n > 0 {
		prev = l.entries[n-1].Receipt.Hash()
	}
	r := Receipt{
		Seq:      uint64(len(l.entries)),
		Decision: decision,
		Binding:  binding,
		IssuedAt: issuedAt,
		PrevHash: prev,
	}
	sig := Sign(priv, r)
	if !Verify(l.pub, r, sig) {
		return Entry{}, errors.New("receipt: signature failed self-verify")
	}
	e := Entry{Receipt: r, Signature: sig}
	l.entries = append(l.entries, e)
	return e, nil
}

// Len returns the number of receipts.
func (l *Log) Len() int { return len(l.entries) }

// At returns the receipt at index seq (ok=false if out of range).
func (l *Log) At(seq int) (Receipt, bool) {
	if seq < 0 || seq >= len(l.entries) {
		return Receipt{}, false
	}
	return l.entries[seq].Receipt, true
}

// Root returns the RFC 6962 Merkle root over all receipts.
func (l *Log) Root() [32]byte {
	return MerkleRoot(l.canonicalLeaves())
}

// Proof returns the inclusion proof for the receipt at index seq.
func (l *Log) Proof(seq int) ([][32]byte, error) {
	return InclusionProof(l.canonicalLeaves(), seq)
}

func (l *Log) canonicalLeaves() [][]byte {
	out := make([][]byte, len(l.entries))
	for i, e := range l.entries {
		out[i] = e.Receipt.CanonicalBytes()
	}
	return out
}

// Verify checks the whole log: contiguous sequence numbers, an intact hash chain,
// and a valid signature on every receipt. Returns nil if the log is sound.
func (l *Log) Verify() error {
	var prev [32]byte
	for i, e := range l.entries {
		if e.Receipt.Seq != uint64(i) {
			return errors.New("receipt: sequence gap")
		}
		if e.Receipt.PrevHash != prev {
			return errors.New("receipt: broken hash chain")
		}
		if !Verify(l.pub, e.Receipt, e.Signature) {
			return errors.New("receipt: bad signature")
		}
		prev = e.Receipt.Hash()
	}
	return nil
}
