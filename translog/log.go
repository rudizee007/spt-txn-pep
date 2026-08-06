package translog

import (
	"crypto/ed25519"
	"errors"
	"sync"
)

// Entry is a log record together with its signature.
type Entry struct {
	Record    Record
	Signature []byte
}

// Log is an append-only, hash-chained log of authorization decisions. Its RFC 6962 Merkle root
// (Root) is the single value anchored on-chain — a periodic write, never read in
// the decision hot path.
//
// Concurrency: a PEP calls Append from per-request net/http goroutines while an
// operator may read Root/At/Len/Proof concurrently. Every access to entries is
// therefore guarded by mu. Without it, two concurrent Appends race on the entry
// slice — duplicate Seq, forked PrevHash, lost writes, torn reads — which
// corrupts the very transparency chain this log exists to protect, and a read
// racing a slice reallocation can panic. (Mirrors pkg/audit.Log, which has
// always locked; this log did not, until this change.)
type Log struct {
	mu      sync.Mutex
	pub     ed25519.PublicKey
	entries []Entry
}

// NewLog starts an empty log that verifies signatures against pub.
func NewLog(pub ed25519.PublicKey) *Log {
	return &Log{pub: pub}
}

// Append creates the next record (Seq = current length, PrevHash = the last
// record's hash), signs it with priv, self-verifies, and appends it. Safe for
// concurrent use: the read of the tail, the Seq assignment and the append are
// one critical section, so the chain cannot fork under concurrent callers.
func (l *Log) Append(priv ed25519.PrivateKey, decision Decision, binding [32]byte, issuedAt int64) (Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var prev [32]byte
	if n := len(l.entries); n > 0 {
		prev = l.entries[n-1].Record.Hash()
	}
	r := Record{
		Seq:      uint64(len(l.entries)),
		Decision: decision,
		Binding:  binding,
		IssuedAt: issuedAt,
		PrevHash: prev,
	}
	sig := Sign(priv, r)
	if !Verify(l.pub, r, sig) {
		return Entry{}, errors.New("translog: signature failed self-verify")
	}
	e := Entry{Record: r, Signature: sig}
	l.entries = append(l.entries, e)
	return e, nil
}

// Len returns the number of records.
func (l *Log) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

// At returns the record at index seq (ok=false if out of range).
func (l *Log) At(seq int) (Record, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if seq < 0 || seq >= len(l.entries) {
		return Record{}, false
	}
	return l.entries[seq].Record, true
}

// Root returns the RFC 6962 Merkle root over all records.
func (l *Log) Root() [32]byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	return MerkleRoot(l.canonicalLeavesLocked())
}

// Proof returns the inclusion proof for the record at index seq.
func (l *Log) Proof(seq int) ([][32]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return InclusionProof(l.canonicalLeavesLocked(), seq)
}

// canonicalLeavesLocked builds the leaf set. The caller MUST hold l.mu — it is
// only ever called from methods that already lock, so it does not re-lock (the
// mutex is not reentrant).
func (l *Log) canonicalLeavesLocked() [][]byte {
	out := make([][]byte, len(l.entries))
	for i, e := range l.entries {
		out[i] = e.Record.CanonicalBytes()
	}
	return out
}

// Verify checks the whole log: contiguous sequence numbers, an intact hash chain,
// and a valid signature on every record. Returns nil if the log is sound.
func (l *Log) Verify() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	var prev [32]byte
	for i, e := range l.entries {
		if e.Record.Seq != uint64(i) {
			return errors.New("translog: sequence gap")
		}
		if e.Record.PrevHash != prev {
			return errors.New("translog: broken hash chain")
		}
		if !Verify(l.pub, e.Record, e.Signature) {
			return errors.New("translog: bad signature")
		}
		prev = e.Record.Hash()
	}
	return nil
}
