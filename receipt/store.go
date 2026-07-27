package receipt

// Portable persistence for a receipt log.
//
// A log is produced by the enforcement path (every gate decision appends one
// receipt) and is anchored on-chain by a separate, later process. Those are two
// programs, so the log has to survive the gap between them. This file is that
// gap: a versioned, self-describing JSON encoding that carries the verifying
// public key, every signed receipt, and the Merkle root the writer computed.
//
// The format is deliberately verifiable rather than trusted. LoadLog re-checks
// the signature on every receipt, re-walks the hash chain, and recomputes the
// Merkle root from the receipts themselves — the Root field in the file is
// compared, never believed. A file that has been truncated, reordered, or edited
// fails to load at all. There is no partial-trust path.
//
// The receipt-signing private key is never written. Only the public key is, so
// a saved log can be verified by anyone and forged by no one.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	// FormatReceiptLog identifies the on-disk encoding. It is domain-separated
	// from every other SPT-Txn construction and bumped on any format change.
	FormatReceiptLog = "spt-txn/receipt-log/v1"

	// maxLogEntries bounds how many receipts LoadLog will allocate for. A log
	// this long is not something SPT-Txn produces; the cap exists so a hostile
	// file cannot turn a load into an out-of-memory.
	maxLogEntries = 100_000

	// maxLogBytes bounds how much of a file LoadLog will read, for the same
	// reason.
	maxLogBytes = 64 << 20
)

var (
	// ErrFormat means the file is not an SPT-Txn receipt log this build can read.
	ErrFormat = errors.New("receipt: unrecognized receipt-log format")
	// ErrRootMismatch means the receipts in the file do not hash to the root the
	// file claims — truncation, reordering, or edited contents.
	ErrRootMismatch = errors.New("receipt: merkle root does not match the receipts in the file")
)

// logFile is the on-disk shape. Every fixed-width binary field is hex so the
// file is diffable and greppable without a decoder.
type logFile struct {
	Format  string      `json:"format"`
	Layout  uint8       `json:"layout"`
	PubKey  string      `json:"pubkey"` // hex ed25519 public key (32 bytes)
	Root    string      `json:"root"`   // hex RFC 6962 Merkle root (32 bytes)
	Count   int         `json:"count"`
	Entries []entryFile `json:"entries"`
}

type entryFile struct {
	Seq      uint64 `json:"seq"`
	Decision uint8  `json:"decision"`
	Binding  string `json:"binding"`  // hex (32 bytes)
	IssuedAt int64  `json:"issuedAt"` // unix seconds
	PrevHash string `json:"prevHash"` // hex (32 bytes)
	Sig      string `json:"sig"`      // hex ed25519 signature (64 bytes)
}

// PublicKey returns a copy of the key this log's receipts verify against.
func (l *Log) PublicKey() ed25519.PublicKey {
	out := make(ed25519.PublicKey, len(l.pub))
	copy(out, l.pub)
	return out
}

// Encode serializes the log as JSON. The private key is not part of the log and
// is therefore not written.
func (l *Log) Encode(w io.Writer) error {
	root := l.Root()
	f := logFile{
		Format:  FormatReceiptLog,
		Layout:  LayoutVersion,
		PubKey:  hex.EncodeToString(l.pub),
		Root:    hex.EncodeToString(root[:]),
		Count:   len(l.entries),
		Entries: make([]entryFile, len(l.entries)),
	}
	for i, e := range l.entries {
		f.Entries[i] = entryFile{
			Seq:      e.Receipt.Seq,
			Decision: uint8(e.Receipt.Decision),
			Binding:  hex.EncodeToString(e.Receipt.Binding[:]),
			IssuedAt: e.Receipt.IssuedAt,
			PrevHash: hex.EncodeToString(e.Receipt.PrevHash[:]),
			Sig:      hex.EncodeToString(e.Signature),
		}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(f)
}

// Save writes the log to path, replacing any existing file atomically. The file
// is created 0600: it is evidence, and evidence that anyone can rewrite in place
// is not evidence.
func (l *Log) Save(path string) error {
	path = filepath.Clean(path)
	if path == "" || path == "." {
		return errors.New("receipt: empty log path")
	}
	dir := filepath.Dir(path)

	tmp, err := os.CreateTemp(dir, ".spt-receipts-*.tmp")
	if err != nil {
		return fmt.Errorf("receipt: create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename below succeeds

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("receipt: chmod temp: %w", err)
	}
	if err := l.Encode(tmp); err != nil {
		tmp.Close()
		return fmt.Errorf("receipt: write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("receipt: sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("receipt: close temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("receipt: rename into place: %w", err)
	}
	return nil
}

// ReadLog parses a serialized log and returns it only if it is sound: known
// format and layout, well-formed fields, a valid signature on every receipt, an
// intact hash chain, and a Merkle root that the receipts actually produce.
func ReadLog(r io.Reader) (*Log, error) {
	raw, err := io.ReadAll(io.LimitReader(r, maxLogBytes+1))
	if err != nil {
		return nil, fmt.Errorf("receipt: read: %w", err)
	}
	if len(raw) > maxLogBytes {
		return nil, fmt.Errorf("receipt: log exceeds %d bytes", maxLogBytes)
	}

	var f logFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("receipt: parse: %w", err)
	}

	if f.Format != FormatReceiptLog {
		return nil, fmt.Errorf("%w: %q", ErrFormat, f.Format)
	}
	if f.Layout != LayoutVersion {
		return nil, fmt.Errorf("%w: layout version %d, this build writes %d", ErrFormat, f.Layout, LayoutVersion)
	}
	if len(f.Entries) > maxLogEntries {
		return nil, fmt.Errorf("receipt: log has %d receipts, cap is %d", len(f.Entries), maxLogEntries)
	}
	if f.Count != len(f.Entries) {
		return nil, fmt.Errorf("receipt: count field says %d, file holds %d receipts", f.Count, len(f.Entries))
	}

	pub, err := hex.DecodeString(f.PubKey)
	if err != nil {
		return nil, fmt.Errorf("receipt: pubkey: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("receipt: pubkey must be %d bytes, got %d", ed25519.PublicKeySize, len(pub))
	}

	wantRoot, err := hex32(f.Root)
	if err != nil {
		return nil, fmt.Errorf("receipt: root: %w", err)
	}

	l := &Log{pub: ed25519.PublicKey(pub), entries: make([]Entry, len(f.Entries))}
	for i, e := range f.Entries {
		binding, err := hex32(e.Binding)
		if err != nil {
			return nil, fmt.Errorf("receipt %d: binding: %w", i, err)
		}
		prev, err := hex32(e.PrevHash)
		if err != nil {
			return nil, fmt.Errorf("receipt %d: prevHash: %w", i, err)
		}
		sig, err := hex.DecodeString(e.Sig)
		if err != nil {
			return nil, fmt.Errorf("receipt %d: sig: %w", i, err)
		}
		if len(sig) != ed25519.SignatureSize {
			return nil, fmt.Errorf("receipt %d: signature must be %d bytes, got %d", i, ed25519.SignatureSize, len(sig))
		}
		l.entries[i] = Entry{
			Receipt: Receipt{
				Seq:      e.Seq,
				Decision: Decision(e.Decision),
				Binding:  binding,
				IssuedAt: e.IssuedAt,
				PrevHash: prev,
			},
			Signature: sig,
		}
	}

	// Signatures and hash chain. Fail closed.
	if err := l.Verify(); err != nil {
		return nil, err
	}
	// The root in the file is checked against the receipts, never trusted. This
	// is what catches a file whose receipts are individually valid but as a set
	// have been truncated or reordered.
	if got := l.Root(); got != wantRoot {
		return nil, fmt.Errorf("%w: file says %x, receipts hash to %x", ErrRootMismatch, wantRoot, got)
	}
	return l, nil
}

// LoadLog reads and verifies a receipt log from path.
func LoadLog(path string) (*Log, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ReadLog(f)
}

func hex32(s string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(s)
	if err != nil {
		return out, err
	}
	if len(b) != 32 {
		return out, fmt.Errorf("must be 32 bytes, got %d", len(b))
	}
	copy(out[:], b)
	return out, nil
}
