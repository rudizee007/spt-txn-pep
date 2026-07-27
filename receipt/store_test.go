package receipt

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// threeReceiptLog builds the same three decisions used by the KAT.
func threeReceiptLog(t *testing.T) (*Log, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	l := NewLog(pub)
	for _, tc := range []struct {
		d Decision
		b byte
		a int64
	}{
		{Allow, 0x11, 1_700_000_000},
		{DenyViolation, 0x22, 1_700_000_060},
		{DenyUnavailable, 0x33, 1_700_000_120},
	} {
		if _, err := l.Append(priv, tc.d, b32(tc.b), tc.a); err != nil {
			t.Fatal(err)
		}
	}
	return l, priv
}

// A saved log loads back identical: same root, same length, and it still
// verifies. This is the property the on-chain anchor depends on — the root
// anchored by a later process must be the root the enforcement path produced.
func TestSaveLoadRoundTrip(t *testing.T) {
	l, _ := threeReceiptLog(t)
	path := filepath.Join(t.TempDir(), "receipts.json")
	if err := l.Save(path); err != nil {
		t.Fatal(err)
	}

	got, err := LoadLog(path)
	if err != nil {
		t.Fatalf("LoadLog: %v", err)
	}
	if got.Len() != l.Len() {
		t.Fatalf("len = %d, want %d", got.Len(), l.Len())
	}
	if got.Root() != l.Root() {
		t.Fatalf("root = %x, want %x", got.Root(), l.Root())
	}
	if err := got.Verify(); err != nil {
		t.Fatalf("loaded log fails Verify: %v", err)
	}
	if !bytes.Equal(got.PublicKey(), l.PublicKey()) {
		t.Fatal("loaded log has a different verifying key")
	}

	// Inclusion proofs survive the round trip against the loaded root.
	root := got.Root()
	for i := 0; i < got.Len(); i++ {
		p, err := got.Proof(i)
		if err != nil {
			t.Fatal(err)
		}
		r, ok := got.At(i)
		if !ok {
			t.Fatalf("At(%d) missing", i)
		}
		if !VerifyInclusion(root, r.CanonicalBytes(), i, got.Len(), p) {
			t.Fatalf("inclusion proof %d fails after round trip", i)
		}
	}
}

// The signing key must never reach the file. A saved log is public evidence.
func TestSaveOmitsPrivateKey(t *testing.T) {
	l, priv := threeReceiptLog(t)
	var buf bytes.Buffer
	if err := l.Encode(&buf); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(buf.Bytes(), []byte(hexOf(priv.Seed()))) {
		t.Fatal("serialized log contains the receipt-signing seed")
	}
	if bytes.Contains(buf.Bytes(), []byte(hexOf(priv))) {
		t.Fatal("serialized log contains the receipt-signing private key")
	}
	for _, k := range []string{"priv", "secret", "seed"} {
		if strings.Contains(strings.ToLower(buf.String()), k) {
			t.Fatalf("serialized log mentions %q", k)
		}
	}
}

// Evidence files are not world-readable.
func TestSavePermissions(t *testing.T) {
	l, _ := threeReceiptLog(t)
	path := filepath.Join(t.TempDir(), "receipts.json")
	if err := l.Save(path); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("mode = %o, want 600", perm)
	}
}

// Save replaces an existing file rather than appending to or corrupting it.
func TestSaveOverwritesAtomically(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "receipts.json")
	if err := os.WriteFile(path, []byte("stale garbage that is not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	l, _ := threeReceiptLog(t)
	if err := l.Save(path); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadLog(path); err != nil {
		t.Fatalf("LoadLog after overwrite: %v", err)
	}
	// No temp files left behind.
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 {
		t.Fatalf("expected only receipts.json, got %d entries", len(ents))
	}
}

// Editing a committed receipt breaks its signature; the file must not load.
func TestLoadRejectsEditedReceipt(t *testing.T) {
	l, _ := threeReceiptLog(t)
	f := decodeToFile(t, l)
	f.Entries[0].Binding = strings.Repeat("99", 32)
	if _, err := ReadLog(bytes.NewReader(encode(t, f))); err == nil {
		t.Fatal("an edited receipt must not load")
	}
}

// Dropping the last receipt leaves every remaining signature valid and the chain
// intact — only the recomputed root catches it. This is the case the Root field
// exists for.
func TestLoadRejectsTruncation(t *testing.T) {
	l, _ := threeReceiptLog(t)
	f := decodeToFile(t, l)
	f.Entries = f.Entries[:len(f.Entries)-1]
	f.Count = len(f.Entries)

	_, err := ReadLog(bytes.NewReader(encode(t, f)))
	if err == nil {
		t.Fatal("a truncated log must not load")
	}
	if !errors.Is(err, ErrRootMismatch) {
		t.Fatalf("want ErrRootMismatch, got %v", err)
	}
}

// A rewritten root with untouched receipts must also be caught.
func TestLoadRejectsForgedRoot(t *testing.T) {
	l, _ := threeReceiptLog(t)
	f := decodeToFile(t, l)
	f.Root = strings.Repeat("ab", 32)
	_, err := ReadLog(bytes.NewReader(encode(t, f)))
	if !errors.Is(err, ErrRootMismatch) {
		t.Fatalf("want ErrRootMismatch, got %v", err)
	}
}

// Swapping the verifying key so a forged log "verifies" against an attacker key
// still fails, because the receipts were signed by the original key.
func TestLoadRejectsSwappedPubKey(t *testing.T) {
	l, _ := threeReceiptLog(t)
	other, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	f := decodeToFile(t, l)
	f.PubKey = hexOf(other)
	if _, err := ReadLog(bytes.NewReader(encode(t, f))); err == nil {
		t.Fatal("a log whose key does not match its signatures must not load")
	}
}

// Reordering receipts breaks the sequence numbers and the hash chain.
func TestLoadRejectsReordering(t *testing.T) {
	l, _ := threeReceiptLog(t)
	f := decodeToFile(t, l)
	f.Entries[0], f.Entries[2] = f.Entries[2], f.Entries[0]
	if _, err := ReadLog(bytes.NewReader(encode(t, f))); err == nil {
		t.Fatal("a reordered log must not load")
	}
}

// Unknown format or layout fails closed rather than being parsed optimistically.
func TestLoadRejectsUnknownFormat(t *testing.T) {
	l, _ := threeReceiptLog(t)

	f := decodeToFile(t, l)
	f.Format = "some-other-log/v9"
	if _, err := ReadLog(bytes.NewReader(encode(t, f))); !errors.Is(err, ErrFormat) {
		t.Fatalf("want ErrFormat for bad format, got %v", err)
	}

	f = decodeToFile(t, l)
	f.Layout = LayoutVersion + 1
	if _, err := ReadLog(bytes.NewReader(encode(t, f))); !errors.Is(err, ErrFormat) {
		t.Fatalf("want ErrFormat for bad layout, got %v", err)
	}
}

// A count that disagrees with the entry list is a malformed file.
func TestLoadRejectsCountMismatch(t *testing.T) {
	l, _ := threeReceiptLog(t)
	f := decodeToFile(t, l)
	f.Count = 99
	if _, err := ReadLog(bytes.NewReader(encode(t, f))); err == nil {
		t.Fatal("a count mismatch must not load")
	}
}

// Malformed input is rejected, not panicked on.
func TestLoadRejectsGarbage(t *testing.T) {
	for _, in := range []string{"", "{", "null", "[]", `{"format":"spt-txn/receipt-log/v1"}`, `{"format":"spt-txn/receipt-log/v1","layout":1,"pubkey":"zz","root":"","count":0,"entries":[]}`} {
		if _, err := ReadLog(strings.NewReader(in)); err == nil {
			t.Fatalf("input %q must not load", in)
		}
	}
}

// An empty log round-trips (the anchoring command is what refuses to anchor it).
func TestEmptyLogRoundTrips(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	l := NewLog(pub)
	path := filepath.Join(t.TempDir(), "receipts.json")
	if err := l.Save(path); err != nil {
		t.Fatal(err)
	}
	got, err := LoadLog(path)
	if err != nil {
		t.Fatalf("LoadLog: %v", err)
	}
	if got.Len() != 0 {
		t.Fatalf("len = %d, want 0", got.Len())
	}
}

// ── helpers ─────────────────────────────────────────────────────────────────

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0x0f])
	}
	return string(out)
}

func decodeToFile(t *testing.T, l *Log) logFile {
	t.Helper()
	var buf bytes.Buffer
	if err := l.Encode(&buf); err != nil {
		t.Fatal(err)
	}
	var f logFile
	if err := json.Unmarshal(buf.Bytes(), &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func encode(t *testing.T, f logFile) []byte {
	t.Helper()
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
