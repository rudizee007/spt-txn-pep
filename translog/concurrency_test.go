package translog

import (
	"crypto/ed25519"
	"path/filepath"
	"sync"
	"testing"
)

// TestLogAppendConcurrent is the regression test for the F1 data race. Before
// translog.Log had a mutex, concurrent Append calls (as issued per-request from
// gateway.Wrap's net/http goroutines) raced on the entry slice: duplicate Seq,
// forked PrevHash, lost writes, and readers racing a slice reallocation could
// panic — corrupting the transparency chain the log exists to protect. This
// test drives concurrent Appends and reads and asserts the chain stays sound.
// Run with -race.
func TestLogAppendConcurrent(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	l := NewLog(pub)

	const n = 500
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := l.Append(priv, Allow, b32(byte(i)), int64(i)); err != nil {
				errs <- err
			}
		}(i)
	}
	// Concurrent readers, to catch a read racing a write under -race.
	for r := 0; r < 8; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_ = l.Root()
				_ = l.Len()
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent Append error: %v", err)
	}

	if l.Len() != n {
		t.Fatalf("want %d entries, got %d", n, l.Len())
	}
	// The chain must be sound: contiguous Seq 0..n-1, intact hash chain, valid sigs.
	if err := l.Verify(); err != nil {
		t.Fatalf("chain corrupted under concurrency: %v", err)
	}
	// Seq values must be exactly the set {0..n-1}, no duplicates, no gaps.
	seen := make([]bool, n)
	for i := 0; i < l.Len(); i++ {
		rec, ok := l.At(i)
		if !ok {
			t.Fatalf("missing entry %d", i)
		}
		s := int(rec.Seq)
		if s < 0 || s >= n || seen[s] {
			t.Fatalf("bad or duplicate Seq %d at index %d", s, i)
		}
		seen[s] = true
	}
}

// TestLogSaveConcurrentWithAppend is the regression test for the Encode/Save
// snapshot race: Encode must capture root+entries atomically, or a Save racing
// an Append writes a file whose root does not match its own entries and reloads
// as ErrRootMismatch. Save in a loop against concurrent Appends, then confirm
// the final file reloads soundly. Run with -race.
func TestLogSaveConcurrentWithAppend(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	l := NewLog(pub)
	path := filepath.Join(t.TempDir(), "log.json")

	var wg sync.WaitGroup
	const n = 300
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < n; i++ {
			if _, err := l.Append(priv, Allow, b32(byte(i)), int64(i)); err != nil {
				t.Errorf("append: %v", err)
				return
			}
		}
	}()
	// Save repeatedly while appends are in flight. Each saved file must itself be
	// internally consistent (root matches its own entries), so LoadLog succeeds
	// on every snapshot, whatever count it captured.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			if err := l.Save(path); err != nil {
				t.Errorf("save: %v", err)
				return
			}
			if _, err := LoadLog(path); err != nil {
				t.Errorf("load of concurrently-written snapshot failed (torn Encode): %v", err)
				return
			}
		}
	}()
	wg.Wait()

	// Final consistent snapshot round-trips and matches the live log length.
	if err := l.Save(path); err != nil {
		t.Fatalf("final save: %v", err)
	}
	got, err := LoadLog(path)
	if err != nil {
		t.Fatalf("final load: %v", err)
	}
	if got.Len() != l.Len() {
		t.Fatalf("reloaded %d entries, live log has %d", got.Len(), l.Len())
	}
}
