package gate

import "sync"

// MemSpendLog is an in-memory, single-instance SpendLog for tests and the local
// demo. It is deliberately NOT durable across restarts: a production
// single-instance gate must use an fsync'd append-only file so that a crash
// cannot reopen a replay window (SPEC-X402 §5), and any multi-replica deployment
// must move single-use on-chain (Option 2). Using this in production as-is is a
// known, labeled limitation, not a hidden one.
type MemSpendLog struct {
	mu   sync.Mutex
	seen map[[32]byte]struct{}
}

// NewMemSpendLog returns an empty in-memory spend log.
func NewMemSpendLog() *MemSpendLog {
	return &MemSpendLog{seen: make(map[[32]byte]struct{})}
}

// Spend records nonce as used, returning ErrReplay if it was already present.
func (m *MemSpendLog) Spend(nonce [32]byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.seen[nonce]; ok {
		return ErrReplay
	}
	m.seen[nonce] = struct{}{}
	return nil
}
