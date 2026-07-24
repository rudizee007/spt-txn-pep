package mcpgate

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/rudizee007/spt-txn-x402-solana/gate"
	"github.com/rudizee007/spt-txn-x402-solana/receipt"
)

func b32(x byte) [32]byte {
	var a [32]byte
	for i := range a {
		a[i] = x
	}
	return a
}

func addr(x byte) string {
	a := b32(x)
	return gate.EncodeBase58(a[:])
}

// setup returns an enforcer approved for exactly: pay <=1.000000 asset to
// merchant for invoice:42, with the clock pinned at t=1000.
func setup() (e *Enforcer, asset, merchant string) {
	_, rk, _ := ed25519.GenerateKey(nil)
	asset = addr(0xAA)
	merchant = addr(0xBB)
	e = &Enforcer{
		Scheme:    "exact",
		Network:   "solana:devnet",
		Allowlist: gate.Allowlist{Schemes: map[string]byte{"exact": 1}, Networks: map[string]byte{"solana:devnet": 2}},
		Policy:    ExactPayment{Asset: asset, PayTo: merchant, Resource: "invoice:42", MaxAmount: 1_000_000},
		Spend:     gate.NewMemSpendLog(),
		Log:       receipt.NewLog(rk.Public().(ed25519.PublicKey)),
		RKey:      rk,
		Now:       func() time.Time { return time.Unix(1000, 0) },
	}
	return e, asset, merchant
}

func legit(asset, merchant string, nonce byte) ToolCall {
	return ToolCall{
		To: merchant, Asset: asset, Amount: "1000000", Resource: "invoice:42",
		Nonce: b32(nonce), Expiry: time.Unix(2000, 0),
	}
}

func TestAllowApprovedCall(t *testing.T) {
	e, asset, merchant := setup()
	if r := e.Authorize(legit(asset, merchant, 1)); !r.Allowed() {
		t.Fatalf("want ALLOW, got %v (%s)", r.Class, r.Reason)
	}
}

func TestDenyHijackedRecipient(t *testing.T) {
	e, asset, merchant := setup()
	c := legit(asset, merchant, 2)
	c.To = addr(0xEE) // attacker's address
	if r := e.Authorize(c); r.Allowed() {
		t.Fatal("payment to an unapproved recipient must be denied")
	}
}

func TestDenyHijackedAmount(t *testing.T) {
	e, asset, merchant := setup()
	c := legit(asset, merchant, 3)
	c.Amount = "1000000000" // 1000 USDC, over the approved 1
	if r := e.Authorize(c); r.Allowed() {
		t.Fatal("payment over the approved limit must be denied")
	}
}

func TestDenyHijackedResource(t *testing.T) {
	e, asset, merchant := setup()
	c := legit(asset, merchant, 4)
	c.Resource = "invoice:999"
	if r := e.Authorize(c); r.Allowed() {
		t.Fatal("payment for an unapproved resource must be denied")
	}
}

func TestReplayDenied(t *testing.T) {
	e, asset, merchant := setup()
	c := legit(asset, merchant, 5)
	if r := e.Authorize(c); !r.Allowed() {
		t.Fatalf("first use should allow, got %s", r.Reason)
	}
	if r := e.Authorize(c); r.Allowed() {
		t.Fatal("reused (replayed) authorization must be denied")
	}
}

func TestExpiredDenied(t *testing.T) {
	e, asset, merchant := setup()
	c := legit(asset, merchant, 6)
	c.Expiry = time.Unix(500, 0) // before the pinned now=1000
	if r := e.Authorize(c); r.Allowed() {
		t.Fatal("expired authorization must be denied")
	}
}

func TestDeniedCallDoesNotSpendNonce(t *testing.T) {
	// A policy denial must NOT burn the nonce, so a legitimate retry works.
	e, asset, merchant := setup()
	bad := legit(asset, merchant, 7)
	bad.Resource = "invoice:999"
	if r := e.Authorize(bad); r.Allowed() {
		t.Fatal("setup: bad call should deny")
	}
	good := legit(asset, merchant, 7) // same nonce, corrected request
	if r := e.Authorize(good); !r.Allowed() {
		t.Fatalf("a corrected retry on an unspent nonce should allow, got %s", r.Reason)
	}
}
