package gate

import (
	"errors"
	"testing"
	"time"
)

const usdcMint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"

// --- policy / spend-log doubles ---------------------------------------------

type okPolicy struct{}

func (okPolicy) Verify(PaymentRequirements, Token) error { return nil }

type denyPolicy struct{}

func (denyPolicy) Verify(PaymentRequirements, Token) error {
	return errors.New("amount over ceiling")
}

type unavailPolicy struct{}

func (unavailPolicy) Verify(PaymentRequirements, Token) error {
	return Unavailable(errors.New("trust registry unreachable"))
}

// deadLog returns a non-replay error → the gate must map it to DENY_UNAVAILABLE.
type deadLog struct{}

func (deadLog) Spend([32]byte) error { return errors.New("disk write failed") }

// --- helpers ----------------------------------------------------------------

func testAllowlist() Allowlist {
	return Allowlist{
		Schemes:  map[string]byte{"exact": 1},
		Networks: map[string]byte{"solana:devnet": 2},
	}
}

func testPR() PaymentRequirements {
	return PaymentRequirements{
		Scheme:            "exact",
		Network:           "solana:devnet",
		Asset:             usdcMint,
		PayTo:             usdcMint,
		MaxAmountRequired: "1000000",
		Resource:          "https://api.example.com/resource",
	}
}

// TestEvaluateFailClosedMatrix asserts each non-ALLOW path resolves to the
// correct DENY class, and that ALLOW is only reached when everything holds.
func TestEvaluateFailClosedMatrix(t *testing.T) {
	al := testAllowlist()
	pr := testPR()
	now := time.Unix(1_700_000_000, 0)
	fresh := func(n byte) Token { return Token{Nonce: bytes32(n), Expiry: now.Add(time.Minute)} }

	// ALLOW
	if d := Evaluate(al, pr, fresh(1), okPolicy{}, NewMemSpendLog(), now); d.Class != Allow {
		t.Fatalf("ALLOW case: got %s (%s)", d.Class, d.Reason)
	}

	// unknown scheme → DENY_VIOLATION
	badpr := pr
	badpr.Scheme = "upto"
	if d := Evaluate(al, badpr, fresh(2), okPolicy{}, NewMemSpendLog(), now); d.Class != DenyViolation {
		t.Fatalf("unknown scheme: got %s", d.Class)
	}

	// expired → DENY_VIOLATION
	if d := Evaluate(al, pr, Token{Nonce: bytes32(3), Expiry: now.Add(-time.Second)}, okPolicy{}, NewMemSpendLog(), now); d.Class != DenyViolation {
		t.Fatalf("expired: got %s", d.Class)
	}

	// replay → DENY_VIOLATION (same nonce, same log, twice)
	log := NewMemSpendLog()
	_ = Evaluate(al, pr, fresh(4), okPolicy{}, log, now)
	if d := Evaluate(al, pr, fresh(4), okPolicy{}, log, now); d.Class != DenyViolation {
		t.Fatalf("replay: got %s (%s)", d.Class, d.Reason)
	}

	// spend-log outage → DENY_UNAVAILABLE
	if d := Evaluate(al, pr, fresh(5), okPolicy{}, deadLog{}, now); d.Class != DenyUnavailable {
		t.Fatalf("dead spend-log: got %s", d.Class)
	}

	// policy violation → DENY_VIOLATION
	if d := Evaluate(al, pr, fresh(6), denyPolicy{}, NewMemSpendLog(), now); d.Class != DenyViolation {
		t.Fatalf("policy deny: got %s", d.Class)
	}

	// policy outage → DENY_UNAVAILABLE
	if d := Evaluate(al, pr, fresh(7), unavailPolicy{}, NewMemSpendLog(), now); d.Class != DenyUnavailable {
		t.Fatalf("policy unavailable: got %s", d.Class)
	}
}

// TestNonceSurvivesPolicyDeny verifies the ordering decision: because the nonce
// is spent LAST (after policy), a policy denial does NOT consume it — so a
// legitimate caller who fixes the issue can still use the same token. This is
// why spend-then-allow, not spend-first, is correct.
func TestNonceSurvivesPolicyDeny(t *testing.T) {
	al := testAllowlist()
	pr := testPR()
	now := time.Unix(1_700_000_000, 0)
	log := NewMemSpendLog()
	tok := Token{Nonce: bytes32(9), Expiry: now.Add(time.Minute)}

	if d := Evaluate(al, pr, tok, denyPolicy{}, log, now); d.Class != DenyViolation {
		t.Fatalf("precondition: expected policy DENY_VIOLATION, got %s", d.Class)
	}
	if d := Evaluate(al, pr, tok, okPolicy{}, log, now); d.Class != Allow {
		t.Fatalf("nonce should survive a policy denial; got %s (%s)", d.Class, d.Reason)
	}
}

// TestBindingEmittedOnDeny confirms evidence is tied to the exact payment even
// on denial: the DENY carries the same binding an ALLOW would have.
func TestBindingEmittedOnDeny(t *testing.T) {
	al := testAllowlist()
	pr := testPR()
	now := time.Unix(1_700_000_000, 0)
	tok := Token{Nonce: bytes32(11), Expiry: now.Add(time.Minute)}

	want, err := ComputeBinding(al, pr, tok.Nonce)
	if err != nil {
		t.Fatal(err)
	}
	d := Evaluate(al, pr, tok, denyPolicy{}, NewMemSpendLog(), now)
	if d.Class != DenyViolation {
		t.Fatalf("expected DENY_VIOLATION, got %s", d.Class)
	}
	if d.Binding != want {
		t.Fatal("DENY did not carry the payment binding for evidence")
	}
}
