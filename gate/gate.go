package gate

import (
	"errors"
	"fmt"
	"time"
)

// DecisionClass is the outcome of the gate. The two DENY classes are kept
// distinct so operators can tell an attack (Violation) from an outage
// (Unavailable) — SPEC-X402 §5. This distinction is load-bearing for incident
// response and must never collapse into a single "denied".
type DecisionClass int

const (
	Allow DecisionClass = iota
	DenyViolation
	DenyUnavailable
)

func (d DecisionClass) String() string {
	switch d {
	case Allow:
		return "ALLOW"
	case DenyViolation:
		return "DENY_VIOLATION"
	case DenyUnavailable:
		return "DENY_UNAVAILABLE"
	default:
		return "UNKNOWN"
	}
}

// Token is the minimal view of an SPT-Txn token the gate needs to decide. The
// full token and its 8-step verification live in the published engine; the gate
// consumes an already-verified token plus its single-use nonce and expiry. Scope
// is evaluated by the PolicyVerifier, not here — the gate adds no policy
// semantics of its own (SPEC-X402 §3).
type Token struct {
	Nonce  [32]byte  // jti; single-use
	Expiry time.Time // zero means "no expiry set" (still must pass policy)
}

// PolicyVerifier evaluates whether a payment is permitted by a token's scope. It
// is the pluggable ABAC→TBAC decision point (bring-your-own engine — OPA,
// Sumsub, custom — or the published SPT-Txn verifier). It returns nil for ALLOW,
// or an error for DENY. Wrap the error with Unavailable() to signal an outage
// (→ DENY_UNAVAILABLE) rather than a policy violation.
type PolicyVerifier interface {
	Verify(pr PaymentRequirements, tok Token) error
}

// SpendLog records single-use nonces. Spend MUST persist a nonce durably BEFORE
// the gate can return ALLOW, and MUST fail closed if it cannot read/write
// (SPEC-X402 §5). M1 ships a single-instance implementation; multi-replica
// deployments require Option 2 (structural single-use on-chain).
type SpendLog interface {
	// Spend atomically records nonce as used. It returns ErrReplay if the nonce
	// was already present, or any other non-nil error if the store is
	// unavailable (which the gate maps to DENY_UNAVAILABLE).
	Spend(nonce [32]byte) error
}

var (
	// ErrReplay is returned by SpendLog.Spend when a nonce was already spent.
	ErrReplay = errors.New("gate: nonce already spent (replay)")
	// errUnavailable is the sentinel wrapped by Unavailable().
	errUnavailable = errors.New("unavailable")
)

// Unavailable wraps err so the gate classifies the failure as DENY_UNAVAILABLE
// rather than DENY_VIOLATION. A PolicyVerifier returns Unavailable(err) for an
// outage (registry unreachable, timeout) as opposed to a genuine policy denial.
func Unavailable(err error) error { return fmt.Errorf("%w: %v", errUnavailable, err) }

func isUnavailable(err error) bool { return errors.Is(err, errUnavailable) }

// Decision is the gate's output. Binding is emitted on every path, including
// DENY, so an evidence record is always tied to the exact payment considered.
type Decision struct {
	Class   DecisionClass
	Reason  string
	Binding [32]byte
}

// Evaluate is the gate's pure decision function. Every non-ALLOW path is
// fail-closed and Evaluate never sends a payment. Order is deliberate:
//
//  1. Binding — unknown scheme/network, malformed pubkey, or bad amount is a
//     DENY_VIOLATION (a request we structurally cannot authorize).
//  2. Freshness — an expired token is a DENY_VIOLATION.
//  3. Policy (scope) — via the pluggable verifier; violation vs outage is
//     preserved.
//  4. Single-use — the nonce is spent LAST, immediately before ALLOW. This
//     satisfies "persist-before-ALLOW" (SPEC-X402 §5) while ensuring a token is
//     NOT burned by a policy denial or a binding error, so a legitimate caller
//     can retry after fixing a scope/parameter mistake. A replay is a
//     DENY_VIOLATION; a spend-log outage is a DENY_UNAVAILABLE.
func Evaluate(al Allowlist, pr PaymentRequirements, tok Token, pol PolicyVerifier, log SpendLog, now time.Time) Decision {
	binding, err := ComputeBinding(al, pr, tok.Nonce)
	if err != nil {
		return Decision{DenyViolation, "binding: " + err.Error(), binding}
	}
	if !tok.Expiry.IsZero() && now.After(tok.Expiry) {
		return Decision{DenyViolation, "token expired", binding}
	}
	if err := pol.Verify(pr, tok); err != nil {
		if isUnavailable(err) {
			return Decision{DenyUnavailable, "policy unavailable: " + err.Error(), binding}
		}
		return Decision{DenyViolation, "policy: " + err.Error(), binding}
	}
	// Spend-then-allow: this is the last gate before ALLOW.
	if err := log.Spend(tok.Nonce); err != nil {
		if errors.Is(err, ErrReplay) {
			return Decision{DenyViolation, "replay: nonce already spent", binding}
		}
		return Decision{DenyUnavailable, "spend-log unavailable: " + err.Error(), binding}
	}
	return Decision{Allow, "in-scope, single-use, bound", binding}
}
