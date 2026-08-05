// Package mcpgate enforces SPT-Txn authorization on AI-agent tool-calls — the
// MCP policy-enforcement-point profile. It reuses the exact gate decision and
// transparency log that the HTTP x402 PEP uses (package gateway): one trust-boundary
// core, two transports (HTTP requests and MCP tool-calls). A hijacked or
// prompt-injected tool-call that does not match the authorized payment is
// denied, and a signed transparency-log entry is emitted on every decision.
//
// No new trust-boundary code: the decision is gate.Evaluate and the evidence is
// translog.Log, unchanged from the published engine.
package mcpgate

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/rudizee007/spt-txn-pep/gate"
	"github.com/rudizee007/spt-txn-pep/translog"
)

// ToolCall is an agent's requested payment tool-call, plus the single-use
// authorization it presents.
type ToolCall struct {
	To       string   // recipient (base58 pubkey)
	Asset    string   // SPL mint (base58 pubkey)
	Amount   string   // atomic units, base-10 string
	Resource string   // resource id, bound byte-exact
	Nonce    [32]byte // single-use authorization nonce (jti)
	Expiry   time.Time
}

// Result is the enforcement outcome for one tool-call.
type Result struct {
	Class    gate.DecisionClass
	Reason   string
	LogEntry string // locator (seq:hashPrefix) in the transparency log
}

// Allowed reports whether the tool-call may proceed.
func (r Result) Allowed() bool { return r.Class == gate.Allow }

// Enforcer is the MCP-side policy-enforcement point. It shares the gate +
// translog core with the HTTP PEP; only the transport differs.
type Enforcer struct {
	Scheme    string
	Network   string
	Allowlist gate.Allowlist
	Policy    gate.PolicyVerifier
	Spend     gate.SpendLog
	Log       *translog.Log
	RKey      ed25519.PrivateKey
	Now       func() time.Time // injectable for tests; defaults to time.Now
}

func (e *Enforcer) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// Authorize decides ALLOW/DENY for a tool-call and emits a signed log entry on
// every path. It never performs the payment; ALLOW means the caller may proceed.
func (e *Enforcer) Authorize(c ToolCall) Result {
	pr := gate.PaymentRequirements{
		Scheme:            e.Scheme,
		Network:           e.Network,
		Asset:             c.Asset,
		PayTo:             c.To,
		MaxAmountRequired: c.Amount,
		Resource:          c.Resource,
	}
	tok := gate.Token{Nonce: c.Nonce, Expiry: c.Expiry}
	d := gate.Evaluate(e.Allowlist, pr, tok, e.Policy, e.Spend, e.now())
	entry, _ := e.Log.Append(e.RKey, translog.Decision(d.Class), d.Binding, e.now().Unix())
	h := entry.Record.Hash()
	return Result{
		Class:   d.Class,
		Reason:  d.Reason,
		LogEntry: fmt.Sprintf("%d:%x", entry.Record.Seq, h[:6]),
	}
}

// ExactPayment authorizes exactly one asset/recipient/resource up to a maximum
// amount — the single capability the human approved for the agent. Anything
// else is a policy DENY. It implements gate.PolicyVerifier.
type ExactPayment struct {
	Asset     string
	PayTo     string
	Resource  string
	MaxAmount uint64
}

// Verify returns nil (ALLOW) only if the requested payment matches the approved
// capability; otherwise a policy error (DENY_VIOLATION).
func (a ExactPayment) Verify(pr gate.PaymentRequirements, _ gate.Token) error {
	switch {
	case pr.Asset != a.Asset:
		return errors.New("asset not authorized")
	case pr.PayTo != a.PayTo:
		return errors.New("recipient not authorized")
	case pr.Resource != a.Resource:
		return errors.New("resource not authorized")
	}
	amt, err := strconv.ParseUint(pr.MaxAmountRequired, 10, 64)
	if err != nil {
		return errors.New("bad amount")
	}
	if amt > a.MaxAmount {
		return errors.New("amount over approved limit")
	}
	return nil
}
