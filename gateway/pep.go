// Package gateway is a drop-in x402 authorization enforcement point (PEP): wrap
// any http.Handler and it enforces the SPT-Txn decision on every request, emits a
// signed transparency-log entry, and forwards to the protected resource only on
// ALLOW. It also serves the transparency log read-only (transparency.go).
//
// NOTE: a log entry is NOT the Transaction Receipt of draft-coetzee-oauth-spt-txn-
// tokens-03. See the translog package doc.
//
// It is built entirely on the gate + translog packages — no new trust-boundary
// code. The middleware is the adoption surface: any x402 resource server adds
// per-transaction authorization and a tamper-evident audit trail with one Wrap().
package gateway

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/rudizee007/spt-txn-pep/evidence"
	"github.com/rudizee007/spt-txn-pep/gate"
	"github.com/rudizee007/spt-txn-pep/translog"
)

// Header names for the presented authorization and the emitted log-entry tag.
const (
	HeaderToken    = "X-SPT-Txn"
	HeaderLogEntry = "X-SPT-Txn-Log-Entry"
)

// presentedToken is the SPT-Txn authorization a client presents, carried in the
// X-SPT-Txn header as base64(JSON). In production this is the full signed token
// verified against the trust registry; the PEP consumes the verified token and
// enforces the per-request decision (binding, policy, single-use).
type presentedToken struct {
	Nonce  string `json:"nonce"`  // 32-byte hex (jti)
	Expiry int64  `json:"expiry"` // unix seconds
}

// EncodeToken builds the X-SPT-Txn header value for a token (client-side helper).
func EncodeToken(nonce [32]byte, expiry time.Time) string {
	b, _ := json.Marshal(presentedToken{Nonce: hex.EncodeToString(nonce[:]), Expiry: expiry.Unix()})
	return base64.StdEncoding.EncodeToString(b)
}

// PEP enforces SPT-Txn authorization in front of a protected resource.
//
// Construct with NewPEP. Building the struct directly is unsupported: NewPEP is
// where the invariants are enforced, and the most important of them is that a
// PEP cannot exist without an evidence.Emitter.
type PEP struct {
	Allowlist gate.Allowlist
	Policy    gate.PolicyVerifier
	Spend     gate.SpendLog
	Log       *translog.Log
	RKey      ed25519.PrivateKey
	// Evidence emits the spec Transaction Receipt for every decision. Required —
	// see NewPEP. Use evidence.None{} to opt out explicitly.
	Evidence evidence.Emitter
	// Name identifies this enforcement point in emitted receipts.
	Name string
	// Requirements returns the x402 PaymentRequirements this resource demands for
	// a given request (asset, payTo, amount, resource...).
	Requirements func(*http.Request) gate.PaymentRequirements
	// Now is injectable for tests; defaults to time.Now.
	Now func() time.Time
	// Logf, if set, receives evidence-failure alarms and non-conformance
	// warnings; defaults to log.Printf. A library should not hardcode the global
	// logger, but it must still be able to shout when the audit path breaks.
	Logf func(format string, args ...any)

	// nonConformant is set by NewPEP when Evidence is a no-op (evidence.None).
	// Surfaced via Conformant(). Not caller-settable in any meaningful way.
	nonConformant bool
}

// NewPEP validates a PEP's configuration and returns it ready to Wrap.
//
// It refuses to build without an evidence.Emitter. draft-03 requires a PEP to
// emit a signed Transaction Receipt at every decision including denials, so a
// PEP that cannot emit one is not an SPT-Txn PEP. Refusing at construction makes
// that structural: there is no silent default under which evidence quietly stops
// being produced, and no runtime nil-check that a later refactor can delete.
//
// Deployments that genuinely do not want receipts pass evidence.None{} — an
// explicit, visible, non-conformant choice rather than an accident.
func NewPEP(p PEP) (*PEP, error) {
	switch {
	case p.Evidence == nil:
		return nil, errors.New("gateway: nil Evidence emitter — pass evidence.None{} to opt out explicitly")
	case p.Log == nil:
		return nil, errors.New("gateway: nil transparency Log")
	case len(p.RKey) != ed25519.PrivateKeySize:
		return nil, errors.New("gateway: bad log-signing key size")
	case p.Requirements == nil:
		return nil, errors.New("gateway: nil Requirements func")
	case p.Name == "":
		return nil, errors.New("gateway: empty Name — receipts must identify their PEP")
	}
	pep := &p
	// Make a no-op emitter a DETECTABLE, loud choice rather than a silent
	// fail-open. None is still accepted (an explicit test/demo opt-out), but the
	// PEP now records that it is non-conformant and shouts once at construction.
	if _, noop := p.Evidence.(evidence.Noop); noop {
		pep.nonConformant = true
		pep.logf("evidence: WARNING None emitter — this PEP records NO receipts and is NOT conformant with draft-03 (a receipt at every decision, including denials). Acceptable only as a deliberate test/demo/benchmark choice; a health endpoint SHOULD surface Conformant()==false.")
	} else if d, ok := p.Evidence.(evidence.Durable); ok && !d.Durable() {
		pep.logf("evidence: WARNING emitter reports Durable()==false — Emit may return before the receipt is durable, which voids the fail-closed guarantee that an ALLOW is served only once its receipt is durably recorded.")
	}
	return pep, nil
}

// Conformant reports whether this PEP emits real receipts. It is false only when
// the PEP was built with evidence.None{}. A health endpoint SHOULD surface this
// so a non-conformant deployment is visible rather than silent.
func (p *PEP) Conformant() bool { return !p.nonConformant }

// logf routes evidence alarms/warnings through the injected Logf, or the global
// logger by default. A broken audit path must never be silent.
func (p *PEP) logf(format string, args ...any) {
	if p.Logf != nil {
		p.Logf(format, args...)
		return
	}
	log.Printf(format, args...)
}

// receiptFor maps a gate decision onto the draft's receipt vocabulary. PERMIT/
// DENY and ok/violation/unavailable are the specified strings, not our own.
func (p *PEP) receiptFor(d gate.Decision, tokenHash string) evidence.Receipt {
	r := evidence.Receipt{
		PEP:          p.Name,
		Decision:     evidence.Deny,
		Class:        evidence.ClassViolation,
		RulePath:     d.Reason,
		TokenHash:    tokenHash,
		IntentDigest: hex.EncodeToString(d.Binding[:]),
	}
	switch d.Class {
	case gate.Allow:
		r.Decision, r.Class = evidence.Permit, evidence.ClassOK
	case gate.DenyUnavailable:
		r.Class = evidence.ClassUnavailable
	}
	return r
}

func (p *PEP) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// Wrap returns middleware that enforces the gate on each request and forwards to
// next only on ALLOW. Every decision on a PRESENTED token — allow and every
// denial — emits a signed receipt and a transparency-log entry. A request that
// presents no parseable token is refused (401) WITHOUT writing anchored evidence:
// recording unauthenticated requests would let anyone drive unbounded signing and
// chain growth, so that class is deferred behind admission control.
//
// Evidence posture (Option A, consistent with spt-txn-gateway):
//   - ALLOW is served only if BOTH evidence artifacts are durable. The receipt
//     (authority) is emitted FIRST, then the chain entry (ordering) is appended;
//     if either fails the request is 503 and — crucially — NO signed ALLOW is
//     left in the transparency chain for a request that was never served.
//     (Previously the entry was appended BEFORE Emit and its error discarded, so
//     an Emit failure left a signed ALLOW for a refused request.)
//   - A DENY is the fail-safe outcome: its evidence is recorded best-effort and a
//     failure is alarmed, but the denial still returns. Gating denials on durable
//     evidence would let anyone who breaks the evidence path halt all denials too
//     (a self-inflicted denial of service) without preventing any access a
//     402/401 doesn't.
func (p *PEP) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := r.Header.Get(HeaderToken)
		tok, ok := parseToken(raw)
		if !ok {
			// A request that never presented a parseable token has no authority to
			// record and no binding to chain. Signing a receipt and appending an
			// anchored chain entry here would let unauthenticated traffic drive
			// unbounded signing and grow the transparency chain without limit — an
			// amplification lever available to anyone. So this class is deliberately
			// NOT written into the anchored evidence; it is still refused,
			// fail-closed. Recording it belongs behind admission control (rate
			// limiting) and is left for a deliberate follow-up, not defaulted on.
			http.Error(w, "missing or malformed X-SPT-Txn authorization", http.StatusUnauthorized)
			return
		}
		req := p.Requirements(r)
		d := gate.Evaluate(p.Allowlist, req, tok, p.Policy, p.Spend, p.now())
		rc := p.receiptFor(d, tokenFingerprint(raw))

		if d.Class == gate.Allow {
			// Receipt first (authority), then chain entry (ordering). Both must be
			// durable before we serve; either failure is a 503, and no false ALLOW
			// is ever written to the chain. NOTE for auditors: a receipt-first
			// ordering means an Append failure can leave a durable PERMIT receipt
			// with no matching chain entry and no service — that pairing is an
			// evidence-incomplete signal (the request 503'd), not proof of service.
			if _, err := p.Evidence.Emit(rc); err != nil {
				http.Error(w, "authorization unavailable: receipt not durably recorded", http.StatusServiceUnavailable)
				return
			}
			entry, err := p.Log.Append(p.RKey, mapDecision(d.Class), d.Binding, p.now().Unix())
			if err != nil {
				http.Error(w, "authorization unavailable: decision not durably logged", http.StatusServiceUnavailable)
				return
			}
			w.Header().Set(HeaderLogEntry, logEntryTag(entry))
			next.ServeHTTP(w, r)
			return
		}

		// DENY (violation or unavailable): safe outcome. Record both artifacts
		// best-effort, alarm on failure, still deny.
		p.recordDeny(rc, mapDecision(d.Class), d.Binding)
		if d.Class == gate.DenyUnavailable {
			http.Error(w, "authorization unavailable: "+d.Reason, http.StatusServiceUnavailable)
		} else { // DenyViolation
			http.Error(w, "authorization denied: "+d.Reason, http.StatusPaymentRequired)
		}
	})
}

// recordDeny emits the receipt and appends the transparency-log entry for a
// denial. Both are best-effort and get the SAME failure posture — a failure is
// alarmed but never changes the denial outcome. This removes the earlier
// asymmetry where the log-append error was discarded while the receipt error was
// fatal.
func (p *PEP) recordDeny(rc evidence.Receipt, dec translog.Decision, binding [32]byte) {
	if _, err := p.Evidence.Emit(rc); err != nil {
		p.logf("EVIDENCE FAILURE (deny receipt, still denying): %v", err)
	}
	if _, err := p.Log.Append(p.RKey, dec, binding, p.now().Unix()); err != nil {
		p.logf("EVIDENCE FAILURE (deny log entry, still denying): %v", err)
	}
}

// mapDecision maps a gate decision class to the transparency-log decision
// EXPLICITLY. gate.DecisionClass and translog.Decision happen to share numeric
// values today, but that alignment is coincidental; a raw conversion would
// silently mislabel permanent, anchored evidence if either enum is ever
// reordered. The panic makes an unmapped class a build/test failure, not a
// signed lie in the chain.
func mapDecision(c gate.DecisionClass) translog.Decision {
	switch c {
	case gate.Allow:
		return translog.Allow
	case gate.DenyViolation:
		return translog.DenyViolation
	case gate.DenyUnavailable:
		return translog.DenyUnavailable
	default:
		panic(fmt.Sprintf("gateway: unmapped gate decision class %d", int(c)))
	}
}

func parseToken(h string) (gate.Token, bool) {
	var t gate.Token
	if h == "" {
		return t, false
	}
	raw, err := base64.StdEncoding.DecodeString(h)
	if err != nil {
		return t, false
	}
	var pt presentedToken
	if err := json.Unmarshal(raw, &pt); err != nil {
		return t, false
	}
	nb, err := hex.DecodeString(pt.Nonce)
	if err != nil || len(nb) != 32 {
		return t, false
	}
	copy(t.Nonce[:], nb)
	t.Expiry = time.Unix(pt.Expiry, 0)
	return t, true
}

// logEntryTag is a compact locator for the emitted entry in the transparency
// log: its sequence number plus a hash prefix.
func logEntryTag(e translog.Entry) string {
	h := e.Record.Hash()
	return fmt.Sprintf("%d:%s", e.Record.Seq, hex.EncodeToString(h[:8]))
}

// tokenFingerprint is the base64url SHA-256 of the presented token, as the draft
// requires ("the base64url SHA-256 hash of the presented token"). Empty when no
// token was presented. The token itself never reaches a receipt.
func tokenFingerprint(tok string) string {
	if tok == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(tok))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
