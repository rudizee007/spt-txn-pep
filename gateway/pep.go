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
	return &p, nil
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
// next only on ALLOW. Every decision (ALLOW or DENY) emits a signed log entry.
func (p *PEP) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, ok := parseToken(r.Header.Get(HeaderToken))
		if !ok {
			http.Error(w, "missing or malformed X-SPT-Txn authorization", http.StatusUnauthorized)
			return
		}
		req := p.Requirements(r)
		d := gate.Evaluate(p.Allowlist, req, tok, p.Policy, p.Spend, p.now())

		// Two distinct artifacts, both emitted for every decision including
		// denials. The log entry orders and chains the decision; the receipt
		// records what authority governed it.
		entry, _ := p.Log.Append(p.RKey, translog.Decision(d.Class), d.Binding, p.now().Unix())

		// Evidence is a PRECONDITION of the decision, not a side effect. If the
		// receipt cannot be durably recorded we have no proof of what we
		// authorized, so an ALLOW becomes DENY/unavailable rather than
		// proceeding unrecorded. Failing open here would mean the one decision
		// nobody can audit is the one made while the evidence path was broken.
		if _, err := p.Evidence.Emit(p.receiptFor(d, tokenFingerprint(r.Header.Get(HeaderToken)))); err != nil {
			http.Error(w, "authorization unavailable: receipt not durably recorded", http.StatusServiceUnavailable)
			return
		}

		switch d.Class {
		case gate.Allow:
			w.Header().Set(HeaderLogEntry, logEntryTag(entry))
			next.ServeHTTP(w, r)
		case gate.DenyUnavailable:
			http.Error(w, "authorization unavailable: "+d.Reason, http.StatusServiceUnavailable)
		default: // DenyViolation
			http.Error(w, "authorization denied: "+d.Reason, http.StatusPaymentRequired)
		}
	})
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
