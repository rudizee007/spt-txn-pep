// Package gateway is a drop-in x402 authorization enforcement point (PEP): wrap
// any http.Handler and it enforces the SPT-Txn decision on every request, emits a
// signed receipt, and forwards to the protected resource only on ALLOW. It also
// serves the receipt transparency log (transparency.go).
//
// It is built entirely on the gate + receipt packages — no new trust-boundary
// code. The middleware is the adoption surface: any x402 resource server adds
// per-transaction authorization and a tamper-evident audit trail with one Wrap().
package gateway

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/rudizee007/spt-txn-x402-solana/gate"
	"github.com/rudizee007/spt-txn-x402-solana/receipt"
)

// Header names for the presented authorization and the emitted receipt tag.
const (
	HeaderToken   = "X-SPT-Txn"
	HeaderReceipt = "X-SPT-Txn-Receipt"
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
type PEP struct {
	Allowlist gate.Allowlist
	Policy    gate.PolicyVerifier
	Spend     gate.SpendLog
	Log       *receipt.Log
	RKey      ed25519.PrivateKey
	// Requirements returns the x402 PaymentRequirements this resource demands for
	// a given request (asset, payTo, amount, resource...).
	Requirements func(*http.Request) gate.PaymentRequirements
	// Now is injectable for tests; defaults to time.Now.
	Now func() time.Time
}

func (p *PEP) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// Wrap returns middleware that enforces the gate on each request and forwards to
// next only on ALLOW. Every decision (ALLOW or DENY) emits a signed receipt.
func (p *PEP) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, ok := parseToken(r.Header.Get(HeaderToken))
		if !ok {
			http.Error(w, "missing or malformed X-SPT-Txn authorization", http.StatusUnauthorized)
			return
		}
		req := p.Requirements(r)
		d := gate.Evaluate(p.Allowlist, req, tok, p.Policy, p.Spend, p.now())

		// Evidence as a byproduct: a signed, chained receipt for every decision.
		entry, _ := p.Log.Append(p.RKey, receipt.Decision(d.Class), d.Binding, p.now().Unix())

		switch d.Class {
		case gate.Allow:
			w.Header().Set(HeaderReceipt, receiptTag(entry))
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

// receiptTag is a compact locator for the emitted receipt in the transparency
// log: its sequence number plus a hash prefix.
func receiptTag(e receipt.Entry) string {
	h := e.Receipt.Hash()
	return fmt.Sprintf("%d:%s", e.Receipt.Seq, hex.EncodeToString(h[:8]))
}
