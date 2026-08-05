package gateway

import (
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rudizee007/spt-txn-pep/evidence"
	"github.com/rudizee007/spt-txn-pep/gate"
	"github.com/rudizee007/spt-txn-pep/translog"
)

// recorder captures emitted receipts; failNext makes the next Emit fail.
type recorder struct {
	got  []evidence.Receipt
	fail bool
}

func (e *recorder) Emit(r evidence.Receipt) (string, error) {
	if e.fail {
		return "", errors.New("log unreachable")
	}
	e.got = append(e.got, r)
	return "loc-" + r.Decision, nil
}

// tokenReq builds a request carrying a valid, unique presented token.
func tokenReq(now time.Time, seed byte) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "https://api.example.com/data", nil)
	req.Header.Set(HeaderToken, EncodeToken(b32(seed), now.Add(time.Minute)))
	return req
}

func pepWith(t *testing.T, em evidence.Emitter, pol gate.PolicyVerifier, now time.Time) *PEP {
	t.Helper()
	_, rk, _ := ed25519.GenerateKey(nil)
	p, err := NewPEP(PEP{
		Allowlist:    gate.Allowlist{Schemes: map[string]byte{"exact": 1}, Networks: map[string]byte{"solana:devnet": 2}},
		Policy:       pol,
		Spend:        gate.NewMemSpendLog(),
		Log:          translog.NewLog(rk.Public().(ed25519.PublicKey)),
		RKey:         rk,
		Requirements: func(*http.Request) gate.PaymentRequirements { return fixedReq() },
		Now:          func() time.Time { return now },
		Evidence:     em,
		Name:         "pep.test",
	})
	if err != nil {
		t.Fatalf("NewPEP: %v", err)
	}
	return p
}

// A PEP that cannot emit evidence is not an SPT-Txn PEP. Refusing at
// construction is what makes that structural rather than a runtime check a
// refactor could delete.
func TestNewPEP_RefusesWithoutEmitter(t *testing.T) {
	_, rk, _ := ed25519.GenerateKey(nil)
	base := PEP{
		Log:          translog.NewLog(rk.Public().(ed25519.PublicKey)),
		RKey:         rk,
		Requirements: func(*http.Request) gate.PaymentRequirements { return fixedReq() },
		Name:         "pep.test",
	}
	if _, err := NewPEP(base); err == nil {
		t.Fatal("must refuse to build a PEP with no Evidence emitter")
	}

	// Opting out has to be possible — but explicitly.
	base.Evidence = evidence.None{}
	if _, err := NewPEP(base); err != nil {
		t.Fatalf("evidence.None{} must be an accepted explicit opt-out: %v", err)
	}
}

func TestNewPEP_ValidatesTheRest(t *testing.T) {
	_, rk, _ := ed25519.GenerateKey(nil)
	ok := PEP{
		Log:          translog.NewLog(rk.Public().(ed25519.PublicKey)),
		RKey:         rk,
		Requirements: func(*http.Request) gate.PaymentRequirements { return fixedReq() },
		Evidence:     evidence.None{},
		Name:         "pep.test",
	}
	for name, mutate := range map[string]func(p *PEP){
		"nil log":          func(p *PEP) { p.Log = nil },
		"short key":        func(p *PEP) { p.RKey = ed25519.PrivateKey{1, 2, 3} },
		"nil requirements": func(p *PEP) { p.Requirements = nil },
		"empty name":       func(p *PEP) { p.Name = "" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := ok
			mutate(&bad)
			if _, err := NewPEP(bad); err == nil {
				t.Fatalf("must refuse: %s", name)
			}
		})
	}
}

// The draft requires a receipt at EVERY decision, including denials. A denial is
// the evidence that matters most, so it is the case worth pinning.
func TestWrap_EmitsReceiptOnAllowAndDeny(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)

	t.Run("allow -> PERMIT/ok", func(t *testing.T) {
		em := &recorder{}
		p := pepWith(t, em, allowAll{}, now)
		rr := httptest.NewRecorder()
		p.Wrap(protected).ServeHTTP(rr, tokenReq(now, 0x5A))

		if len(em.got) != 1 {
			t.Fatalf("want 1 receipt, got %d", len(em.got))
		}
		r := em.got[0]
		if r.Decision != evidence.Permit || r.Class != evidence.ClassOK {
			t.Errorf("want PERMIT/ok, got %s/%s", r.Decision, r.Class)
		}
		if r.PEP != "pep.test" {
			t.Errorf("receipt must identify the PEP, got %q", r.PEP)
		}
		if r.TokenHash == "" {
			t.Error("a presented token must produce a token hash")
		}
		if r.IntentDigest == "" {
			t.Error("the bound intent digest must be recorded")
		}
	})

	t.Run("deny -> DENY/violation", func(t *testing.T) {
		em := &recorder{}
		p := pepWith(t, em, denyPol{}, now)
		rr := httptest.NewRecorder()
		p.Wrap(protected).ServeHTTP(rr, tokenReq(now, 0x5A))

		if len(em.got) != 1 {
			t.Fatalf("a denial MUST still emit a receipt; got %d", len(em.got))
		}
		if r := em.got[0]; r.Decision != evidence.Deny || r.Class != evidence.ClassViolation {
			t.Errorf("want DENY/violation, got %s/%s", r.Decision, r.Class)
		}
	})
}

// Evidence is a precondition of the decision, not a side effect. If the receipt
// cannot be recorded, an ALLOW must NOT proceed — otherwise the one decision
// nobody can audit is the one made while the evidence path was broken.
func TestWrap_FailsClosedWhenEvidenceCannotBeRecorded(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	em := &recorder{fail: true}
	p := pepWith(t, em, allowAll{}, now) // policy ALLOWS

	reached := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true })

	rr := httptest.NewRecorder()
	p.Wrap(next).ServeHTTP(rr, tokenReq(now, 0x7C))

	if reached {
		t.Fatal("protected resource was reached despite the receipt failing to record")
	}
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("want 503 (unavailable, not violation), got %d", rr.Code)
	}
}

// The token itself must never reach a receipt — only its hash.
func TestReceipt_CarriesHashNotToken(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	em := &recorder{}
	p := pepWith(t, em, allowAll{}, now)
	req := tokenReq(now, 0x3D)
	raw := req.Header.Get(HeaderToken)

	p.Wrap(protected).ServeHTTP(httptest.NewRecorder(), req)

	if len(em.got) != 1 {
		t.Fatalf("want 1 receipt, got %d", len(em.got))
	}
	if em.got[0].TokenHash == raw {
		t.Fatal("receipt carries the raw token instead of its hash")
	}
	if tokenFingerprint("") != "" {
		t.Error("no token must yield no hash")
	}
}
