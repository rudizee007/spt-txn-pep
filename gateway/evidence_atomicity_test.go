package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rudizee007/spt-txn-pep/evidence"
	"github.com/rudizee007/spt-txn-pep/gate"
	"github.com/rudizee007/spt-txn-pep/translog"
)

// When an ALLOW's receipt cannot be recorded, the request 503s AND no signed
// ALLOW is left in the transparency chain. (Previously the chain entry was
// appended before Emit and its error discarded, so a failed Emit left a provable
// ALLOW for a request that was refused and never served.)
func TestWrap_AllowEmitFailure_LeavesNoChainEntry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	em := &recorder{fail: true}
	p := pepWith(t, em, allowAll{}, now)

	reached := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true })
	rr := httptest.NewRecorder()
	p.Wrap(next).ServeHTTP(rr, tokenReq(now, 0x11))

	if reached {
		t.Fatal("served an ALLOW whose receipt failed to record")
	}
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d", rr.Code)
	}
	if p.Log.Len() != 0 {
		t.Fatalf("no ALLOW entry may be chained when evidence fails, got %d", p.Log.Len())
	}
}

// A DENY whose evidence cannot be recorded still DENIES (402), rather than being
// converted to 503. Gating denials on durable evidence would let a broken
// evidence path halt all denials — a self-inflicted denial of service — without
// preventing any access a 402 doesn't. The two evidence errors now share this
// best-effort posture (no more discard-one/fatal-the-other asymmetry).
func TestWrap_DenyEmitFailure_StillDenies(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	em := &recorder{fail: true}
	p := pepWith(t, em, denyPol{}, now)

	rr := httptest.NewRecorder()
	p.Wrap(protected).ServeHTTP(rr, tokenReq(now, 0x22))

	if rr.Code != http.StatusPaymentRequired {
		t.Fatalf("a DENY must still return 402 even when evidence fails, got %d", rr.Code)
	}
	if p.Log.Len() != 1 {
		t.Fatalf("the deny log entry should still be appended (append did not fail), got %d", p.Log.Len())
	}
}

// A request with no parseable token must be refused (401) WITHOUT writing
// anchored evidence — signing a receipt and appending a chain entry for
// unauthenticated traffic is an amplification lever. This test guards against
// re-introducing that.
func TestWrap_NoToken_RecordsNothing(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	em := &recorder{}
	p := pepWith(t, em, allowAll{}, now)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://api.example.com/data", nil) // no token
	p.Wrap(protected).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rr.Code)
	}
	if len(em.got) != 0 {
		t.Fatalf("no-token must emit NO receipt (amplification lever), got %d", len(em.got))
	}
	if p.Log.Len() != 0 {
		t.Fatalf("no-token must append NO chain entry, got %d", p.Log.Len())
	}
}

// mapDecision must map every gate class explicitly, so a future enum reorder
// fails here rather than silently mislabeling anchored evidence.
func TestMapDecision(t *testing.T) {
	for in, want := range map[gate.DecisionClass]translog.Decision{
		gate.Allow:           translog.Allow,
		gate.DenyViolation:   translog.DenyViolation,
		gate.DenyUnavailable: translog.DenyUnavailable,
	} {
		if got := mapDecision(in); got != want {
			t.Errorf("mapDecision(%d) = %d, want %d", int(in), got, want)
		}
	}
}

// None is a DETECTABLE, non-conformant choice — not a silent fail-open. A PEP
// built with None still constructs (explicit opt-out) but reports
// Conformant()==false; a real emitter reports true.
func TestNewPEP_ConformanceIsVisible(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)

	pNone := pepWith(t, evidence.None{}, allowAll{}, now)
	if pNone.Conformant() {
		t.Error("a PEP built with evidence.None{} must report Conformant()==false")
	}
	pReal := pepWith(t, &recorder{}, allowAll{}, now)
	if !pReal.Conformant() {
		t.Error("a PEP built with a real emitter must report Conformant()==true")
	}
	if _, ok := evidence.Emitter(evidence.None{}).(evidence.Noop); !ok {
		t.Error("evidence.None must implement evidence.Noop so a PEP can detect it")
	}
}
