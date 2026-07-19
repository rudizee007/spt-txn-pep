package gateway

import (
	"crypto/ed25519"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
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

type allowAll struct{}

func (allowAll) Verify(gate.PaymentRequirements, gate.Token) error { return nil }

type denyPol struct{}

func (denyPol) Verify(gate.PaymentRequirements, gate.Token) error {
	return errors.New("amount over ceiling")
}

func fixedReq() gate.PaymentRequirements {
	return gate.PaymentRequirements{
		Scheme:            "exact",
		Network:           "solana:devnet",
		Asset:             "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
		PayTo:             "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
		MaxAmountRequired: "1000000",
		Resource:          "https://api.example.com/data",
	}
}

func newPEP(pol gate.PolicyVerifier, now time.Time) (*PEP, *receipt.Log) {
	_, rk, _ := ed25519.GenerateKey(nil)
	log := receipt.NewLog(rk.Public().(ed25519.PublicKey))
	return &PEP{
		Allowlist:    gate.Allowlist{Schemes: map[string]byte{"exact": 1}, Networks: map[string]byte{"solana:devnet": 2}},
		Policy:       pol,
		Spend:        gate.NewMemSpendLog(),
		Log:          log,
		RKey:         rk,
		Requirements: func(*http.Request) gate.PaymentRequirements { return fixedReq() },
		Now:          func() time.Time { return now },
	}, log
}

var protected = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	io.WriteString(w, "PREMIUM")
})

func doGet(t *testing.T, url, token string) (int, string, http.Header) {
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	if token != "" {
		req.Header.Set(HeaderToken, token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp.StatusCode, string(body), resp.Header
}

func TestPEP_AllowForwards(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	p, log := newPEP(allowAll{}, now)
	ts := httptest.NewServer(p.Wrap(protected))
	defer ts.Close()

	code, body, hdr := doGet(t, ts.URL, EncodeToken(b32(0x5A), now.Add(time.Minute)))
	if code != http.StatusOK || body != "PREMIUM" {
		t.Fatalf("expected 200 PREMIUM, got %d %q", code, body)
	}
	if hdr.Get(HeaderReceipt) == "" {
		t.Fatal("expected a receipt header on ALLOW")
	}
	if log.Len() != 1 {
		t.Fatalf("expected 1 receipt, got %d", log.Len())
	}
}

func TestPEP_DenyBlocks(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	p, log := newPEP(denyPol{}, now)
	ts := httptest.NewServer(p.Wrap(protected))
	defer ts.Close()

	code, body, _ := doGet(t, ts.URL, EncodeToken(b32(0x6B), now.Add(time.Minute)))
	if code != http.StatusPaymentRequired {
		t.Fatalf("expected 402, got %d", code)
	}
	if body == "PREMIUM" {
		t.Fatal("resource must not be served on DENY")
	}
	if log.Len() != 1 {
		t.Fatal("a DENY must still emit a receipt")
	}
}

func TestPEP_ReplayBlocks(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	p, _ := newPEP(allowAll{}, now)
	ts := httptest.NewServer(p.Wrap(protected))
	defer ts.Close()
	tok := EncodeToken(b32(0x5A), now.Add(time.Minute))

	if code, _, _ := doGet(t, ts.URL, tok); code != http.StatusOK {
		t.Fatalf("first request should be 200, got %d", code)
	}
	if code, _, _ := doGet(t, ts.URL, tok); code != http.StatusPaymentRequired {
		t.Fatalf("replay should be 402, got %d", code)
	}
}

func TestPEP_MissingToken(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	p, _ := newPEP(allowAll{}, now)
	ts := httptest.NewServer(p.Wrap(protected))
	defer ts.Close()
	if code, _, _ := doGet(t, ts.URL, ""); code != http.StatusUnauthorized {
		t.Fatalf("missing token should be 401, got %d", code)
	}
}
