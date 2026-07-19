package gateway

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/rudizee007/spt-txn-x402-solana/receipt"
)

func TestTransparencyRootAndProof(t *testing.T) {
	_, rk, _ := ed25519.GenerateKey(nil)
	log := receipt.NewLog(rk.Public().(ed25519.PublicKey))
	if _, err := log.Append(rk, receipt.Allow, b32(0x11), 1); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(rk, receipt.DenyViolation, b32(0x22), 2); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(rk, receipt.Allow, b32(0x33), 3); err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer((&Transparency{Log: log}).Handler())
	defer ts.Close()

	// Root reflects the whole log.
	resp, err := http.Get(ts.URL + "/transparency/root")
	if err != nil {
		t.Fatal(err)
	}
	var rr rootResp
	json.NewDecoder(resp.Body).Decode(&rr)
	resp.Body.Close()
	if rr.Size != 3 || rr.Root == "" {
		t.Fatalf("root response: %+v", rr)
	}

	// Every receipt's inclusion proof verifies against that same root.
	for i := 0; i < 3; i++ {
		resp, err := http.Get(ts.URL + "/transparency/receipt/" + strconv.Itoa(i))
		if err != nil {
			t.Fatal(err)
		}
		var pr proofResp
		json.NewDecoder(resp.Body).Decode(&pr)
		resp.Body.Close()
		if !pr.Verified {
			t.Fatalf("receipt %d: proof did not verify", i)
		}
		if pr.Root != rr.Root {
			t.Fatalf("receipt %d: root mismatch", i)
		}
	}

	// Unknown receipt -> 404.
	r404, err := http.Get(ts.URL + "/transparency/receipt/99")
	if err != nil {
		t.Fatal(err)
	}
	r404.Body.Close()
	if r404.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown receipt, got %d", r404.StatusCode)
	}
}
