package gateway

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/rudizee007/spt-txn-x402-solana/receipt"
)

// Transparency serves the receipt log read-only: the current Merkle root (the
// value anchored on-chain) and a per-receipt inclusion proof. An auditor fetches
// the root, then proves any single decision belongs to it without seeing the
// others — the "compliance evidence as a service" surface.
type Transparency struct {
	Log *receipt.Log
}

type rootResp struct {
	Size int    `json:"size"`
	Root string `json:"merkle_root"`
}

type proofResp struct {
	Seq      int      `json:"seq"`
	Size     int      `json:"size"`
	Root     string   `json:"merkle_root"`
	Leaf     string   `json:"leaf_hex"` // canonical receipt bytes
	Proof    []string `json:"proof"`    // audit path, bottom-up (hex)
	Verified bool     `json:"verified"`
}

// Handler returns the transparency endpoints:
//
//	GET /transparency/root          -> {size, merkle_root}
//	GET /transparency/receipt/{seq} -> {seq, size, root, leaf, proof, verified}
func (t *Transparency) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/transparency/root", func(w http.ResponseWriter, r *http.Request) {
		root := t.Log.Root()
		writeJSON(w, rootResp{Size: t.Log.Len(), Root: hex.EncodeToString(root[:])})
	})

	mux.HandleFunc("/transparency/receipt/", func(w http.ResponseWriter, r *http.Request) {
		seq, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/transparency/receipt/"))
		if err != nil {
			http.Error(w, "bad sequence number", http.StatusBadRequest)
			return
		}
		rec, ok := t.Log.At(seq)
		if !ok {
			http.Error(w, "no such receipt", http.StatusNotFound)
			return
		}
		proof, err := t.Log.Proof(seq)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		root := t.Log.Root()
		leaf := rec.CanonicalBytes()
		ph := make([]string, len(proof))
		for i, h := range proof {
			ph[i] = hex.EncodeToString(h[:])
		}
		writeJSON(w, proofResp{
			Seq:      seq,
			Size:     t.Log.Len(),
			Root:     hex.EncodeToString(root[:]),
			Leaf:     hex.EncodeToString(leaf),
			Proof:    ph,
			Verified: receipt.VerifyInclusion(root, leaf, seq, t.Log.Len(), proof),
		})
	})

	return mux
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
