package gate

import (
	"encoding/hex"
	"math/big"
	"testing"
)

// bytes32 returns a [32]byte filled with b (test helper).
func bytes32(b byte) [32]byte {
	var a [32]byte
	for i := range a {
		a[i] = b
	}
	return a
}

func must(b [32]byte, err error) [32]byte {
	if err != nil {
		panic(err)
	}
	return b
}

// TestBindingKnownAnswer is the differential KAT: the value below is produced by
// an INDEPENDENT implementation (gate/kat/binding_ref.py). If the Go
// canonicalizer and the Python reference disagree on a single byte, this fails —
// which is exactly the canonicalization-mismatch bypass we are guarding against.
func TestBindingKnownAnswer(t *testing.T) {
	got := must(computeBindingRaw(
		1, 2,
		bytes32(0x11), bytes32(0x22),
		big.NewInt(1_000_000),
		"https://api.example.com/resource",
		bytes32(0x5A),
	))
	const want = "1b05fa44923f7265a43e58730bacb4a888f0d89cffe23c084c33697c7406bdeb"
	if hex.EncodeToString(got[:]) != want {
		t.Fatalf("binding KAT mismatch:\n  got  %s\n  want %s\n(regenerate/verify with gate/kat/binding_ref.py)",
			hex.EncodeToString(got[:]), want)
	}
}

// TestBindingFieldFlip asserts every bound field changes the binding. The
// resource flip (trailing slash) also proves we do NOT silently normalize URLs.
func TestBindingFieldFlip(t *testing.T) {
	base := must(computeBindingRaw(1, 2, bytes32(0x11), bytes32(0x22), big.NewInt(1_000_000), "https://api.example.com/resource", bytes32(0x5A)))
	flips := []struct {
		name string
		got  [32]byte
	}{
		{"scheme", must(computeBindingRaw(2, 2, bytes32(0x11), bytes32(0x22), big.NewInt(1_000_000), "https://api.example.com/resource", bytes32(0x5A)))},
		{"network", must(computeBindingRaw(1, 3, bytes32(0x11), bytes32(0x22), big.NewInt(1_000_000), "https://api.example.com/resource", bytes32(0x5A)))},
		{"asset", must(computeBindingRaw(1, 2, bytes32(0x12), bytes32(0x22), big.NewInt(1_000_000), "https://api.example.com/resource", bytes32(0x5A)))},
		{"payTo", must(computeBindingRaw(1, 2, bytes32(0x11), bytes32(0x23), big.NewInt(1_000_000), "https://api.example.com/resource", bytes32(0x5A)))},
		{"amount", must(computeBindingRaw(1, 2, bytes32(0x11), bytes32(0x22), big.NewInt(1_000_001), "https://api.example.com/resource", bytes32(0x5A)))},
		{"resource", must(computeBindingRaw(1, 2, bytes32(0x11), bytes32(0x22), big.NewInt(1_000_000), "https://api.example.com/resource/", bytes32(0x5A)))},
		{"nonce", must(computeBindingRaw(1, 2, bytes32(0x11), bytes32(0x22), big.NewInt(1_000_000), "https://api.example.com/resource", bytes32(0x5B)))},
	}
	for _, f := range flips {
		if f.got == base {
			t.Errorf("flipping %q did not change the binding", f.name)
		}
	}
}

// TestDecodePubkey32 freezes a real base58 → 32-byte vector (mainnet USDC mint),
// cross-checked against the Python reference.
func TestDecodePubkey32(t *testing.T) {
	pk, err := decodePubkey32("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")
	if err != nil {
		t.Fatal(err)
	}
	const want = "c6fa7af3bedbad3a3d65f36aabc97431b1bbe4c2d2f6e0e47ca60203452f5d61"
	if hex.EncodeToString(pk[:]) != want {
		t.Fatalf("USDC mint decode: got %s want %s", hex.EncodeToString(pk[:]), want)
	}
	if _, err := decodePubkey32("0OIl"); err == nil { // 0,O,I,l are not in base58
		t.Fatal("expected invalid base58 error")
	}
	if _, err := decodePubkey32("abc"); err == nil { // valid base58, wrong length
		t.Fatal("expected wrong-length error")
	}
}

// TestAmount16LE covers little-endianness, the u128 ceiling, and rejection of
// negative / overflowing amounts (no silent truncation on the money path).
func TestAmount16LE(t *testing.T) {
	one, err := amount16LE(big.NewInt(1))
	if err != nil {
		t.Fatal(err)
	}
	if one[0] != 1 || one[15] != 0 {
		t.Fatalf("little-endian encoding wrong: %x", one)
	}

	max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1))
	le, err := amount16LE(max)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(le[:]) != "ffffffffffffffffffffffffffffffff" {
		t.Fatalf("u128 max LE = %s", hex.EncodeToString(le[:]))
	}

	if _, err := amount16LE(new(big.Int).Lsh(big.NewInt(1), 128)); err != ErrAmountOverflow {
		t.Fatalf("expected ErrAmountOverflow, got %v", err)
	}
	if _, err := amount16LE(big.NewInt(-1)); err != ErrAmountNegative {
		t.Fatalf("expected ErrAmountNegative, got %v", err)
	}
}

// TestComputeBindingAllowlistPath exercises the full parse path and its
// fail-closed edges (unknown scheme/network, non-integer amount).
func TestComputeBindingAllowlistPath(t *testing.T) {
	al := Allowlist{
		Schemes:  map[string]byte{"exact": 1},
		Networks: map[string]byte{"solana:devnet": 2},
	}
	pr := PaymentRequirements{
		Scheme:            "exact",
		Network:           "solana:devnet",
		Asset:             "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
		PayTo:             "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
		MaxAmountRequired: "1000000",
		Resource:          "https://api.example.com/resource",
	}
	if _, err := ComputeBinding(al, pr, bytes32(0x5A)); err != nil {
		t.Fatalf("well-formed request should bind: %v", err)
	}

	bad := pr
	bad.Scheme = "upto"
	if _, err := ComputeBinding(al, bad, bytes32(0x5A)); err != ErrUnknownScheme {
		t.Fatalf("expected ErrUnknownScheme, got %v", err)
	}
	bad = pr
	bad.Network = "ethereum:1"
	if _, err := ComputeBinding(al, bad, bytes32(0x5A)); err != ErrUnknownNetwork {
		t.Fatalf("expected ErrUnknownNetwork, got %v", err)
	}
	bad = pr
	bad.MaxAmountRequired = "12.5"
	if _, err := ComputeBinding(al, bad, bytes32(0x5A)); err != ErrBadAmount {
		t.Fatalf("expected ErrBadAmount, got %v", err)
	}
}
