# `gate/` — the SPT-Txn x402 payment gate (Option 1, off-chain)

The gate decides **ALLOW / DENY for an x402 payment *before* any transaction is
signed**. It is the payer-side policy enforcement point: given an x402
`PaymentRequirements` and a verified SPT-Txn token, it computes the intent
binding, runs the pluggable policy, enforces single-use, and emits a decision
plus a binding for the evidence record. It never holds the resource server's
authority and never sends a payment itself (that is `settle/`).

Spec: [`../docs/SPEC-X402.md`](../docs/SPEC-X402.md). Read §4 before touching
`binding.go` — that file is the trust boundary.

## Files

| File | Role |
|---|---|
| `binding.go` | **Trust boundary.** The fixed-width, domain-separated intent binding (SPEC §4). Never hashes raw JSON. |
| `base58.go` | Base58 address decode (an encoding, not crypto), inlined so the gate has no third-party deps. |
| `gate.go` | The `Evaluate` decision function, the `ALLOW` / `DENY_VIOLATION` / `DENY_UNAVAILABLE` classes, and the `PolicyVerifier` + `SpendLog` interfaces. |
| `mem_spendlog.go` | In-memory single-instance spend log for tests/demo (durability caveats in SPEC §5). |
| `*_test.go` | KAT, field-flip, base58, amount, and the fail-closed matrix. |
| `kat/binding_ref.py` | **Independent** Python reference for the binding — the differential oracle. |

## What is bound (SPEC §4)

`scheme_tag` (allowlist enum) · `network_tag` (allowlist enum) · `asset` (32B) ·
`pay_to` (32B) · `amount` (u128 LE, 16B) · `resource` (SHA-256, byte-exact) ·
`nonce` (32B). Deliberately **not** bound: `extra.feePayer`, `maxTimeoutSeconds`,
`description`, `mimeType` — `feePayer` is pinned instead by the settle-side
pre-send assertion (SPEC §6.4).

## Run the tests

```sh
# Go unit + differential KAT + fail-closed matrix
go test ./gate/

# Regenerate / verify the independent binding vectors
python3 gate/kat/binding_ref.py
```

The KAT value in `binding_test.go` is produced by `kat/binding_ref.py`. If the Go
canonicalizer and the Python reference ever disagree on one byte,
`TestBindingKnownAnswer` fails — the canonicalization-mismatch bypass (threat
model risk #1) caught at build time.

## Status (M1)

Done: the binding canonicalizer, the decision function with both DENY classes,
single-use with spend-then-allow ordering, and the differential KAT + field-flip
tests. The KAT is verified against the independent Python reference. Next in M1:
the `settle/` `TransferChecked` pre-send assertion (SPEC §6.4), a local `mock/`
x402 resource-server + facilitator, and wiring `go test` + the KAT into CI.

> Note: this package now vendors the binding + decision core directly rather than
> importing `cmd/x402gate` from the reference repo, so the public repo builds and
> a judge reproduces it with no cross-repo checkout. The published 8-step verifier
> plugs in behind the `PolicyVerifier` interface.
