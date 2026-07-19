# `gateway/` — drop-in x402 authorization (PEP) + transparency log

Two adoption-surface pieces, both thin wrappers over the proven `gate` + `receipt`
packages — no new trust-boundary code.

## PEP middleware (`pep.go`)

Wrap any `http.Handler` and it enforces the SPT-Txn decision on every request,
emits a signed receipt, and forwards to the protected resource **only on ALLOW**.

```go
pep := &gateway.PEP{
    Allowlist:    al,             // accepted (scheme, network) tags
    Policy:       myPolicy,       // your OPA / Sumsub / in-house engine
    Spend:        gate.NewMemSpendLog(),
    Log:          receiptLog,
    RKey:         receiptSigningKey,
    Requirements: func(r *http.Request) gate.PaymentRequirements { ... },
}
http.Handle("/premium", pep.Wrap(myResourceHandler))
```

The client presents its authorization in the `X-SPT-Txn` header. Outcomes:

- **ALLOW** → resource served, `X-SPT-Txn-Receipt` header set.
- **DENY (violation)** → `402 Payment Required` with the reason.
- **DENY (unavailable)** → `503` — an outage, distinct from a violation.
- **Missing/malformed authorization** → `401`.

A single-use token replayed to the PEP is refused (nonce spend-log), so the
per-transaction authorization model is enforced at the edge.

## Transparency log (`transparency.go`)

Serves the receipt log read-only — the "compliance evidence as a service" surface:

```
GET /transparency/root          -> { size, merkle_root }
GET /transparency/receipt/{seq} -> { seq, size, root, leaf, proof, verified }
```

The `merkle_root` is the value anchored on-chain (see `cmd/anchordevnet`). An
auditor fetches the root, then proves any single decision belongs to it via its
inclusion proof — without seeing the other receipts.

## Run the demo

```sh
go test ./gateway/
go run ./cmd/gateway
```

The demo shows an authorized request served, a replay refused, an over-scope
request denied, a missing-authorization rejected, and then the anchorable root
plus a verifiable inclusion proof.
