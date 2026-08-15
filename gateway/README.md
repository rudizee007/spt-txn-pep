# `gateway/` — drop-in x402 authorization (PEP) + transparency log

Two adoption-surface pieces, both thin wrappers over the proven `gate` + `translog`
packages — no new trust-boundary code.

## PEP middleware (`pep.go`)

Wrap any `http.Handler` and it enforces the SPT-Txn decision on every request,
emits a Transaction Receipt **and** a signed transparency-log entry, and forwards
to the protected resource **only on ALLOW**.

```go
pep, err := gateway.NewPEP(gateway.PEP{
    Name:         "my-resource-server", // identifies this PEP in every receipt
    Evidence:     myEmitter,            // evidence.Emitter — required
    Allowlist:    al,                   // accepted (scheme, network) tags
    Policy:       myPolicy,             // your OPA / Sumsub / in-house engine
    Spend:        gate.NewMemSpendLog(),
    Log:          transparencyLog,
    RKey:         logSigningKey,
    Requirements: func(r *http.Request) gate.PaymentRequirements { ... },
})
if err != nil {
    return err
}
http.Handle("/premium", pep.Wrap(myResourceHandler))
```

**Always construct through `NewPEP`.** A bare `&gateway.PEP{...}` literal skips
validation and leaves `Evidence` nil, and the first authorized request panics.
`NewPEP` refuses to build without an emitter, because draft-03 requires a
receipt at every decision — a PEP that cannot emit one is not an SPT-Txn PEP.

Deployments that genuinely want no receipts pass `evidence.None{}`. That is a
visible, non-conformant choice rather than an accident: `NewPEP` warns once, and
`pep.Conformant()` reports `false` so a health endpoint can surface it. An
emitter that reports `evidence.Durable() == false` is warned about too, since
the fail-closed guarantee is only as strong as that answer.

The client presents its authorization in the `X-SPT-Txn` header. Outcomes:

- **ALLOW** → resource served, `X-SPT-Txn-Log-Entry` header set. The receipt is
  emitted and the chain entry appended *before* the resource is served; if
  either is not durable the request gets `503` and nothing false is written.
- **DENY (violation)** → `402 Payment Required` with the reason.
- **DENY (unavailable)** → `503` — an outage, distinct from a violation.
- **Missing/malformed authorization** → `401`.

A single-use token replayed to the PEP is refused (nonce spend-log), so the
per-transaction authorization model is enforced at the edge.

## Transparency log (`transparency.go`)

Serves the transparency log read-only — the "compliance evidence as a service" surface:

```
GET /transparency/root          -> { size, merkle_root }
GET /transparency/entry/{seq} -> { seq, size, root, leaf, proof, verified }
```

The `merkle_root` is the value that gets anchored on-chain — a periodic write,
never a read in the decision path. An auditor fetches the root, then proves any
single decision belongs to it via its inclusion proof, without seeing the other
entries.

## Run it

```sh
go test ./gateway/
```

This module is a library and ships no commands. A runnable end-to-end demo —
an authorized request served, a replay refused, an over-scope request denied, a
missing authorization rejected, then the root and a verifiable inclusion proof —
lives in the `spt-txn-x402-solana` repository under `cmd/gateway`.

Note that a request presenting **no** parseable token is refused without a
receipt or a chain entry, deliberately: unauthenticated traffic must not be able
to drive unbounded signing or grow the transparency chain. So five requests of
the shape above produce four records, not five.
