# SPT-Txn — enforcement points

**Zero dependencies. Chain-agnostic. One `Wrap()`.**

Per-transaction authorization and a tamper-evident audit trail for any HTTP
resource server or MCP tool server. `go.mod` has no `require` block: this module
depends on nothing but the Go standard library, and it is going to stay that way.

```go
pep := &gateway.PEP{ /* ... */ }
http.ListenAndServe(":8080", pep.Wrap(yourHandler))
```

Every request is authorized against a declared transaction, a signed Transaction
Receipt and a transparency-log entry are recorded, and the request reaches the
protected resource **only on ALLOW**.

## Two artifacts, two questions

Every decision — including a denial — produces both:

- A **Transaction Receipt** (`evidence`) records *what authority governed this
  decision*: PEP identity, decision class, rule path, policy hash, jurisdiction.
- A **transparency-log entry** (`translog`) records *where that decision sits* in
  a hash-chained, inclusion-provable RFC 6962 Merkle log.

They compose. Neither substitutes for the other.

The receipt is a seam rather than an implementation: `evidence` is an interface,
a struct of strings and an explicit no-op — no crypto, no canonicalization, no
imports at all. The reference implementation lives in
[`spt-txn-poc/pkg/receipt`](https://github.com/rudizee007/spt-txn-poc), next to
the verifier, because the canonicalizer is the primary bypass surface and issuer
and verifier must be the same version *by construction*, not by convention.
Depending on it from here would also drag a zero-knowledge-proof stack into the
dependency graph of anyone who only wanted middleware. So the dependency points
the other way: this module defines the interface, the engine implements it, and
a deployment may supply its own.

Evidence is a precondition of the decision, not a side effect. An `Emit` error
means "not durably recorded", and the PEP must answer `DENY`/`unavailable`
rather than proceed. A PEP constructed without an `Emitter` is refused outright,
and `evidence.None` — the deliberate "no receipts" choice — is *detectable* at
runtime, so a deployment cannot quietly drift into non-conformance.

## What's here

| Package | What it does |
|---|---|
| `gate` | The decision core: offline intent binding, `ALLOW` / `DENY_VIOLATION` / `DENY_UNAVAILABLE` |
| `evidence` | The **Transaction Receipt** seam — interface, draft-03 field set, detectable no-op. Zero imports. |
| `translog` | Hash-chained records + RFC 6962 Merkle transparency log; concurrency-safe under per-request goroutines |
| `gateway` | **HTTP PEP** — `PEP.Wrap(http.Handler)` middleware, plus a transparency-log HTTP service |
| `mcpgate` | **MCP PEP** — the same decision core enforcing agent tool calls |

Both enforcement points call the same `gate`. Neither holds policy logic of its own.

## Why this is a separate module

These packages were extracted from `spt-txn-x402-solana`, where adopting the
middleware meant pulling `solana-go` and ~28 indirect dependencies — a blockchain
SDK and a Mongo driver — into the dependency graph of anyone who only wanted
per-transaction authorization.

SPT-Txn is chain-agnostic. This module makes that **structural rather than
asserted**: the dependency direction runs one way, from chain-specific consumers
*to* this module, never back. If anything here ever needs a chain, the claim is
gone.

## Licence and scope

Apache-2.0. **Enforcement points are free** — running one costs nothing, and it
always will. What is commercial is operating a *fleet* of them and proving
compliance with them: the control plane (issuer registry, revocation
distribution, trust-snapshot hosting), receipt aggregation and retention, control
mappings and compliance packs.

Security features are never gated. Verifying a status list and pinning a trust
snapshot are free; hosting and distributing them at fleet scale is not.

## Specification

`draft-coetzee-oauth-spt-txn-tokens-03` —
https://datatracker.ietf.org/doc/draft-coetzee-oauth-spt-txn-tokens/

Datatracker is the single source of truth for the draft version.

Reference implementation: https://github.com/rudizee007/spt-txn-poc

## Status — read this before relying on it

**Proof of concept. Not externally audited. Not for production use.**

On the project's assurance ladder these packages sit at *tested and adversarially
reviewed*; independent audit and production hardening are the next steps, and
neither has happened. "Adversarially reviewed" here means AI-agent review plus the
maintainer's own analysis — not an assessment by an independent security firm.

## Contributing

Trust-boundary changes (the decision path, intent binding, receipt signing) are
reviewed spec-first and adversarially before merge. Please open an issue
describing the gap before sending a PR that touches `gate`, `evidence` or
`translog`.

**Do not add a third-party dependency to this module without discussion.** The
absence of one is a feature, not an oversight.
