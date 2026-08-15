# The presentation seam — what the enforcement point checks, and what it doesn't

**Status: design note. Describes the current state accurately and specifies the
work to close the gap. Nothing here is implemented yet.**

This module ships an enforcement point. The reference engine
(`spt-txn-poc`) ships an eight-step offline verifier. They are not connected,
and this note says exactly where the join goes, what it costs, and the one way
of doing it that would introduce a vulnerability.

---

## 1. What the enforcement point checks today

`gateway.PEP.Wrap` runs, for every request:

- **Allowlist** — the `(scheme, network)` pair must be one this deployment accepts.
- **Binding** — a fixed-width digest over scheme, network, asset, payTo, amount,
  resource and nonce, so a decision is about *one* payment and not a class of them.
- **Single use** — the nonce is recorded in a `SpendLog` before ALLOW; a replay
  is refused.
- **Freshness** — expiry against an injectable clock.
- **Policy** — delegated to a `gate.PolicyVerifier` the deployment supplies.
- **Evidence** — a Transaction Receipt and a signed, hash-chained transparency-log
  entry, both durable before the resource is served.

Deny-by-default and fail-closed throughout: an evidence failure on the ALLOW path
is a `503`, not a served request.

## 2. What it does not check

**It does not verify a credential.** The presented token is:

```go
func EncodeToken(nonce [32]byte, expiry time.Time) string {
	b, _ := json.Marshal(presentedToken{Nonce: hex..., Expiry: expiry.Unix()})
	return base64.StdEncoding.EncodeToString(b)
}
```

Base64 of a two-field JSON object. No signature, no issuer, no CAT, no
delegation chain, no DPoP proof. `parseToken` decodes those two fields into
`gate.Token{Nonce, Expiry}` and nothing else.

Consequently `PolicyVerifier.Verify(pr PaymentRequirements, tok Token) error`
receives **no credential to verify**. A policy backed by the SPT-Txn verifier
cannot be written against this interface — it would be handed a nonce and an
expiry and asked to run an eight-step verification against a token it cannot
see. The doc comment on `PolicyVerifier` mentions "the published SPT-Txn
verifier" as a candidate implementation; that is an intention, not a capability,
and this note exists so nobody else reads it the way we did.

**This is a deliberate stopping point, not an oversight.** The edge enforces
shape, uniqueness and freshness — the properties that must hold at every
deployment regardless of who issues authority. *Who* is authorized, and under
what delegated scope, is a policy question, and pushing it behind an interface
is what lets a deployment bring OPA, an in-house engine, or the SPT-Txn verifier
without this module taking a dependency on any of them. The gap is that the
third option is not yet reachable.

## 3. The verifier on the other side

`spt-txn-poc/pkg/verify` is the public facade over the eight-step engine. It
runs fully offline against a locally held Trust Registry snapshot:

```go
type Input struct {
	TxnToken  string
	DPoPProof string
	HTM, HTU  string   // the HTTP method + URI the DPoP proof binds
	CT        string   // single parent CT (one-hop)
	CTChain   []string // ordered delegation chain, root→leaf
	CAT       string   // root CAT
	Txn       TxnContext
	Audience  string
}

type Decision struct{ Allow bool; Step int; StepName, Reason string }
```

Everything it needs is a string carried in the presentation. Nothing in it
requires network access at decision time.

## 4. Closing the seam

In order:

1. **Version the presentation format.** `presentedToken` gains the fields the
   verifier needs — the transaction token, the root CAT, the ordered CT chain,
   and the DPoP proof — plus an explicit version tag. An unknown version denies.
   Keep `nonce` and `expiry` at the top level only if §5 is honoured.
2. **Carry the presentation on `gate.Token`** as opaque strings, populated by
   `parseToken`. Additive; existing fields keep their meaning.
3. **Decide how DPoP's `HTM`/`HTU` reach the policy.** The PEP holds the
   `*http.Request`; `PolicyVerifier` does not. Either surface them on
   `PaymentRequirements` (which the PEP already builds from the request) or widen
   the interface. Surfacing them is the smaller change.
4. **Write the adapter in the engine**, not here — this module keeps no
   dependencies. It implements `gate.PolicyVerifier` over `verify.Verifier`,
   mapping x402 `PaymentRequirements` onto `verify.TxnContext`.
5. **Map the decision honestly.** `verify.Decision{Allow:false}` for a failed
   check is `DENY_VIOLATION`. A snapshot that cannot be loaded, or any other
   dependency failure, must be wrapped with `gate.Unavailable()` so it becomes
   `DENY_UNAVAILABLE`. Operators must be able to tell an attack from an outage;
   collapsing the two is a defect, not a simplification.
6. **Update the client** to mint and present a real chain. Until this step the
   demo shows enforcement shape only, and should say so.

## 5. The way to get this wrong

**Do not keep the spend-log nonce in the unsigned outer envelope.**

Today the nonce comes from the outer JSON, which is attacker-controlled and
unauthenticated — which is harmless while nothing else is authenticated either.
The moment a signed token is carried inside, an outer nonce becomes a replay
bypass: present the same signed token with a fresh outer nonce and the spend log
sees a new value while the credential is a replay.

The spend log MUST key on the identifier the verifier authenticated — the
token's own `jti` — and never on a field an attacker can vary. If both exist,
they must be compared and a mismatch must deny.

Two related rules follow:

- **Parse the credential once.** The edge should treat the presentation as
  opaque and hand it to the verifier. Two parsers over one credential is the
  canonicalization-mismatch class that this project designs out everywhere else;
  reintroducing it at the edge would be the most expensive kind of consistency.
- **The receipt's `token_hash` stays a hash of the presented bytes**, which is
  already what `tokenFingerprint` computes over the raw header. It should not be
  recomputed from parsed fields.

## 6. What this is not

Closing this seam does **not** put a CAT on chain. The Solana escrow's trust
anchor is an issuer public key on an on-chain allowlist, pinned by the payer at
deposit; it verifies an issuer signature over a fixed-width binding via the
native Ed25519 precompile. Composition with the identity side is therefore at
the **key** — the Ed25519 key that roots a CAT chain issued from an enterprise
IdP is the key registered with `add_issuer` and pinned — not at the token.

That composition is real and worth building. It is a different piece of work
from this one, and describing it as "the IdP token is verified on-chain" would
be false.

## 7. Current state, stated plainly

| Property | Enforced at the edge today | Enforced by the engine's verifier |
|---|---|---|
| Allowlisted scheme/network | yes | — |
| Payment binding (one exact payment) | yes | yes |
| Single use | yes (outer nonce) | yes (token `jti`) |
| Freshness | yes | yes |
| Issuer signature | **no** | yes |
| Delegation chain + attenuation | **no** | yes |
| Holder binding (DPoP) | **no** | yes |
| Status-list revocation | **no** | yes |
| Receipt + transparency log | yes | yes |

The left column is what a deployment gets from this module today. The right
column is what closing the seam adds.
