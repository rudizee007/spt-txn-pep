// Package evidence defines how a PEP emits a spec Transaction Receipt.
//
// draft-coetzee-oauth-spt-txn-tokens-03 §Receipts:
//
//	An issuer or PEP that emits evidence MUST emit a signed Transaction Receipt
//	at the moment of each decision, including denials.
//
// This package is the seam that lets a PEP satisfy that without taking on a
// dependency. It contains an interface, a plain struct of strings, and a no-op —
// no crypto, no canonicalization, no imports at all. The reference
// implementation lives in spt-txn-poc/pkg/receipt; a deployment may supply its
// own.
//
// # Why the dependency is inverted
//
// The receipt implementation and the canonicalizer (JCS, RFC 8785) live in
// spt-txn-poc, next to the verifier, deliberately: the canonicalizer is the
// threat-#1 surface, and issuer and verifier must be the same version by
// construction, not by convention. Splitting it across a module boundary would
// allow one side to build against a different version — different canonical
// bytes, an authorization bypass, nothing in the type system to catch it.
//
// But spt-txn-poc requires gnark, ML-DSA and ~20 other modules. Depending on it
// from here would put a zero-knowledge-proof stack in the dependency graph of
// anyone who wanted an authorization middleware, and this module's entire value
// is having no dependencies. So the dependency points the other way: we define
// the interface, they implement it. Accept interfaces, return structs.
//
// See RECEIPT-ARTIFACTS-DESIGN.md §6.
//
// # This is not the transparency log
//
// A Transaction Receipt (this package) answers *what authority governed this
// decision, under which policy and jurisdiction*. A translog entry answers
// *where this decision sits in a tamper-evident, inclusion-provable chain*.
// They compose; neither substitutes for the other.
package evidence

// Receipt is the field set draft-03 requires, as plain strings.
//
// A struct rather than positional parameters, deliberately: adding a field later
// is then additive for implementers instead of a breaking interface change. The
// draft's field list is not guaranteed to be final.
//
// Values only ever carry hashes, enums and references. The draft is explicit
// that receipts MUST NOT carry payloads or personally identifiable information.
type Receipt struct {
	// PEP identifies the enforcement point making the decision.
	PEP string
	// Decision is "PERMIT" or "DENY".
	Decision string
	// Class is "ok", "violation" (a check failed) or "unavailable" (a dependency
	// was unreachable). Operators MUST be able to tell an attack from an outage,
	// so these are distinct and mandatory.
	Class string
	// RulePath is the policy rule that fired.
	RulePath string
	// TokenHash is the base64url SHA-256 of the presented token; "" if none.
	TokenHash string
	// PolicyHash is the base64url SHA-256 of the policy bundle evaluated.
	PolicyHash string
	// IntentDigest is the bound intent digest, if any.
	IntentDigest string
	// Jurisdiction is the jurisdiction profile applied, if any.
	Jurisdiction string
}

// Decision and class values, matching the draft exactly. Using these rather than
// string literals keeps a PEP's vocabulary aligned with the specification.
const (
	Permit = "PERMIT"
	Deny   = "DENY"

	ClassOK          = "ok"
	ClassViolation   = "violation"
	ClassUnavailable = "unavailable"
)

// Emitter signs a receipt and durably records it, returning a locator (for
// example a receipt hash) that a client can use to retrieve or prove it.
//
// An error means "not durably recorded". A PEP MUST treat that as
// DENY/unavailable rather than proceeding: evidence is a precondition of the
// decision, not a side effect of it.
type Emitter interface {
	Emit(Receipt) (locator string, err error)
}

// None is an explicit no-op Emitter for deployments that genuinely do not want
// receipts — a local demo, a test, a benchmark.
//
// It exists so that "no receipts" must be *chosen* rather than defaulted into.
// A PEP constructed without an Emitter is refused outright; there is no silent
// path where evidence quietly stops being produced, which is exactly the kind of
// check a later refactor could otherwise delete.
//
// Using None in production means the deployment is not conformant with
// draft-03, which requires a receipt at every decision. That is a deliberate,
// visible choice — and, via the Noop marker below, a *detectable* one: a PEP can
// tell it was handed None and surface non-conformance rather than looking
// identical to a real emitter at runtime.
type None struct{}

// Emit discards the receipt and reports success.
func (None) Emit(Receipt) (string, error) { return "", nil }

// noopEmitter marks None as a deliberate no-op. The method is unexported so only
// this package can claim it — an external emitter cannot accidentally be treated
// as a no-op, and real emitters never implement it.
func (None) noopEmitter() {}

// Noop is implemented only by Emitters that deliberately record nothing (None).
// A PEP type-asserts for it to detect the non-conformant "no receipts" choice
// and surface it — so None is a *visible* opt-out, not a silent fail-open.
//
//	if _, ok := em.(evidence.Noop); ok { /* warn: not conformant */ }
type Noop interface{ noopEmitter() }

// Durable is an OPTIONAL capability an Emitter implements to assert that Emit
// records durably (e.g. fsync, or a durable local buffer) BEFORE returning
// success. A buffering or async emitter that returns nil before the receipt is
// durable MUST return false here — the fail-closed guarantee ("an ALLOW is not
// served unless its receipt is durably recorded") is only as strong as this.
//
// It is advisory: a PEP MAY warn when a non-None emitter does not implement
// Durable (it then cannot prove durability), but the interface stays optional so
// existing emitters keep compiling.
type Durable interface{ Durable() bool }
