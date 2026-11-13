# Protocol v1 compatibility

Permit separates protocol compatibility from package/API versioning.

## Wire stability

Once Protocol v1 is declared frozen:

- existing v1 envelope and core claim meanings do not change;
- unknown core fields remain fail-closed;
- new vendor metadata uses `extensions`;
- a new security-critical field or credential type requires an explicitly documented protocol evolution;
- old deterministic test vectors remain permanently valid unless their signing key is intentionally marked revoked by the embedding product.

## Exact bytes

Signature interoperability is defined over decoded payload bytes, not a canonical JSON representation. Implementations must preserve the payload byte sequence for signature verification.

Protocol v1 uses canonical padded standard Base64 in the envelope so encoders have one portable spelling.

## JSON

Payloads and wrappers contain exactly one JSON value. Security-critical objects use exact field sets.

JSON object member names must be unique. Conforming verifiers reject duplicates rather than accepting parser-specific first-wins or last-wins behavior; this rule applies recursively to the envelope, trust store, payload, and extensions.

## SemVer

`version_policy.min` and `version_policy.max` use SemVer 2.0 ordering. Build metadata does not affect precedence. Prerelease precedence follows SemVer 2.0.

## Extensions

`extensions` is the only open namespace. A verifier may retain, expose, or ignore extension entries, but core authorization must not depend on an unrecognized extension.

If an extension becomes security-critical across products, it should graduate into a future protocol definition rather than being silently reinterpreted by existing clients.

## Reference implementation API

Permit's Racket package may evolve during 0.x, but the project should prefer additive APIs after Protocol v1 freezes. Product code should use verified credential objects and policy functions rather than reading raw JSON hashes.

### Support and deprecation windows

- The Racket versions exercised by the CI matrix are the supported floor for
  each release; older Racket versions may work but carry no expectation.
- During 0.x a minor release may change the Racket API. Every breaking
  change is listed in the changelog with its replacement and a migration
  note in the affected guide or manual page.
- When a public name is deprecated, the changelog marks it in one release,
  and it is removed no earlier than the following release. Deprecated names
  keep working, including their security behavior, until removal.
- Facade changes are slower than internal ones: `(require permit)`,
  `(require permit/issuer)`, `(require permit/adapter)`, and the opt-in
  `(require permit/json)` utility are documented public module paths, and the CLI
  surface documented by `raco permit help` is public operator behavior.
  Everything else is internal in 0.x even when Racket allows requiring it.
- Protocol v1 vectors and wire semantics are governed by the wire-stability
  rules above, not by Racket package versioning; API changes never
  retroactively invalidate existing vectors.

## Cross-language conformance

The corpus under `test-vectors/v1/` is part of the interoperability contract. Other implementations should verify the exact payload bytes, signature, trust rules, and positive/negative policy cases before claiming Protocol v1 compatibility.


## Missing evaluation context

Cross-language policy engines must fail closed when a signed constraint cannot be evaluated because required product metadata was omitted. In particular, a constrained `version_policy` is not treated as unconstrained when no version is supplied, and a finite `features_through` window does not authorize a feature without its introduction timestamp.
