# Changelog

## Unreleased

### Fixed

- Repair stale pre-rename GitHub URLs in the contributor guide and signed
  v0.2.0 release evidence link; include every root Markdown entry (including
  ROADMAP and CONTRIBUTING) in the documentation-link CI gate.

- Prefer OpenSSL 3 Ed25519 and use an explicit libsodium backend fallback
  where available, without mutating the caller's global crypto-factory
  parameter. Extend RFC 8032 known-answer, rejection and ambient-factory
  tests; document native runtime requirements and the official Racket
  catalog build failure (compiled but 6 cryptographic tests failed).
  Never skip verification when both native providers are unavailable.

- Reject invalid JSON scalar tokens, including valid number/literal prefixes
  followed by garbage, closing L1 from the October security review without
  changing Protocol v1.

## 0.2.0 - 2026-10-21

### Fixed

- Close the findings of the first independent security review
  (`docs/security-review-2026-10.md`). The C runner now rejects NUL
  escapes inside JSON strings, integers beyond signed 64-bit (no silent
  clamping), non-finite capability values, and trailing bytes after the
  DER public key; the grace addition saturates instead of overflowing.
  The Racket reference now rejects `\u0000` on the same layer and
  detects aliased trust keys by DER bytes instead of Base64 text, and
  its schema bounds integer fields to signed 64-bit so both
  implementations decide identically. Regression tests pin every finding;
  the normative rules live in `docs/protocol-v1.md`.

### Added

- Add the issuer-side rights-snapshot layer to `permit/issuer`
  (`docs/decisions/0001`): `subject`, `grant`, `constraints`, and
  `entitlement-payload` spell the closed entitlement schema with validation
  at the call site; `successor-payload` is the one supported spelling of a
  new revision in an existing lineage (identity inherited, revision
  advanced, everything else replaceable); `payload->bytes` is the single
  serialization step the exact-byte rule allows. This is the boundary
  Commerce's issuer adapter consumes instead of assembling JSON.
- Type every refusal (`docs/decisions/0002`). `exn:fail:permit` carries a
  `reason`; `verify-credential` raises `exn:fail:permit:verify` with one of
  `verify-failure-reasons` (envelope, key-unknown, key-revoked, signature,
  schema, issuer, key-window, key-purpose — pipeline order, so the reason
  names the guard), and `issue-credential` raises `exn:fail:permit:issue`
  with one of `issue-failure-reasons` (schema, issuer, key-unknown,
  key-status, key-window, key-purpose, key-mismatch). Products translate a
  refused license file by reason instead of matching message text; the CLI
  prints the reason on its own line. Messages and fail-closed behavior are
  unchanged; time outcomes remain `credential-status` reasons.
- Make the rejection class a cross-language contract. Each `expected`
  rejection in `conformance.json` is one verify reason and one C `Outcome`
  (table in `test-vectors/README.md`); the Racket vector test asserts the
  reason instead of matching message text. Three vectors cover the classes
  that had none: `malformed-envelope.json` (`envelope-reject`),
  `not-a-credential.permit.json` (`payload-reject`, genuine signature over
  non-credential bytes), and `foreign-issuer.permit.json`
  (`issuer-mismatch-reject`, genuine signature under a foreign issuer).
- Cover the policy functions that had no cross-language vector: `edition`,
  `addon`, `capability`, and `limit` conformance queries (twelve cases,
  including scope through a product family, the version-context fail-closed
  rule, and null for an unset value), implemented in the C runner so both
  sides decide identically.
- Cover lineage selection in the vectors: `lineage` cases present several
  statements of one entitlement and name the `credential_id` the newest
  revision must have, in either order; `lineage-conflict-reject` and
  `lineage-mismatch-reject` pin the fail-closed cases (two payloads at the
  highest revision; statements from different lineages). The C runner
  implements `select-latest-entitlement` for them. This closes the last
  policy surface the security review found without independent C evidence.
- Name Commerce as the family commercial-management owner and define the
  one-way `Commerce issuer adapter -> permit/issuer` boundary without moving
  payment, account, delivery, or framework behavior into Permit.
- Add `docs/integration-evidence.md`, the record the v0.2 gate asks for:
  gptp-studio as the first real integration, with its offline startup,
  credential replacement, key rotation, expiry, and corrupt-state
  behavior pinned by tests, plus the problems the integration surfaced.
- Declare `rackunit-lib` as a runtime package dependency because the public
  source package includes the `permit-test` collection.
- Add a C conformance runner under `conformance/c/` that executes the
  Protocol v1 vector corpus as an independent non-Racket implementation:
  exact-byte Ed25519 authentication, trust-store rules, closed schemas,
  rejection classes, and policy decisions with exact failure reasons. CI
  builds and runs it on macOS and Linux.
- Register the package in the public catalog and fix the `license` field
  to a bare SPDX symbol so the catalog recognizes Apache-2.0.
- Add the release checklist used to cut Permit versions, including the
  signed source release procedure.
- Document the Racket API support and deprecation windows in the
  compatibility guide.
- Scribble manual (`permit-doc`): the client verification surface, policy
  evaluation, issuer API, CLI, and local-trial runtime, rendered as the
  package documentation for the catalog.
- Add a maintainer architecture map, contribution contract, roadmap, and ADR template so future work can proceed without relying on conversation history.
- Strengthen CI with manual compilation and byte-for-byte vector reproducibility checks.
- Consolidate every Racket test under `permit-test/` so local and package-level test entry points cover the same suite.
- Expand the deterministic Protocol v1 corpus to cover entitlement, managed activation, signed trial, trial extension, offline grace, and published-through feature decisions.
- Add English and Chinese step-by-step guides that separate issuer secrets, shipped trust data, verification, and product policy evaluation.
- Add an opaque issuer credential predicate and writer so programmatic issuers can safely persist the result of `issue-credential` without importing raw envelope internals.
- Document the durable sibling-library integration contract for products that compose Permit with Rivet or Glaze.
- Add repeatable `raco permit keygen --purpose ...` for least-privilege signing keys while preserving the all-purpose default for small deployments.

- Split the Racket API into a curated client facade and explicit `permit/issuer` signing surface.
- Add guarded `issue-credential` checks for issuer, key status/purpose/window, and private/public key correspondence.
- Add privacy-preserving random installation/trial identifiers.
- Add a storage-agnostic local trial state machine with clock high-water tracking and signed trial-extension support.

### Security

- Seal the `verified-credential` constructor so product policy can only receive credentials produced by signature verification.

### Protocol v1 hardening

- Separate logical `entitlement_id` from unique signed `credential_id` and add monotonic revisions.
- Bind activation leases to an exact entitlement id, revision, credential id, and installation id.
- Add replay-safe signed trial-extension credentials.
- Make key validity windows constrain authenticated issuance time so retired keys do not expire perpetual rights.
- Harden SemVer, Base64, recursive duplicate-key JSON rejection, trust-store aliases, per-key credential purposes, scalar capability conflicts, and strict JSON parsing.
- Add explicit vs published-through feature grant modes, add-on and standard-limit policy queries, plus split normative protocol documentation.

### Release evidence

- Racket reference: 366 tests green on macOS arm64 (Apple Silicon) with
  Racket 9.3 (CS); CI runs the same suite on Racket 9.0 and 9.3 across
  Linux, Windows, and macOS, and regenerates the vector corpus with a
  byte-for-byte diff check.
- Independent implementation: the C conformance runner executes the
  Protocol v1 corpus — 85 checks, 0 failures — built with OpenSSL 3.5.9
  on macOS arm64, with CI covering Linux, macOS, and Windows.
- Fresh-install gate: the package installs from a clean clone of the
  release commit and passes the same suite before the tag is cut.
- First integration: gptp-studio consumes the public `permit` facade in
  production (`docs/integration-evidence.md`); the first independent
  security review is closed with every finding fixed
  (`docs/security-review-2026-10.md`).

## 0.1.0 - 2026-10-15

- Define Permit Protocol v1 with exact-payload Ed25519 envelopes.
- Add entitlement, signed trial, and activation-lease schemas.
- Add grants, bundles, capability limits, independent commercial windows, installation binding, and version policy.
- Add trust stores with key rotation and revocation states.
- Add the Racket reference API and `raco permit` CLI.
- Add deterministic cross-language test vectors and cross-platform CI.
