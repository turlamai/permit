# Documentation map

Permit keeps one canonical document for each durable decision. README files
teach the first path; normative documents define behavior; evidence pages
record what has actually been verified. Do not duplicate a rule across
several guides.

## Start here

- [Getting started](getting-started.md) · [中文](getting-started.zh-CN.md) —
  which files stay private, which ship with the application, and how
  verification differs from policy evaluation.
- [Architecture](architecture.md) — module map, data flow, and the trust
  boundary between verification, policy, and issuance.
- [Adoption, maturity and support](USING.md) · [中文](USING.zh-CN.md) — when
  Permit fits, upgrade boundaries, and supported paths.

## Protocol v1 (normative)

- [Protocol v1](protocol-v1.md) — the normative wire specification.
- [Entitlements](entitlement-v1.md) — grants, windows, and revisions.
- [Activation](activation-v1.md) — short-lived installation leases.
- [Trust model](trust-model.md) — key states, purposes, and rotation.
- [Lifecycle](lifecycle.md) — credential states and deterministic replacement.
- [Compatibility](compatibility.md) — what changes require what evidence.

## Boundaries

- [Framework integration](framework-integration.md) — the canonical boundary
  with Rivet, Glaze, products, and update signing; sibling repositories
  summarize and link here.
- [Management boundaries](management-boundaries.md) — what Commerce and other
  management systems may do through the issuer API, and what they may not.
- [Threat model](threat-model.md) — attackers, assets, and failure posture.

## Operations and evidence

- [Crypto runtime](crypto-runtime.md) — Ed25519 backend selection,
  `raco permit doctor`, and official package-build evidence.
- [Desktop adapter v1](desktop-adapter-v1.md) — the versioned host-facing
  contract implemented by `permit/adapter`.
- [Local trials](local-trials.md) — first-run trial state and installation
  identity.
- [Integration evidence](integration-evidence.md) — recorded product
  integration results.
- [Security review 2026-10](security-review-2026-10.md) — review scope and
  findings.
- [Release checklist](release-checklist.md) — the evidence required for a
  tagged release.
- [Roadmap](../ROADMAP.md) — the path to 1.0.

## Decisions

- [ADR-0001: Issuer rights snapshots](decisions/0001-issuer-rights-snapshots.md)
- [ADR-0002: Typed verification failures](decisions/0002-typed-verification-failures.md)

## Source entry points

| Path | Responsibility |
| --- | --- |
| `permit/main.rkt` | client-only default facade |
| `permit/issuer.rkt` | explicit issuer-side signing surface |
| `permit/adapter.rkt` | versioned host adapter result |
| `permit/local-trial.rkt` | first-run trial runtime |
| `permit/cli.rkt` | `raco permit` keygen/issue/sign/verify/inspect/check/doctor |
| `permit/private/` | implementation-only JSON, time, encoding, DER, semver |
| `permit-test/` | unit, integration, documentation and vector tests |
| `test-vectors/v1/` | deterministic cross-language conformance corpus |
| `examples/` | schema-valid commercial model payloads |
