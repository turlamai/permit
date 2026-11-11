# Permit

**Signed product rights for independent software — verifiable offline, manageable online when you need it.**

[![CI](https://github.com/turlamai/permit/actions/workflows/ci.yml/badge.svg)](https://github.com/turlamai/permit/actions/workflows/ci.yml) ![Racket](https://img.shields.io/badge/Racket-9F1D20?logo=racket&logoColor=white) [![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE) ![Protocol](https://img.shields.io/badge/protocol-v1-C15F3C) [![Version](https://img.shields.io/github/v/release/turlamai/permit?label=version)](https://github.com/turlamai/permit/releases/latest)

**English** · [中文](README.zh-CN.md)

Permit is a framework-neutral protocol and Racket reference implementation for answering one product question:

> What may this person, organization, or installation use right now?

Payment providers can tell you that money moved. Account systems can tell you who signed in. Permit turns durable product rights into signed, portable credentials that an application can verify locally with an embedded public trust store — without requiring an account, a network round trip, or a framework-owned licensing subsystem. The bilingual homepage is [permit.jrtx.site](https://permit.jrtx.site/).

## Cryptographic runtime requirements

Permit needs a working **Ed25519** implementation to verify or issue
credentials. The Racket reference tries OpenSSL 3+, libsodium, then Nettle
through explicit upstream crypto-lib providers, and falls back to the pure
Racket [`ed25519`](https://pkgs.racket-lang.org/package/ed25519) package when
no native provider is usable. The pure fallback is a full RFC 8032
implementation, not a weaker algorithm, and it is what keeps signing and
verification working on minimal package-builder machines; it is not constant
time, so production issuers should keep a native provider where possible.
Run `raco permit doctor` to print the selected backend and per-provider
Ed25519 availability as JSON. See the
[native backend diagnostics and official package-build evidence](docs/crypto-runtime.md).

## Start here

Compose Permit beside an application when signed, offline-verifiable rights are needed. Start with an entitlement and omit activation unless the product explicitly needs an online lease. Free products do not need a licensing subsystem.

[Fit, maturity, upgrades and support](docs/USING.md) · [简体中文](docs/USING.zh-CN.md)

## Why Permit?

Commercial applications need two properties that are often treated as opposites:

- **Offline-verifiable** — the installed application can authorize features without phoning home.
- **Online-manageable** — Commerce or another explicit issuer service may renew subscriptions, allocate seats, rotate keys, or refresh short-lived activation leases without changing the verification protocol.

Permit separates those concerns. Long-lived **entitlements** describe commercial rights, optional **activation leases** bind a right to an installation for a limited period, and **trials** remain their own credential type. Products opt into only the layers they need.

Permit composes beside an application framework:

```text
                         Product
                       /         \
              Rivet or Glaze     Permit
              runtime / update   product rights
```

[Rivet](https://github.com/turlamai/rivet) and [Glaze](https://github.com/turlamai/glaze) do not depend on Permit. Update-artifact signing and Permit credential signing also use separate keys and trust policies. See the [framework integration contract](docs/framework-integration.md) for the durable dependency and responsibility boundaries.

Online products may add [Commerce](https://github.com/turlamai/commerce)
for provider events, commercial projections, issuance workflow, and credential
claim delivery. Commerce consumes the explicit issuer API; Permit never imports
Commerce, and products still authorize locally from verified credentials.

## What it models

One Protocol v1 vocabulary covers the common commercial shapes without baking pricing or payment policy into the app:

| Product model | Right to use | Updates | Newly published features |
| --- | --- | --- | --- |
| Perpetual purchase | no expiry | unrestricted or bounded | unrestricted or bounded |
| Perpetual + maintenance window | perpetual | through maintenance date | normally unrestricted |
| Perpetual + feature window | perpetual | normally unrestricted | through feature-window date |
| Subscription | through subscription date | policy-defined | policy-defined |
| Trial | through trial date | policy-defined | policy-defined |

Grants may name editions, features, add-ons, bundles, and scalar capabilities. Team ownership, named seats, device activations, and concurrent seats are distinct claims rather than one overloaded counter. `installation_id` is an application-generated, privacy-preserving identifier — not a hardware fingerprint.

## Quick start

New to signed credentials? Follow the [step-by-step getting-started guide](docs/getting-started.md). It explains which files stay private, which files ship with the application, and how verification differs from policy evaluation.

Install the Racket package from the official catalog:

```bash
raco pkg install --auto permit
```

or straight from this repository:

```bash
raco pkg install --auto --name permit https://github.com/turlamai/permit.git
```

Generate an Ed25519 key pair and starter trust store:

```bash
raco permit keygen \
  --private private-key.der \
  --public public-key.der \
  --trust-store trust-store.json \
  --key-id license-2026 \
  --issuer com.example \
  --purpose entitlement
```

`--purpose` may be repeated to create a least-privilege signing key. Omit it only when one small deployment intentionally uses a single key for every v1 credential type. On POSIX systems `keygen` writes the private key with mode `0600`; keep it out of source control and application bundles. Start from a schema-valid template under [`examples/`](examples/), then sign the exact bytes of the payload file:

```bash
raco permit issue \
  --key private-key.der \
  --key-id license-2026 \
  --trust-store trust-store.json \
  --payload entitlement.json \
  --output entitlement.permit.json
```

Verify the signature, trust key, issuer, and schema:

```bash
raco permit verify \
  --trust-store trust-store.json \
  --credential entitlement.permit.json
```

Then evaluate product policy:

```bash
raco permit check \
  --trust-store trust-store.json \
  --credential entitlement.permit.json \
  --product example-app \
  --feature example-feature \
  --feature-published-at 2026-10-01T00:00:00Z \
  --version 2.0.0
```

`inspect` is deliberately labelled unverified. Never authorize a feature from inspected claims alone.

## Protocol v1

A credential is a small JSON envelope:

```json
{
  "permit_version": 1,
  "algorithm": "Ed25519",
  "key_id": "license-2026",
  "payload": "<base64 of the exact JSON bytes>",
  "signature": "<base64 Ed25519 signature>"
}
```

Ed25519 signs the decoded `payload` bytes **exactly**. A verifier checks the signature before parsing authorization claims and never parses then re-serializes the JSON for verification. That rule avoids cross-language canonicalization ambiguity.

Protocol v1 includes:

- `entitlement`, `trial`, `trial-extension`, and `activation` credentials
- independent `use_expires_at`, `updates_through`, and `features_through` windows
- optional product-version bounds and installation binding
- edition, explicit-feature, published-through future-feature, add-on, bundle, and scalar-capability grants
- team, named-seat, device, and concurrent-seat limits
- stable `entitlement_id` + monotonic `revision` for renewals and reissues
- signed absolute-date trial extensions that are replay-safe
- short-lived activation leases bound to the exact entitlement snapshot, with explicit offline grace
- multi-key trust stores with `next`, `active`, `retired`, and `revoked` states plus per-key credential purposes
- deterministic cross-language test vectors

Start with the [getting-started guide](docs/getting-started.md). For implementation work, read the [architecture map](docs/architecture.md). For protocol work, continue with the [normative Protocol v1 specification](docs/protocol-v1.md), then see [entitlements](docs/entitlement-v1.md), [activation](docs/activation-v1.md), [trust](docs/trust-model.md), [lifecycle](docs/lifecycle.md), [compatibility](docs/compatibility.md), [threat model](docs/threat-model.md), the [framework integration contract](docs/framework-integration.md), and the [management boundary](docs/management-boundaries.md).

## Client and issuer APIs

The default `(require permit)` facade is intentionally client-only: verification, trust-store loading, policy evaluation, installation identity, and local-trial runtime. It does not export private-key generation, signing, raw envelope constructors, or raw schema parsing.

Issuer-side code opts in explicitly:

```racket
(require permit/issuer)

(define envelope
  (issue-credential payload-bytes private-key "license-2026" trust-store))
```

`issue-credential` is the safe path: it checks schema, issuer, active key status, credential-purpose authorization, signing-key issuance window, and that the supplied private key matches the selected trust-store public key. The CLI `raco permit issue` uses the same path. `raco permit sign` remains a deliberately low-level escape hatch.

## Racket API

```racket
#lang racket/base

(require permit)

(define store (read-trust-store "trust-store.json"))
(define entitlement
  (verify-credential "entitlement.permit.json" store))

(when (feature-entitled? entitlement
                         "example-app"
                         "example-feature"
                         #:published-at "2026-10-01T00:00:00Z")
  (enable-pcap-export!))
```

Renewal or a plan change issues a complete new snapshot with the same `entitlement_id`, a higher `revision`, and a new `credential_id`. This is deterministic replacement among credentials the client has actually received; it is not offline revocation.

An online-managed product verifies both the durable right and a short-lived installation lease:

```racket
(credential-usable? entitlement
                    #:installation-id installation-id
                    #:activation activation-lease)
```

An offline product omits the activation layer entirely.

## Local first-run trials

A unique local trial cannot be signed before an app contacts an issuer, so Permit keeps it outside Protocol v1 and provides a small storage-agnostic runtime instead:

```racket
(define trial
  (make-local-trial #:duration-seconds (* 14 24 60 60)))

(define result (evaluate-local-trial trial))
(write-local-trial (local-trial-evaluation-state result) "permit-trial.json")
```

The state uses a random trial id and a last-seen clock high-water mark. It can also consume verified Protocol v1 `trial-extension` credentials. This is deliberate nuisance resistance, not a claim that an offline local trial cannot be reset by a user controlling the machine.

`generate-installation-id` provides the same privacy-preserving random identity style for products that opt into activation leases. See [local trials and installation identity](docs/local-trials.md).

## Trust and rotation

Applications ship only public keys. A trust store can stage a `next` key before an issuer starts signing with it, keep an `active` key for normal issuance, retain a `retired` key for credentials issued before its issuance cutoff, and reject a `revoked` key immediately. Key time windows constrain the credential's authenticated `issued_at`, not the future wall-clock moment when a perpetual credential is verified.

This lets a release carry tomorrow's public key before the issuing service switches over, while preserving a deterministic offline verification path.

## Deliberate boundary

Permit does **not** implement payment processing, customer accounts, email, pricing, tax, a dashboard, hosted metering, or a license server. Commerce owns the family payment-to-rights orchestration path; identity and product services own accounts. These systems may issue and refresh Permit credentials through the explicit issuer API, but they do not belong in the verification core.

Seat allocation, device reclamation, subscription renewal, and credential delivery are Commerce or other management operations. Account recovery remains an identity/product operation. The Protocol v1 boundary defines the signed artifacts those systems exchange with products.

## Development

```bash
raco pkg install --auto --no-docs --link
raco make permit/main.rkt permit/cli.rkt permit-doc/scribblings/permit.scrbl
raco test -p permit
```

The deterministic corpus under [`test-vectors/v1`](test-vectors/v1) is the interoperability contract for other language implementations; the C runner in [`conformance/c`](conformance/c) executes it as an independent implementation.
See the [documentation map](docs/README.md) for every canonical guide, [CONTRIBUTING.md](CONTRIBUTING.md) for the complete change checklist, and [ROADMAP.md](ROADMAP.md) for the evidence required on the path to 1.0.

## Repository structure

```text
permit/
├── permit/                 # public facade, implementation and CLI
├── permit-doc/             # installed Scribble reference manual
├── docs/                   # architecture, normative protocol and boundaries
├── examples/               # schema-valid commercial model payloads
├── test-vectors/v1/        # deterministic cross-language conformance corpus
├── conformance/c/          # standalone C conformance runner over the corpus
├── permit-test/            # unit, integration, documentation and vector tests
└── site/                   # bilingual product homepage
```

## Status

Protocol v1 is implemented for every v1 credential type, but the repository has not declared a stable 1.0 compatibility promise. Security-sensitive fields fail closed; only `extensions` is open-ended.

## License

[Apache-2.0](LICENSE)
