# Architecture

This document is the map for maintainers extending Permit. The protocol specification remains normative for wire behavior; this document explains how the Racket implementation preserves it.

## Design goals

Permit has two simultaneous goals:

1. A product can verify signed rights while fully offline.
2. An optional management service can later renew, allocate, or refresh those rights without replacing the client-side protocol.

The implementation therefore separates authenticated facts from product policy and keeps online systems outside the trusted verification core.

## Dependency direction

```text
                          product application
                         /                   \
               application framework       Permit facade
                                            /           \
                                      verification     policy
                                       /       \          |
                                  envelope    schema     time/version
                                      |
                                    crypto

              Commerce issuer adapter -> permit/issuer -> signed files
```

Dependencies point inward. The client facade never imports the issuer surface. Permit does not import Rivet, Glaze, payment SDKs, account systems, or network clients.

## Module responsibilities

| Module | Responsibility | Must not do |
| --- | --- | --- |
| `permit/main.rkt` | Stable client-facing facade | Export private-key or raw-envelope capabilities |
| `permit/envelope.rkt` | Strict envelope parsing and exact-byte Ed25519 operations | Interpret commercial claims |
| `permit/schema.rkt` | Closed Protocol v1 claim validation | Decide whether a valid claim is currently usable |
| `permit/trust.rkt` | Public-key lookup, purpose restrictions, rotation windows | Fetch keys from a network |
| `permit/credential.rkt` | Verified credential boundary and lineage selection | Manufacture unverified credentials |
| `permit/policy.rkt` | Pure authorization decisions over verified values | Read files, contact services, or mutate product state |
| `permit/local-trial.rkt` | Explicitly non-authoritative local trial state | Pretend local state is tamper-proof |
| `permit/issuer.rkt` | Safe opt-in credential issuance | Leak into the default client facade |
| `permit/cli.rkt` | Thin operator interface over library behavior | Become a second implementation of protocol rules |
| `permit/private/` | Small reusable parsers and value helpers | Expose an accidental public API |

## Security boundaries

The most important type transition is:

```text
untrusted bytes -> authenticated exact bytes -> validated claims -> policy decision
```

`verify-credential` is the only supported client path across the first three stages. The constructor for `verified-credential` stays private so callers cannot skip authentication. Policy functions accept only `verified-credential?` values.

The outer envelope is parsed only far enough to select a public key and verify the signature. The payload is parsed after signature verification. Unknown security-critical fields and duplicate JSON members fail closed.

## Extension rules

Use the following decision order for new work:

1. If the data is issuer-specific bookkeeping and has no shared authorization meaning, place it under namespaced `extensions`.
2. If it changes interoperable authorization semantics, write a protocol proposal before changing code.
3. If it belongs to checkout, provider events, allocation operations, recovery, delivery, or dashboards, keep it in Commerce or another explicit management component and exchange signed Protocol v1 artifacts at the boundary. Login and account recovery remain identity/product concerns rather than Permit behavior.
4. If it is product-specific policy, keep it in the product unless at least two independent products need the same portable meaning.

Never silently reinterpret an existing field. Compatible additions need specification text, positive and negative vectors, Racket tests, and migration guidance. Incompatible wire changes require a new protocol version.

## Test architecture

The test suite is deliberately layered:

- unit tests cover strict JSON, schemas, trust, crypto, identities, and policy;
- integration tests cover the CLI and public facade;
- deterministic vectors are the language-neutral conformance contract;
- the C runner under `conformance/c/` executes those vectors as an independent non-Racket implementation and must agree with the Racket harness on every case;
- documentation tests reject broken local links;
- CI installs the repository as a real package on Windows, macOS, and Linux across the supported Racket versions;
- the quality job rebuilds the manual and regenerates vectors, then requires a clean tree.

For a bug in authenticated or policy behavior, first add the smallest failing regression test. Add a vector as well when another language implementation could make the same mistake.

## Stable and internal surfaces

The supported public client surface is `(require permit)`. Issuers use `(require permit/issuer)`. CLI behavior documented in `raco permit help` is public operator behavior.

Other modules are implementation details in v0.x even when Racket allows requiring them directly. The wire protocol has its own compatibility rules and may be more stable than the Racket API before 1.0.

## Management components

[Commerce](https://github.com/turlamai/commerce) is the family owner for
provider-neutral payment orchestration, commercial projections, rights
intents, issuance workflow, claim delivery, and operator audit. Its explicit
issuer adapter may consume `permit/issuer`; Permit never imports Commerce.
Identity providers or product services continue to own login and account
recovery. Any management component outputs signed credentials; the client
remains useful without it and never treats an online response boolean as
authority. The complete ownership graph lives in the
[family architecture](https://github.com/turlamai/keel/blob/main/docs/family-architecture.md).
