# Framework integration

Permit is a sibling of an application framework, not a framework subsystem.
An application may depend on both; Rivet and Glaze do not depend on Permit.
Online products may separately use Commerce, whose explicit issuer adapter may
consume `permit/issuer`. Permit never depends on Commerce.

```text
                         Product
                    /       |       \
             Rivet/Glaze  Permit  Commerce client (optional)
            runtime/update rights          |
                                           v
                                   Commerce service
                                           |
                                           v
                                    permit/issuer
```

## Responsibility boundary

| Owner | Responsibilities |
| --- | --- |
| Product | Feature names, editions, commercial policy, authorization UI, credential refresh timing, and the decision to run fully offline or require activation leases |
| Permit | Signed credential format, trust-store verification, entitlement/trial/activation semantics, policy evaluation, privacy-preserving installation identifiers, and local-trial state |
| Rivet or Glaze | Application lifecycle, native UI, packaging, platform secure-storage primitives, distribution, and update-artifact verification |
| Commerce | Provider/payment orchestration, commercial projections, managed allocation workflows, rights intents, credential issuance/claim delivery, and operator audit |
| Product or identity service | Stable subject binding, login, account recovery, and customer-facing commercial UX |

This direction is intentional:

```text
product -> framework
product -> Permit
product -> Commerce client        (optional)
Commerce issuer adapter -> permit/issuer

framework -X-> Permit
framework -X-> Commerce
Permit    -X-> framework
Permit    -X-> Commerce
```

No adapter is required for normal use. Product code imports the framework and
Permit independently:

```racket
#lang racket/base

(require permit
         glaze/core) ; or the Rivet modules used by the product

(define trust-store (read-trust-store "trust-store.json"))
(define entitlement
  (verify-credential "entitlement.permit.json" trust-store))

(when (feature-entitled? entitlement "example-product" "pro-feature")
  (enable-pro-feature!))
```

The framework may provide a general secure-storage service. The product may
use it to store a Permit credential, local-trial state, or `installation_id`,
but the storage API remains general-purpose and Permit remains storage-agnostic.
Do not add entitlement, trial, activation, payment, or account policy to the
framework to make this composition work.

The Commerce client, when used, requests checkout or claims delivery; its
response is never local authorization evidence. The product authorizes only
from a verified Permit credential. Commerce receives opaque stable subject ids
and does not become the login or account-recovery system.

## Separate trust domains

The following keys are not interchangeable:

- Provider API/webhook secrets authenticate payment-system input to Commerce.
- Commerce claim/session and data-encryption keys protect workflow and stored
  operational state.
- Permit credential-signing keys authenticate commercial rights.
- Update-manifest or update-artifact keys authenticate software releases.
- Platform publisher credentials authenticate OS packages and applications.

Compromise, rotation, or retirement in one trust domain must not silently
change another. Products should use distinct keys, identifiers, storage, and
operational procedures for each domain.

## Framework maintenance rule

Rivet and Glaze may document Permit as an optional product-layer companion,
but must not add a package dependency on it or recreate a built-in licensing
subsystem. If a product later needs convenience glue, keep that code in the
product or a separately versioned adapter so framework users who do not sell
commercial software inherit no policy or dependency.

The canonical five-repository graph and release order are defined by the
[family architecture](https://github.com/turlamai/keel/blob/main/docs/family-architecture.md).

## Versioned desktop host contract

For a Racket shared core hosted by SwiftUI, WinUI or GTK, use the
[desktop client adapter contract v1](desktop-adapter-v1.md) and its
[public-facade test harness](../permit-test/desktop-contract-v1-test.rkt).
The host provides its own app-bundled trust root and persistence; the contract
never makes Commerce, Rivet or Glaze a Permit dependency.
