# Desktop client integration contract v1

**Scope:** Version 1 of the host-to-Permit adapter contract, not a new
signed wire format. [Protocol v1](protocol-v1.md) remains normative.
The [shared-core adapter](../examples/desktop-client-v1.rkt) and its
[executable tests](../permit-test/desktop-contract-v1-test.rkt)
are deliberately independent of Rivet, Glaze, Commerce and UI frameworks.

## Ownership and RPC boundary

A Racket shared core imports the **public Permit client facade**. SwiftUI,
WinUI and GTK hosts call the core through a product-owned RPC/FFI boundary.
Only an issuer service or test fixture imports the opt-in issuer module;
production product binaries never carry signing keys, payment secrets or
payment-provider logic.

The host owns the bundled trusted public root, signed credential storage,
installation identity, product/feature names, version and publication context,
offline-refresh policy, and localized UI. The core verifies signatures and
evaluates rights. A customer-provided trust-store file **must never** replace
the application-owned public trust root.

Inputs: product ID, edition/feature, untrusted signed credential bytes,
the trusted store, optional product SemVer and installation ID, explicit UTC
evaluation time, optional verified activation and trial-extension credentials.
Verify credential bytes first; pass only sealed verified credentials to policy
functions. Do not use private Permit modules as authorization shortcuts.

The adapter returns non-sensitive state (Free or Pro in the example),
entitlement boolean, and typed reason strings. A host can add
contract_version=1 and convert that result to JSON for SwiftUI, WinUI or GTK.
Do not send raw credentials, subject IDs, signed claims or device fingerprints
to UI telemetry. UI state is not proof of remote purchase.

Verification rejection is distinct from a valid-but-unusable license.
Map the public typed verification reasons (envelope, key-unknown, key-revoked,
signature, schema, issuer, key-window, key-purpose) to import errors.
For valid-but-unusable credentials, use credential-status reasons such as
use-expired, issued-in-future and installation-mismatch. Never parse
exception-message text for control flow.

## Safe import sequence

1. Load the trust store from an authenticated application resource; rotate
   it only as part of a trusted application update, not from a user-supplied
   license attachment.
2. Verify all candidate signed credentials. Preserve the previous known-good
   credential on malformed, forged, wrong-issuer, unknown-key or revoked-key
   input; these errors must not promote UI to Pro.
3. For **one issuer + entitlement lineage**, use select-latest-entitlement
   before evaluating any policy. A later signed revision granting no edition,
   feature or add-on must replace a cached older Pro right. Protocol v1
   requires at least one grant; a no-rights grant scoped to the product is a
   valid withdrawal. Do not refuse to import that revision merely because
   it no longer grants Pro. Equal highest revisions with differing payloads
   are an error. Distinct lineages remain product policy.
4. Evaluate edition-entitled?, feature-entitled? and credential-status with
   the necessary product version, installation ID, publication timestamp
   and (when needed) signed activation. Missing evaluation context fails
   closed. Use-expires-at, updates-through and features-through are
   *independent* limits, not aliases.
5. Persist a verified accepted import atomically in product-owned storage.
   Use OS secure-storage facilities where appropriate. Permit remains
   storage-agnostic and does not implement a payment dashboard, account,
   checkout, key-vault, GUI or recovery service.

## Stable IDs and policies

Use permanent product, edition and feature identifiers, e.g.
example-desktop / pro / export. Never redefine one ID after shipping or
allow a wildcard to bypass explicit grants. Publication-stream features
require an immutable product-supplied introduction timestamp and the
published-through feature policy.

- **Offline revocation:** an offline client does not learn later revocations
  or withdrawals until it receives newer trusted evidence. Local files are
  not tamper-proof monotonic revision state: users may restore older bytes.
  Do not claim that a signed revision alone solves offline replay.
- **Subscription grace:** the product chooses whether a short activation
  lease, bounded offline grace and trusted time are mandatory. A static
  credential does not enforce instant cancellation while fully offline.
  An activation lease's offline grace is separate from use expiry.
- **Devices/reinstall:** generate a random application installation ID
  and persist it. Do not fingerprint hardware. The product defines how a
  customer transfers, recovers or reissues rights after reinstall, with
  issuer/account services where needed. Never ship the private signing key.
- **Time rollback:** evaluation before signed issued-at is rejected, but a
  user-controlled clock cannot establish trusted freshness. Use an online
  policy when cancellation or time freshness is a hard requirement.
- **Rotation:** a retired public key remains trusted for credentials issued
  inside its signed issuance window. A revoked key is untrusted. Ship future
  public keys via trusted application updates, not customer import.
- **Trial:** signed trial credentials and local first-run trials have
  different tamper guarantees; products define the migration policy.
- **Commerce:** receipt, checkout callback or payment-provider response is
  not an entitlement. Local authorization remains independent of Commerce.

## Executable compatibility matrix

The [desktop contract suite](../permit-test/desktop-contract-v1-test.rkt)
is automatically included by the package test command: raco test -p permit.
It creates test-only ephemeral Ed25519 issuer keys and exercises real
verification and policy through the public client API. It covers:

| Case | Expected result |
| --- | --- |
| Missing credential / raw object | Free / argument rejected |
| Perpetual Pro, named feature | Pro, explicit feature allowed |
| Expired subscription | Free with expiry reason |
| Update and feature publication cutoffs | Independent authorization |
| Signed trial before and after expiry | Pro then Free |
| Wrong product, version absent/out of range | Denied |
| Wrong installation ID | Denied |
| Local clock earlier than issued-at | Issued-in-future refusal |
| Newer signed withdrawal | Latest revision wins; no Pro |
| Retired/active key rotation | Historical and new rights verify |
| Revoked key, wrong issuer, tampered signature | Typed verification rejection |

These tests do **not** validate host secure storage, a trusted monotonic
ledger, actual payment providers, package-signing identities, or a customer's
activation workflow. Protocol interoperability also has an independent C
vector runner. Product platform evidence and the
[official Racket package builder](crypto-runtime.md) are separate gates.
Never assert full production readiness from this suite alone.

See the existing [integration evidence](integration-evidence.md) for
gptp-studio and the [MoveBit pilot feedback](https://github.com/turlamai/permit/issues/15)
on signed withdrawals. Generic contracts live here; product-specific
Free/Pro decisions and recovery UX remain in their products. Incompatible
host RPC changes require a new contract version; signed wire changes follow
the separate [Protocol compatibility policy](compatibility.md).
