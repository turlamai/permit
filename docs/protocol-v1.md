# Permit Protocol v1

This document is the normative entry point for Permit Protocol v1. The words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used in the RFC 2119 sense.

Permit is **offline-verifiable and online-manageable**. A client can authenticate durable product rights without contacting an issuer. Products that need timely seat reclamation, revocation, or subscription control add short-lived signed management artifacts rather than turning a server boolean into the root of trust.

Protocol v1 does not define checkout, tax, accounts, email delivery, dashboards, SaaS metering, or a hosted license server.

## 1. Layers

Permit deliberately separates four layers:

1. **Envelope** — exact-byte Ed25519 authentication.
2. **Credential model** — entitlement, trial, trial-extension, and activation claims.
3. **Policy** — use, update, feature, version, installation, and activation decisions.
4. **Management plane** — optional future services that issue or refresh signed credentials.

An authenticated credential is not automatically usable. Verification proves who signed the exact bytes and that the claims conform to the schema. Policy evaluation decides whether those claims are effective at a particular time and installation.

## 2. Signed envelope

The outer document MUST be one UTF-8 JSON object and MUST contain exactly:

| Field | Value |
| --- | --- |
| `permit_version` | integer `1` |
| `algorithm` | string `Ed25519` |
| `key_id` | non-empty string |
| `payload` | canonical padded standard Base64 |
| `signature` | canonical padded standard Base64 of a 64-byte Ed25519 signature |

The signature operation is:

```text
signature = Ed25519.Sign(private_key, BASE64_DECODE(payload))
```

A verifier MUST authenticate the decoded payload bytes **exactly**. It MUST NOT parse the payload and then verify a re-serialization. Whitespace, property order, escapes, and a trailing newline are therefore authenticated bytes.

Unknown or missing envelope fields MUST be rejected. Trailing JSON values MUST be rejected.

## 3. Verification pipeline

A conforming verifier performs these stages in order:

1. Parse only the small outer envelope.
2. Resolve `key_id` from the configured trust store and reject unknown or `revoked` keys. A trust store MUST NOT alias the same public key under several key ids.
3. Verify the Ed25519 signature over the exact decoded payload bytes.
4. Parse the authenticated payload with duplicate-object-member rejection and validate its closed schema.
5. Require the payload `issuer` to match the selected trust store.
6. Require authenticated `issued_at` to lie inside the signing key's issuance window.
7. Require the signing key's `purposes` to authorize the signed credential `type`.
8. Hand the resulting verified credential to the policy evaluator.

The application MUST NOT authorize from raw output of an inspect/debug command.

## 4. Payload rules

Every payload is exactly one UTF-8 JSON object.

Security-critical schemas are closed: unknown fields outside `extensions` MUST be rejected. Vendor data belongs under `extensions`; extension keys SHOULD be namespaced, for example `example.com/order_id`.

JSON object member names MUST be unique at every nesting level. Conforming verifiers MUST reject duplicates before authorization, including spellings that decode to the same member name. Cross-language implementations must not rely on first-wins or last-wins parser behavior.

JSON strings MUST NOT contain U+0000. Escapes that decode to it (`\u0000`) are rejected: implementations compare string values with C-string or length-aware primitives, and a NUL inside a member name or identifier could alias a schema field. Non-NUL control-character escapes stay valid, but an unescaped control character (U+0000 through U+001F) inside a string MUST be rejected; encoders must use the `\u00XX` form.

Integer fields (`revision`, `entitlement_revision`, `offline_grace_seconds`, and every `limits` entry) MUST fit in a signed 64-bit integer (at most `9223372036854775807`). Conforming verifiers MUST reject larger integers rather than clamp or truncate them, so that implementations with and without arbitrary-precision integers decide identically. Real-valued capability values MUST be finite; `Infinity`, `-Infinity`, and `NaN` are rejected.

All protocol timestamps use exactly:

```text
YYYY-MM-DDTHH:MM:SSZ
```

They are UTC, second precision, and have no local-time or offset form.

Version bounds use strict SemVer 2.0 strings such as `2.4.0` or `2.4.0-beta.1`. A leading `v`, missing components, or leading zeroes in numeric identifiers are not Protocol v1 SemVer.

## 5. Common credential identity

Each signed statement has a globally unique `credential_id`.

Entitlement-like credentials additionally have:

- `entitlement_id` — stable identity for one logical commercial right across renewals or reissues;
- `revision` — non-negative integer that increases when that logical right is reissued.

Two different payloads MUST NOT intentionally reuse the same `entitlement_id` and `revision`.

A client that has several revisions MAY select the highest revision it has received. **Revision is not revocation.** A fully offline client that never receives revision 2 cannot infer that revision 1 was superseded.

## 6. Credential types

Protocol v1 assigns wire semantics to four credential types:

| Type | Purpose |
| --- | --- |
| `entitlement` | durable commercial right |
| `trial` | finite entitlement evaluated through the same product policy |
| `trial-extension` | signed absolute extension for a named trial id |
| `activation` | short-lived installation lease bound to an exact entitlement snapshot |

See:

- [Entitlements and trials](entitlement-v1.md)
- [Activation leases](activation-v1.md)
- [Trust model](trust-model.md)
- [Lifecycle](lifecycle.md)
- [Compatibility rules](compatibility.md)
- [Threat model](threat-model.md)

## 7. Trust semantics

A trust key has a lifecycle status of `next`, `active`, `retired`, or `revoked`.

The key's `not_before` / `not_after` range constrains the authenticated credential `issued_at`. It does **not** constrain the wall-clock time when a client verifies an old credential. This is essential for perpetual offline rights: a credential legitimately signed during a key's issuance window remains authentic after that key is retired.

`revoked` is different: a revoked public key MUST fail verification regardless of credential issue time.

## 8. Fail-closed rules

A conforming implementation rejects:

- unsupported protocol/envelope versions or algorithms;
- unknown or missing core fields;
- invalid or non-canonical Base64;
- malformed timestamps or SemVer bounds;
- unknown, revoked, or issuer-mismatched trust keys;
- credentials issued outside the signing key's issuance window;
- credential types outside the signing key's declared `purposes`;
- duplicate JSON object member names;
- invalid signatures;
- unsupported credential types;
- mismatched activation entitlement id, revision, credential id, or installation id.

## 9. Evolution

Protocol v1 is intentionally strict. Additive vendor information goes under `extensions`. A new security-critical top-level field or a new credential wire type is not silently interpreted by a v1 verifier.

Future protocol versions may define delegated issuers, signed revocation lists, store-receipt exchange, or enterprise floating-lease protocols. Existing v1 credentials remain byte-for-byte verifiable under their v1 rules.
