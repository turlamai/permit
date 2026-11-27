# Native Ed25519 providers and official package-build evidence

Permit Protocol v1 requires **Ed25519**, not a choice of signature algorithm.
The Racket reference implementation tries a fixed, explicit list of native
`crypto-lib` factories — **OpenSSL 3+** (`crypto/libcrypto`), **libsodium**
(`crypto/sodium`), then **Nettle** (`crypto/nettle`) — and falls back to the
pure-Racket [`ed25519`](https://pkgs.racket-lang.org/package/ed25519) package
when none is usable. These are four Ed25519 implementations, not alternative
signature algorithms. Available providers are checked independently against
the RFC 8032 known-answer vector and invalid-signature rejection in
`permit-test/core-test.rkt`, and the pure backend is cross-checked against
native keys/signatures in `permit-test/pure-backend-test.rkt`. The public
credential envelope and exact-byte signing semantics do not change when a
backend changes. The pure backend is a complete RFC 8032 implementation, not
a weaker algorithm; it is not constant time (see below).

Native system libraries remain optional at Racket package compilation time.
At runtime Permit uses the first usable native provider and otherwise selects
the pure backend, so key generation, parsing, signing, and verification work
even on the official `x86_64-linux-natipkg` builder, which contains OpenSSL
**1.1** rather than OpenSSL 3. The pure backend still rejects invalid
signatures, `S >= L`, non-canonical point encodings, and malformed keys; it
never silently accepts a credential or skips signature checks.

The optional upstream libgcrypt Ed25519 implementation is deliberately **not**
a fallback here: the 2026-11-03 GitHub Linux Racket 9.3 test of PR #21
showed that it rejects RFC 8032's empty-message known-answer signature with
`Zero prefix in S-expression`. A provider that cannot sign all valid
Ed25519 messages must not silently become a universal signing backend.

## Diagnosing an unsupported native environment

Run in the exact Racket environment used to verify or issue credentials:

```sh
raco permit doctor
racket -e '(require crypto crypto/libcrypto crypto/sodium crypto/nettle) (for ([p (list (cons (quote openssl3) libcrypto-factory) (cons (quote sodium) sodium-factory) (cons (quote nettle) nettle-factory))]) (displayln (list (car p) (factory-version (cdr p)) (and (get-pk (quote eddsa) (cdr p)) #t))))'
raco test -p permit
```

`raco permit doctor` prints `{backend, native-available?, providers[], pure-backend}` as JSON: the same provider selection the library uses, without needing key material.

Each diagnostic line is `(provider version EdDSA-available?)`. A `#f`
version means the native library was unavailable; an available library still
requires a true `EdDSA-available?` result. Always verify the RFC 8032
known-answer test, invalid-signature rejection, trust-store key parsing,
issuer key generation, and cross-language C vectors; `raco make` alone
cannot prove Ed25519 works.

## Official Racket package build service

The [official `permit` package builder](https://pkg-build.racket-lang.org/server/built/test-fail/permit.txt)
ran on **2026-11-03 10:20–10:21 UTC**, on Racket 9.3
`x86_64-linux-natipkg`, and reported **7/151 failures**. Failures covered
issuer key generation, DER/key decoding, and signed-credential tests because
no working native Ed25519 provider existed, although install and documentation
succeeded. That transcript is historical: Permit now ships a pure backend for
exactly this environment. Official-build success is still established only by
a new dated transcript with zero failures, not by the fallback's unit tests.
Do not manufacture a green result by suppressing the crypto tests.

## Pure backend

- Package: `ed25519` v0.1, pure Racket, no FFI, RFC 8032 vectors plus OpenSSL
  3 cross-checks in its own CI.
- Selection: `current-ed25519-backend` is `'auto` (native first, then pure) by
  default; `'native` and `'pure` pin a backend for diagnostics and tests.
- Key encodings are unchanged: PKCS#8 private keys (the canonical 48-byte form
  and the `OneAsymmetricKey` form crypto-lib emits) and 44-byte
  `SubjectPublicKeyInfo` public keys.
- **Not constant time.** Native providers remain preferred for production
  issuers; the pure backend exists for verifiers and for environments where
  no native provider is installable.

Before calling a release or this issue resolved:

1. Run the cross-platform GitHub Racket/C test matrix on the exact new
   commit and record checks which have actually completed.
2. After merge/publish, inspect the public
   [Permit package build result](https://pkgs.racket-lang.org/package/permit)
   and the exact build-failure transcript, if any. If the official machine
   has neither required native provider, record an explicit unsupported
   environment rather than manufacturing a green test outcome.
3. Install `permit` **by published package name** from a clean Racket
   environment and run its tests and sample verifier.
4. Revalidate Commerce's pinned Permit integration; the released dependency
   must not be assumed compatible from unit tests alone.

This is operational backend selection, not key custody, a protocol change,
a relaxation of Ed25519 verification, or permission to place private keys
in customer applications.

## Reproducible performance measurements

From a checkout with Permit installed, run:

```sh
racket examples/crypto-benchmark.rkt --backend auto --iterations 100
racket examples/crypto-benchmark.rkt --backend pure --iterations 100
racket examples/crypto-benchmark.rkt --backend native --iterations 100
raco test examples/crypto-benchmark.rkt
```

Native mode fails explicitly when unavailable. Each run generates an ephemeral key,
warms up both operations and measures signing and verification separately using
monotonic wall-clock time for a fixed 1024-byte message. JSON includes the Racket
version, OS, architecture, requested mode, provider report, iteration count and
elapsed/mean milliseconds. Compare repeated runs on the same machine and runtime;
no universal latency target is implied. This does not benchmark complete credential
policy evaluation or demonstrate constant-time behavior. Never use production keys.

The GitHub Actions `Crypto benchmark` workflow runs the same tool on Linux,
macOS and Windows with Racket 9.3. Pull requests changing the tool or workflow
run two iterations as a smoke check; manual dispatch and relevant main pushes
run 100 per mode. Main triggers cover benchmark fixtures, workflow, library
source and package metadata. Download
the JSON artifacts for the exact commit and runner. An unavailable native
provider is recorded explicitly; `auto` and `pure` must both execute successfully.
Hosted runner measurements are diagnostic, not stable production latency targets.

## Credential verification and policy benchmark

Run `racket examples/credential-benchmark.rkt --backend auto --iterations 100`
(or `pure` / `native`). The fixed perpetual entitlement fixture is signed with
an ephemeral key and evaluated at a fixed timestamp. Measurements separately
cover serialized-envelope parsing, signature and credential validation;
cached usability plus allowed/denied edition decisions; and the combined path.
The trust store is initialized outside the timed region. Every policy iteration
checks the expected outcomes. This is a narrow local entitlement scenario, not
network activation, disk persistence, all policy combinations or production
latency certification. Run `raco test examples/credential-benchmark.rkt` for
the small pure-backend regression. No production credential input is accepted.
