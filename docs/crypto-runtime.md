# Native Ed25519 providers and official package-build evidence

Permit Protocol v1 requires **Ed25519**, not a choice of signature algorithm.
The Racket reference implementation uses a fixed, explicit list of native
`crypto-lib` factories: **OpenSSL 3+** (`crypto/libcrypto`), **libsodium**
(`crypto/sodium`), then **Nettle**
(`crypto/nettle`). These are Ed25519 providers supplied by the upstream
cryptography package, not alternative signature algorithms. Available
providers are checked independently against the RFC 8032 known-answer vector
and invalid-signature rejection in `permit-test/core-test.rkt`. The public
credential envelope and exact-byte signing semantics do not change when
a backend changes. There is no weak or non-cryptographic fallback.

The native system libraries are optional at Racket package compilation time;
they are required at **credential key generation, parsing, signing and
verification** runtime. OpenSSL 3+ is normally available on full installations;
libsodium needs a compatible shared library, and Nettle needs compatible
`libnettle` and
`libhogweed` libraries. Importability alone does not establish Ed25519
capability. The Racket `x86_64-linux-natipkg-3` native-library package
contains OpenSSL **1.1**, not OpenSSL 3, which explains why the OpenSSL 3
factory may be unavailable even when the Racket distribution ships OpenSSL.
Availability of the other two providers on an official builder VM must
be measured, not assumed. If none is usable, Permit raises an error and
remains unable to authorize signed credentials; it must not silently accept
a credential or skip signature checks.

The optional upstream libgcrypt Ed25519 implementation is deliberately **not**
a fallback here: the 2026-11-03 GitHub Linux Racket 9.3 test of PR #21
showed that it rejects RFC 8032's empty-message known-answer signature with
`Zero prefix in S-expression`. A provider that cannot sign all valid
Ed25519 messages must not silently become a universal signing backend.

## Diagnosing an unsupported native environment

Run in the exact Racket environment used to verify or issue credentials:

```sh
racket -e '(require crypto crypto/libcrypto crypto/sodium crypto/nettle) (for ([p (list (cons (quote openssl3) libcrypto-factory) (cons (quote sodium) sodium-factory) (cons (quote nettle) nettle-factory))]) (displayln (list (car p) (factory-version (cdr p)) (and (get-pk (quote eddsa) (cdr p)) #t))))'
raco test -p permit
```

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
issuer key generation, DER/key decoding, and signed-credential tests due to
missing working Ed25519 providers, although install and documentation
succeeded. Previous OpenSSL 3 + libsodium support was therefore insufficient
for this service. This change adds only the explicitly named upstream Nettle provider; **official-build success is not established** until a
new dated builder log on this exact change has zero failures. If the additional
provider does not exist in the isolated VM, the fix requires distributing an
appropriate native dependency on `x86_64-linux-natipkg`, not suppressing
the crypto tests.

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
