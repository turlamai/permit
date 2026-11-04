# C conformance runner

A non-Racket implementation of Permit Protocol v1 verification. It exercises
the portable vector corpus in [`test-vectors/v1/`](../../test-vectors/v1/) end
to end: exact-byte Ed25519 authentication, trust-store rules, closed claim
schemas, and the positive and negative policy cases. Passing this runner is
the cross-language evidence that the corpus, not one language's reading of
it, defines the protocol.

The runner is a single C11 source file with one dependency: OpenSSL 3.x
(`libcrypto`) for Ed25519 and SHA-256. It links no Racket code and shares no
logic with the reference implementation, which is the point — agreement can
only come from the vectors.

## Build and run

```bash
make
./permit-conformance ../../test-vectors/v1
```

The Makefile prefers Homebrew's `openssl@3` on macOS (the system crypto
library is LibreSSL and has no Ed25519), then falls back to `pkg-config`.
On Linux, install the OpenSSL development files (`libssl-dev` and
`pkg-config` on Debian-style distributions).

Windows is exercised in CI through an MSYS2 MinGW-w64 toolchain with its
`openssl` package. Any C11 toolchain with an OpenSSL 3 development
installation should build the runner (for example vcpkg's `openssl` with
MSVC); the C standard library usage is deliberately portable.

## What it checks

1. The byte-level manifest (`credential-vectors.json`): payload file
   lengths, SHA-256 digests, envelope payload bytes, signatures, and that
   every positive credential verifies against the default trust store.
2. The exact-byte signature guard: appending a single payload byte breaks
   verification.
3. Every case in `conformance.json`: verification outcomes, rejection
   classes (tampered payloads, unknown key ids, revoked keys, issuance
   windows, key purposes, duplicate JSON members, raw control characters in
   JSON strings, aliased trust keys), and policy decisions with exact failure
   reasons where the corpus fixes them. Structural JSON failures use
   `json-structural-reject`; envelope-shape failures use `envelope-reject`.

The rejection paths mirror the reference verification order: envelope
structure, key lookup, signature, payload schema, issuer, issuance window,
key purpose. Policy windows are inclusive at both ends, and missing
evaluation context fails closed.

To confirm the runner is not vacuously green, any modification to a vector
file or an expected verdict in a corpus copy must produce failures and exit
status 1.

## Relationship to the Racket suite

`permit-test/vector-test.rkt` executes the same corpus through the Racket
reference implementation. The two harnesses must always agree; they are
independent readers of one contract. Update the corpus first, then both
implementations together, following [CONTRIBUTING.md](../../CONTRIBUTING.md).
