# Contributing to Permit

Thank you for helping improve Permit. Licensing code is security-sensitive, so the project favors small, reviewable changes with explicit invariants over clever shortcuts.

## Start here

1. Read the [architecture](docs/architecture.md) and [Protocol v1 specification](docs/protocol-v1.md).
2. For security-sensitive work, also read the [threat model](docs/threat-model.md) and [security policy](SECURITY.md).
3. Install the linked package and run the complete suite:

   ```bash
   raco pkg install --auto --no-docs --link
   raco make permit/main.rkt permit/cli.rkt permit-doc/scribblings/permit.scrbl
   raco test -p permit
   ```

4. Keep changes focused. Add a regression test before or with a behavioral fix.

## Change classes

### Racket implementation change

Preserve the public client/issuer split. Prefer pure functions in policy code, precise argument errors at boundaries, and names that match the protocol vocabulary.

### Protocol or wire-format change

Open a design discussion before implementation. Update the normative specification, compatibility notes, schemas, positive and rejection vectors, the Racket implementation, and user documentation together. Existing Protocol v1 vectors are append-only unless a published vector is proven invalid.

### Documentation change

Write first for a developer who has never built a licensing system. Introduce the trust boundary before commands, distinguish verification from policy evaluation, and label examples as illustrative rather than production secrets.

## Required checks

Before opening a pull request, run:

```bash
raco make permit/main.rkt permit/cli.rkt permit-doc/scribblings/permit.scrbl
raco test -p permit
racket test-vectors/v1/generate.rkt
git diff --exit-code -- test-vectors/v1
```

The final command proves deterministic vectors reproduce byte-for-byte. If it reports a change, either the generator is not deterministic or the vector change needs explicit review.

## Pull requests

Explain the problem, the preserved invariants, and the evidence used to verify the result. Call out compatibility or security effects directly. Do not mix protocol changes with unrelated formatting or website work.

Never commit production private keys, customer credentials, payment data, account exports, or machine fingerprints. The repository's deterministic test key is public test material only.

## Documentation languages

Use English for default public docs and preserve complete Chinese README and onboarding paths. Keep examples, supported-platform limits, troubleshooting and privacy/security promises consistent in the same change. Preserve identifiers and copyable commands; technical protocols have one normative English source, not separate language implementations. See the [family documentation language policy](https://github.com/turlamai/turlamai.github.io/blob/master/docs/DOCUMENTATION-LANGUAGES.md) for scope and review checks.
