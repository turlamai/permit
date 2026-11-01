# Integration evidence

The v0.2 gate asks for product evidence, not unit-test confidence: a real
Rivet or Glaze product integrating the public client facade, with the
integration's offline startup, credential replacement, key rotation,
expiry, and corrupt-state behavior recorded. This file is that record for
the first integration. Later integrations append their own sections.

## gptp-studio (first integration, 2026-10-16)

[gptp-studio](https://github.com/turlamai/gptp-studio) is an
automotive PTP engineering desktop (Rivet line, Racket + GTK). Its
commercial gate historically carried a self-rolled RSA-2048 +
canonical-JSON license module; integration replaced it with Permit
(commit `321676a`, adapter fixes `5b2fc2a`, behavior coverage `50b9551`).

- Facade used: `permit` (client only). The product never requires
  `permit/issuer`; its tests use a throwaway issuer to sign real
  credentials, mirroring how a vendor issues.
- Trust store: `app/keys/trust-store.json` ships with the application
  (key `gptp-pro-2026`, purposes limited to entitlement/trial/
  trial-extension — no activation, because the product is fully offline);
  the private key never leaves the vendor vault.
- Activation artifact: `~/.gptp-studio/entitlement.permit.json`, verified
  by `support/entitlement.rkt` against the shipped store on every tier
  decision; edition entitlement (`edition-entitled?`) grants the pro
  tier.
- Environments exercised: macOS arm64, Racket 9.3 (minimal-racket);
  571 product tests green including 33 gate-behavior tests
  (`tests/gate-test.rkt`); CI runs the same suite on Ubuntu and Windows
  runners.

### Recorded behavior

| Behavior | What the integration does | Where it is pinned |
|---|---|---|
| Offline startup | The gate verifies the credential purely from the shipped trust store — no network on any tier decision; trial state persists in a local JSON file. | `tests/gate-test.rkt` runs the whole flow with no network; `app/gate.rkt` requires only `permit` |
| Credential replacement | Activating a second valid credential overwrites the stored file; the gate follows it (new subject reported). A refused activation (expired file) leaves the stored credential in charge — the gate never downgrades because of a bad activation attempt. | replacement block of `tests/gate-test.rkt` |
| Key rotation | Two app generations in one test: store v1 (K1 active) and store v2 (K1 retired with a `not_after` issuance cutoff, K2 active). The pre-rotation credential verifies under both stores; the post-rotation credential verifies only under v2; safe issuance refuses the retired signing key outright. | rotation block of `tests/gate-test.rkt` |
| Expiry | An expired `use_expires_at` fails the gate with the typed customer-facing reason `expired` (status reasons, not an exception). | expiry block of `tests/gate-test.rkt` |
| Corrupt state | A missing credential file, garbage bytes in place of a credential, and a corrupt gate-state file all produce typed failures or empty state — never a crash, never a tier elevation. | corrupt-state block of `tests/gate-test.rkt` |

### Problems found by the integration (and fixed)

1. **The adapter module never reached the repository.** `321676a`
   described `support/entitlement.rkt` in its message but staged the file
   only onto disk; every CI run after it failed at compile. Fixed in
   `5b2fc2a`. Lesson: a rename/rename-adjacent commit needs a
   `git status` check against its own message before push.
2. **Fresh installs could not activate.** The gate copied the credential
   into `~/.gptp-studio/` without creating the directory first; a machine
   with no prior state crashed on first activation. Found via the
   replacement test on a scratch home; the gate now creates its state
   directory before any write (`50b9551`).
3. **The gate was untestable end to end.** The trust store path and the
   user state directory were hard-bound, so activation flows could only
   run against the shipped store and the real home. Two seams
   (`GPTP_STUDIO_HOME`, `GPTP_STUDIO_TRUST_STORE`) make the flows
   testable; production behavior is unchanged (`50b9551`).
4. **API drift from a parallel upstream.** Rivet's multi-installable feed
   change (component field) broke the product's update tests
   independently of Permit; fixed in the same window (`d95b44e`) under
   the family rule that whoever pushed red main fixes it.

None of these required a Permit API change; points 2 and 3 are product
side. The integration confirmed the rotation design works as documented:
retired keys preserved historical perpetual credentials while safe
issuance refused new ones.
