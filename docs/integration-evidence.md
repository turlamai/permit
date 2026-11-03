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


## MoveBit (second product pilot, 2026-11-01)

[MoveBit PR #82](https://github.com/turlamai/movebit/pull/82) merged as
`aff7cbe17d71663f8ef03cb116cf0fa1b1d4e2cc`. It established
a Free-first commercial policy and an **optional** Permit client adapter.
[MoveBit PR #112](https://github.com/turlamai/movebit/pull/112) merged as
`c46e17b5b59b06c44a2b2db8dfe568d75aff41ae`. The latter
added a bounded signed-credential import into machine-local application
storage, with an app-owned public trust-store injection seam. Its test
workflow pinned Permit source commit
`df47436013c5e3929c58dd809a97db77b2cfd423`, installed Permit
only in the Linux integration job, then exercised real ephemeral Ed25519
fixtures. The exact PR #112 head
`59196c58b02a96b5b1bc04c506425b3574edf061` reported successful
Racket test and packaged acceptance checks on Windows, Linux and macOS in
GitHub on 2026-11-03.

This is a **staged optional licensing core**, not an enabled checkout, Pro
gate or shipped trust root. The host RPC and UI import are not enabled in
those PRs. The regression cases explicitly include wrong-product and
expired credentials, version mismatch, conflicting revision, newer signed
withdrawal and attempted reimport of older rights. A valid *later*
withdrawal is accepted even if the license now grants no Pro access.

The portable learning is that revision comparison must happen **after**
signature verification and **before** entitlement evaluation. This is
covered in the [desktop adapter v1 contract](desktop-adapter-v1.md) and its
in-repository Racket tests. But a local file is user-writable and provides
no trusted monotonic anti-rollback ledger. An offline client may not
observe remote refunds/revocations at all. The product must choose an
activation/refresh policy if timely cancellation is promised.

These product check results are not evidence that the public Racket package
catalog's latest build succeeded; that is tracked separately in
[the runtime gate](crypto-runtime.md).
