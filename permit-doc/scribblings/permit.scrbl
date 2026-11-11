#lang scribble/manual

@(require (for-label racket/base
                     json
                     permit
                     permit/issuer
                     permit/adapter))

@title[#:tag "permit"]{Permit: Signed Product Rights}
@author[(author+email "Turing Lambda" "jirentianxiang1024@gmail.com")]

@defmodule[permit]

Permit is a framework-neutral protocol and Racket reference
implementation for answering one product question: what may this
person, organization, or installation use right now? Long-lived
@emph{entitlements} describe commercial rights, optional short-lived
@emph{activation leases} bind a right to an installation, and local
first-run @emph{trials} are their own convenience state. Everything is
verified offline against an Ed25519 trust store that ships inside the
application; issuance and rotation are online concerns that never
change the verification protocol.

Permit is deliberately not anti-tamper DRM, and a permanently offline
credential cannot learn about a revocation that happened elsewhere —
see @hyperlink["https://github.com/turlamai/permit/blob/main/docs/threat-model.md"]{the
threat model} for the honest boundaries. The normative protocol lives in
@hyperlink["https://github.com/turlamai/permit/blob/main/docs/protocol-v1.md"]{Protocol
v1}; this manual documents the Racket surface.

@section{Trust stores}

Applications ship public keys only. A trust store is JSON application
configuration, delivered through the application's authenticated
release path:

@codeblock|{
{
  "protocol": "permit-trust-store",
  "version": 1,
  "issuer": "com.example",
  "keys": {
    "license-2027": {
      "algorithm": "Ed25519",
      "public_key": "<Base64 SubjectPublicKeyInfo DER>",
      "status": "active",
      "purposes": ["entitlement", "trial", "trial-extension"],
      "not_before": "2027-01-01T00:00:00Z",
      "not_after": null
    }
  }
}
}|

Key statuses are @tt{next} (pre-distributed, must have @tt{not_before}),
@tt{active} (normal issuance), @tt{retired} (no new issuance, must have
an @tt{not_after} issuance cutoff — old credentials stay authentic), and
@tt{revoked} (every credential under the key fails). Each key declares
the credential types it may sign; an activation-signing key therefore
cannot mint a perpetual entitlement. The time windows constrain the
credential's authenticated @tt{issued_at}, not the wall clock at
verification — retiring a key never kills a perpetual entitlement.

@defproc[(read-trust-store [source (or/c path-string? input-port?)])
         trust-store?]{
Parses and validates a trust store document. Unknown key statuses,
missing purposes, and wrong algorithms are rejected here.
}

@defproc[(jsexpr->trust-store [value jsexpr?]) trust-store?]{
The same validation for an already-parsed document.
}

@defproc[(trust-store? [v any/c]) boolean?]{}
@defproc[(trust-store-issuer [store trust-store?]) string?]{
The only credential issuer this store will accept.
}

@section{Verifying credentials}

A credential is a small JSON envelope whose @tt{payload} is base64
bytes signed exactly with Ed25519. Verification authenticates those
bytes first and only then parses authorization claims — the verifier
never re-serializes JSON, which removes canonicalization ambiguity
across languages.

@defproc[(verify-credential [source (or/c path-string? input-port?)]
                            [store trust-store?])
         verified-credential?]{
Verifies signature, trust key, issuer, key purpose, and key issuance
window, then parses and schema-checks the payload. Any refusal raises
@racket[exn:fail:permit:verify] — an invalid credential is an error, not a
boolean — with a @racket[reason] naming the guard; see
@secref["verification-failures"].
}

@defproc[(verified-credential? [v any/c]) boolean?]{
Only values returned by @racket[verify-credential] satisfy this
predicate; the constructor is sealed so unverified claims cannot flow
into policy checks.
}

The claims accessors (all @racket[(-> verified-credential? ...)]):
@defproc[(verified-credential-type [c verified-credential?]) string?]{
@tt{"entitlement"}, @tt{"trial"}, @tt{"trial-extension"}, or
@tt{"activation"}.
}
@defproc[(verified-credential-id [c verified-credential?]) string?]{}
@defproc[(verified-credential-issuer [c verified-credential?]) string?]{}
@defproc[(verified-credential-issued-at [c verified-credential?]) string?]{}
@defproc[(verified-credential-entitlement-id [c verified-credential?]) (or/c string? #f)]{}
@defproc[(verified-credential-revision [c verified-credential?]) exact-nonnegative-integer?]{}
@defproc[(verified-credential-subject-type [c verified-credential?]) (or/c string? #f)]{}
@defproc[(verified-credential-subject-id [c verified-credential?]) (or/c string? #f)]{}
@defproc[(verified-credential-subject-display [c verified-credential?]) (or/c string? #f)]{
The customer-facing name (an email address, for example). Display only —
never an authorization input.
}
@defproc[(verified-credential-channel [c verified-credential?]) (or/c string? #f)]{}
@defproc[(verified-credential-use-expires-at [c verified-credential?]) (or/c string? #f)]{
Canonical UTC timestamp; @racket[#f] means the right does not expire.
}
@defproc[(verified-credential-updates-through [c verified-credential?]) (or/c string? #f)]{}
@defproc[(verified-credential-features-through [c verified-credential?]) (or/c string? #f)]{}

@subsection[#:tag "verification-failures"]{Verification failures}

A refusal is always an exception — fail-closed never returns a value — and
carries a reason so a product can tell the customer what was wrong with a
license file without matching message text. Time outcomes (expiry,
not-yet-valid, installation mismatch, missing activation) are not refusals;
they come back from @racket[credential-status] as status reasons. See
@hyperlink["https://github.com/turlamai/permit/blob/main/docs/decisions/0002-typed-verification-failures.md"]{decision
0002}.

@defstruct*[(exn:fail:permit exn:fail) ([reason symbol?])]{
The parent of every Permit refusal, on the verifier and the issuer side.
@racket[exn:fail:permit-reason] is the one accessor for both.
}

@defstruct*[(exn:fail:permit:verify exn:fail:permit) ()]{
Raised by @racket[verify-credential]. Its @racket[reason] is one of
@racket[verify-failure-reasons]. Messages keep the
@racket[raise-arguments-error] layout, so callers that matched message text
keep working. A store that is not a @racket[trust-store?] is a plain
contract error, not a refusal.
}

@defthing[verify-failure-reasons (listof symbol?)]{
@racket['(envelope key-unknown key-revoked signature schema issuer key-window key-purpose)]
in pipeline order — the wrapper could not be read or is not a Protocol v1
envelope; the @tt{key_id} is not in the store; the key is revoked; the
Ed25519 signature does not verify; the authenticated payload failed strict
parsing or schema validation; the signed @tt{issuer} differs from the
store's; @tt{issued_at} falls outside the key's issuance window; the key's
purposes do not include the credential type. Because the order is the
order a conforming verifier checks in, the reason also tells you which
guard refused.
}

@section{Evaluating policy}

Policy evaluation is total and offline: every check takes the verified
credential, an evaluation instant (@racket[(current-rfc3339)] by
default), and optional binding parameters.

@defproc[(credential-usable? [c verified-credential?]
                             [#:at at string? (current-rfc3339)]
                             [#:installation-id installation-id (or/c string? #f) #f]
                             [#:activation activation (or/c verified-credential? #f) #f]
                             [#:trial-extensions trial-extensions (listof verified-credential?) '()])
         boolean?]{
True when the credential is currently within its use window, matches
the installation binding if any, and carries a valid activation lease
if the entitlement demands one.
}

@defproc[(credential-status [c verified-credential?]
                            [#:at at string? (current-rfc3339)]
                            [#:installation-id installation-id (or/c string? #f) #f]
                            [#:activation activation (or/c verified-credential? #f) #f]
                            [#:trial-extensions trial-extensions (listof verified-credential?) '()])
         (hash/c symbol? any/c)]{
The full verdict: @racket['usable?], @racket['reasons] (a list of
symbols such as @racket['use-expired] or @racket['not-active-yet]), and
@racket['effective_use_expires_at] after trial extensions.
}

@defproc[(activation-valid? [entitlement verified-credential?]
                            [activation verified-credential?]
                            [installation-id string?]
                            [#:at at string? (current-rfc3339)])
         boolean?]{
Checks that a lease is current and bound to the exact entitlement id,
revision, credential id, issuer, and installation.
}

@defproc[(trial-extension-valid? [trial verified-credential?]
                                 [extension verified-credential?]
                                 [#:at at string? (current-rfc3339)])
         boolean?]{
Checks the signed relationship and activation time of a trial extension.
}

@defproc[(edition-entitled? [c verified-credential?]
                            [product string?]
                            [edition string?]
                            [#:at at string? (current-rfc3339)]
                            [#:product-family product-family (or/c string? #f) #f]
                            [#:version version (or/c string? #f) #f]
                            [#:installation-id installation-id (or/c string? #f) #f]
                            [#:activation activation (or/c verified-credential? #f) #f]
                            [#:trial-extensions trial-extensions (listof verified-credential?) '()])
         boolean?]{
True when a grant covers the product at the edition and the credential
is usable. The same keyword shape applies to
@racket[feature-entitled?], @racket[addon-entitled?], and
@racket[update-entitled?].
}

@defproc[(feature-entitled? [c verified-credential?]
                            [product string?]
                            [feature string?]
                            [#:published-at published-at (or/c string? #f) #f]
                            [#:at at string? (current-rfc3339)] ...
                            ) boolean?]{
Product-feature check with the @tt{published-through} window: a
feature published after @racket[features_through] is not covered, so a
perpetual customer keeps everything published inside the window they
bought. Requires @racket[#:published-at] — the application's honest
build-time or manifest timestamp for that feature.
}

@defproc[(update-entitled? [c verified-credential?]
                           [product string?]
                           [update-published-at string?]
                           [#:at at string? (current-rfc3339)] ...
                           ) boolean?]{
Update-rights check against @tt{updates_through}.
}

@defproc[(capability-value [c verified-credential?]
                           [product string?]
                           [capability symbol?]
                           [#:default default any/c #f]
                           [#:at at string? (current-rfc3339)] ...) any/c]{}
@defproc[(limit-value [c verified-credential?]
                      [limit symbol?]
                      [#:default default any/c #f]
                      [#:at at string? (current-rfc3339)] ...) any/c]{
Scalar capabilities and seat limits (named seats, device activations,
concurrent seats) from the credential's constraints.
}

@defproc[(version-allowed? [c verified-credential?] [version string?]) boolean?]{
SemVer 2.0 check against the credential's version bounds.
}

@defproc[(select-latest-entitlement
          [credentials (and/c (listof verified-credential?) pair?)])
         verified-credential?]{
Deterministic replacement among credentials actually received: highest
@tt{revision} for the same @tt{entitlement_id}. This is replacement,
not offline revocation.
}

@section{Issuing credentials}

@defmodule[permit/issuer]

The issuer surface is an explicit opt-in; the client facade above
never exports private-key operations. It re-exports @racket[trust-store?],
@racket[read-trust-store], and @racket[jsexpr->trust-store] so an issuer
adapter needs only this module.

@defproc[(generate-ed25519-keypair)
         (values pk-key? pk-key?)]{}
@defproc[(read-ed25519-private-key [source path-string?]) pk-key?]{}
@defproc[(read-ed25519-public-key [source path-string?]) pk-key?]{}
@defproc[(ed25519-private-key->der [key pk-key?]) bytes?]{}
@defproc[(ed25519-public-key->der [key pk-key?]) bytes?]{}
@defproc[(public-key->base64 [key pk-key?]) string?]{}

@defproc[(issued-credential? [value any/c]) boolean?]{
Recognizes the opaque result of @racket[issue-credential].
}

@defproc[(issue-credential [payload bytes?]
                           [private-key pk-key?]
                           [key-id string?]
                           [store trust-store?])
         issued-credential?]{
The safe issuance path: schema-validates the payload, pins issuer,
active key status, key purpose, and the key's issuance window, and
verifies the private key matches the trust-store public key. The
@racket[raco permit issue] command goes through this function;
@racket[raco permit sign] is the deliberate low-level escape hatch.
}

@defproc[(write-issued-credential [credential issued-credential?]
                                  [destination (or/c path-string? output-port?)])
         void?]{
Serializes an issued credential as its Protocol v1 JSON envelope. This is the
supported programmatic path from safe issuance to storage or delivery.
}

@subsection{Rights snapshots}

An issuer builds a complete rights snapshot, serializes it once, and hands
those bytes to @racket[issue-credential]. These constructors spell the closed
entitlement schema so that adapters never do; every field is an explicit
keyword with a @racket['null] or empty default wherever the schema allows
one. See
@hyperlink["https://github.com/turlamai/permit/blob/main/docs/decisions/0001-issuer-rights-snapshots.md"]{decision
0001} for the boundary this layer defines.

@defproc[(subject [#:type type string?]
                  [#:id id string?]
                  [#:display display (or/c string? 'null) 'null])
         jsexpr?]{
A credential subject. @racket[type] is one of @racket["person"],
@racket["organization"], @racket["account"], @racket["device"],
@racket["installation"], or @racket["anonymous"]; @racket[id] is the
issuer's stable opaque identifier.
}

@defproc[(grant [#:products products (listof string?) '()]
                [#:product-families product-families (listof string?) '()]
                [#:edition edition (or/c string? 'null) 'null]
                [#:feature-policy feature-policy (or/c "explicit" "published-through") "explicit"]
                [#:features features (listof string?) '()]
                [#:addons addons (listof string?) '()]
                [#:capabilities capabilities (hash/c symbol? (or/c string? boolean? rational?)) (hasheq)])
         jsexpr?]{
One grant. The scope must name at least one product or product family;
@racket["published-through"] grants leave @racket[features] empty and let
@racket[features_through] decide.
}

@defproc[(constraints [#:use-expires-at use-expires-at (or/c string? 'null) 'null]
                      [#:updates-through updates-through (or/c string? 'null) 'null]
                      [#:features-through features-through (or/c string? 'null) 'null]
                      [#:version-min version-min (or/c string? 'null) 'null]
                      [#:version-max version-max (or/c string? 'null) 'null]
                      [#:named-seats named-seats (or/c exact-nonnegative-integer? 'null) 'null]
                      [#:device-activations device-activations (or/c exact-nonnegative-integer? 'null) 'null]
                      [#:concurrent-seats concurrent-seats (or/c exact-nonnegative-integer? 'null) 'null]
                      [#:installation-id installation-id (or/c string? 'null) 'null]
                      [#:activation-required? activation-required? boolean? #f])
         jsexpr?]{
The three independent windows, version policy, limits, and installation
binding. All defaults describe a perpetual, unlimited, unbound right.
}

@defproc[(entitlement-payload [#:issuer issuer string?]
                              [#:credential-id credential-id string?]
                              [#:entitlement-id entitlement-id string?]
                              [#:subject subject jsexpr?]
                              [#:grants grants (listof jsexpr?)]
                              [#:issued-at issued-at string?]
                              [#:type type (or/c "entitlement" "trial") "entitlement"]
                              [#:revision revision exact-nonnegative-integer? 0]
                              [#:channel channel string? (if (equal? type "trial") "trial" "commercial")]
                              [#:constraints constraints jsexpr? (constraints)]
                              [#:not-before not-before (or/c string? 'null) 'null]
                              [#:extensions extensions jsexpr? (hasheq)])
         jsexpr?]{
A complete entitlement-like payload. The result has already passed
@racket[validate-credential-claims]: an invalid snapshot raises the schema
error at the call site instead of inside the signer.
}

@defproc[(successor-payload [previous jsexpr?]
                            [#:credential-id credential-id string?]
                            [#:issued-at issued-at string?]
                            [#:subject subject (or/c jsexpr? #f) #f]
                            [#:channel channel (or/c string? #f) #f]
                            [#:grants grants (or/c (listof jsexpr?) #f) #f]
                            [#:constraints constraints (or/c jsexpr? #f) #f]
                            [#:not-before not-before (or/c string? 'null) 'null]
                            [#:extensions extensions (or/c jsexpr? #f) #f])
         jsexpr?]{
The next revision of an existing lineage, the only supported spelling of
renewal, plan change, seat change, and withdrawal. @racket[entitlement_id],
@racket[issuer], and @racket[type] are inherited and cannot be replaced;
@racket[revision] becomes @racket[previous]'s plus one; each @racket[#f]
keyword keeps the previous value. A withdrawal is a successor whose
@racket[constraints] already expired — Permit does not pretend to revoke
offline.
}

@defproc[(payload->bytes [payload jsexpr?]) bytes?]{
The one serialization step. Sign and store exactly these bytes; the
protocol's exact-byte rule forbids re-serializing the jsexpr afterwards.
}

@subsection{Issuance failures}

@defstruct*[(exn:fail:permit:issue exn:fail:permit) ()]{
Every refusal by @racket[issue-credential] after its argument checks; read
the reason with @racket[exn:fail:permit-reason] (see
@secref["verification-failures"] for the parent). The reason is one of
@racket[issue-failure-reasons]; the message keeps the
@racket[raise-arguments-error] layout, so callers that matched message text
keep working. Argument-shape errors (a non-@racket[bytes?] payload, a
non-@racket[trust-store?] store) remain ordinary contract errors.
}

@defthing[issue-failure-reasons (listof symbol?)]{
@racket['(schema issuer key-unknown key-status key-window key-purpose key-mismatch)]
— the payload failed schema validation; its @racket[issuer] differs from the
trust store's; the @racket[key-id] is not in the store; the key is not
@racket["active"]; @racket[issued_at] falls outside the key's issuance
window; the key's purposes do not include the credential type; the private
key does not correspond to the store's public key.
}

@section{Host adapter}

@defmodule[permit/adapter]

A host UI — SwiftUI, WinUI 3, GTK, or any other native shell — should not
re-implement verification, status, and feature composition.
@racket[permit/adapter] evaluates one candidate credential, or no credential
at all, into one small JSON-shaped result. The result is deliberately free of
subject identity, claims, raw credential bytes, and trust material, and
verification failures are a separate field from valid-but-unusable states, so
a host can distinguish a forged or corrupt import from an expired license
without parsing messages. The contract between hosts and this module is
versioned; see
@hyperlink["https://github.com/turlamai/permit/blob/main/docs/desktop-adapter-v1.md"]{the
desktop adapter contract}.

@defthing[adapter-contract-version exact-positive-integer?]{The adapter contract version, currently @racket[1].}

@defproc[(adapter-evaluate
          [#:trust-store store trust-store?]
          [#:product product string?]
          [#:at at string?]
          [#:credential-bytes credential-bytes (or/c bytes? #f) #f]
          [#:feature feature (or/c string? #f) #f]
          [#:version version (or/c string? #f) #f]
          [#:installation-id installation-id (or/c string? #f) #f]
          [#:activation-bytes activation-bytes (or/c bytes? #f) #f]
          [#:trial-extension-bytes extension-bytes (listof bytes?) '()])
         hash?]{
Returns a JSON-shaped hash carrying @racket['contract_version],
@racket['product], @racket['at], @racket['state] — one of
@racket["free"] (no credential), @racket["pro"] (verified and usable),
@racket["inactive"] (verified but not currently usable), or
@racket["invalid"] (verification failed) — plus @racket['usable?],
@racket['reasons], @racket['entitlement_id], @racket['revision],
@racket['type], and @racket['feature_allowed]. Malformed or forged
credential bytes never raise: they become @racket["invalid"] with the
public verification reason. Argument type errors still raise
@racket[exn:fail:contract].
}

@section{Command line}

@verbatim|{raco permit keygen --private k.der --public pub.der \
           --trust-store trust.json --key-id license-2027 \
           --issuer com.example
raco permit issue  --key k.der --key-id license-2027 \
           --trust-store trust.json --payload ent.json \
           --output customer.permit.json
raco permit sign   --key k.der --payload ent.json \
           --output customer.permit.json
raco permit verify --trust-store trust.json \
           --credential customer.permit.json
raco permit check  --trust-store trust.json \
           --credential customer.permit.json \
           --product example-app --edition pro
raco permit inspect --credential customer.permit.json
raco permit doctor}|#

@tt{inspect} is deliberately labelled unverified; never authorize a
feature from inspected claims alone. @tt{sign} is the deliberately
low-level escape hatch that skips the issuer-side checks of
@tt{issue}. @tt{doctor} prints the selected Ed25519 backend and
per-provider availability as JSON.

@section{Local trials and installation identity}

@defproc[(generate-installation-id) string?]{
A random, privacy-preserving installation identifier — not a hardware
fingerprint.
}

@defproc[(make-local-trial
          [#:duration-seconds duration-seconds exact-positive-integer? (* 14 24 60 60)]
          [#:at at string? (current-rfc3339)]
          [#:id id string? (generate-local-trial-id)])
         local-trial?]{}
@defproc[(evaluate-local-trial [trial local-trial?]
                               [#:at at string? (current-rfc3339)]
                               [#:extensions extensions (listof verified-credential?) '()]
                               [#:issuer issuer (or/c string? #f) #f]
                               [#:rollback-tolerance-seconds tolerance exact-nonnegative-integer? 300])
         local-trial-evaluation?]{
Evaluates the trial against the stored clock high-water mark and any
verified @tt{trial-extension} credentials. The result carries the
updated state to persist.
}

@defproc[(local-trial-evaluation-state [r local-trial-evaluation?]) local-trial?]{}
@defproc[(local-trial-evaluation-active? [r local-trial-evaluation?]) boolean?]{}
@defproc[(local-trial-evaluation-reason [r local-trial-evaluation?]) (or/c symbol? #f)]{}
@defproc[(local-trial-evaluation-remaining-seconds [r local-trial-evaluation?]) (or/c exact-integer? #f)]{}
@defproc[(local-trial->jsexpr [t local-trial?]) jsexpr?]{}
@defproc[(jsexpr->local-trial [v jsexpr?]) local-trial?]{}
@defproc[(write-local-trial [t local-trial?] [destination path-string?]) void?]{}
@defproc[(read-local-trial [source path-string?]) local-trial?]{

A local trial is signed nowhere — it is convenience state with a random
id and a last-seen clock high-water mark. That is nuisance resistance,
not tamper resistance; a user controlling the machine can reset it.
}
