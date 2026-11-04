#lang racket/base

(require crypto
         (only-in crypto/libcrypto libcrypto-factory)
         (only-in crypto/sodium sodium-factory)
         json
         rackunit
         racket/file
         racket/list
         racket/runtime-path
         "../permit/credential.rkt"
         "../permit/envelope.rkt"
         "../permit/policy.rkt"
         "../permit/trust.rkt")

(define-runtime-path vector-root "../test-vectors/v1")
(define payload-path (build-path vector-root "entitlement-payload.json"))
(define credential-path (build-path vector-root "entitlement.permit.json"))
(define trust-path (build-path vector-root "trust-store.json"))
(define tampered-path (build-path vector-root "tampered-payload.permit.json"))
(define unknown-key-path (build-path vector-root "unknown-key.permit.json"))
(define retired-trust-path (build-path vector-root "retired-trust-store.json"))
(define revoked-trust-path (build-path vector-root "revoked-trust-store.json"))
(define next-future-trust-path (build-path vector-root "next-future-trust-store.json"))
(define duplicate-key-trust-path (build-path vector-root "duplicate-key-alias-trust-store.json"))
(define activation-only-trust-path (build-path vector-root "activation-only-trust-store.json"))
(define duplicate-member-envelope-path (build-path vector-root "duplicate-member-envelope.json"))
(define credential-vector-manifest-path (build-path vector-root "credential-vectors.json"))
(define conformance-path (build-path vector-root "conformance.json"))
(define managed-credential-path (build-path vector-root "managed-entitlement.permit.json"))
(define activation-credential-path (build-path vector-root "activation.permit.json"))
(define trial-credential-path (build-path vector-root "trial.permit.json"))
(define trial-extension-credential-path (build-path vector-root "trial-extension.permit.json"))

(define hex-digits "0123456789abcdef")

(define (bytes->hex-string value)
  (list->string
   (append-map
    (lambda (byte)
      (list (string-ref hex-digits (quotient byte 16))
            (string-ref hex-digits (remainder byte 16))))
    (bytes->list value))))

(define credential
  (verify-credential credential-path (read-trust-store trust-path)))

(check-equal? (verified-credential-id credential) "cred_vector_01")
(check-equal? (verified-credential-entitlement-id credential) "ent_vector_01")
(check-equal? (verified-credential-revision credential) 0)
(check-equal? (verified-credential-payload credential) (file->bytes payload-path))

(check-true
 (update-entitled? credential
                   "gptp-studio"
                   "2027-10-15T23:59:59Z"
                   #:at "2030-01-01T00:00:00Z"
                   #:version "2.0.0"))
(check-false
 (update-entitled? credential
                   "gptp-studio"
                   "2027-10-16T00:00:00Z"
                   #:at "2030-01-01T00:00:00Z"
                   #:version "2.0.0"))

;; Any payload-byte change invalidates the exact-byte signature.
(define envelope (read-envelope credential-path))
(check-false
 (verify-envelope-signature
  (struct-copy permit-envelope
               envelope
               [payload (bytes-append (permit-envelope-payload envelope) #" ")])
  (trust-key-public-key
   (trust-store-key (read-trust-store trust-path)
                    (permit-envelope-key-id envelope)))))


;; Static fail-closed corpus for other language implementations.
(check-exn #rx"invalid Ed25519 signature"
           (lambda ()
             (verify-credential tampered-path (read-trust-store trust-path))))
(check-exn #rx"unknown key_id"
           (lambda ()
             (verify-credential unknown-key-path (read-trust-store trust-path))))

(define retired-credential
  (verify-credential credential-path (read-trust-store retired-trust-path)))
(check-equal? (verified-credential-id retired-credential) "cred_vector_01")

(check-exn #rx"revoked"
           (lambda ()
             (verify-credential credential-path (read-trust-store revoked-trust-path))))
(check-exn #rx"issuance window"
           (lambda ()
             (verify-credential credential-path (read-trust-store next-future-trust-path))))
(check-exn #rx"same public key"
           (lambda ()
             (read-trust-store duplicate-key-trust-path)))
(check-exn #rx"not authorized for credential type"
           (lambda ()
             (verify-credential credential-path (read-trust-store activation-only-trust-path))))
(check-exn #rx"duplicate JSON object member"
           (lambda ()
             (read-envelope duplicate-member-envelope-path)))

(check-false (version-allowed? credential "4.0.0"))

;; Every positive credential kind has a byte-level, cross-language manifest.
;; This catches accidental newline conversion, regenerated signatures, and
;; manifest drift independently of the higher-level policy checks below.
(define credential-vector-manifest
  (call-with-input-file credential-vector-manifest-path read-json))
(check-equal? (hash-ref credential-vector-manifest 'protocol) "permit-vector-manifest")
(check-equal? (hash-ref credential-vector-manifest 'version) 1)
(for ([entry (in-list (hash-ref credential-vector-manifest 'credentials))])
  (define payload
    (file->bytes (build-path vector-root (hash-ref entry 'payload_file))))
  (define vector-envelope
    (read-envelope (build-path vector-root (hash-ref entry 'credential_file))))
  (check-equal? (bytes-length payload) (hash-ref entry 'payload_length))
  (check-equal? (bytes->hex-string
                 (parameterize
                     ([crypto-factories
                       (list libcrypto-factory sodium-factory)])
                   (digest 'sha256 payload)))
                (hash-ref entry 'payload_sha256_hex))
  (check-equal? (permit-envelope-payload vector-envelope) payload)
  (check-equal? (permit-envelope-key-id vector-envelope)
                (hash-ref credential-vector-manifest 'key_id))
  (check-equal? (hash-ref (envelope->jsexpr vector-envelope) 'signature)
                (hash-ref entry 'signature_base64))
  (check-not-exn
   (lambda ()
     (verify-credential vector-envelope (read-trust-store trust-path)))))

(define store (read-trust-store trust-path))
(define managed-credential (verify-credential managed-credential-path store))
(define activation-credential (verify-credential activation-credential-path store))
(define trial-credential (verify-credential trial-credential-path store))
(define trial-extension-credential
  (verify-credential trial-extension-credential-path store))

(check-equal?
 (hash-ref
  (credential-status managed-credential
                     #:installation-id "ins_vector_A"
                     #:at "2027-06-01T00:00:00Z")
  'reasons)
 '(activation-required))
(check-true
 (credential-usable? managed-credential
                     #:installation-id "ins_vector_A"
                     #:activation activation-credential
                     #:at "2027-06-01T00:00:00Z"))
(check-false
 (credential-usable? managed-credential
                     #:installation-id "ins_vector_B"
                     #:activation activation-credential
                     #:at "2027-06-01T00:00:00Z"))
(check-true
 (credential-usable? managed-credential
                     #:installation-id "ins_vector_A"
                     #:activation activation-credential
                     #:at "2028-01-01T01:00:00Z"))
(check-false
 (credential-usable? managed-credential
                     #:installation-id "ins_vector_A"
                     #:activation activation-credential
                     #:at "2028-01-01T01:00:01Z"))

(check-true
 (feature-entitled? managed-credential
                    "example-desktop"
                    "feature-at-cutoff"
                    #:published-at "2027-06-30T23:59:59Z"
                    #:installation-id "ins_vector_A"
                    #:activation activation-credential
                    #:at "2027-07-01T00:00:00Z"))
(check-false
 (feature-entitled? managed-credential
                    "example-desktop"
                    "feature-after-cutoff"
                    #:published-at "2027-07-01T00:00:00Z"
                    #:installation-id "ins_vector_A"
                    #:activation activation-credential
                    #:at "2027-07-01T00:00:00Z"))
(check-false
 (feature-entitled? managed-credential
                    "example-desktop"
                    "feature-without-metadata"
                    #:installation-id "ins_vector_A"
                    #:activation activation-credential
                    #:at "2027-07-01T00:00:00Z"))

(check-true
 (credential-usable? trial-credential #:at "2026-10-29T00:00:00Z"))
(check-false
 (credential-usable? trial-credential #:at "2026-10-29T00:00:01Z"))
(check-true
 (credential-usable? trial-credential
                     #:trial-extensions (list trial-extension-credential)
                     #:at "2026-11-05T00:00:00Z"))
(check-false
 (credential-usable? trial-credential
                     #:trial-extensions
                     (list trial-extension-credential trial-extension-credential)
                     #:at "2026-11-05T00:00:01Z"))

;; Execute the language-neutral conformance description as data. Other
;; implementations can use a different harness, but the checked-in expected
;; outcomes must never drift away from the reference implementation.
;;
;; Each rejection class is one verify-failure reason (decision 0002); the
;; vector asserts the reason, never the message text. The C runner's Outcome
;; enum carries the same classes, so this table is the cross-language reason
;; contract. trust-store-reject and duplicate-json-reject are refusals of
;; the trust store and of the envelope reader respectively, before
;; verify-credential's pipeline begins.
(define rejection-reasons
  (hash "envelope-reject" 'envelope
        "unknown-key-reject" 'key-unknown
        "revoked-key-reject" 'key-revoked
        "signature-reject" 'signature
        "payload-reject" 'schema
        "issuer-mismatch-reject" 'issuer
        "issuance-window-reject" 'key-window
        "key-purpose-reject" 'key-purpose))

(define (verify-reason thunk)
  (with-handlers ([exn:fail:permit:verify? exn:fail:permit-reason])
    (thunk)
    'verified))

(define (vector-path filename)
  (build-path vector-root filename))

(define (verify-case-credential test-case [field 'credential])
  (verify-credential
   (vector-path (hash-ref test-case field))
   (read-trust-store (vector-path (hash-ref test-case 'trust_store)))))

(define (evaluate-policy-case test-case)
  (define query (hash-ref test-case 'query))
  (define credential (verify-case-credential test-case))
  (define activation
    (and (hash-has-key? test-case 'activation)
         (verify-case-credential test-case 'activation)))
  (define extensions
    (for/list ([filename (in-list (hash-ref test-case 'trial_extensions '()))])
      (verify-credential
       (vector-path filename)
       (read-trust-store (vector-path (hash-ref test-case 'trust_store))))))
  (define at (hash-ref query 'at #f))
  (define installation-id (hash-ref query 'installation_id #f))
  (case (string->symbol (hash-ref query 'kind))
    [(update)
     (values
      (update-entitled? credential
                        (hash-ref query 'product)
                        (hash-ref query 'published_at)
                        #:at at
                        #:version (hash-ref query 'version #f)
                        #:installation-id installation-id
                        #:activation activation
                        #:trial-extensions extensions)
      '())]
    [(version)
     (values (version-allowed? credential (hash-ref query 'version)) '())]
    [(edition)
     (values
      (edition-entitled? credential
                         (hash-ref query 'product)
                         (hash-ref query 'edition)
                         #:product-family (hash-ref query 'product_family #f)
                         #:at at
                         #:version (hash-ref query 'version #f)
                         #:installation-id installation-id
                         #:activation activation
                         #:trial-extensions extensions)
      '())]
    [(addon)
     (values
      (addon-entitled? credential
                       (hash-ref query 'product)
                       (hash-ref query 'addon)
                       #:product-family (hash-ref query 'product_family #f)
                       #:at at
                       #:version (hash-ref query 'version #f)
                       #:installation-id installation-id
                       #:activation activation
                       #:trial-extensions extensions)
      '())]
    ;; value queries compare against `equals`; a missing value is JSON null
    [(capability)
     (values
      (equal? (capability-value credential
                                (hash-ref query 'product)
                                (hash-ref query 'name)
                                #:default 'null
                                #:product-family (hash-ref query 'product_family #f)
                                #:at at
                                #:version (hash-ref query 'version #f)
                                #:installation-id installation-id
                                #:activation activation
                                #:trial-extensions extensions)
              (hash-ref query 'equals))
      '())]
    [(limit)
     (values
      (equal? (limit-value credential
                           (hash-ref query 'name)
                           #:default 'null
                           #:at at
                           #:version (hash-ref query 'version #f)
                           #:installation-id installation-id
                           #:activation activation
                           #:trial-extensions extensions)
              (hash-ref query 'equals))
      '())]
    [(usable)
     (define status
       (credential-status credential
                          #:at at
                          #:installation-id installation-id
                          #:activation activation
                          #:trial-extensions extensions))
     (values (hash-ref status 'usable?) (hash-ref status 'reasons))]
    [(feature)
     (values
      (feature-entitled? credential
                         (hash-ref query 'product)
                         (hash-ref query 'feature)
                         #:published-at (hash-ref query 'published_at #f)
                         #:at at
                         #:installation-id installation-id
                         #:activation activation
                         #:trial-extensions extensions)
      '())]
    [else
     (error 'evaluate-policy-case
            "unknown conformance query kind: ~a"
            (hash-ref query 'kind))]))

;; Lineage cases present several credentials of one entitlement and select
;; the newest; conflicting or unrelated statements fail closed.
(define (lineage-case test-case)
  (define case-name (hash-ref test-case 'name))
  (define expected (hash-ref test-case 'expected))
  (define store (read-trust-store (vector-path (hash-ref test-case 'trust_store))))
  (define credentials
    (for/list ([filename (in-list (hash-ref test-case 'credentials))])
      (verify-credential (vector-path filename) store)))
  (cond
    [(equal? expected "lineage-conflict-reject")
     (check-exn #rx"conflicting credentials share the highest revision"
                (lambda () (select-latest-entitlement credentials))
                case-name)]
    [(equal? expected "lineage-mismatch-reject")
     (check-exn #rx"different entitlement lineages"
                (lambda () (select-latest-entitlement credentials))
                case-name)]
    [else
     (check-equal? (verified-credential-id (select-latest-entitlement credentials))
                   (hash-ref (hash-ref test-case 'query) 'selects)
                   case-name)]))

(define conformance
  (call-with-input-file conformance-path read-json))
(check-equal? (hash-ref conformance 'protocol) "permit-conformance")
(check-equal? (hash-ref conformance 'version) 1)
(for ([test-case (in-list (hash-ref conformance 'cases))])
  (define expected (hash-ref test-case 'expected))
  (define case-name (hash-ref test-case 'name))
  (cond
    [(hash-has-key? test-case 'credentials) (lineage-case test-case)]
    [(equal? expected "verify")
     (check-not-exn (lambda () (verify-case-credential test-case)) case-name)]
    [(hash-has-key? rejection-reasons expected)
     (check-equal? (verify-reason (lambda () (verify-case-credential test-case)))
                   (hash-ref rejection-reasons expected)
                   case-name)]
    [(equal? expected "trust-store-reject")
     (check-exn #rx"same public key"
                (lambda () (read-trust-store (vector-path (hash-ref test-case 'trust_store))))
                case-name)]
    [(equal? expected "duplicate-json-reject")
     (check-exn #rx"duplicate JSON object member"
                (lambda () (read-envelope (vector-path (hash-ref test-case 'credential))))
                case-name)]
    [(equal? expected "json-structural-reject")
     ;; Strict-JSON structural failure: duplicate member, raw control
     ;; character, invalid escape, or trailing bytes. Kept distinct from
     ;; envelope-shape rejection so both implementations report one class.
     (check-exn exn:fail?
                (lambda () (read-envelope (vector-path (hash-ref test-case 'credential))))
                case-name)]
    [(boolean? expected)
     (define-values (actual reasons) (evaluate-policy-case test-case))
     (check-equal? actual expected case-name)
     (when (hash-has-key? test-case 'expected_reasons)
       (check-equal? (map symbol->string reasons)
                     (hash-ref test-case 'expected_reasons)
                     case-name))]
    [else
     (error 'vector-test "unknown conformance expectation: ~e" expected)]))
