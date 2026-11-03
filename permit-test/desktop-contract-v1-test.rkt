#lang racket/base

;; Versioned desktop integration contract. These tests deliberately cross
;; the public client facade with genuine Ed25519 signatures issued only
;; from a test-local issuer. A passing result is NOT proof of a trusted
;; monotonic store, native host secure storage, or offline revocation.
(require json
         rackunit
         racket/port
         "../permit/main.rkt"
         (only-in "../permit/issuer.rkt"
                  exn:fail:permit:issue?
                  generate-ed25519-keypair
                  public-key->base64
                  entitlement-payload
                  successor-payload
                  subject
                  grant
                  constraints
                  payload->bytes
                  issue-credential
                  write-issued-credential)
         "../examples/desktop-client-v1.rkt")

(define now "2026-11-03T00:00:00Z")
(define product "example-desktop")
(define-values (private-a public-a) (generate-ed25519-keypair))
(define-values (private-b public-b) (generate-ed25519-keypair))

(define (key-entry public #:status [status "active"]
                   #:not-after [not-after 'null])
  (hasheq 'algorithm "Ed25519"
          'public_key (public-key->base64 public)
          'status status
          'purposes '("entitlement" "trial")
          'not_before 'null
          'not_after not-after))

(define (trust-store-with keys #:issuer [issuer "example.test"])
  (jsexpr->trust-store
   (hasheq 'protocol "permit-trust-store"
           'version 1
           'issuer issuer
           'keys keys)))

(define store-a
  (trust-store-with (hasheq 'key-a (key-entry public-a))))
(define rotated-store
  (trust-store-with
   (hasheq 'key-a (key-entry public-a #:status "retired"
                              #:not-after "2026-10-31T23:59:59Z")
           'key-b (key-entry public-b))))

(define explicit-grant
  (grant #:products (list product)
         #:edition "pro"
         #:features '("export")))
(define published-grant
  (grant #:products (list product)
         #:feature-policy "published-through"))
(define withdrawal-grant
  ;; Protocol v1 requires at least one grant; a grant with no rights is a
  ;; valid signed withdrawal without expanding the wire schema.
  (grant #:products (list product)))

(define (claims credential-id
                #:type [type "entitlement"]
                #:entitlement-id [entitlement-id "right-001"]
                #:issued-at [issued-at "2026-10-01T00:00:00Z"]
                #:grants [grants (list explicit-grant)]
                #:constraints [limits (constraints)])
  (entitlement-payload
   #:type type
   #:issuer "example.test"
   #:credential-id credential-id
   #:entitlement-id entitlement-id
   #:subject (subject #:type "anonymous" #:id "test-holder")
   #:grants grants
   #:constraints limits
   #:issued-at issued-at))

(define (issued payload [key private-a] [key-id "key-a"] [store store-a])
  (issue-credential (payload->bytes payload) key key-id store))
(define (verified payload)
  (verify-credential (issued payload) store-a))
(define (state credential #:version [version #f]
               #:installation-id [installation-id #f]
               #:at [at now])
  (desktop-entitlement-status credential product "pro"
                              #:at at
                              #:version version
                              #:installation-id installation-id))
(define (serialized credential)
  (call-with-output-bytes
   (lambda (out) (write-issued-credential credential out))))

;; Free fallback, perpetual, explicit feature and wrong product.
(check-equal? (hash-ref (state #f) 'state) "free")
(check-exn exn:fail:contract?
           (lambda () (state (hasheq 'unverified #t))))
(define perpetual (verified (claims "cred-perpetual")))
(check-equal? (hash-ref (state perpetual) 'state) "pro")
(check-true (feature-entitled? perpetual product "export" #:at now))
(check-false (edition-entitled? perpetual "foreign-product" "pro" #:at now))
(check-false (feature-entitled? perpetual product "unknown" #:at now))

;; Subscription expires independently of perpetual update/feature windows.
(define expired
  (verified (claims "cred-expired"
                    #:constraints (constraints
                                   #:use-expires-at "2026-10-15T00:00:00Z"))))
(check-false (hash-ref (state expired) 'entitled?))
(check-not-false (member "use-expired" (hash-ref (state expired) 'reasons)))

(define maintenance
  (verified (claims "cred-maintenance"
                    #:constraints (constraints
                                   #:updates-through "2026-10-20T00:00:00Z"
                                   #:features-through "2026-10-25T00:00:00Z")
                    #:grants (list explicit-grant published-grant))))
(check-true (edition-entitled? maintenance product "pro" #:at now))
(check-true (update-entitled? maintenance product
                              "2026-10-19T00:00:00Z" #:at now))
(check-false (update-entitled? maintenance product
                               "2026-10-21T00:00:00Z" #:at now))
(check-true (feature-entitled? maintenance product "new-feature"
                               #:published-at "2026-10-24T00:00:00Z"
                               #:at now))
(check-false (feature-entitled? maintenance product "new-feature"
                                #:published-at "2026-10-26T00:00:00Z"
                                #:at now))
(check-false (feature-entitled? maintenance product "new-feature" #:at now))
(check-true (feature-entitled? maintenance product "export" #:at now))

;; Signed trial, version-bound rights and installation mismatch fail closed.
(define trial
  (verified (claims "cred-trial" #:type "trial"
                    #:constraints (constraints
                                   #:use-expires-at "2026-11-10T00:00:00Z"))))
(check-true (hash-ref (state trial) 'entitled?))
(check-false (hash-ref (state trial #:at "2026-11-11T00:00:00Z") 'entitled?))
(define bounded
  (verified (claims "cred-bounded"
                    #:constraints (constraints
                                   #:version-min "2.0.0"
                                   #:version-max "3.0.0"
                                   #:installation-id "install-A"))))
(check-false (hash-ref (state bounded #:installation-id "install-A") 'entitled?))
(check-false (hash-ref (state bounded #:version "2.1.0"
                              #:installation-id "install-B") 'entitled?))
(check-true (hash-ref (state bounded #:version "2.1.0"
                             #:installation-id "install-A") 'entitled?))
(check-false (hash-ref (state bounded #:version "3.1.0"
                              #:installation-id "install-A") 'entitled?))

;; Host-clock rollback is detectable against issued_at but cannot provide
;; an authoritative clock or global replay protection.
(check-false (hash-ref (state perpetual #:at "2026-09-01T00:00:00Z")
                       'entitled?))
(check-not-false
 (member "issued-in-future"
         (hash-ref (state perpetual #:at "2026-09-01T00:00:00Z") 'reasons)))

;; A newer, genuinely signed withdrawal must supersede a cached older
;; grant even though the new snapshot grants no Pro edition.
(define before-withdrawal (claims "cred-legacy"))
(define after-withdrawal
  (successor-payload before-withdrawal
                     #:credential-id "cred-withdrawal"
                     #:issued-at "2026-10-15T00:00:00Z"
                     #:grants (list withdrawal-grant)))
(define old-right (verified before-withdrawal))
(define withdrawn-right (verified after-withdrawal))
(check-true (hash-ref (state old-right) 'entitled?))
(check-equal? (verified-credential-revision withdrawn-right) 1)
(check-equal?
 (verified-credential-id
  (select-latest-entitlement (list withdrawn-right old-right)))
 "cred-withdrawal")
(check-false
 (hash-ref (state (select-latest-entitlement
                   (list old-right withdrawn-right))) 'entitled?))

;; Rotation retains historical rights; revoked keys and an alien issuer
;; never become a UI authorization state.
(check-true
 (verified-credential?
  (verify-credential (issued before-withdrawal) rotated-store)))
(define fresh-right
  (claims "cred-new-key" #:issued-at "2026-11-01T00:00:00Z"))
(check-true
 (verified-credential?
  (verify-credential (issued fresh-right private-b "key-b" rotated-store)
                     rotated-store)))
(check-exn exn:fail:permit:issue?
           (lambda () (issued fresh-right private-a "key-a" rotated-store)))
(check-exn exn:fail:permit:verify?
           (lambda ()
             (verify-credential
              (issued before-withdrawal)
              (trust-store-with
               (hasheq 'key-a (key-entry public-a #:status "revoked"))))))
(check-exn exn:fail:permit:verify?
           (lambda ()
             (verify-credential
              (issued before-withdrawal)
              (trust-store-with
               (hasheq 'key-a (key-entry public-a))
               #:issuer "foreign.test"))))

;; Signature tampering must be a typed verification rejection, not a Free/Pro
;; decision based on unsigned claims.
(define wire (read-json (open-input-bytes (serialized (issued before-withdrawal)))))
(define signature (hash-ref wire 'signature))
(define changed-first-char
  (if (char=? (string-ref signature 0) #\A) "B" "A"))
(define tampered
  (string->bytes/utf-8
   (jsexpr->string
    (hash-set wire 'signature
              (string-append changed-first-char (substring signature 1))))))
(check-exn
 (lambda (e)
   (and (exn:fail:permit:verify? e)
        (eq? (exn:fail:permit-reason e) 'signature)))
 (lambda () (verify-credential (open-input-bytes tampered) store-a)))
