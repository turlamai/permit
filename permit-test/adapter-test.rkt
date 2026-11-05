#lang racket/base

;; Cross-product adapter contract fixtures. Each case is one host question
;; (Free? Pro? expired? wrong product? rotated key?) answered by the public
;; `permit/adapter` helper, so SwiftUI/WinUI/GTK hosts and product shared
;; cores can exercise the same matrix.

(require rackunit
         racket/file
         racket/runtime-path
         "../permit/adapter.rkt"
         "../permit/trust.rkt")

(define-runtime-path vector-root "../test-vectors/v1")

(define (vector name)
  (build-path vector-root name))

(define (bytes name)
  (file->bytes (vector name)))

(define store (read-trust-store (vector "trust-store.json")))
(define retired-store (read-trust-store (vector "retired-trust-store.json")))

(define (evaluate #:store [trust-store store]
                  #:product [product "gptp-studio"]
                  #:at [at "2026-10-20T00:00:00Z"]
                  #:credential [credential-name #f]
                  #:activation [activation-name #f]
                  #:installation-id [installation-id #f]
                  #:feature [feature #f])
  (adapter-evaluate #:trust-store trust-store
                    #:product product
                    #:at at
                    #:credential-bytes (and credential-name (bytes credential-name))
                    #:activation-bytes (and activation-name (bytes activation-name))
                    #:installation-id installation-id
                    #:feature feature))

(define (state result) (hash-ref result 'state))
(define (reasons result) (hash-ref result 'reasons))
(define (usable? result) (hash-ref result 'usable?))

(test-case "Free is an explicit state, not a verification failure"
  (define result (evaluate))
  (check-equal? (state result) "free")
  (check-false (usable? result))
  (check-equal? (reasons result) '("no-credential"))
  (check-equal? (hash-ref result 'contract_version) 1))

(test-case "a valid perpetual entitlement is Pro"
  (define result (evaluate #:credential "entitlement.permit.json"))
  (check-equal? (state result) "pro")
  (check-true (usable? result))
  (check-equal? (reasons result) '())
  (check-equal? (hash-ref result 'entitlement_id) "ent_vector_01")
  (check-equal? (hash-ref result 'revision) 0)
  (check-equal? (hash-ref result 'type) "entitlement"))

(test-case "tampering is an import error, never a usable state"
  (define result (evaluate #:credential "tampered-payload.permit.json"))
  (check-equal? (state result) "invalid")
  (check-false (usable? result))
  (check-equal? (reasons result) '("signature")))

(test-case "malformed credential bytes fail closed at the host boundary"
  (define result
    (adapter-evaluate #:trust-store store
                      #:product "gptp-studio"
                      #:at "2026-10-20T00:00:00Z"
                      #:credential-bytes #"not a credential"))
  (check-equal? (state result) "invalid")
  (check-false (usable? result)))

(test-case "activation-required is valid-but-inactive before activation"
  (define without (evaluate #:credential "managed-entitlement.permit.json"
                            #:at "2027-06-01T00:00:00Z"))
  (check-equal? (state without) "inactive")
  (check-false (usable? without))
  (check-true (and (member "activation-required" (reasons without)) #t)))

(test-case "activation plus the matching installation id becomes Pro"
  (define result (evaluate #:credential "managed-entitlement.permit.json"
                           #:activation "activation.permit.json"
                           #:installation-id "ins_vector_A"
                           #:at "2027-06-01T00:00:00Z"))
  (check-equal? (state result) "pro")
  (check-true (usable? result)))

(test-case "expired trial and clock rollback stay inactive with typed reasons"
  (define expired (evaluate #:credential "trial.permit.json"
                            #:at "2027-06-01T00:00:00Z"))
  (check-equal? (state expired) "inactive")
  (check-true (and (member "use-expired" (reasons expired)) #t))
  (define rollback (evaluate #:credential "entitlement.permit.json"
                             #:at "2020-01-01T00:00:00Z"))
  (check-equal? (state rollback) "inactive")
  (check-true (and (member "issued-in-future" (reasons rollback)) #t)))

(test-case "wrong product never grants a feature"
  (define result (evaluate #:credential "entitlement.permit.json"
                           #:product "other-product"
                           #:feature "pcap-export"))
  (check-equal? (state result) "pro")
  (check-false (hash-ref result 'feature_allowed)))

(test-case "a retired trust key still verifies historical credentials"
  (define result (evaluate #:store retired-store
                           #:credential "entitlement.permit.json"))
  (check-equal? (state result) "pro")
  (check-true (usable? result)))
