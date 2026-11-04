#lang racket/base

;; Stable host-facing adapter contract for Permit Protocol v1. SwiftUI,
;; WinUI, GTK and other hosts should consume this one JSON-shaped result
;; instead of re-implementing verification/status/feature composition.
;;
;; The result is deliberately small and non-sensitive: no subject id, claims,
;; raw credential bytes or trust material. Verification failures and
;; valid-but-unusable states are separate fields so a host can distinguish
;; "forged/corrupt import" from "expired license" without parsing messages.

(require "credential.rkt"
         "policy.rkt"
         "trust.rkt")

(provide adapter-contract-version
         adapter-evaluate)

(define adapter-contract-version 1)

(define (check-inputs who store product at)
  (unless (trust-store? store)
    (raise-argument-error who "trust-store?" store))
  (unless (string? product)
    (raise-argument-error who "string? (product id)" product))
  (unless (string? at)
    (raise-argument-error who "string? (RFC 3339 evaluation time)" at)))

(define (empty-result base state usable? reasons)
  (hash-set* base
             'state state
             'usable? usable?
             'reasons reasons
             'entitlement_id 'null
             'revision 'null
             'type 'null
             'feature_allowed 'null))

;; Evaluates one candidate credential (or no credential) for a product.
;; Never raises for malformed/forged credential bytes; those become
;; state="invalid" with the public verify reason. Argument type errors still
;; raise exn:fail:contract.
(define (adapter-evaluate #:trust-store store
                          #:product product
                          #:at at
                          #:credential-bytes [credential-bytes #f]
                          #:feature [feature #f]
                          #:version [version #f]
                          #:installation-id [installation-id #f]
                          #:activation-bytes [activation-bytes #f]
                          #:trial-extension-bytes [extension-bytes '()])
  (check-inputs 'adapter-evaluate store product at)
  (when (and feature (not (string? feature)))
    (raise-argument-error 'adapter-evaluate "(or/c #f string?)" feature))
  (when (and version (not (string? version)))
    (raise-argument-error 'adapter-evaluate "(or/c #f string?)" version))
  (when (and installation-id (not (string? installation-id)))
    (raise-argument-error 'adapter-evaluate "(or/c #f string?)" installation-id))
  (when (and credential-bytes (not (bytes? credential-bytes)))
    (raise-argument-error 'adapter-evaluate "(or/c #f bytes?)" credential-bytes))
  (when (and activation-bytes (not (bytes? activation-bytes)))
    (raise-argument-error 'adapter-evaluate "(or/c #f bytes?)" activation-bytes))
  (unless (and (list? extension-bytes)
               (for/and ([item (in-list extension-bytes)]) (bytes? item)))
    (raise-argument-error 'adapter-evaluate "(listof bytes?)" extension-bytes))
  (define (verify-source bytes)
    (verify-credential (open-input-bytes bytes) store))
  (define base
    (hash 'contract_version adapter-contract-version
          'product product
          'at at))
  (cond
    [(not credential-bytes)
     (empty-result base "free" #f '("no-credential"))]
    [else
     (with-handlers
         ([exn:fail:permit:verify?
           (lambda (failure)
             (empty-result base
                           "invalid"
                           #f
                           (list (symbol->string (exn:fail:permit-reason failure)))))]
          [exn:fail?
           (lambda (_)
             ;; Corrupt bytes that fail before a typed verify verdict still
             ;; must not crash a host boundary.
             (empty-result base "invalid" #f '("invalid-credential")))])
       (define credential (verify-source credential-bytes))
       (define activation (and activation-bytes (verify-source activation-bytes)))
       (define extensions (map verify-source extension-bytes))
       (define status
         (credential-status credential
                            #:at at
                            #:installation-id installation-id
                            #:activation activation
                            #:trial-extensions extensions))
       (define usable? (hash-ref status 'usable?))
       (define feature-allowed
         (and feature
              (feature-entitled? credential product feature
                                 #:version version
                                 #:at at
                                 #:installation-id installation-id
                                 #:activation activation
                                 #:trial-extensions extensions)))
       (hash-set* base
                  'state (if usable? "pro" "inactive")
                  'usable? usable?
                  'reasons (map symbol->string (hash-ref status 'reasons '()))
                  'entitlement_id (or (verified-credential-entitlement-id credential) 'null)
                  'revision (or (verified-credential-revision credential) 'null)
                  'type (verified-credential-type credential)
                  'feature_allowed (if feature feature-allowed 'null)))]))
