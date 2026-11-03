#lang racket/base

;; Protocol v1 desktop shared-core example. The host owns key custody,
;; credential import/persistence, and trust-root installation. This module
;; never imports Permit issuer operations or any framework/payment service.
(require permit)

(provide desktop-entitlement-status)

;; A host may serialize the returned non-sensitive hash as JSON for
;; SwiftUI/WinUI/GTK. Only verified credentials may reach this boundary.
;; The host must select the newest authenticated entitlement revision
;; before calling this function and supply its own evaluation context.
(define (desktop-entitlement-status credential product edition
                                    #:at at
                                    #:version [version #f]
                                    #:installation-id [installation-id #f])
  (cond
    [(not credential)
     (hasheq 'state "free"
             'entitled? #f
             'reasons '("missing-credential"))]
    [else
     (unless (verified-credential? credential)
       (raise-argument-error
        'desktop-entitlement-status
        "(or/c verified-credential? #f)"
        credential))
     (define status
       (credential-status credential #:at at
                          #:installation-id installation-id))
     (define granted?
       (edition-entitled? credential product edition
                          #:at at
                          #:version version
                          #:installation-id installation-id))
     (hasheq 'state (if granted? "pro" "free")
             'entitled? granted?
             'reasons (if granted?
                          '()
                          (append (map symbol->string (hash-ref status 'reasons))
                                  '("not-entitled"))))]))
