#lang racket/base

(require rackunit
         racket/file
         racket/port
         "../permit/cli.rkt"
         "../permit/trust.rkt")

(define temp-dir (make-temporary-file "permit-cli-purpose-~a" 'directory))
(define private-path (build-path temp-dir "private.der"))
(define public-path (build-path temp-dir "public.der"))
(define trust-path (build-path temp-dir "trust.json"))

(dynamic-wind
 void
 (lambda ()
   (parameterize ([current-output-port (open-output-string)])
     (run-cli
      (list "keygen"
            "--private" (path->string private-path)
            "--public" (path->string public-path)
            "--trust-store" (path->string trust-path)
            "--key-id" "entitlement-only"
            "--issuer" "example.test"
            "--purpose" "entitlement")))
   (define store (read-trust-store trust-path))
   (define key (trust-store-key store "entitlement-only"))
   (check-equal? (trust-key-purposes key) '("entitlement"))
   ;; A signing key must not be world-readable. Windows exposes only the
   ;; read-only attribute, so the POSIX mode check is skipped there.
   (unless (eq? (system-type) 'windows)
     (check-equal? (file-or-directory-permissions private-path 'bits) #o600)))
 (lambda ()
   (delete-directory/files temp-dir)))
