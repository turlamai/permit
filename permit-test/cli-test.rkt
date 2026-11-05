#lang racket/base

(require json
         rackunit
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

(test-case "doctor reports the selected Ed25519 backend as JSON"
  (define output (open-output-bytes))
  (define code
    (parameterize ([current-output-port output])
      (run-cli (list "doctor"))))
  (define report (string->jsexpr (bytes->string/utf-8 (get-output-bytes output))))
  (check-equal? code 0)
  (check-true (hash-ref report 'ok))
  (define crypto (hash-ref report 'crypto))
  (check-true (and (member (hash-ref crypto 'backend) '("native" "pure")) #t))
  (check-equal? (hash-ref crypto 'pure-backend) "ed25519 0.1")
  (check-true (list? (hash-ref crypto 'providers)))
  (check-true (ormap (lambda (p) (equal? (hash-ref p 'name) "openssl3"))
                     (hash-ref crypto 'providers))))
