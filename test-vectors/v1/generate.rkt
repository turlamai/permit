#lang racket/base

;; Reproduce the signed positive vectors from public RFC 8032 test key 1.
;; This key is test material only. Never use it for real credentials.

(require crypto
         (only-in crypto/libcrypto libcrypto-factory)
         json
         racket/file
         racket/list
         racket/runtime-path
         "../../permit/envelope.rkt")

(define-runtime-path vector-root ".")

(define key-id "rfc8032-test-1")
(define private-seed-hex
  "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")

(define (hex-string->bytes value)
  (unless (and (string? value)
               (even? (string-length value))
               (regexp-match? #px"^[0-9a-fA-F]*$" value))
    (raise-argument-error 'hex-string->bytes "even-length hexadecimal string" value))
  (list->bytes
   (for/list ([index (in-range 0 (string-length value) 2)])
     (string->number (substring value index (+ index 2)) 16))))

;; PKCS#8 PrivateKeyInfo prefix for a 32-byte Ed25519 seed.
(define private-key-der
  (bytes-append
   (hex-string->bytes "302e020100300506032b657004220420")
   (hex-string->bytes private-seed-hex)))

(define vector-files
  '(("managed-entitlement-payload.json" "managed-entitlement.permit.json")
    ("activation-payload.json" "activation.permit.json")
    ("trial-payload.json" "trial.permit.json")
    ("trial-extension-payload.json" "trial-extension.permit.json")
    ;; negative vectors that need a genuine signature: the rejection must
    ;; happen after authentication, at the issuer and schema stages
    ("foreign-issuer-payload.json" "foreign-issuer.permit.json")
    ("not-a-credential-payload.json" "not-a-credential.permit.json")
    ;; lineage selection: a third revision and a conflicting same-revision
    ;; statement over the managed lineage
    ("managed-entitlement-r3-payload.json" "managed-entitlement-r3.permit.json")
    ("managed-entitlement-r3-conflict-payload.json"
     "managed-entitlement-r3-conflict.permit.json")))

(provide generate-vectors!)

(define (generate-vectors!)
  ;; Resolve the native provider only when maintainers intentionally regenerate
  ;; fixtures. The official package builder imports every .rkt under this
  ;; package during `raco test --drdr --package permit`; importing a generator
  ;; must not require an Ed25519 signer or rewrite committed test vectors.
  (define private-key
    (datum->pk-key private-key-der 'PrivateKeyInfo (list libcrypto-factory)))
  (for ([entry (in-list vector-files)])
    (define payload-path (build-path vector-root (first entry)))
    (define credential-path (build-path vector-root (second entry)))
    (define envelope
      (make-signed-envelope key-id (file->bytes payload-path) private-key))
    (call-with-output-file credential-path
      (lambda (out)
        (write-json (envelope->jsexpr envelope) out #:indent 2)
        (newline out))
      #:exists 'truncate/replace)))

(module+ main
  (generate-vectors!))
