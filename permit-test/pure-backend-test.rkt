#lang racket/base

;; The pure backend must be a drop-in provider, not a separate code path:
;; it reproduces RFC 8032, interoperates with native keys/signatures, and
;; keeps the DER/base64 trust-store formats byte-identical.

(require rackunit
         racket/file
         "../permit/crypto.rkt"
         "../permit/private/ed25519-der.rkt")

(define (hex->bytes value)
  (list->bytes
   (for/list ([index (in-range 0 (string-length value) 2)])
     (string->number (substring value index (+ index 2)) 16))))

(define (call-with-temporary-bytes value action)
  (define path (make-temporary-file "permit-pure-~a"))
  (dynamic-wind
   void
   (lambda ()
     (call-with-output-file path
       #:exists 'truncate/replace
       (lambda (out) (write-bytes value out)))
     (action path))
   (lambda () (when (file-exists? path) (delete-file path)))))

(define rfc-seed
  (hex->bytes "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"))
(define rfc-public
  (hex->bytes "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"))
(define rfc-signature
  (hex->bytes
   (string-append "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                  "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")))

(test-case "pure backend signs, verifies, and rejects tampering"
  (parameterize ([current-ed25519-backend 'pure])
    (define-values (private public) (generate-ed25519-keypair))
    (define signature (ed25519-sign private #"pure provider"))
    (check-equal? (bytes-length signature) 64)
    (check-true (ed25519-verify public #"pure provider" signature))
    (check-false (ed25519-verify public #"Pure provider" signature))
    (check-false (ed25519-verify public #"pure provider"
                                 (bytes-append (subbytes signature 0 63) #"\x00")))))

(test-case "pure backend reproduces RFC 8032 test 1"
  (call-with-temporary-bytes
   (private-key-der rfc-seed)
   (lambda (path)
     (parameterize ([current-ed25519-backend 'pure])
       (define private (read-ed25519-private-key path))
       (define public (ed25519-private-key->public-key private))
       (check-equal? (ed25519-sign private #"") rfc-signature)
       (check-true (ed25519-verify public #"" rfc-signature))
       (check-equal? (ed25519-public-key->der public) (public-key-der rfc-public))))))

(test-case "pure and native backends are interchangeable"
  (define native-keypair
    (with-handlers ([exn:fail? (lambda (_) #f)])
      (parameterize ([current-ed25519-backend 'native])
        (call-with-values generate-ed25519-keypair cons))))
  (when native-keypair
    (define native-private (car native-keypair))
    (define native-public (cdr native-keypair))
    (define message #"cross-provider message")
    (define native-signature (ed25519-sign native-private message))
    (define private-der (ed25519-private-key->der native-private))
    (define public-der (ed25519-public-key->der native-public))
    (parameterize ([current-ed25519-backend 'pure])
      (call-with-temporary-bytes
       private-der
       (lambda (private-path)
         (call-with-temporary-bytes
          public-der
          (lambda (public-path)
            (define pure-private (read-ed25519-private-key private-path))
            (define pure-public (read-ed25519-public-key public-path))
            ;; Ed25519 is deterministic: the same seed and message must produce
            ;; identical bytes in both providers.
            (check-equal? (ed25519-sign pure-private message) native-signature)
            (check-true (ed25519-verify pure-public message native-signature))
            (check-true (ed25519-verify native-public message
                                        (ed25519-sign pure-private message))))))))))

(test-case "trust-store Base64 round-trips through the pure backend"
  (parameterize ([current-ed25519-backend 'pure])
    (define-values (private public) (generate-ed25519-keypair))
    (define text (public-key->base64 public))
    (define decoded (base64->public-key text))
    (check-equal? (ed25519-public-key->der decoded)
                  (ed25519-public-key->der public))
    (check-true (ed25519-verify decoded #"trust" (ed25519-sign private #"trust")))))

(test-case "a 32-byte public key is accepted as a raw pure key"
  (parameterize ([current-ed25519-backend 'pure])
    (check-true (ed25519-verify rfc-public #"" rfc-signature))
    (check-false (ed25519-verify rfc-public #"x" rfc-signature))))
