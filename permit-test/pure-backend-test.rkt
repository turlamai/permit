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
    ;; Flip a bit instead of overwriting the last byte with zero: a random
    ;; signature already ends in zero once in 256 runs, which made this a
    ;; flaky failure on the Racket 9.0 job.
    (define tampered (bytes-copy signature))
    (bytes-set! tampered 63 (bitwise-xor (bytes-ref tampered 63) #x01))
    (check-false (ed25519-verify public #"pure provider" tampered))))

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


;; Private-key DER is an untrusted input boundary. Reject arbitrary embedded
;; 04 22 04 20 markers, wrong OIDs/lengths, and trailing data instead of
;; extracting a seed by searching for a matching byte sequence.
(test-case "private-key DER must have a complete Ed25519 ASN.1 structure"
  (define canonical (private-key-der rfc-seed))
  (check-equal? (der->seed canonical) rfc-seed)
  (define altered-oid (bytes-copy canonical))
  (bytes-set! altered-oid 11 #x71)
  (check-exn exn:fail? (lambda () (der->seed altered-oid)))
  (check-exn exn:fail?
             (lambda () (der->seed (bytes-append #"\x04\x22\x04\x20" rfc-seed))))
  (check-exn exn:fail?
             (lambda () (der->seed (bytes-append canonical #"\x00")))))

(test-case "RFC 5958 private key embedded public half must match the seed"
  ;; crypto-lib writes OneAsymmetricKey with an IMPLICIT [1] public BIT STRING.
  (define oak
    (bytes-append
     #"\x30\x51\x02\x01\x01\x30\x05\x06\x03\x2b\x65\x70\x04\x22\x04\x20"
     rfc-seed
     #"\x81\x21\x00"
     rfc-public))
  (check-equal? (der->seed oak) rfc-seed)
  (parameterize ([current-ed25519-backend 'pure])
    (call-with-temporary-bytes
     oak
     (lambda (path)
       (check-equal? (ed25519-sign (read-ed25519-private-key path) #"")
                     rfc-signature))))
  (define mismatched-public (bytes-copy oak))
  (bytes-set! mismatched-public 51
              (bitwise-xor (bytes-ref mismatched-public 51) 1))
  (parameterize ([current-ed25519-backend 'pure])
    (call-with-temporary-bytes
     mismatched-public
     (lambda (path)
       (check-exn exn:fail? (lambda () (read-ed25519-private-key path))))))
  (define wrong-tag (bytes-copy oak))
  (bytes-set! wrong-tag 48 #x80)
  (check-exn exn:fail? (lambda () (der->seed wrong-tag))))

(test-case "pure Ed25519 private-key wrapper never prints raw seed bytes"
  (parameterize ([current-ed25519-backend 'pure])
    (define-values (private public) (generate-ed25519-keypair))
    (check-equal? (format "~s" private) "#<ed25519-key>")
    (check-true (ed25519-verify public #"redacted"
                                (ed25519-sign private #"redacted")))))

(test-case "RFC 8032 test 2 and signature length boundaries across backends"
  ;; RFC 8032 section 7.1, TEST 2: a one-byte message.
  (define seed
    (hex->bytes "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"))
  (define expected-public
    (hex->bytes "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"))
  (define expected-signature
    (hex->bytes
     (string-append "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
                    "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")))
  (define message (bytes #x72))
  (define backends
    (if (hash-ref (ed25519-provider-report) 'native-available?)
        '(pure native auto)
        '(pure auto)))
  (for ([backend (in-list backends)])
    (parameterize ([current-ed25519-backend backend])
      (call-with-temporary-bytes
       (private-key-der seed)
       (lambda (private-path)
         (call-with-temporary-bytes
          (public-key-der expected-public)
          (lambda (public-path)
            (define private (read-ed25519-private-key private-path))
            (define public (read-ed25519-public-key public-path))
            (check-equal? (ed25519-public-key->der
                           (ed25519-private-key->public-key private))
                          (public-key-der expected-public))
            (check-equal? (ed25519-sign private message) expected-signature)
            (check-true (ed25519-verify public message expected-signature))
            (check-false (ed25519-verify public #"s" expected-signature))
            (for ([length (in-list '(0 1 31 32 63 65 128))])
              (check-false (ed25519-verify public message (make-bytes length 0))))
            (for ([index (in-list '(0 31 32 63))])
              (define changed (bytes-copy expected-signature))
              (bytes-set! changed index (bitwise-xor 1 (bytes-ref changed index)))
              (check-false (ed25519-verify public message changed))))))))))
