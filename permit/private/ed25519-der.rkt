#lang racket/base

;; Fixed DER encodings for Ed25519 keys (RFC 8410). The native crypto-lib
;; path encodes/decodes keys itself; the pure provider and the trust-store
;; format need byte-exact PKCS#8 and SubjectPublicKeyInfo forms, so both
;; backends produce and accept these same bytes.

(require racket/bytes)

(provide private-key-der
         public-key-der
         der->seed
         der->public-key)

;; PrivateKeyInfo v2:
;;   30 2e 02 01 00 30 05 06 03 2b 65 70 04 22 04 20 <32-byte seed>
(define pkcs8-prefix
  #"\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x70\x04\x22\x04\x20")

;; SubjectPublicKeyInfo:
;;   30 2a 30 05 06 03 2b 65 70 03 21 00 <32-byte public key>
(define spki-prefix
  #"\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00")

(define seed-length 32)
(define public-key-length 32)

(define (private-key-der seed)
  (unless (and (bytes? seed) (= seed-length (bytes-length seed)))
    (raise-argument-error 'private-key-der "32-byte seed" seed))
  (bytes-append pkcs8-prefix seed))

;; crypto-lib emits RFC 5958 OneAsymmetricKey v1 with the Ed25519
;; public key in the IMPLICIT [1] BIT STRING. Its complete DER encoding is:
;;   30 51 02 01 01 30 05 06 03 2b 65 70 04 22 04 20 <seed>
;;   81 21 00 <32-byte public key>
;; The public half is checked against the seed by the caller.
(define one-asymmetric-prefix
  #"\x30\x51\x02\x01\x01\x30\x05\x06\x03\x2b\x65\x70\x04\x22\x04\x20")
(define one-asymmetric-public-tag #"\x81\x21\x00")

;; No searching for an interior marker: a blob with a different algorithm,
;; malformed length, wrong version or trailing bytes is not an Ed25519 key.
(define (der->seed der)
  (unless (bytes? der)
    (raise-argument-error 'der->seed "bytes?" der))
  (define size (bytes-length der))
  (define canonical?
    (and (= size 48)
         (bytes=? (subbytes der 0 16) pkcs8-prefix)))
  (define with-public?
    (and (= size 83)
         (bytes=? (subbytes der 0 16) one-asymmetric-prefix)
         (bytes=? (subbytes der 48 51) one-asymmetric-public-tag)))
  (unless (or canonical? with-public?)
    (raise-arguments-error 'der->seed
                           "not a canonical Ed25519 PrivateKeyInfo/OneAsymmetricKey"
                           "bytes" size))
  (subbytes der 16 48))

(define (public-key-der public)
  (unless (and (bytes? public) (= public-key-length (bytes-length public)))
    (raise-argument-error 'public-key-der "32-byte public key" public))
  (bytes-append spki-prefix public))

(define (der->public-key der)
  (unless (bytes? der)
    (raise-argument-error 'der->public-key "bytes?" der))
  (define prefix-length (bytes-length spki-prefix))
  (unless (and (= (bytes-length der) (+ prefix-length public-key-length))
               (bytes=? (subbytes der 0 prefix-length) spki-prefix))
    (raise-arguments-error 'der->public-key
                           "not an Ed25519 SubjectPublicKeyInfo"
                           "bytes"
                           (if (bytes? der) (bytes-length der) der)))
  (subbytes der prefix-length (+ prefix-length public-key-length)))
