#lang racket/base

(require crypto
         (only-in crypto/libcrypto libcrypto-factory)
         (only-in crypto/sodium sodium-factory)
         (only-in crypto/nettle nettle-factory)
         (prefix-in pure: ed25519)
         racket/file
         racket/promise
         "private/encoding.rkt"
         "private/ed25519-der.rkt")

(provide generate-ed25519-keypair
         read-ed25519-private-key
         read-ed25519-public-key
         ed25519-private-key->der
         ed25519-private-key->public-key
         ed25519-public-key->der
         ed25519-sign
         ed25519-verify
         public-key->base64
         base64->public-key
         current-ed25519-backend)

;; The Racket package builder's natipkg image supplies OpenSSL 1.1, which does
;; not satisfy crypto-lib's OpenSSL 3 provider. Try an explicit, reviewed set
;; of native providers (OpenSSL 3, libsodium, Nettle) and fall back to the pure
;; Racket `ed25519` package when none is usable. The provider is selected once
;; per process; `current-ed25519-backend` lets tests and diagnostics pin a
;; backend without changing callers. The pure backend is not constant time;
;; production issuers should keep using a native provider when available.
(define factories
  (list libcrypto-factory sodium-factory nettle-factory))

(define current-ed25519-backend
  (make-parameter
   'auto
   (lambda (value)
     (unless (memq value '(auto native pure))
       (raise-argument-error 'current-ed25519-backend
                             "(or/c 'auto 'native 'pure)"
                             value))
     value)))

;; A key is either a crypto-lib `pk-key` (native) or a raw 32-byte seed/public
;; key (pure). Callers treat it as opaque and use the functions below.
(struct ed25519-key (backend private? value) #:transparent)

(define native-available?
  (delay
    (with-handlers ([exn:fail? (lambda (_) #f)])
      (parameterize ([crypto-factories factories])
        (generate-private-key 'eddsa '((curve ed25519))))
      #t)))

(define (selected-backend)
  (case (current-ed25519-backend)
    [(auto) (if (force native-available?) 'native 'pure)]
    [else (current-ed25519-backend)]))

(define (native-key? key private?)
  (and (pk-key? key)
       (or (not private?) (private-key? key))
       (let ([datum (pk-key->datum key (if private? 'rkt-private 'rkt-public))])
         (and (list? datum) (pair? datum) (eq? (car datum) 'eddsa) (member 'ed25519 datum)))))

(define (ensure-key who key private?)
  ;; Callers may pass the opaque key produced here, a raw crypto-lib `pk-key`
  ;; (permit's own tests do this to exercise each native factory), or a raw
  ;; 32-byte seed/public key for the pure backend. Coerce to the opaque form.
  (define wrapped
    (cond
      [(ed25519-key? key) key]
      [(and (pk-key? key) (native-key? key private?))
       (ed25519-key 'native private? key)]
      [(and (bytes? key) (= 32 (bytes-length key)))
       (ed25519-key 'pure private? key)]
      [else #f]))
  (unless (and wrapped
               (eq? (ed25519-key-private? wrapped) private?))
    (raise-arguments-error
     who
     (if private? "expected an Ed25519 private key" "expected an Ed25519 public key")
     "key"
     key))
  wrapped)

(define (require-native who)
  (unless (force native-available?)
    (raise-arguments-error
     who
     "no native Ed25519 provider is available; set current-ed25519-backend to 'pure"
     "providers"
     '(openssl3 libsodium nettle))))

(define (generate-ed25519-keypair)
  (case (selected-backend)
    [(native)
     (require-native 'generate-ed25519-keypair)
     (define private-key
       (parameterize ([crypto-factories factories])
         (generate-private-key 'eddsa '((curve ed25519)))))
     (values (ed25519-key 'native #t private-key)
             (ed25519-key 'native #f (pk-key->public-only-key private-key)))]
    [(pure)
     (define keypair (pure:generate-keypair))
     (values (ed25519-key 'pure #t (pure:keypair-secret keypair))
             (ed25519-key 'pure #f (pure:keypair-public keypair)))]))

(define (pure-decode who raw private?)
  (with-handlers
      ([exn:fail?
        (lambda (_)
          (raise-arguments-error who
                                 "could not decode Ed25519 key"
                                 "accepted formats"
                                 (if private? '(PrivateKeyInfo) '(SubjectPublicKeyInfo))))])
    (if private?
        (der->seed raw)
        (der->public-key raw))))

(define (decode-key who raw formats private?)
  (define backend (selected-backend))
  (define native
    (and (eq? backend 'native)
         (for/or ([format (in-list formats)])
           (with-handlers ([exn:fail? (lambda (_) #f)])
             (define key (datum->pk-key raw format factories))
             (and (native-key? key private?) key)))))
  (cond
    [native (ed25519-key 'native private? native)]
    ;; A native provider may be available while a particular key encoding is
    ;; only in the fixed DER form; the pure decoder stays strict about it.
    [(eq? backend 'native) (ed25519-key 'pure private? (pure-decode who raw private?))]
    [else (ed25519-key 'pure private? (pure-decode who raw private?))]))

(define (read-ed25519-private-key path)
  (decode-key 'read-ed25519-private-key
              (file->bytes path)
              '(OneAsymmetricKey PrivateKeyInfo rkt-private)
              #t))

(define (read-ed25519-public-key path)
  (decode-key 'read-ed25519-public-key
              (file->bytes path)
              '(SubjectPublicKeyInfo rkt-public openssh-public)
              #f))

(define (ed25519-private-key->der key)
  (define checked (ensure-key 'ed25519-private-key->der key #t))
  (case (ed25519-key-backend checked)
    [(native) (pk-key->datum (ed25519-key-value checked) 'PrivateKeyInfo)]
    [(pure) (private-key-der (ed25519-key-value checked))]))

(define (ed25519-private-key->public-key key)
  (define checked (ensure-key 'ed25519-private-key->public-key key #t))
  (case (ed25519-key-backend checked)
    [(native)
     (ed25519-key 'native #f (pk-key->public-only-key (ed25519-key-value checked)))]
    [(pure)
     (ed25519-key 'pure #f (pure:secret->public (ed25519-key-value checked)))]))

(define (ed25519-public-key->der key)
  (define checked (ensure-key 'ed25519-public-key->der key #f))
  (case (ed25519-key-backend checked)
    [(native) (pk-key->datum (ed25519-key-value checked) 'SubjectPublicKeyInfo)]
    [(pure) (public-key-der (ed25519-key-value checked))]))

(define (ed25519-sign private-key message)
  (unless (bytes? message)
    (raise-argument-error 'ed25519-sign "bytes?" message))
  (define checked (ensure-key 'ed25519-sign private-key #t))
  (case (ed25519-key-backend checked)
    [(native) (pk-sign (ed25519-key-value checked) message)]
    [(pure) (pure:sign message (ed25519-key-value checked))]))

(define (ed25519-verify public-key message signature)
  (unless (bytes? message)
    (raise-argument-error 'ed25519-verify "bytes?" message))
  (unless (bytes? signature)
    (raise-argument-error 'ed25519-verify "bytes?" signature))
  (define checked (ensure-key 'ed25519-verify public-key #f))
  (and (= (bytes-length signature) 64)
       (case (ed25519-key-backend checked)
         [(native) (pk-verify (ed25519-key-value checked) message signature)]
         [(pure) (pure:verify message signature (ed25519-key-value checked))])))

(define (public-key->base64 key)
  (bytes->base64 (ed25519-public-key->der key)))

(define (base64->public-key value)
  (decode-key 'base64->public-key
              (base64->bytes 'base64->public-key value)
              '(SubjectPublicKeyInfo)
              #f))
