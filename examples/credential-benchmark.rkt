#lang racket/base
(require racket/cmdline racket/file racket/port racket/runtime-path
         json permit permit/crypto permit/envelope)

(define-runtime-path fixture "perpetual.json")

;; Diagnostic fixture only. Keys are ephemeral; no production inputs.
(define (run-benchmark mode iterations)
  (parameterize ([current-ed25519-backend mode])
    (define-values (private public) (generate-ed25519-keypair))
    (define store
      (jsexpr->trust-store
       (hasheq 'protocol "permit-trust-store" 'version 1 'issuer "com.example"
               'keys (hasheq 'benchmark
                             (hasheq 'algorithm "Ed25519"
                                     'public_key (public-key->base64 public)
                                     'status "active" 'purposes '("entitlement")
                                     'not_before 'null 'not_after 'null)))))
    (define payload (file->bytes fixture))
    (define envelope (make-signed-envelope "benchmark" payload private))
    (define wire (call-with-output-bytes (lambda (out) (write-envelope envelope out))))
    (define (verify!) (verify-credential (open-input-bytes wire) store))
    (define verified (verify!))
    (define (policy! credential)
      (unless (and (credential-usable? credential #:at "2027-01-01T00:00:00Z")
                   (edition-entitled? credential "example-app" "pro"
                                      #:at "2027-01-01T00:00:00Z")
                   (not (edition-entitled? credential "other-app" "pro"
                                           #:at "2027-01-01T00:00:00Z")))
        (error 'credential-benchmark "unexpected entitlement decision")))
    (define (full!) (policy! (verify!)))
    (define (measure thunk)
      (for ([i (in-range 3)]) (thunk))
      (collect-garbage)
      (define start (current-inexact-monotonic-milliseconds))
      (for ([i (in-range iterations)]) (thunk))
      (define elapsed (- (current-inexact-monotonic-milliseconds) start))
      (hasheq 'elapsed_ms elapsed 'mean_ms (/ elapsed iterations)))
    (hasheq 'schema 1 'racket_version (version)
            'os (symbol->string (system-type 'os))
            'machine (symbol->string (system-type 'arch))
            'requested_backend (symbol->string mode)
            'providers (ed25519-provider-report)
            'iterations iterations
            'payload_bytes (bytes-length payload)
            'envelope_bytes (bytes-length wire)
            'verify_credential (measure verify!)
            'cached_policy (measure (lambda () (policy! verified)))
            'verify_and_policy (measure full!))))

(module+ main
  (define mode 'auto)
  (define iterations 100)
  (command-line
   #:program "permit-credential-benchmark"
   #:once-each
   [("--backend") name "auto, native, or pure"
    (unless (member name '("auto" "native" "pure"))
      (raise-user-error 'benchmark "invalid backend: ~a" name))
    (set! mode (string->symbol name))]
   [("--iterations") count "Positive iteration count"
    (define n (string->number count))
    (unless (exact-positive-integer? n)
      (raise-user-error 'benchmark "iterations must be positive"))
    (set! iterations n)]
   #:args () (void))
  (write-json (run-benchmark mode iterations))
  (newline))

(module+ test
  (require rackunit)
  (define result (run-benchmark 'pure 2))
  (check-equal? (hash-ref result 'schema) 1)
  (check-equal? (hash-ref result 'iterations) 2)
  (check-true (> (hash-ref result 'envelope_bytes) (hash-ref result 'payload_bytes)))
  (for ([operation '(verify_credential cached_policy verify_and_policy)])
    (check-true (>= (hash-ref (hash-ref result operation) 'mean_ms) 0)))
  (check-not-exn (lambda () (jsexpr->string result))))
