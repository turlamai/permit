#lang racket/base
(require racket/cmdline
         json
         permit/crypto)

;; Diagnostic benchmark only: ephemeral keys, no credential or production
;; key material, no timing-based pass/fail thresholds.
(define (run-benchmark mode iterations)
  (parameterize ([current-ed25519-backend mode])
    (define report (ed25519-provider-report))
    (define-values (private public) (generate-ed25519-keypair))
    (define message (make-bytes 1024 65))
    (define signature (ed25519-sign private message))
    (define (verify!)
      (unless (ed25519-verify public message signature)
        (error 'benchmark "signature verification failed")))
    ;; Warm up both operations before collecting elapsed wall-clock times.
    (for ([i (in-range 3)]) (ed25519-sign private message) (verify!))
    (define (measure thunk)
      (collect-garbage)
      (define start (current-inexact-monotonic-milliseconds))
      (for ([i (in-range iterations)]) (thunk))
      (define elapsed (- (current-inexact-monotonic-milliseconds) start))
      (hasheq 'elapsed_ms elapsed
              'mean_ms (/ elapsed iterations)))
    (hasheq 'schema 1
            'racket_version (version)
            'os (symbol->string (system-type 'os))
            'machine (symbol->string (system-type 'arch))
            'requested_backend (symbol->string mode)
            'providers report
            'iterations iterations
            'message_bytes (bytes-length message)
            'sign (measure (lambda () (ed25519-sign private message)))
            'verify (measure verify!))))

(module+ main
  (define mode 'auto)
  (define iterations 100)
  (command-line
   #:program "permit-crypto-benchmark"
   #:once-each
   [("--backend") name "auto, native, or pure"
    (unless (member name '("auto" "native" "pure"))
      (raise-user-error 'benchmark "invalid backend: ~a" name))
    (set! mode (string->symbol name))]
   [("--iterations") count "Positive iteration count"
    (define n (string->number count))
    (unless (exact-positive-integer? n)
      (raise-user-error 'benchmark "iterations must be a positive integer"))
    (set! iterations n)]
   #:args () (void))
  (write-json (run-benchmark mode iterations))
  (newline))

(module+ test
  (require rackunit)
  (define result (run-benchmark 'pure 2))
  (check-equal? (hash-ref result 'schema) 1)
  (check-equal? (hash-ref result 'iterations) 2)
  (check-equal? (hash-ref result 'message_bytes) 1024)
  (for ([operation '(sign verify)])
    (define measurement (hash-ref result operation))
    (check-true (>= (hash-ref measurement 'elapsed_ms) 0))
    (check-true (>= (hash-ref measurement 'mean_ms) 0)))
  (check-not-exn (lambda () (jsexpr->string result))))
