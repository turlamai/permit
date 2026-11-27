#lang racket/base
(require json racket/format racket/file racket/cmdline)

(define (write-summary directory [out (current-output-port)])
  (displayln "### Permit diagnostic benchmark (mean milliseconds per operation)" out)
  (displayln "Shared-runner observations, not performance guarantees or thresholds." out)
  (newline out)
  (displayln "| Mode | Workload | Iterations | Operation | Mean ms |" out)
  (displayln "| --- | --- | ---: | --- | ---: |" out)
  (for* ([mode '("auto" "pure" "native")]
         [workload '("crypto" "credential")])
    (define path
      (build-path directory
                  (string-append (if (equal? workload "credential") "credential-" "")
                                 mode ".json")))
    (define report (call-with-input-file path read-json))
    (unless (equal? (hash-ref report 'requested_backend) mode)
      (error 'benchmark-summary "backend mismatch"))
    (cond
      [(equal? (hash-ref report 'status #f) "unavailable")
       (unless (equal? mode "native")
         (error 'benchmark-summary "required backend unavailable"))
       (fprintf out "| ~a | ~a | — | unavailable | — |\n" mode workload)]
      [else
       (define count (hash-ref report 'iterations))
       (unless (and (equal? (hash-ref report 'schema) 1)
                    (exact-positive-integer? count))
         (error 'benchmark-summary "invalid report metadata"))
       (for ([operation (in-list (if (equal? workload "crypto")
                                    '(sign verify)
                                    '(verify_credential cached_policy verify_and_policy)))])
         (define mean (hash-ref (hash-ref report operation) 'mean_ms))
         (unless (and (real? mean) (<= 0 mean) (< mean +inf.0))
           (error 'benchmark-summary "invalid measurement"))
         (fprintf out "| ~a | ~a | ~a | ~a | ~a |\n"
                  mode workload count operation (~r mean #:precision '(= 6))))]))
  (newline out)
  (displayln "Raw JSON artifacts retain OS, architecture, Racket version and provider metadata." out))

(module+ main
  (command-line #:args (directory) (write-summary directory)))

(module+ test
  (require rackunit racket/port)
  (define directory (make-temporary-file "benchmark-summary-~a" 'directory))
  (dynamic-wind
    void
    (lambda ()
      (for* ([mode '("auto" "pure" "native")]
             [prefix '("" "credential-")])
        (define report
          (if (equal? mode "native")
              (hasheq 'requested_backend mode 'status "unavailable")
              (for/fold ([report (hasheq 'schema 1 'requested_backend mode 'iterations 2)])
                        ([operation '(sign verify verify_credential cached_policy verify_and_policy)])
                (hash-set report operation (hasheq 'mean_ms 0.125)))))
        (call-with-output-file (build-path directory (string-append prefix mode ".json"))
          (lambda (out) (write-json report out))))
      (define summary (call-with-output-string (lambda (out) (write-summary directory out))))
      (check-true (regexp-match? #rx"0[.]125000" summary))
      (check-true (regexp-match? #rx"native [|] credential [|] — [|] unavailable" summary))
      (delete-file (build-path directory "auto.json"))
      (check-exn exn:fail? (lambda () (call-with-output-string (lambda (out) (write-summary directory out))))))
    (lambda () (delete-directory/files directory))))
