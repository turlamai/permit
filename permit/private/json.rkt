#lang racket/base

(require json
         racket/file
         racket/port
         racket/string)

(provide read-json-bytes/strict
         read-json-source/strict)

(define max-depth 64)

(define (fail who message . fields)
  (apply raise-arguments-error who message fields))

(define (json-whitespace? ch)
  (or (char=? ch #\space)
      (char=? ch #\tab)
      (char=? ch #\return)
      (char=? ch #\newline)))

;; Validate each scalar token in full, not just the prefix parsed by read-json.
;; This closes the 123x -> 123 acceptance noted as L1 in the security review.
(define scalar-token-rx
  #px"^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)$")

(define (read-json-bytes/strict who raw)
  (unless (bytes? raw)
    (raise-argument-error who "bytes?" raw))
  (define text
    (with-handlers ([exn:fail?
                     (lambda (e)
                       (fail who
                             "JSON is not valid UTF-8"
                             "detail"
                             (exn-message e)))])
      (bytes->string/utf-8 raw)))
  (define length* (string-length text))

  (define (skip-ws index)
    (let loop ([index index])
      (if (and (< index length*) (json-whitespace? (string-ref text index)))
          (loop (add1 index))
          index)))

  (define (scan-string index)
    (unless (and (< index length*) (char=? (string-ref text index) #\"))
      (fail who "expected JSON string" "offset" index))
    (let loop ([cursor (add1 index)])
      (when (>= cursor length*)
        (fail who "unterminated JSON string" "offset" index))
      (define ch (string-ref text cursor))
      (cond
        [(char=? ch #\") (add1 cursor)]
        [(char=? ch #\\)
         (when (>= (add1 cursor) length*)
           (fail who "unterminated JSON escape" "offset" cursor))
         ;; U+0000 is rejected on both implementations: the C runner
         ;; compares strings with strlen, and member names decoded with a
         ;; NUL could alias schema fields. Non-NUL control escapes stay
         ;; valid and behave identically on both sides.
         (when (and (char=? (string-ref text (add1 cursor)) #\u)
                    (<= (+ cursor 6) length*)
                    (for/and ([k (in-range 2 6)])
                      (char=? (string-ref text (+ cursor k)) #\0)))
           (fail who "NUL escape in JSON string" "offset" cursor))
         (loop (+ cursor 2))]
        ;; RFC 8259 requires U+0000 through U+001F to be escaped inside a
        ;; string. Accepting a raw control character (including a raw NUL)
        ;; would let a payload that this reader accepts be rejected by, or
        ;; truncated in, the C conformance runner; protocol-v1 also forbids
        ;; U+0000 in a string outright.
        [(< (char->integer ch) 32)
         (fail who
               "unescaped control character in JSON string"
               "offset"
               cursor
               "code"
               (char->integer ch))]
        [else (loop (add1 cursor))])))

  (define (decode-object-key start end)
    (define token (substring text start end))
    (define value
      (with-handlers ([exn:fail?
                       (lambda (e)
                         (fail who
                               "invalid JSON object key"
                               "offset"
                               start
                               "detail"
                               (exn-message e)))])
        (read-json (open-input-string token))))
    (unless (string? value)
      (fail who "JSON object key must decode to a string" "offset" start))
    value)

  (define scan-value #f)

  (define (scan-array index depth)
    (when (> depth max-depth)
      (fail who "JSON nesting exceeds protocol limit" "max_depth" max-depth))
    (let loop ([cursor (skip-ws (add1 index))])
      (when (>= cursor length*)
        (fail who "unterminated JSON array" "offset" index))
      (cond
        [(char=? (string-ref text cursor) #\]) (add1 cursor)]
        [else
         (define after-value (skip-ws (scan-value cursor depth)))
         (when (>= after-value length*)
           (fail who "unterminated JSON array" "offset" index))
         (define delimiter (string-ref text after-value))
         (cond
           [(char=? delimiter #\,) (loop (skip-ws (add1 after-value)))]
           [(char=? delimiter #\]) (add1 after-value)]
           [else
            (fail who
                  "expected comma or closing bracket"
                  "offset"
                  after-value)])])))

  (define (scan-object index depth)
    (when (> depth max-depth)
      (fail who "JSON nesting exceeds protocol limit" "max_depth" max-depth))
    (define seen (make-hash))
    (let loop ([cursor (skip-ws (add1 index))])
      (when (>= cursor length*)
        (fail who "unterminated JSON object" "offset" index))
      (cond
        [(char=? (string-ref text cursor) #\}) (add1 cursor)]
        [else
         (define key-start cursor)
         (define key-end (scan-string key-start))
         (define key (decode-object-key key-start key-end))
         (when (hash-has-key? seen key)
           (fail who "duplicate JSON object member" "key" key "offset" key-start))
         (hash-set! seen key #t)
         (define colon (skip-ws key-end))
         (unless (and (< colon length*) (char=? (string-ref text colon) #\:))
           (fail who "expected colon after JSON object key" "offset" colon))
         (define after-value
           (skip-ws (scan-value (skip-ws (add1 colon)) depth)))
         (when (>= after-value length*)
           (fail who "unterminated JSON object" "offset" index))
         (define delimiter (string-ref text after-value))
         (cond
           [(char=? delimiter #\,) (loop (skip-ws (add1 after-value)))]
           [(char=? delimiter #\}) (add1 after-value)]
           [else
            (fail who
                  "expected comma or closing brace"
                  "offset"
                  after-value)])])))

  (set! scan-value
        (lambda (index depth)
          (define cursor (skip-ws index))
          (when (>= cursor length*)
            (fail who "expected JSON value" "offset" cursor))
          (define ch (string-ref text cursor))
          (cond
            [(char=? ch #\{) (scan-object cursor (add1 depth))]
            [(char=? ch #\[) (scan-array cursor (add1 depth))]
            [(char=? ch #\") (scan-string cursor)]
            [else
             (define end
               (let loop ([end cursor])
                 (cond
                   [(>= end length*) end]
                   [else
                    (define next (string-ref text end))
                    (if (or (json-whitespace? next)
                            (char=? next #\,)
                            (char=? next #\])
                            (char=? next #\}))
                        end
                        (loop (add1 end)))])))
             (unless (regexp-match? scalar-token-rx
                                    (substring text cursor end))
               (fail who "invalid JSON scalar" "offset" cursor))
             end])))

  (define scanned-end (skip-ws (scan-value 0 0)))
  (unless (= scanned-end length*)
    (fail who "trailing data after JSON value" "offset" scanned-end))

  ;; The scanner is deliberately only the structural/duplicate-key guard.
  ;; The standard JSON reader remains authoritative for string escapes,
  ;; numbers, literals, and the resulting Racket jsexpr.
  (with-handlers ([exn:fail?
                   (lambda (e)
                     (fail who "invalid JSON" "detail" (exn-message e)))])
    (read-json (open-input-bytes raw))))

(define (read-json-source/strict who source)
  (cond
    [(input-port? source)
     (read-json-bytes/strict who (port->bytes source))]
    [(path-string? source)
     (read-json-bytes/strict who (file->bytes source))]
    [else
     (raise-argument-error who "(or/c input-port? path-string?)" source)]))
