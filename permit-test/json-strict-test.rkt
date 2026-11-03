#lang racket/base

(require rackunit
         "../permit/private/json.rkt")

(test-case "strict JSON accepts valid scalar roots"
  (check-equal? (read-json-bytes/strict 'test #" 123 \n") 123)
  (check-equal? (read-json-bytes/strict 'test #"-1.25e+2") -125.0)
  (check-equal? (read-json-bytes/strict 'test #"true") #t)
  (check-equal? (read-json-bytes/strict 'test #"null") 'null))

(test-case "strict JSON rejects partial root and nested scalar parses"
  (for ([raw (in-list (list #"123x" #"truegarbage" #"nullx"
                            #"01" #"1." #"-" #"1e"
                            #"[123x]" #"{\"value\":123x}"
                            #"[truegarbage]" #"{\"a\":falsex}"))])
    (check-exn exn:fail?
               (lambda () (read-json-bytes/strict 'test raw)))))

(test-case "strict JSON rejects unescaped control characters"
  ;; RFC 8259 requires U+0000 through U+001F inside a string to be escaped.
  ;; A raw NUL is also forbidden outright by protocol v1.
  (for ([raw (in-list (list
                       (string->bytes/utf-8 "{\"value\":\"a\u0000b\"}")
                       (string->bytes/utf-8 "{\"value\":\"a\u0001b\"}")
                       (string->bytes/utf-8 "{\"value\":\"a\tb\"}")
                       (string->bytes/utf-8 "{\"a\nb\":\"value\"}")) )])
    (check-exn exn:fail?
               (lambda () (read-json-bytes/strict 'test raw)))))

(test-case "strict JSON keeps escaped non-NUL controls and rejects NUL escapes"
  (check-equal? (read-json-bytes/strict 'test #"{\"value\":\"a\\u0001b\"}")
                (hasheq 'value "a\u0001b"))
  (check-exn exn:fail?
             (lambda () (read-json-bytes/strict 'test #"{\"value\":\"a\\u0000b\"}"))))
