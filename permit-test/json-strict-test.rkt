#lang racket/base

(require rackunit
         racket/file
         racket/port
         permit/json)

(test-case "public bytes, port and file readers share strict behavior"
  (define path (make-temporary-file "permit-json-~a.json"))
  (dynamic-wind
    void
    (lambda ()
      (for ([raw (in-list
                  (list #"{\"a\":[true,null,1]}"
                        #"{\"a\":1,\"\\u0061\":2}"
                        #"{\"a\":[{\"b\":1,\"b\":2}]}"
                        #"{} {}" #"[1,]" #"{\"a\":1,}"
                        (bytes #xff)
                        (bytes-append (make-bytes 65 91) #"0" (make-bytes 65 93))))]
            [valid? (in-list '(#t #f #f #f #f #f #f #f))])
        (call-with-output-file path #:exists 'truncate
          (lambda (out) (write-bytes raw out)))
        (for ([read-it (in-list
                       (list (lambda () (read-json-bytes/strict 'public-json raw))
                             (lambda ()
                               (define port (open-input-bytes raw))
                               (define value (read-json-source/strict 'public-json port))
                               (check-false (port-closed? port))
                               (check-true (eof-object? (read-byte port)))
                               value)
                             (lambda () (read-json-source/strict 'public-json path))
                             (lambda () (read-json-source/strict 'public-json (path->string path)))))])
          (if valid?
              (check-equal? (read-it) (hasheq 'a '(#t null 1)))
              (check-exn exn:fail? read-it)))))
    (lambda () (delete-file path))))

(test-case "public JSON utility rejects unsupported input types"
  (check-exn exn:fail:contract?
             (lambda () (read-json-bytes/strict 'public-json "{}")))
  (check-exn exn:fail:contract?
             (lambda () (read-json-source/strict 'public-json #"{}"))))

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
