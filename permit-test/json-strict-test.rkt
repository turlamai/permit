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

(test-case "strict JSON depth limit is inclusive and applies to mixed containers"
  (define (nested-array n)
    (bytes-append (make-bytes n 91) #"0" (make-bytes n 93)))
  (define (nested-object n)
    (if (zero? n) #"0"
        (bytes-append #"{\"a\":" (nested-object (sub1 n)) #"}")))
  (for ([make-nested (in-list (list nested-array nested-object))])
    (check-not-exn (lambda () (read-json-bytes/strict 'test (make-nested 64))))
    (check-exn exn:fail? (lambda () (read-json-bytes/strict 'test (make-nested 65)))))
  (check-not-exn
   (lambda () (read-json-bytes/strict 'test
                 (bytes-append #"{\"a\":" (nested-array 63) #"}"))))
  (check-exn exn:fail?
             (lambda () (read-json-bytes/strict 'test
                           (bytes-append #"{\"a\":" (nested-array 64) #"}")))))

(test-case "duplicate member detection uses decoded names and object scope"
  (for ([raw (in-list
              (list #"{\"x\":0,\"\\u0078\":1}"
                    #"{\"a/b\":0,\"a\\/b\":1}"
                    #"{\"a\":[{\"x\":0,\"\\u0078\":1}]}"
                    (string->bytes/utf-8 "{\"é\":0,\"\\u00e9\":1}")))])
    (check-exn exn:fail? (lambda () (read-json-bytes/strict 'test raw))))
  (check-not-exn
   (lambda () (read-json-bytes/strict 'test #"[{\"x\":0},{\"x\":1}]")))
  (check-not-exn
   (lambda () (read-json-bytes/strict 'test #"{\"x\":{\"x\":0}}"))))

(test-case "invalid UTF-8 and raw controls cannot cross the JSON boundary"
  (for ([raw (in-list
              (list (bytes #xc0 #xaf) (bytes #xe2 #x82)
                    (bytes #xed #xa0 #x80) (bytes #xf4 #x90 #x80 #x80)
                    (bytes #x80)))])
    (check-exn exn:fail?
               (lambda () (read-json-bytes/strict 'test
                             (bytes-append #"\"" raw #"\"")))))
  (for ([code (in-range 32)])
    (check-exn exn:fail?
               (lambda () (read-json-bytes/strict 'test
                             (bytes 34 code 34))))))
