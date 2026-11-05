#lang racket/base

(require json
         racket/cmdline
         racket/file
         racket/list
         racket/port
         "credential.rkt"
         "crypto.rkt"
         "envelope.rkt"
         (only-in "issuer.rkt" issue-credential)
         "policy.rkt"
         "private/time.rkt"
         "schema.rkt"
         "trust.rkt")

(provide run-cli)

(define (die message)
  (eprintf "permit: ~a\n" message)
  (exit 2))

(define (write-json-line value [out (current-output-port)])
  (write-json value out)
  (newline out))

(define (require-option command name value)
  (unless value
    (die (format "~a requires ~a" command name)))
  value)

(define (keygen args)
  (define private-path #f)
  (define public-path #f)
  (define trust-path #f)
  (define key-id #f)
  (define issuer #f)
  (define purposes '())
  (define allowed-purposes '("entitlement" "trial" "trial-extension" "activation"))
  (parameterize ([current-command-line-arguments (list->vector args)])
    (command-line #:program "raco permit keygen"
                  #:once-each
                  [("--private") path "Private key output (PKCS#8 DER)" (set! private-path path)]
                  [("--public") path "Public key output (SPKI DER)" (set! public-path path)]
                  [("--trust-store") path "Optional trust-store JSON output" (set! trust-path path)]
                  [("--key-id") value "Key identifier for trust store" (set! key-id value)]
                  [("--issuer") value "Issuer for trust store" (set! issuer value)]
                  #:multi
                  [("--purpose")
                   value
                   "Allowed credential type; repeat for least-privilege keys"
                   (unless (member value allowed-purposes)
                     (die (format "unknown key purpose ~a; expected one of ~a"
                                  value
                                  allowed-purposes)))
                   (set! purposes (cons value purposes))]))
  (require-option 'keygen "--private" private-path)
  (require-option 'keygen "--public" public-path)
  (when trust-path
    (require-option 'keygen "--key-id" key-id)
    (require-option 'keygen "--issuer" issuer))
  (define effective-purposes
    (if (null? purposes)
        allowed-purposes
        (reverse (remove-duplicates purposes string=?))))
  (define-values (private-key public-key) (generate-ed25519-keypair))
  (call-with-output-file private-path
                         (lambda (out) (write-bytes (ed25519-private-key->der private-key) out))
                         #:mode 'binary
                         #:exists 'error)
  ;; `call-with-output-file` creates the key with the process umask, which is
  ;; commonly 022 and therefore world-readable. A signing key must not be.
  ;; Windows has no POSIX mode bits; it only exposes the read-only flag.
  (unless (eq? (system-type) 'windows)
    (file-or-directory-permissions private-path #o600))
  (call-with-output-file public-path
                         (lambda (out) (write-bytes (ed25519-public-key->der public-key) out))
                         #:mode 'binary
                         #:exists 'error)
  (when trust-path
    (define store
      (hasheq 'protocol
              "permit-trust-store"
              'version
              1
              'issuer
              issuer
              'keys
              (hash (string->symbol key-id)
                    (hasheq 'algorithm
                            "Ed25519"
                            'public_key
                            (public-key->base64 public-key)
                            'status
                            "active"
                            'purposes
                            effective-purposes
                            'not_before
                            'null
                            'not_after
                            'null))))
    (call-with-output-file trust-path (lambda (out) (write-json-line store out)) #:exists 'error))
  (write-json-line
   (hasheq 'private_key private-path
           'public_key public-path
           'trust_store (or trust-path 'null)
           'purposes effective-purposes)))

(define (issue-command args)
  (define key-path #f)
  (define key-id #f)
  (define trust-path #f)
  (define payload-path #f)
  (define output-path #f)
  (parameterize ([current-command-line-arguments (list->vector args)])
    (command-line
     #:program "raco permit issue"
     #:once-each
     [("--key") path "Ed25519 private key" (set! key-path path)]
     [("--key-id") value "Trust-store key identifier" (set! key-id value)]
     [("--trust-store") path "Trust store governing safe issuance" (set! trust-path path)]
     [("--payload") path "Credential payload JSON" (set! payload-path path)]
     [("--output") path "Signed credential output" (set! output-path path)]))
  (for ([entry (in-list (list (cons "--key" key-path)
                              (cons "--key-id" key-id)
                              (cons "--trust-store" trust-path)
                              (cons "--payload" payload-path)
                              (cons "--output" output-path)))])
    (require-option 'issue (car entry) (cdr entry)))
  (define payload (file->bytes payload-path))
  (define claims (parse-credential-payload payload))
  (define envelope
    (issue-credential payload
                      (read-ed25519-private-key key-path)
                      key-id
                      (read-trust-store trust-path)))
  (write-envelope envelope output-path)
  (write-json-line
   (hasheq 'credential output-path
           'credential_id (hash-ref claims 'credential_id)
           'type (hash-ref claims 'type)
           'key_id key-id
           'payload_bytes (bytes-length payload))))

;; Low-level escape hatch for tests/recovery tooling. It validates the payload
;; schema but intentionally does not apply trust-store issuance policy.
(define (sign-command args)
  (define key-path #f)
  (define key-id #f)
  (define payload-path #f)
  (define output-path #f)
  (parameterize ([current-command-line-arguments (list->vector args)])
    (command-line
     #:program "raco permit sign"
     #:once-each
     [("--key") path "Ed25519 private key" (set! key-path path)]
     [("--key-id") value "Envelope key identifier" (set! key-id value)]
     [("--payload") path "Credential payload JSON" (set! payload-path path)]
     [("--output") path "Signed credential output" (set! output-path path)]))
  (for ([entry (in-list (list (cons "--key" key-path)
                              (cons "--key-id" key-id)
                              (cons "--payload" payload-path)
                              (cons "--output" output-path)))])
    (require-option 'sign (car entry) (cdr entry)))
  (define payload (file->bytes payload-path))
  (define claims (parse-credential-payload payload))
  (define envelope
    (make-signed-envelope key-id payload (read-ed25519-private-key key-path)))
  (write-envelope envelope output-path)
  (write-json-line
   (hasheq 'credential output-path
           'credential_id (hash-ref claims 'credential_id)
           'type (hash-ref claims 'type)
           'key_id key-id
           'payload_bytes (bytes-length payload))))

(define (load-verified command store-path credential-path)
  (require-option command "--trust-store" store-path)
  (require-option command "--credential" credential-path)
  (verify-credential credential-path (read-trust-store store-path)))

(define (verify-command args)
  (define store-path #f)
  (define credential-path #f)
  (define payload-output #f)
  (parameterize ([current-command-line-arguments (list->vector args)])
    (command-line
     #:program "raco permit verify"
     #:once-each [("--trust-store") path "Trust-store JSON" (set! store-path path)]
     [("--credential") path "Signed credential" (set! credential-path path)]
     [("--payload-out") path "Write exact verified payload bytes" (set! payload-output path)]))
  (define credential (load-verified 'verify store-path credential-path))
  (when payload-output
    (call-with-output-file payload-output
                           (lambda (out) (write-bytes (verified-credential-payload credential) out))
                           #:mode 'binary
                           #:exists 'truncate/replace))
  (write-json-line (hasheq 'verified
                           #t
                           'credential_id
                           (verified-credential-id credential)
                           'entitlement_id
                           (or (verified-credential-entitlement-id credential) 'null)
                           'type
                           (verified-credential-type credential)
                           'key_id
                           (verified-credential-key-id credential))))

(define (inspect-command args)
  (define credential-path #f)
  (parameterize ([current-command-line-arguments (list->vector args)])
    (command-line #:program "raco permit inspect"
                  #:once-each
                  [("--credential") path "Signed credential" (set! credential-path path)]))
  (require-option 'inspect "--credential" credential-path)
  (define envelope (read-envelope credential-path))
  (define claims (parse-credential-payload (permit-envelope-payload envelope)))
  (write-json-line (hasheq 'warning
                           "UNVERIFIED: run permit verify before trusting these claims"
                           'key_id
                           (permit-envelope-key-id envelope)
                           'claims
                           claims)))

(define (check-command args)
  (define store-path #f)
  (define credential-path #f)
  (define activation-path #f)
  (define trial-extension-paths '())
  (define product #f)
  (define product-family #f)
  (define feature #f)
  (define addon #f)
  (define edition #f)
  (define capability #f)
  (define limit #f)
  (define update-published-at #f)
  (define feature-published-at #f)
  (define installation-id #f)
  (define version #f)
  (define at (current-rfc3339))
  (parameterize ([current-command-line-arguments (list->vector args)])
    (command-line
     #:program "raco permit check"
     #:once-each
     [("--trust-store") path "Trust-store JSON" (set! store-path path)]
     [("--credential") path "Signed entitlement or trial" (set! credential-path path)]
     [("--activation") path "Optional signed activation lease" (set! activation-path path)]
     [("--product") value "Product identifier" (set! product value)]
     [("--product-family") value "Optional product-family identifier" (set! product-family value)]
     [("--feature") value "Feature to evaluate" (set! feature value)]
     [("--addon") value "Add-on to evaluate" (set! addon value)]
     [("--edition") value "Edition to evaluate" (set! edition value)]
     [("--capability") value "Scalar capability to read" (set! capability value)]
     [("--limit") value "Limit to read" (set! limit value)]
     [("--update-published-at") value "Release publication time" (set! update-published-at value)]
     [("--feature-published-at") value "Feature publication time" (set! feature-published-at value)]
     [("--installation-id")
      value
      "Stable application installation identifier"
      (set! installation-id value)]
     [("--version") value "Application SemVer" (set! version value)]
     [("--at") value "Policy evaluation time" (set! at value)]
     #:multi
     [("--trial-extension")
      path
      "Signed trial-extension credential; may be repeated"
      (set! trial-extension-paths (cons path trial-extension-paths))]))
  (define store (read-trust-store (require-option 'check "--trust-store" store-path)))
  (define credential
    (verify-credential (require-option 'check "--credential" credential-path) store))
  (define activation (and activation-path (verify-credential activation-path store)))
  (define trial-extensions
    (for/list ([path (in-list (reverse trial-extension-paths))])
      (verify-credential path store)))
  (define status
    (credential-status credential
                       #:at at
                       #:installation-id installation-id
                       #:activation activation
                       #:trial-extensions trial-extensions))
  (define required-product
    (and (or feature addon edition capability update-published-at)
         (require-option 'check "--product for product-scoped query" product)))
  (define result
    (hash-set*
     status
     ;; status reasons are symbols; JSON output carries them as strings
     'reasons
     (map symbol->string (hash-ref status 'reasons '()))
     'credential_id
     (verified-credential-id credential)
     'entitlement_id
     (or (verified-credential-entitlement-id credential) 'null)
     'type
     (verified-credential-type credential)
     'feature_allowed
     (if feature
         (feature-entitled? credential required-product feature
                            #:published-at feature-published-at
                            #:at at
                            #:product-family product-family
                            #:version version
                            #:installation-id installation-id
                            #:activation activation
                            #:trial-extensions trial-extensions)
         'null)
     'addon_allowed
     (if addon
         (addon-entitled? credential required-product addon
                          #:at at
                          #:product-family product-family
                          #:version version
                          #:installation-id installation-id
                          #:activation activation
                          #:trial-extensions trial-extensions)
         'null)
     'edition_allowed
     (if edition
         (edition-entitled? credential required-product edition
                            #:at at
                            #:product-family product-family
                            #:version version
                            #:installation-id installation-id
                            #:activation activation
                            #:trial-extensions trial-extensions)
         'null)
     'update_allowed
     (if update-published-at
         (update-entitled? credential required-product update-published-at
                           #:at at
                           #:product-family product-family
                           #:version version
                           #:installation-id installation-id
                           #:activation activation
                           #:trial-extensions trial-extensions)
         'null)
     'capability_value
     (if capability
         (capability-value credential required-product capability
                           #:default 'null
                           #:at at
                           #:product-family product-family
                           #:version version
                           #:installation-id installation-id
                           #:activation activation
                           #:trial-extensions trial-extensions)
         'null)
     'limit_value
     (if limit
         (limit-value credential limit
                      #:default 'null
                      #:at at
                      #:installation-id installation-id
                      #:activation activation
                      #:trial-extensions trial-extensions)
         'null)))
  (write-json-line result))

(define (doctor-command args)
  (when (pair? args)
    (die "doctor takes no arguments"))
  (write-json-line
   (hash 'ok #t
         'crypto (ed25519-provider-report)))
  0)

(define (usage)
  (displayln "Permit — signed entitlements for independent software")
  (displayln "usage: raco permit <keygen|issue|sign|verify|inspect|check|doctor> [options]")
  (displayln "  issue   safely issue using trust-store key policy")
  (displayln "  sign    low-level schema-valid signing without issuer policy")
  (displayln "  doctor  print Ed25519 provider diagnostics as JSON"))

(define (run-cli [args (vector->list (current-command-line-arguments))])
  (with-handlers ([exn:fail? (lambda (e)
                               (eprintf "permit: ~a\n" (exn-message e))
                               ;; typed refusals name the guard on a line of
                               ;; their own so scripts read it without
                               ;; parsing the message
                               (when (exn:fail:permit? e)
                                 (eprintf "reason: ~a\n" (exn:fail:permit-reason e)))
                               (exit 1))])
    (cond
      [(null? args) (usage)]
      [else
       (case (string->symbol (car args))
         [(keygen) (keygen (cdr args))]
         [(issue) (issue-command (cdr args))]
         [(sign) (sign-command (cdr args))]
         [(verify) (verify-command (cdr args))]
         [(inspect) (inspect-command (cdr args))]
         [(check) (check-command (cdr args))]
         [(doctor) (doctor-command (cdr args))]
         [(help --help -h) (usage)]
         [else (die (format "unknown command: ~a" (car args)))])])))

(module+ main
  (run-cli))
