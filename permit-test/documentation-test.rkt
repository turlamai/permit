#lang racket/base

(require rackunit
         racket/file
         racket/list
         racket/path
         racket/runtime-path
         racket/string)

(define-runtime-path repository-root/raw "..")
(define repository-root (simplify-path repository-root/raw #t))

(define (markdown-file? path)
  (and (file-exists? path)
       (equal? (path-get-extension path) #".md")))

(define markdown-files
  (append
   ;; Root-level roadmap and contribution guides are public entry points too:
   ;; never allow them to escape the local-link regression gate.
   (filter markdown-file?
           (directory-list repository-root #:build? #t))
   (append-map
    (lambda (directory)
      (find-files markdown-file? (build-path repository-root directory)))
    '("docs" "examples" "test-vectors"))))

(define markdown-link-pattern #px"\\[[^]]*\\]\\(([^)]+)\\)")
(define external-link-pattern #px"^(?:https?://|mailto:|#)")

(define (strip-fragment target)
  (car (string-split target "#" #:trim? #f)))

(for ([document (in-list markdown-files)])
  (define contents (file->string document))
  (for ([match (in-list (regexp-match* markdown-link-pattern
                                       contents
                                       #:match-select values))])
    (define target (cadr match))
    (unless (regexp-match? external-link-pattern target)
      (define local-target (strip-fragment target))
      (unless (string=? local-target "")
        (define resolved
          (simplify-path (build-path (path-only document) local-target) #f))
        (check-true
         (or (file-exists? resolved) (directory-exists? resolved))
         (format "~a links to missing local target ~a"
                 (find-relative-path repository-root document)
                 target))))))

;; Cross-repository onboarding, release evidence and trust-boundary links
;; must not point to the retired repository owner. Historical changelog
;; entries may retain history; current normative entry points may not.
(for ([entry '("CONTRIBUTING.md"
               "ROADMAP.md"
               "docs/architecture.md"
               "docs/integration-evidence.md"
               "docs/management-boundaries.md")])
  (check-false
   (string-contains? (file->string (build-path repository-root entry))
                     "https://github.com/turinglambdaai/")
   (format "~a must use the current GitHub owner" entry)))
