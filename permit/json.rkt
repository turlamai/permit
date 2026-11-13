#lang racket/base

;; Explicit data-reading utility; parsing alone never authenticates a credential.
(require "private/json.rkt")

(provide read-json-bytes/strict
         read-json-source/strict)
