#lang info

(define collection 'multi)
(define deps
  '("base"
    "crypto-lib"
    "net-lib"
    "rackunit-lib"
    ["ed25519" #:version "0.1"]))
(define build-deps '("racket-doc" "scribble-lib"))
(define pkg-desc "Offline-verifiable, online-manageable signed entitlements")
(define version "0.2.0")
(define pkg-authors '(turlamai))
(define license 'Apache-2.0)
(define raco-commands
  '(("permit" permit/raco "issue and verify Permit credentials" #f)))

;; Keep the product website out of `raco pkg create` source bundles;
;; docs/, examples/, conformance/ and test-vectors/ stay in — the
;; documentation-link regression test walks them (same discipline as
;; rivet's source-omit-files).
(define source-omit-files
  '("site"))
