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
(define version "0.2")
(define pkg-authors '(turlamai))
(define license 'Apache-2.0)
(define raco-commands
  '(("permit" permit/raco "issue and verify Permit credentials" #f)))
