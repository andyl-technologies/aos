;;; ANDYL OS -- Butane Config Transpiler Package
;;; Copyright (C) 2024 ANDYL OS Contributors
;;;
;;; This module defines the Butane config transpiler package for ANDYL OS:
;;;
;;;   andyl-butane -- Butane YAML to Ignition JSON transpiler
;;;
;;; Butane (formerly the Fedora CoreOS Config Transpiler) converts
;;; human-readable Butane YAML configuration into Ignition JSON.
;;; Butane YAML is the authoring format; Ignition JSON is the machine
;;; format consumed by the Ignition provisioning tool at first boot.
;;;
;;; Usage:
;;;   butane --strict < config.bu > config.ign
;;;   butane --strict --pretty config.bu > config.ign
;;;
;;; The --strict flag causes butane to fail on any warnings, which is
;;; required for production use.  Generated Ignition JSON should also
;;; be validated with ignition-validate (from the andyl-ignition package).
;;;
;;; See:
;;;   RFC-0006 section 2 (Butane YAML to Ignition JSON Transpilation)
;;;   Phase 6 section 6.2 (Butane Package)
;;;
;;; Package dependency graph:
;;;
;;;   andyl-butane
;;;     +-- Go toolchain (build-time only)
;;;     +-- andyl-glibc

(define-module (andyl packages butane)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system go)
  #:use-module (guix utils)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (andyl packages gcc)
  #:use-module (andyl packages glibc)
  #:use-module (andyl config))


;;; =========================================================================
;;; Butane -- Butane Config Transpiler
;;; =========================================================================
;;;
;;; Butane transpiles Butane YAML (human-readable, supports comments,
;;; sugar syntax for common patterns) into Ignition JSON (machine-
;;; readable, consumed by Ignition in the initrd).
;;;
;;; Butane YAML uses the "variant: fcos" and "version: 1.5.0" header
;;; to identify the config format.  The version corresponds to the
;;; Butane spec version, which maps to a specific Ignition spec version
;;; (Butane 1.5.0 -> Ignition 3.4.0).
;;;
;;; Key Butane features over raw Ignition JSON:
;;;   - YAML syntax with comments
;;;   - Inline file contents (no base64 encoding required)
;;;   - Sugar for common patterns (SSH keys, systemd units)
;;;   - Validation of config structure at transpilation time
;;;   - --strict mode for production safety
;;;
;;; Version 0.21.x is used for compatibility with:
;;;   - Butane spec v1.5.0
;;;   - Ignition spec v3.4.0
;;;   - Ignition v2.19.x (andyl-ignition package)

(define-public andyl-butane
  (package
    (name "andyl-butane")
    (version (config-version "image-tools" "butane"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/coreos/butane/archive/refs/tags/v"
                    version ".tar.gz"))
              (sha256
               ;; TODO: Compute actual hash:
               ;;   guix download https://github.com/coreos/butane/archive/refs/tags/v0.21.0.tar.gz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system go-build-system)
    (arguments
     (list
      #:import-path "github.com/coreos/butane"
      #:install-source? #f

      #:phases
      #~(modify-phases %standard-phases
          ;; Build the butane binary from the internal/main entry point.
          (replace 'build
            (lambda* (#:key import-path #:allow-other-keys)
              (invoke "go" "build" "-v"
                      "-o" "bin/butane"
                      (string-append import-path "/internal"))))

          (replace 'install
            (lambda* (#:key outputs #:allow-other-keys)
              (let* ((out    (assoc-ref outputs "out"))
                     (bindir (string-append out "/bin")))
                (mkdir-p bindir)
                (install-file "bin/butane" bindir)))))))

    (native-inputs
     (list andyl-gcc))

    (inputs
     (list andyl-glibc))

    (home-page "https://coreos.github.io/butane/")
    (synopsis "Butane config transpiler for ANDYL OS")
    (description
     "Butane transpiles human-readable Butane YAML configuration files
into Ignition JSON for first-boot machine provisioning.  Butane YAML
supports comments, inline file contents, and sugar syntax for common
patterns (SSH keys, systemd units, file permissions).  The --strict
flag ensures all warnings are treated as errors for production safety.
Used with andyl-ignition for ANDYL OS first-boot provisioning.")
    (license license:asl2.0)))
