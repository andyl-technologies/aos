;;; ANDYL OS -- Bootstrap Seeds Package
;;; Copyright (C) 2024 ANDYL OS Contributors
;;;
;;; This module defines the bootstrap seeds -- the absolute root of the
;;; ANDYL OS build chain.  The only pre-compiled binaries in the entire
;;; system are hex0 (~357 bytes of x86 machine code) and kaem (a minimal
;;; script executor).  These are small enough to audit by hand.
;;;
;;; The bootstrap chain:
;;;   bootstrap-seeds (this package)
;;;     -> mescc-tools (commencement.scm)
;;;       -> GNU Mes
;;;         -> TinyCC
;;;           -> GCC 4.6.4
;;;             -> GCC 7.5.0
;;;               -> GCC 13.x (production)

(define-module (andyl packages bootstrap)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system trivial)
  #:use-module ((guix licenses) #:prefix license:))

;;;
;;; Stage 0: Bootstrap Seeds
;;;
;;; These are the ONLY non-source-built artifacts in the entire ANDYL OS
;;; build chain.  Everything else is compiled from source using tools that
;;; were themselves compiled from source, all the way back to these seeds.
;;;
;;; Source: https://github.com/oriansj/bootstrap-seeds
;;;
;;; The hex0 binary reads hexadecimal pairs from stdin and writes the
;;; corresponding raw bytes to stdout.  That is its entire function.
;;; From this minimal capability, the full bootstrap chain is constructed.

(define-public andyl-bootstrap-seeds
  (package
    (name "andyl-bootstrap-seeds")
    (version "1.0.0")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/oriansj/bootstrap-seeds"
                    "/archive/refs/tags/" version ".tar.gz"))
              (sha256
               ;; TODO: Download the tarball and compute the actual hash:
               ;;   guix download https://github.com/oriansj/bootstrap-seeds/archive/refs/tags/1.0.0.tar.gz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system trivial-build-system)
    (arguments
     (list
      #:modules '((guix build utils))
      #:builder
      #~(begin
          (use-modules (guix build utils))
          (let* ((out     (assoc-ref %outputs "out"))
                 (bindir  (string-append out "/bin"))
                 (source  (assoc-ref %build-inputs "source"))
                 (seeddir (string-append source
                                         "/bootstrap-seeds-"
                                         #$(package-version this-package)
                                         "/NATIVE/x86")))
            ;; Create output directory
            (mkdir-p bindir)

            ;; Install the x86_64 seed binaries.
            ;; hex0: reads hex pairs, writes raw bytes (~357 bytes)
            ;; kaem: minimal script executor
            (for-each
             (lambda (seed)
               (let ((src (string-append seeddir "/" seed)))
                 (when (file-exists? src)
                   (copy-file src (string-append bindir "/" seed))
                   (chmod (string-append bindir "/" seed) #o755))))
             '("hex0-seed"
               "kaem-optional-seed"))

            ;; Also install hex0 source files that later stages need
            ;; to build hex1, hex2, etc.
            (let ((sharedir (string-append out "/share/bootstrap-seeds")))
              (mkdir-p sharedir)
              (copy-recursively source sharedir))))))
    (home-page "https://github.com/oriansj/bootstrap-seeds")
    (synopsis "Minimal binary seeds for bootstrapping from hex0")
    (description
     "Bootstrap seeds provide the absolute root of the ANDYL OS build chain.
The hex0 seed is a ~357-byte x86 binary that reads hexadecimal pairs from
stdin and writes raw bytes to stdout.  The kaem seed is a minimal script
executor.  These are the ONLY pre-compiled binaries in the entire system;
everything else is built from source.")
    (license license:gpl3+)))
