;;; ANDYL OS -- Production GCC Package
;;; Copyright (C) 2024 ANDYL OS Contributors
;;;
;;; This module defines the production GCC compiler for ANDYL OS.
;;; GCC 13.3.0 is built using the intermediate GCC 7.5.0 from the
;;; bootstrap chain (commencement.scm).
;;;
;;; Bootstrap provenance:
;;;   hex0 -> mescc-tools -> Mes -> MesCC -> TinyCC
;;;     -> GCC 4.6.4 -> GCC 7.5.0 (commencement.scm)
;;;       -> GCC 13.3.0 (this package)
;;;
;;; This GCC is used to compile ALL remaining packages in the ANDYL OS
;;; distribution, including glibc, the Linux kernel, and all user-space
;;; software.

(define-module (andyl packages gcc)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu)
  #:use-module (guix utils)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (andyl packages commencement)
  #:use-module (andyl config))

;;;
;;; Production GCC 13.3.0
;;;
;;; This is the final GCC in the bootstrap chain and the compiler used
;;; for all production builds.  It supports C and C++ and produces
;;; optimized code for x86_64 server workloads.
;;;

(define-public andyl-gcc
  (package
    (name "andyl-gcc")
    (version (config-version "toolchain" "gcc"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "mirror://gnu/gcc/gcc-" version
                    "/gcc-" version ".tar.xz"))
              (sha256
               ;; TODO: Compute actual hash:
               ;;   guix download mirror://gnu/gcc/gcc-13.3.0/gcc-13.3.0.tar.xz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system gnu-build-system)
    (native-inputs
     (list andyl-gcc-mesboot))
    (arguments
     (list
      #:configure-flags
      #~(list
         ;; Enable C and C++ -- sufficient for server software
         "--enable-languages=c,c++"

         ;; No 32-bit multilib; we target x86_64 only
         "--disable-multilib"

         ;; We already performed our own multi-stage bootstrap chain
         ;; (hex0 -> ... -> GCC 7.5.0), so skip GCC's internal 3-stage
         ;; bootstrap which would triple the build time
         "--disable-bootstrap"

         ;; Use system zlib when available (avoids building GCC's
         ;; bundled copy)
         "--with-system-zlib"

         ;; Default tuning for modern x86_64 servers
         "--with-arch=x86-64"
         "--with-tune=generic"

         ;; Thread model
         "--enable-threads=posix"

         ;; Enable link-time optimization support
         "--enable-lto"

         ;; Shared libraries for libgcc, libstdc++
         "--enable-shared"

         ;; Default to position-independent executables for security
         "--enable-default-pie"

         ;; Stack-smashing protection by default
         "--enable-default-ssp")

      #:phases
      #~(modify-phases %standard-phases
          (add-before 'configure 'set-bootstrap-compiler
            (lambda* (#:key native-inputs #:allow-other-keys)
              ;; Use GCC 7.5.0 from the bootstrap chain as the
              ;; host compiler for building this GCC
              (let ((gcc7 (assoc-ref native-inputs
                                     "andyl-gcc-mesboot")))
                (when gcc7
                  (setenv "CC" (string-append gcc7 "/bin/gcc"))
                  (setenv "CXX" (string-append gcc7 "/bin/g++"))))))

          ;; GCC test suite is extensive; skip during normal builds
          ;; Run explicitly with: guix build --check andyl-gcc
          (delete 'check))

      #:tests? #f))
    (home-page "https://gcc.gnu.org/")
    (synopsis "GCC 13.3.0 -- production C/C++ compiler for ANDYL OS")
    (description
     "The GNU Compiler Collection, version 13.3.0, built through the
complete ANDYL OS bootstrap chain from hex0 binary seeds.  This is the
production compiler used to build all ANDYL OS packages.  Supports C
and C++ with modern optimization and security features enabled by
default (PIE, SSP).")
    (license license:gpl3+)))
