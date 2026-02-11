;;; ANDYL OS -- Production glibc Package
;;; Copyright (C) 2024 ANDYL OS Contributors
;;;
;;; This module defines the production GNU C Library for ANDYL OS.
;;; glibc is the foundation of the user-space runtime -- every C/C++
;;; program links against it.
;;;
;;; This glibc is built with server-oriented hardening flags:
;;;   - Stack protector (strong)    -- buffer overflow detection
;;;   - Full RELRO (bind-now)       -- prevent GOT overwrite attacks
;;;   - Control-flow Enforcement    -- hardware return address protection
;;;   - Static NSS                  -- reliable name resolution in containers
;;;
;;; glibc appears twice in the ANDYL OS build chain:
;;;   1. andyl-bootstrap-glibc (commencement.scm) -- minimal, for GCC 4.6.4
;;;   2. andyl-glibc (this package) -- production, built with modern GCC

(define-module (andyl packages glibc)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu)
  #:use-module (guix utils)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (andyl packages gcc)
  #:use-module (andyl packages linux)
  #:use-module (andyl config))

;;;
;;; Production glibc 2.39
;;;
;;; Built with the production GCC 13.3.0 and linked against Linux 6.12.x
;;; kernel headers.  This is the C library that all ANDYL OS user-space
;;; packages link against.
;;;

(define-public andyl-glibc
  (package
    (name "andyl-glibc")
    (version (config-version "toolchain" "glibc"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "mirror://gnu/glibc/glibc-" version ".tar.xz"))
              (sha256
               ;; TODO: Compute actual hash:
               ;;   guix download mirror://gnu/glibc/glibc-2.39.tar.xz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system gnu-build-system)

    (arguments
     (list
      ;; glibc MUST be built out-of-tree (in a separate build directory).
      ;; Building in-tree is not supported and will fail.
      #:out-of-source? #t

      ;; glibc's test suite is extensive and slow.  Skip during normal
      ;; builds; run explicitly in CI with: guix build --check andyl-glibc
      #:tests? #f

      #:configure-flags
      #~(list
         ;; Install prefix
         (string-append "--prefix=" (assoc-ref %outputs "out"))

         ;; Point to our kernel headers for syscall definitions
         (string-append "--with-headers="
                        #$(this-package-input "andyl-linux-headers")
                        "/include")

         ;; === Server Hardening Flags ===

         ;; Minimum kernel version: enables syscalls not available on
         ;; older kernels, and allows glibc to use newer kernel features
         ;; (io_uring, etc.) without runtime detection overhead.
         "--enable-kernel=5.15"

         ;; Stack Smashing Protector (SSP): inserts stack canaries to
         ;; detect buffer overflows.  "strong" mode protects functions
         ;; that have local arrays or address-taken local variables.
         "--enable-stack-protector=strong"

         ;; Full RELRO (RELocation Read-Only): resolves all PLT entries
         ;; at load time and marks the GOT as read-only.  Prevents
         ;; GOT overwrite attacks at the cost of slightly longer
         ;; program startup.
         "--enable-bind-now"

         ;; Static NSS (Name Service Switch): statically links NSS
         ;; modules (files, dns) into glibc.  This avoids dynamic
         ;; loading issues in containerized environments where
         ;; /lib/libnss_*.so may not be available.
         "--enable-static-nss"

         ;; Intel Control-flow Enforcement Technology (CET): enables
         ;; hardware-enforced shadow stack and indirect branch tracking
         ;; on supported x86_64 CPUs.  Provides defense against
         ;; ROP/JOP attacks.
         "--enable-cet"

         ;; Don't fail the build on compiler warnings.  Warnings are
         ;; important but should not block the build.
         "--disable-werror"

         ;; Standard paths
         "--sysconfdir=/etc"
         "--localstatedir=/var")

      #:phases
      #~(modify-phases %standard-phases
          ;; glibc's configure script needs a shell
          (add-before 'configure 'set-shell
            (lambda _
              (setenv "SHELL" (which "bash"))
              (setenv "CONFIG_SHELL" (which "bash"))))

          ;; Generate essential UTF-8 locales for server use.
          ;; We keep the locale set minimal:
          ;;   - en_US.UTF-8  (default for English servers)
          ;;   - C.UTF-8      (POSIX-compatible UTF-8)
          ;;   - POSIX        (always available, built-in)
          ;; Additional locales can be generated at deployment time.
          (add-after 'install 'install-utf8-locales
            (lambda* (#:key outputs #:allow-other-keys)
              (let ((out (assoc-ref outputs "out")))
                (invoke "make" "localedata/install-locales"
                        (string-append "DESTDIR=" out)))))

          ;; Remove unnecessary static libraries to reduce image size.
          ;; Keep the ones needed for static linking of critical components:
          ;;   - libc.a       (core C library)
          ;;   - libpthread.a (POSIX threads)
          ;;   - libm.a       (math library)
          ;;   - libdl.a      (dynamic loading)
          ;;   - librt.a      (real-time extensions)
          (add-after 'install 'remove-unnecessary-static-libs
            (lambda* (#:key outputs #:allow-other-keys)
              (let ((libdir (string-append (assoc-ref outputs "out") "/lib")))
                (for-each
                 delete-file
                 (filter
                  (lambda (f)
                    (and (string-suffix? ".a" f)
                         (not (member (basename f)
                                      '("libc.a"
                                        "libpthread.a"
                                        "libm.a"
                                        "libdl.a"
                                        "librt.a")))))
                  (find-files libdir "\\.a$")))))))))

    (native-inputs
     (list andyl-gcc))

    ;; glibc has no runtime inputs -- it IS the base runtime.
    ;; All other packages link against it.
    (inputs '())

    ;; Linux kernel headers are needed by packages that build against
    ;; glibc (they #include kernel types via glibc headers).
    ;; Propagating them ensures every glibc-dependent package gets them.
    (propagated-inputs
     (list andyl-linux-headers))

    (home-page "https://www.gnu.org/software/libc/")
    (synopsis "GNU C Library with server hardening for ANDYL OS")
    (description
     "The GNU C Library, version 2.39, built with server-oriented hardening
flags: strong stack protector, full RELRO, Control-flow Enforcement
Technology (CET), and static NSS.  This is the production C library that
all ANDYL OS user-space packages link against.  Built through the complete
bootstrap chain from hex0 binary seeds using GCC 13.3.0.")
    (license license:lgpl2.1+)))
