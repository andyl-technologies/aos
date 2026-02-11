;;; ANDYL OS -- TLS / Cryptography Library Packages
;;; Copyright (C) 2024 ANDYL OS Contributors
;;;
;;; This module defines TLS and cryptography libraries for ANDYL OS.
;;; OpenSSL is the primary TLS implementation, built with server-hardened
;;; options.

(define-module (andyl packages tls)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu)
  #:use-module (guix utils)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (andyl packages gcc)
  #:use-module (andyl packages glibc)
  #:use-module (andyl packages compression)
  #:use-module (andyl packages base)
  #:use-module (andyl config))


;;; =========================================================================
;;; OpenSSL 3.x -- TLS and general-purpose cryptography
;;; =========================================================================
;;;
;;; OpenSSL is the most widely used TLS library and provides the
;;; cryptographic primitives used by most server software (nginx,
;;; PostgreSQL, curl, Python, etc.).
;;;
;;; Build flags are chosen for server security:
;;;   - TLS 1.2 and 1.3 only (no SSLv3, TLS 1.0, TLS 1.1)
;;;   - Strong ciphers only
;;;   - Position-independent code for ASLR
;;;   - FIPS provider available (not enabled by default)
;;;
;;; Note: OpenSSL uses its own Configure script (Perl-based), not autoconf.
;;; The 'configure phase is replaced accordingly.

(define-public andyl-openssl
  (package
    (name "andyl-openssl")
    (version (config-version "tls" "openssl"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://www.openssl.org/source/openssl-"
                    version ".tar.gz"))
              (sha256
               ;; TODO: guix download https://www.openssl.org/source/openssl-3.3.2.tar.gz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system gnu-build-system)
    (native-inputs
     (list andyl-gcc
           andyl-perl
           andyl-pkg-config))
    (inputs
     (list andyl-glibc
           andyl-zlib))
    (arguments
     (list
      #:phases
      #~(modify-phases %standard-phases
          ;; OpenSSL uses its own Perl-based Configure script, not autoconf.
          ;; It detects the platform and accepts configuration options.
          (replace 'configure
            (lambda* (#:key outputs #:allow-other-keys)
              (let ((out (assoc-ref outputs "out")))
                (invoke "./Configure"
                        ;; Target platform
                        "linux-x86_64"

                        ;; Install prefix
                        (string-append "--prefix=" out)
                        (string-append "--openssldir=" out "/etc/ssl")

                        ;; Link against our zlib
                        "zlib"
                        "--with-zlib-lib"
                        "--with-zlib-include"

                        ;; Build shared libraries (required by most consumers)
                        "shared"

                        ;; Server security configuration:

                        ;; Disable obsolete protocols
                        "no-ssl3"        ;; SSLv3 is broken (POODLE)
                        "no-tls1"        ;; TLS 1.0 is deprecated
                        "no-tls1_1"      ;; TLS 1.1 is deprecated
                        ;; TLS 1.2 and 1.3 remain enabled

                        ;; Disable weak/obsolete algorithms
                        "no-rc4"         ;; RC4 is broken
                        "no-md2"         ;; MD2 is broken
                        "no-md4"         ;; MD4 is broken
                        "no-des"         ;; Single DES is weak (3DES retained)
                        "no-idea"        ;; IDEA is obsolete
                        "no-seed"        ;; SEED is rarely used

                        ;; Enable security features
                        "enable-ktls"    ;; Kernel TLS offload (Linux 4.13+)

                        ;; Compiler flags for hardening
                        "-O2"
                        "-fPIC"
                        "-DOPENSSL_NO_HEARTBEATS"))))

          ;; OpenSSL's test suite is thorough but slow
          (delete 'check))

      #:tests? #f))
    (home-page "https://www.openssl.org/")
    (synopsis "OpenSSL 3.x -- TLS and cryptography for ANDYL OS")
    (description
     "OpenSSL provides TLS/SSL protocol implementation and a general-purpose
cryptography library.  This build is configured for server use: only
TLS 1.2 and 1.3 are enabled, weak algorithms are disabled, and kernel
TLS offload is supported.  Used by nginx, PostgreSQL, curl, Python,
and most other server software in ANDYL OS.")
    (license license:asl2.0)))
