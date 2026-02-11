;;; ANDYL OS -- Compression Library Packages
;;; Copyright (C) 2024 ANDYL OS Contributors
;;;
;;; This module defines compression libraries used throughout ANDYL OS.
;;; These are fundamental dependencies for many packages: GCC needs zlib,
;;; OpenSSL needs zlib, the kernel build needs compression, package
;;; managers need compression, etc.

(define-module (andyl packages compression)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system cmake)
  #:use-module (guix utils)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (andyl packages gcc)
  #:use-module (andyl packages glibc)
  #:use-module (andyl config))


;;; =========================================================================
;;; zlib -- general-purpose lossless compression
;;; =========================================================================
;;;
;;; zlib is one of the most widely-used compression libraries.  Nearly
;;; every network protocol and file format uses it (HTTP gzip, PNG, ZIP,
;;; git pack files, etc.).
;;;
;;; Note: zlib does NOT use a standard autoconf configure script.  It has
;;; its own configure that accepts a --prefix but doesn't follow autoconf
;;; conventions.  We replace the 'configure phase accordingly.

(define-public andyl-zlib
  (package
    (name "andyl-zlib")
    (version (config-version "compression" "zlib"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://zlib.net/zlib-" version ".tar.gz"))
              (sha256
               ;; TODO: guix download https://zlib.net/zlib-1.3.1.tar.gz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system gnu-build-system)
    (native-inputs (list andyl-gcc))
    (inputs (list andyl-glibc))
    (arguments
     (list
      #:phases
      #~(modify-phases %standard-phases
          ;; zlib's configure is not autoconf-based.  It accepts --prefix
          ;; and --shared but not the full set of autoconf flags that
          ;; gnu-build-system passes by default.
          (replace 'configure
            (lambda* (#:key outputs #:allow-other-keys)
              (let ((out (assoc-ref outputs "out")))
                (invoke "./configure"
                        (string-append "--prefix=" out)
                        "--shared")))))
      #:tests? #f))
    (home-page "https://zlib.net/")
    (synopsis "zlib -- general-purpose lossless compression library")
    (description
     "zlib is a general-purpose lossless data compression library used
by countless programs and libraries.  It implements the DEFLATE
compression algorithm used in gzip, ZIP, PNG, and HTTP.")
    (license license:zlib)))


;;; =========================================================================
;;; XZ Utils / liblzma -- LZMA compression library
;;; =========================================================================
;;;
;;; XZ Utils provides the xz command-line compression tool and liblzma,
;;; the LZMA/LZMA2 compression library.  The command-line tool andyl-xz
;;; is also available from (andyl packages base).

(define-public andyl-xz-utils
  (package
    (name "andyl-xz-utils")
    (version (config-version "base" "xz"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/tukaani-project/xz/releases/download/v"
                    version "/xz-" version ".tar.xz"))
              (sha256
               ;; TODO: guix download <url>
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system gnu-build-system)
    (native-inputs (list andyl-gcc))
    (inputs (list andyl-glibc))
    (arguments
     (list
      #:configure-flags
      #~(list "--disable-static"
              "--enable-threads=yes")
      #:tests? #f))
    (home-page "https://tukaani.org/xz/")
    (synopsis "XZ Utils -- LZMA compression tools and library")
    (description
     "XZ Utils provides the xz command for LZMA/LZMA2 compression and
the liblzma library.  LZMA provides high compression ratios and is
used for .xz and .lzma files including source tarballs and kernel
images.")
    (license (list license:gpl2+ license:lgpl2.1+))))


;;; =========================================================================
;;; Zstandard (zstd) -- fast real-time compression
;;; =========================================================================
;;;
;;; Zstandard provides very fast compression with good ratios.  It is used
;;; by Guix for NAR compression (guix publish --compression=zstd), by the
;;; Linux kernel for compressed initramfs and btrfs, and by many network
;;; protocols.

(define-public andyl-zstd
  (package
    (name "andyl-zstd")
    (version (config-version "compression" "zstd"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/facebook/zstd/releases/download/v"
                    version "/zstd-" version ".tar.gz"))
              (sha256
               ;; TODO: guix download <url>
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system gnu-build-system)
    (native-inputs (list andyl-gcc))
    (inputs (list andyl-glibc))
    (arguments
     (list
      ;; zstd uses a plain Makefile, not autoconf.  Skip the configure phase
      ;; and pass PREFIX directly to make.
      #:phases
      #~(modify-phases %standard-phases
          (delete 'configure))
      #:make-flags
      #~(list (string-append "PREFIX=" (assoc-ref %outputs "out"))
              (string-append "CC=" (which "gcc")))
      #:tests? #f))
    (home-page "https://facebook.github.io/zstd/")
    (synopsis "Zstandard -- fast real-time compression algorithm")
    (description
     "Zstandard (zstd) is a fast lossless compression algorithm targeting
real-time compression scenarios.  It provides compression ratios comparable
to zlib at much higher speed, and supports dictionary compression for
small data.")
    (license (list license:bsd-3 license:gpl2))))


;;; =========================================================================
;;; LZ4 -- extremely fast compression
;;; =========================================================================
;;;
;;; LZ4 is the fastest general-purpose compression algorithm.  It is used
;;; by the Linux kernel, ZFS (lz4 compression), and anywhere speed is
;;; more important than ratio.

(define-public andyl-lz4
  (package
    (name "andyl-lz4")
    (version (config-version "compression" "lz4"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/lz4/lz4/releases/download/v"
                    version "/lz4-" version ".tar.gz"))
              (sha256
               ;; TODO: guix download <url>
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system gnu-build-system)
    (native-inputs (list andyl-gcc))
    (inputs (list andyl-glibc))
    (arguments
     (list
      ;; LZ4 uses a plain Makefile, not autoconf.
      #:phases
      #~(modify-phases %standard-phases
          (delete 'configure))
      #:make-flags
      #~(list (string-append "PREFIX=" (assoc-ref %outputs "out"))
              (string-append "CC=" (which "gcc")))
      #:tests? #f))
    (home-page "https://lz4.github.io/lz4/")
    (synopsis "LZ4 -- extremely fast compression algorithm")
    (description
     "LZ4 is a lossless data compression algorithm focused on
compression and decompression speed.  It is used by the Linux kernel,
ZFS, and many other performance-critical applications.")
    (license (list license:bsd-2 license:gpl2))))
