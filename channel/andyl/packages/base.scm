;;; ANDYL OS -- Core Toolchain Packages
;;; Copyright (C) 2024 ANDYL OS Contributors
;;;
;;; This module defines the core toolchain packages that together form the
;;; "standard build environment" for ANDYL OS.  These are the packages that
;;; gnu-build-system provides as implicit inputs: compiler, linker, make,
;;; shell, and essential Unix utilities.
;;;
;;; All packages in this module are built with the production GCC 13.3.0
;;; and glibc 2.39 from the ANDYL OS bootstrap chain.

(define-module (andyl packages base)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu)
  #:use-module (guix utils)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (andyl packages gcc)
  #:use-module (andyl packages glibc)
  #:use-module (andyl config))


;;; =========================================================================
;;; GNU Binutils -- assembler, linker, and binary utilities
;;; =========================================================================

(define-public andyl-binutils
  (package
    (name "andyl-binutils")
    (version (config-version "toolchain" "binutils"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "mirror://gnu/binutils/binutils-" version ".tar.xz"))
              (sha256
               ;; TODO: guix download mirror://gnu/binutils/binutils-2.42.tar.xz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system gnu-build-system)
    (native-inputs (list andyl-gcc))
    (inputs (list andyl-glibc))
    (arguments
     (list
      #:configure-flags
      #~(list "--enable-deterministic-archives"
              "--enable-threads"
              "--enable-gold=default"
              "--enable-plugins"
              "--disable-werror")
      #:tests? #f))
    (home-page "https://www.gnu.org/software/binutils/")
    (synopsis "GNU Binutils -- assembler, linker, and binary utilities")
    (description
     "GNU Binutils provides the assembler (as), linker (ld/gold), and
binary utilities (ar, nm, objdump, readelf, strip, etc.) for ANDYL OS.")
    (license license:gpl3+)))


;;; =========================================================================
;;; GNU Make -- build automation
;;; =========================================================================

(define-public andyl-make
  (package
    (name "andyl-make")
    (version (config-version "base" "make"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "mirror://gnu/make/make-" version ".tar.gz"))
              (sha256
               ;; TODO: guix download mirror://gnu/make/make-4.4.1.tar.gz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system gnu-build-system)
    (native-inputs (list andyl-gcc))
    (inputs (list andyl-glibc))
    (arguments
     (list #:tests? #f))
    (home-page "https://www.gnu.org/software/make/")
    (synopsis "GNU Make -- build automation tool")
    (description
     "GNU Make determines which pieces of a large program need to be
recompiled, and issues the commands to recompile them.")
    (license license:gpl3+)))


;;; =========================================================================
;;; GNU Coreutils -- basic file, shell, and text utilities
;;; =========================================================================

(define-public andyl-coreutils
  (package
    (name "andyl-coreutils")
    (version (config-version "base" "coreutils"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "mirror://gnu/coreutils/coreutils-" version ".tar.xz"))
              (sha256
               ;; TODO: guix download mirror://gnu/coreutils/coreutils-9.5.tar.xz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system gnu-build-system)
    (native-inputs (list andyl-gcc))
    (inputs (list andyl-glibc))
    (arguments
     (list #:tests? #f))
    (home-page "https://www.gnu.org/software/coreutils/")
    (synopsis "GNU Coreutils -- essential Unix utilities")
    (description
     "GNU Coreutils provides the basic file, shell, and text manipulation
utilities: ls, cp, mv, rm, cat, echo, sort, uniq, head, tail, wc, etc.")
    (license license:gpl3+)))


;;; =========================================================================
;;; GNU Bash -- the shell
;;; =========================================================================

(define-public andyl-bash
  (package
    (name "andyl-bash")
    (version (config-version "base" "bash"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "mirror://gnu/bash/bash-" version ".tar.gz"))
              (sha256
               ;; TODO: guix download mirror://gnu/bash/bash-5.2.32.tar.gz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system gnu-build-system)
    (native-inputs (list andyl-gcc))
    (inputs (list andyl-glibc))
    (arguments
     (list
      #:configure-flags
      #~(list "--with-installed-readline"
              "--without-bash-malloc")
      #:tests? #f))
    (home-page "https://www.gnu.org/software/bash/")
    (synopsis "GNU Bash -- the Bourne-Again SHell")
    (description
     "Bash is the GNU Project's shell -- the Bourne Again SHell.
It is the default shell for ANDYL OS and provides interactive and
scripting capabilities.")
    (license license:gpl3+)))


;;; =========================================================================
;;; GNU Findutils -- find, xargs, locate
;;; =========================================================================

(define-public andyl-findutils
  (package
    (name "andyl-findutils")
    (version (config-version "base" "findutils"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "mirror://gnu/findutils/findutils-" version ".tar.xz"))
              (sha256
               ;; TODO: guix download mirror://gnu/findutils/findutils-4.10.0.tar.xz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system gnu-build-system)
    (native-inputs (list andyl-gcc))
    (inputs (list andyl-glibc))
    (arguments
     (list #:tests? #f))
    (home-page "https://www.gnu.org/software/findutils/")
    (synopsis "GNU Findutils -- find, xargs, and locate")
    (description
     "GNU Findutils provides utilities to find files: find, xargs,
and locate.")
    (license license:gpl3+)))


;;; =========================================================================
;;; GNU Gawk -- pattern scanning and processing
;;; =========================================================================

(define-public andyl-gawk
  (package
    (name "andyl-gawk")
    (version (config-version "base" "gawk"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "mirror://gnu/gawk/gawk-" version ".tar.xz"))
              (sha256
               ;; TODO: guix download mirror://gnu/gawk/gawk-5.3.1.tar.xz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system gnu-build-system)
    (native-inputs (list andyl-gcc))
    (inputs (list andyl-glibc))
    (arguments
     (list #:tests? #f))
    (home-page "https://www.gnu.org/software/gawk/")
    (synopsis "GNU Gawk -- pattern scanning and processing language")
    (description
     "GNU Gawk is the GNU implementation of AWK, a programming language
for pattern scanning and text processing.")
    (license license:gpl3+)))


;;; =========================================================================
;;; GNU Grep -- pattern matching
;;; =========================================================================

(define-public andyl-grep
  (package
    (name "andyl-grep")
    (version (config-version "base" "grep"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "mirror://gnu/grep/grep-" version ".tar.xz"))
              (sha256
               ;; TODO: guix download mirror://gnu/grep/grep-3.11.tar.xz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system gnu-build-system)
    (native-inputs (list andyl-gcc))
    (inputs (list andyl-glibc))
    (arguments
     (list #:tests? #f))
    (home-page "https://www.gnu.org/software/grep/")
    (synopsis "GNU Grep -- print lines matching a pattern")
    (description
     "GNU Grep searches input files for lines matching a regular expression
pattern and prints the matching lines.")
    (license license:gpl3+)))


;;; =========================================================================
;;; GNU Sed -- stream editor
;;; =========================================================================

(define-public andyl-sed
  (package
    (name "andyl-sed")
    (version (config-version "base" "sed"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "mirror://gnu/sed/sed-" version ".tar.xz"))
              (sha256
               ;; TODO: guix download mirror://gnu/sed/sed-4.9.tar.xz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system gnu-build-system)
    (native-inputs (list andyl-gcc))
    (inputs (list andyl-glibc))
    (arguments
     (list #:tests? #f))
    (home-page "https://www.gnu.org/software/sed/")
    (synopsis "GNU Sed -- stream editor")
    (description
     "GNU Sed is a stream editor for filtering and transforming text.")
    (license license:gpl3+)))


;;; =========================================================================
;;; GNU Tar -- archiving utility
;;; =========================================================================

(define-public andyl-tar
  (package
    (name "andyl-tar")
    (version (config-version "base" "tar"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "mirror://gnu/tar/tar-" version ".tar.xz"))
              (sha256
               ;; TODO: guix download mirror://gnu/tar/tar-1.35.tar.xz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system gnu-build-system)
    (native-inputs (list andyl-gcc))
    (inputs (list andyl-glibc))
    (arguments
     (list #:tests? #f))
    (home-page "https://www.gnu.org/software/tar/")
    (synopsis "GNU Tar -- archive utility")
    (description
     "GNU Tar creates and manipulates tar archives.")
    (license license:gpl3+)))


;;; =========================================================================
;;; GNU Gzip -- compression utility
;;; =========================================================================

(define-public andyl-gzip
  (package
    (name "andyl-gzip")
    (version (config-version "base" "gzip"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "mirror://gnu/gzip/gzip-" version ".tar.xz"))
              (sha256
               ;; TODO: guix download mirror://gnu/gzip/gzip-1.13.tar.xz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system gnu-build-system)
    (native-inputs (list andyl-gcc))
    (inputs (list andyl-glibc))
    (arguments
     (list #:tests? #f))
    (home-page "https://www.gnu.org/software/gzip/")
    (synopsis "GNU Gzip -- data compression program")
    (description
     "GNU Gzip compresses and decompresses files using the Lempel-Ziv
coding (LZ77).")
    (license license:gpl3+)))


;;; =========================================================================
;;; XZ Utils -- LZMA compression
;;; =========================================================================

(define-public andyl-xz
  (package
    (name "andyl-xz")
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
     (list #:tests? #f))
    (home-page "https://tukaani.org/xz/")
    (synopsis "XZ Utils -- LZMA compression tools and library")
    (description
     "XZ Utils provides the xz command for LZMA/LZMA2 compression and
the liblzma library.")
    (license (list license:gpl2+ license:lgpl2.1+))))


;;; =========================================================================
;;; GNU Diffutils -- file comparison utilities
;;; =========================================================================

(define-public andyl-diffutils
  (package
    (name "andyl-diffutils")
    (version (config-version "base" "diffutils"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "mirror://gnu/diffutils/diffutils-" version ".tar.xz"))
              (sha256
               ;; TODO: guix download mirror://gnu/diffutils/diffutils-3.10.tar.xz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system gnu-build-system)
    (native-inputs (list andyl-gcc))
    (inputs (list andyl-glibc))
    (arguments
     (list #:tests? #f))
    (home-page "https://www.gnu.org/software/diffutils/")
    (synopsis "GNU Diffutils -- file comparison utilities")
    (description
     "GNU Diffutils provides diff, diff3, sdiff, and cmp for comparing
files and showing differences.")
    (license license:gpl3+)))


;;; =========================================================================
;;; GNU Patch -- apply diffs to files
;;; =========================================================================

(define-public andyl-patch
  (package
    (name "andyl-patch")
    (version (config-version "base" "patch"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "mirror://gnu/patch/patch-" version ".tar.xz"))
              (sha256
               ;; TODO: guix download mirror://gnu/patch/patch-2.7.6.tar.xz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system gnu-build-system)
    (native-inputs (list andyl-gcc))
    (inputs (list andyl-glibc))
    (arguments
     (list #:tests? #f))
    (home-page "https://www.gnu.org/software/patch/")
    (synopsis "GNU Patch -- apply diffs to files")
    (description
     "GNU Patch applies diff files (patches) to original files.")
    (license license:gpl3+)))


;;; =========================================================================
;;; pkg-config -- build configuration tool
;;; =========================================================================

(define-public andyl-pkg-config
  (package
    (name "andyl-pkg-config")
    (version (config-version "base" "pkg-config"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://pkgconfig.freedesktop.org/releases/pkg-config-"
                    version ".tar.gz"))
              (sha256
               ;; TODO: guix download <url>
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system gnu-build-system)
    (native-inputs (list andyl-gcc))
    (inputs (list andyl-glibc))
    (arguments
     (list
      #:configure-flags
      #~(list "--with-internal-glib")
      #:tests? #f))
    (home-page "https://www.freedesktop.org/wiki/Software/pkg-config/")
    (synopsis "pkg-config -- build configuration helper tool")
    (description
     "pkg-config helps configure compiler and linker flags for libraries.
Built with internal glib to avoid circular dependencies.")
    (license license:gpl2+)))


;;; =========================================================================
;;; Perl -- required build dependency for many packages
;;; =========================================================================
;;;
;;; Perl is needed as a build-time dependency by autoconf, automake,
;;; glibc locale generation, OpenSSL's Configure script, and many other
;;; packages.

(define-public andyl-perl
  (package
    (name "andyl-perl")
    (version (config-version "base" "perl"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://www.cpan.org/src/5.0/perl-" version ".tar.gz"))
              (sha256
               ;; TODO: guix download https://www.cpan.org/src/5.0/perl-5.38.2.tar.gz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system gnu-build-system)
    (native-inputs (list andyl-gcc))
    (inputs (list andyl-glibc))
    (arguments
     (list
      #:phases
      #~(modify-phases %standard-phases
          ;; Perl uses its own Configure script (capital C), not autoconf.
          (replace 'configure
            (lambda* (#:key outputs #:allow-other-keys)
              (let ((out (assoc-ref outputs "out")))
                (invoke "./Configure"
                        "-des"
                        (string-append "-Dprefix=" out)
                        "-Dman1dir=none"
                        "-Dman3dir=none"
                        "-Dusethreads"
                        "-Duseshrplib"
                        "-Dlocincpth="
                        "-Dloclibpth=")))))
      #:tests? #f))
    (home-page "https://www.perl.org/")
    (synopsis "Perl programming language for ANDYL OS")
    (description
     "Perl is a general-purpose programming language required as a build
dependency by many packages including autoconf, automake, OpenSSL, and
glibc locale generation.")
    (license (list license:gpl1+ license:artistic2.0))))


;;; =========================================================================
;;; GNU Bison -- parser generator
;;; =========================================================================
;;;
;;; Bison is a general-purpose parser generator that converts annotated
;;; context-free grammar specifications into C/C++ parsers.  Required
;;; for building packages that include .y grammar files.

(define-public andyl-bison
  (package
    (name "andyl-bison")
    (version (config-version "base" "bison"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "mirror://gnu/bison/bison-" version ".tar.xz"))
              (sha256
               ;; TODO: guix download mirror://gnu/bison/bison-3.8.2.tar.xz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system gnu-build-system)
    (native-inputs (list andyl-gcc andyl-perl))
    (inputs (list andyl-glibc))
    (arguments
     (list #:tests? #f))
    (home-page "https://www.gnu.org/software/bison/")
    (synopsis "GNU Bison -- parser generator (yacc replacement)")
    (description
     "GNU Bison is a general-purpose parser generator that converts
annotated context-free grammar specifications into C or C++ parsers.
It is the GNU replacement for yacc.")
    (license license:gpl3+)))


;;; =========================================================================
;;; GNU Texinfo -- documentation system
;;; =========================================================================
;;;
;;; Texinfo is the official documentation system for GNU projects.
;;; Many packages generate info pages during their build, requiring
;;; texinfo as a native build input.

(define-public andyl-texinfo
  (package
    (name "andyl-texinfo")
    (version (config-version "base" "texinfo"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "mirror://gnu/texinfo/texinfo-" version ".tar.xz"))
              (sha256
               ;; TODO: guix download mirror://gnu/texinfo/texinfo-7.1.tar.xz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system gnu-build-system)
    (native-inputs (list andyl-gcc andyl-perl))
    (inputs (list andyl-glibc))
    (arguments
     (list #:tests? #f))
    (home-page "https://www.gnu.org/software/texinfo/")
    (synopsis "GNU Texinfo -- documentation system")
    (description
     "GNU Texinfo is the official documentation format of the GNU project.
It produces output in info, HTML, PDF, and other formats from Texinfo
source files.  Required as a build dependency for packages that generate
info pages.")
    (license license:gpl3+)))
