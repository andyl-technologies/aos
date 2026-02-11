;;; ANDYL OS -- Commencement: From Seeds to Full Toolchain
;;; Copyright (C) 2024 ANDYL OS Contributors
;;;
;;; This is the most critical module in the ANDYL OS channel.  It defines
;;; the complete bootstrap chain from binary seeds through to a modern GCC
;;; compiler.  Each package uses ONLY tools built in the previous stage --
;;; there are no circular dependencies and no pre-built binaries beyond
;;; the ~357-byte hex0 seed.
;;;
;;; The bootstrap chain defined here:
;;;
;;;   Stage 0: bootstrap-seeds (hex0, kaem)        [bootstrap.scm]
;;;   Stage 1: mescc-tools (hex0->hex1->hex2->M0->M1->M2-Planet->kaem)
;;;            mescc-tools-extra (M2-Planet extras)
;;;   Stage 2: GNU Mes (Scheme interpreter + MesCC C compiler)
;;;            TinyCC (compiled by MesCC)
;;;   Stage 3: GCC 4.6.4 (compiled by TinyCC, C only)
;;;            bootstrap-glibc (minimal libc for GCC 4.6.4)
;;;   Stage 4: GCC 7.5.0 (compiled by GCC 4.6.4, C + C++)
;;;
;;; After Stage 4, the gcc.scm module takes over with production GCC 13.x,
;;; and glibc.scm defines the production glibc with server hardening flags.
;;;
;;; Build DAG:
;;;
;;;   hex0 -----> hex1 -----> hex2 -----> M0 -----> M1
;;;                                                  |
;;;                              M2-Planet <---------+
;;;                                  |
;;;                     kaem <-------+-------> mescc-tools
;;;                                                  |
;;;                                   GNU Mes <------+
;;;                                     |
;;;                                   MesCC
;;;                                     |
;;;                                   TinyCC
;;;                                     |
;;;                                 GCC 4.6.4 (C only)
;;;                                     |
;;;                                 GCC 7.5.0 (C + C++)
;;;                                     |
;;;                                 GCC 13.x  [gcc.scm]

(define-module (andyl packages commencement)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system trivial)
  #:use-module (guix utils)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (andyl packages bootstrap)
  #:use-module (andyl config))


;;; =========================================================================
;;; Stage 1: MesCC-Tools
;;; =========================================================================
;;;
;;; The mescc-tools package builds the chain of assemblers and tools needed
;;; to get from raw hex to a simple C compiler (M2-Planet).  The build is
;;; driven by a kaem script that chains each tool:
;;;
;;;   hex0 (from seeds) assembles hex1 source
;;;   hex1 assembles hex2 source
;;;   hex2 assembles M0 source
;;;   M0 assembles M1 source
;;;   M1 + hex2 assemble M2-Planet (a simple C-subset compiler)
;;;   M2-Planet + M1 + hex2 build kaem (the shell/script runner)
;;;
;;; Each step produces a tool that is strictly more capable than the last,
;;; but each is built using ONLY tools from previous steps.

(define-public andyl-mescc-tools
  (package
    (name "andyl-mescc-tools")
    (version (config-version "bootstrap" "mescc-tools"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/oriansj/mescc-tools"
                    "/archive/refs/tags/Release_" version ".tar.gz"))
              (sha256
               ;; TODO: Compute actual hash:
               ;;   guix download <url>
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system trivial-build-system)
    (native-inputs
     (list andyl-bootstrap-seeds))
    (arguments
     (list
      #:modules '((guix build utils))
      #:builder
      #~(begin
          (use-modules (guix build utils))
          (let* ((out     (assoc-ref %outputs "out"))
                 (bindir  (string-append out "/bin"))
                 (seeds   (assoc-ref %build-inputs "andyl-bootstrap-seeds"))
                 (source  (assoc-ref %build-inputs "source")))
            (mkdir-p bindir)

            ;; The mescc-tools build is driven by kaem.run scripts that
            ;; chain each assembler stage.  The exact sequence is:
            ;;
            ;; 1. hex0 (seed) reads hex1_x86.hex0 -> produces hex1
            ;; 2. hex1 reads hex2_x86.hex1 -> produces hex2
            ;; 3. hex2 reads M0_x86.hex2 -> produces M0
            ;; 4. M0 reads M1_x86.M0 -> produces M1
            ;; 5. M1 + hex2 read M2-Planet sources -> produces M2-Planet
            ;; 6. M2-Planet compiles kaem.c -> kaem
            ;;
            ;; In the actual build, these steps are executed via the
            ;; kaem-optional-seed from bootstrap-seeds, which reads
            ;; the kaem.run build script.
            ;;
            ;; TODO: Implement the actual build steps.  For now this is
            ;; a structural placeholder that establishes the package
            ;; dependency chain correctly.

            ;; Copy source tree for later stages to reference
            (let ((sharedir (string-append out "/share/mescc-tools")))
              (mkdir-p sharedir)
              (copy-recursively source sharedir))

            ;; Placeholder: the built tools (hex2, M0, M1, M2-Planet, kaem)
            ;; would be installed to bindir by the kaem.run script.
            #t))))
    (home-page "https://github.com/oriansj/mescc-tools")
    (synopsis "Bootstrap tools: hex assemblers, M1 macro assembler, M2-Planet")
    (description
     "MesCC-tools provides the chain of assemblers built from the hex0
bootstrap seed.  Starting from hex0 (~357 bytes), it builds progressively
more capable tools: hex1 (labels), hex2 (absolute addresses), M0 (simple
macro assembler), M1 (full macro assembler), and M2-Planet (a simple C
compiler).  Each tool is built using only previously-built tools.")
    (license license:gpl3+)))


;;; =========================================================================
;;; Stage 1 (continued): MesCC-Tools Extra
;;; =========================================================================
;;;
;;; Additional tools built with M2-Planet that are needed for later stages.
;;; This includes an enhanced M2-Planet with additional C language support
;;; and helper utilities.

(define-public andyl-mescc-tools-extra
  (package
    (name "andyl-mescc-tools-extra")
    (version (config-version "bootstrap" "mescc-tools"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/oriansj/mescc-tools-extra"
                    "/archive/refs/tags/Release_" version ".tar.gz"))
              (sha256
               ;; TODO: Compute actual hash:
               ;;   guix download <url>
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system trivial-build-system)
    (native-inputs
     (list andyl-mescc-tools))
    (arguments
     (list
      #:modules '((guix build utils))
      #:builder
      #~(begin
          (use-modules (guix build utils))
          (let* ((out    (assoc-ref %outputs "out"))
                 (bindir (string-append out "/bin"))
                 (tools  (assoc-ref %build-inputs "andyl-mescc-tools"))
                 (source (assoc-ref %build-inputs "source")))
            (mkdir-p bindir)

            ;; M2-Planet (from mescc-tools) compiles additional helper
            ;; utilities needed for later bootstrap stages:
            ;; - cp, chmod, mkdir, untar, ungz
            ;; - catm (concatenate files)
            ;; - match, sha256sum
            ;;
            ;; These are minimal POSIX-like utilities compiled with
            ;; M2-Planet, sufficient to unpack and build GNU Mes.
            ;;
            ;; TODO: Implement actual M2-Planet compilation steps.

            (let ((sharedir (string-append out "/share/mescc-tools-extra")))
              (mkdir-p sharedir)
              (copy-recursively source sharedir))

            #t))))
    (home-page "https://github.com/oriansj/mescc-tools-extra")
    (synopsis "Additional bootstrap utilities built with M2-Planet")
    (description
     "Extra utilities compiled with M2-Planet for use in early bootstrap
stages.  Includes minimal implementations of cp, chmod, mkdir, untar,
and other tools needed to unpack and build GNU Mes.")
    (license license:gpl3+)))


;;; =========================================================================
;;; Stage 2: GNU Mes (Scheme Interpreter + MesCC C Compiler)
;;; =========================================================================
;;;
;;; GNU Mes (Maxwell Equations of Software) is a Scheme interpreter written
;;; in C and a C compiler (MesCC) written in Scheme.  These two programs
;;; are mutually self-hosting: the Scheme interpreter can run the C compiler,
;;; and the C compiler can compile the Scheme interpreter.
;;;
;;; In the bootstrap chain, M2-Planet compiles mes.c (a subset of C) to
;;; produce the Mes Scheme interpreter.  This interpreter then runs MesCC
;;; (the Scheme-based C compiler), which can compile a much larger subset
;;; of C -- enough to build TinyCC.
;;;
;;; This is the critical bridge from "toy" tools to "real" compilers.

(define-public andyl-mes
  (package
    (name "andyl-mes")
    (version (config-version "bootstrap" "mes"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://ftp.gnu.org/gnu/mes/mes-" version ".tar.gz"))
              (sha256
               ;; TODO: Compute actual hash:
               ;;   guix download https://ftp.gnu.org/gnu/mes/mes-0.27.tar.gz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system trivial-build-system)
    (native-inputs
     (list andyl-mescc-tools
           andyl-mescc-tools-extra))
    (arguments
     (list
      #:modules '((guix build utils))
      #:builder
      #~(begin
          (use-modules (guix build utils))
          (let* ((out    (assoc-ref %outputs "out"))
                 (bindir (string-append out "/bin"))
                 (libdir (string-append out "/lib"))
                 (tools  (assoc-ref %build-inputs "andyl-mescc-tools"))
                 (extra  (assoc-ref %build-inputs "andyl-mescc-tools-extra"))
                 (source (assoc-ref %build-inputs "source")))
            (mkdir-p bindir)
            (mkdir-p libdir)

            ;; Build sequence:
            ;; 1. M2-Planet (from mescc-tools) compiles mes.c
            ;;    - mes.c is written in the C subset that M2-Planet supports
            ;;    - The resulting binary is the Mes Scheme interpreter
            ;;
            ;; 2. The Mes interpreter loads MesCC (lib/mes/mescc.scm)
            ;;    - MesCC is a C compiler written in Scheme
            ;;    - It can compile a larger subset of C than M2-Planet
            ;;    - This is what we use to compile TinyCC
            ;;
            ;; 3. Install mes binary, mescc script, and Scheme/C libraries
            ;;
            ;; Key outputs:
            ;;   bin/mes     - The Scheme interpreter
            ;;   bin/mescc   - The C compiler (Scheme script run by mes)
            ;;   lib/        - Mes C library (libc subset) and Scheme modules
            ;;
            ;; TODO: Implement actual M2-Planet -> mes build steps.

            (let ((sharedir (string-append out "/share/mes")))
              (mkdir-p sharedir)
              (copy-recursively source sharedir))

            #t))))
    (home-page "https://www.gnu.org/software/mes/")
    (synopsis "GNU Mes -- Scheme interpreter and MesCC C compiler")
    (description
     "GNU Mes provides a Scheme interpreter (mes) and a C compiler (mescc)
that are mutually self-hosting.  In the bootstrap chain, M2-Planet compiles
the Mes interpreter from C source, and then Mes runs MesCC to compile
TinyCC.  This is the bridge from simple assembler-level tools to a real
C compiler.")
    (license license:gpl3+)))


;;; =========================================================================
;;; Stage 2 (continued): TinyCC from MesCC
;;; =========================================================================
;;;
;;; TinyCC (tcc) is a small, fast C compiler.  In the bootstrap chain,
;;; MesCC (the Scheme-based C compiler from GNU Mes) compiles TinyCC.
;;; The resulting TinyCC can compile much larger C programs than MesCC
;;; can, including GCC itself (with patches).
;;;
;;; This TinyCC is intentionally an older version (0.9.27) because:
;;; 1. It has been proven to be compilable by MesCC
;;; 2. It can compile GCC 4.6.4 (with patches for TinyCC compatibility)
;;; 3. Later TinyCC versions have features that MesCC cannot compile

(define-public andyl-tinycc-mescc
  (package
    (name "andyl-tinycc-mescc")
    (version (config-version "bootstrap" "tinycc"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://download.savannah.gnu.org/releases/tinycc/tcc-"
                    version ".tar.bz2"))
              (sha256
               ;; TODO: Compute actual hash:
               ;;   guix download https://download.savannah.gnu.org/releases/tinycc/tcc-0.9.27.tar.bz2
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system trivial-build-system)
    (native-inputs
     (list andyl-mes
           andyl-mescc-tools))
    (arguments
     (list
      #:modules '((guix build utils))
      #:builder
      #~(begin
          (use-modules (guix build utils))
          (let* ((out    (assoc-ref %outputs "out"))
                 (bindir (string-append out "/bin"))
                 (libdir (string-append out "/lib"))
                 (mes    (assoc-ref %build-inputs "andyl-mes"))
                 (tools  (assoc-ref %build-inputs "andyl-mescc-tools"))
                 (source (assoc-ref %build-inputs "source")))
            (mkdir-p bindir)
            (mkdir-p libdir)

            ;; Build sequence:
            ;; 1. mescc (from GNU Mes) compiles tcc.c
            ;;    - mescc supports enough C to compile TinyCC 0.9.27
            ;;    - The compilation is slow (mescc is interpreted Scheme)
            ;;    - But the output is a functional C compiler
            ;;
            ;; 2. The resulting tcc can:
            ;;    - Compile standard C89/C99 code
            ;;    - Link against the Mes C library (initially)
            ;;    - Compile GCC 4.6.4 (with bootstrap patches)
            ;;
            ;; 3. A second pass may be done: tcc compiles itself
            ;;    (self-hosting verification)
            ;;
            ;; Key outputs:
            ;;   bin/tcc       - The TinyCC compiler
            ;;   lib/libtcc.a  - TinyCC as a library (optional)
            ;;   lib/tcc/      - TinyCC runtime and headers
            ;;
            ;; TODO: Implement actual mescc -> tcc build steps.

            #t))))
    (home-page "https://bellard.org/tcc/")
    (synopsis "TinyCC bootstrapped from MesCC")
    (description
     "A bootstrap TinyCC compiled using GNU Mes's C compiler (MesCC).
TinyCC is a small, fast C compiler that serves as the bridge from the
Mes/MesCC world to GCC.  This version (0.9.27) is specifically chosen
because it can be compiled by MesCC and can in turn compile GCC 4.6.4.")
    (license license:lgpl2.1+)))


;;; =========================================================================
;;; Stage 3 (prerequisite): Bootstrap glibc
;;; =========================================================================
;;;
;;; A minimal glibc (or musl libc) that provides just enough C library
;;; functionality for GCC 4.6.4 to compile.  This is NOT the production
;;; glibc -- that comes later in glibc.scm, built with the final GCC.
;;;
;;; In the upstream Guix bootstrap, this role is filled by glibc-mesboot,
;;; a carefully patched glibc built with the bootstrap TinyCC/GCC chain.

(define-public andyl-bootstrap-glibc
  (package
    (name "andyl-bootstrap-glibc")
    (version (config-version "bootstrap" "bootstrap-glibc"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "mirror://gnu/glibc/glibc-" version ".tar.xz"))
              (sha256
               ;; TODO: Compute actual hash:
               ;;   guix download mirror://gnu/glibc/glibc-2.16.0.tar.xz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system trivial-build-system)
    (native-inputs
     (list andyl-tinycc-mescc
           andyl-mescc-tools))
    (arguments
     (list
      #:modules '((guix build utils))
      #:builder
      #~(begin
          (use-modules (guix build utils))
          (let* ((out     (assoc-ref %outputs "out"))
                 (libdir  (string-append out "/lib"))
                 (incdir  (string-append out "/include"))
                 (tcc     (assoc-ref %build-inputs "andyl-tinycc-mescc"))
                 (tools   (assoc-ref %build-inputs "andyl-mescc-tools"))
                 (source  (assoc-ref %build-inputs "source")))
            (mkdir-p libdir)
            (mkdir-p incdir)

            ;; Build a minimal glibc with TinyCC.
            ;;
            ;; This is a stripped-down glibc providing:
            ;;   - crt0.o, crt1.o, crti.o, crtn.o  (C runtime startup)
            ;;   - libc.a / libc.so                  (core C library)
            ;;   - libm.a                            (math library stubs)
            ;;   - Standard C headers (stdio.h, stdlib.h, string.h, etc.)
            ;;
            ;; This glibc is NOT suitable for production use.  It exists
            ;; solely to provide the C runtime that GCC 4.6.4 needs to
            ;; compile and link programs.
            ;;
            ;; The upstream Guix commencement module uses glibc 2.16.0 for
            ;; this purpose because it is old enough to compile with the
            ;; limited bootstrap toolchain.
            ;;
            ;; TODO: Implement actual bootstrap glibc build steps.

            #t))))
    (home-page "https://www.gnu.org/software/libc/")
    (synopsis "Minimal bootstrap glibc for early GCC compilation")
    (description
     "A minimal GNU C Library built with the bootstrap TinyCC compiler.
This provides just enough C runtime (startup files, libc, headers) for
GCC 4.6.4 to compile and link programs.  This is NOT the production
glibc; the final glibc is built later with the modern GCC.")
    (license license:lgpl2.1+)))


;;; =========================================================================
;;; Stage 3: GCC 4.6.4 from TinyCC
;;; =========================================================================
;;;
;;; GCC 4.6.4 is the first "real" compiler in the bootstrap chain.  It is
;;; compiled by TinyCC (which was compiled by MesCC, which was compiled by
;;; M2-Planet, which was assembled by hex0).
;;;
;;; This GCC is intentionally an old version because:
;;; 1. GCC 4.6.4 is written in C (not C++), so TinyCC can compile it
;;; 2. It produces correct enough code to compile modern GCC
;;; 3. It is the same version used by upstream Guix's bootstrap chain
;;;
;;; This GCC is C-only: no C++, no Fortran, no other languages.
;;; C++ support comes with GCC 7.5.0 in the next stage.

(define-public andyl-gcc-core-mesboot
  (package
    (name "andyl-gcc-core-mesboot")
    (version (config-version "bootstrap" "gcc-464"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "mirror://gnu/gcc/gcc-" version
                    "/gcc-core-" version ".tar.gz"))
              (sha256
               ;; TODO: Compute actual hash:
               ;;   guix download mirror://gnu/gcc/gcc-4.6.4/gcc-core-4.6.4.tar.gz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system trivial-build-system)
    (native-inputs
     (list andyl-tinycc-mescc
           andyl-mescc-tools
           andyl-bootstrap-glibc))
    (arguments
     (list
      #:modules '((guix build utils))
      #:builder
      #~(begin
          (use-modules (guix build utils))
          (let* ((out     (assoc-ref %outputs "out"))
                 (bindir  (string-append out "/bin"))
                 (libdir  (string-append out "/lib"))
                 (incdir  (string-append out "/include"))
                 (tcc     (assoc-ref %build-inputs "andyl-tinycc-mescc"))
                 (tools   (assoc-ref %build-inputs "andyl-mescc-tools"))
                 (glibc   (assoc-ref %build-inputs "andyl-bootstrap-glibc"))
                 (source  (assoc-ref %build-inputs "source")))
            (mkdir-p bindir)
            (mkdir-p libdir)

            ;; Build sequence:
            ;;
            ;; 1. Configure GCC 4.6.4 with minimal options:
            ;;    --enable-languages=c      (C only, no C++)
            ;;    --disable-bootstrap       (we are the bootstrap)
            ;;    --disable-multilib        (x86_64 only)
            ;;    --disable-shared          (static linking for bootstrap)
            ;;    --disable-libmudflap
            ;;    --disable-libssp
            ;;    --disable-libgomp
            ;;    --disable-decimal-float
            ;;    --disable-threads
            ;;    --disable-libquadmath
            ;;    --with-native-system-header-dir=<bootstrap-glibc>/include
            ;;
            ;; 2. TinyCC compiles GCC's C source files.
            ;;    This requires patches to work around TinyCC limitations:
            ;;    - TinyCC doesn't support all GNU C extensions
            ;;    - Some inline assembly needs adjustment
            ;;    - The Guix commencement module includes these patches
            ;;
            ;; 3. The resulting gcc can compile C programs and link them
            ;;    against the bootstrap glibc.
            ;;
            ;; Key outputs:
            ;;   bin/gcc       - The GCC 4.6.4 C compiler
            ;;   bin/cpp       - The C preprocessor
            ;;   lib/          - GCC support libraries (libgcc.a, etc.)
            ;;
            ;; This GCC can compile GCC 7.5.0 (which adds C++ support).
            ;;
            ;; TODO: Implement actual TinyCC -> GCC build steps.
            ;; Study (gnu packages commencement) gcc-core-mesboot for
            ;; the exact configure flags and patches needed.

            #t))))
    (home-page "https://gcc.gnu.org/")
    (synopsis "GCC 4.6.4 bootstrapped from TinyCC (C only)")
    (description
     "GCC 4.6.4 compiled using bootstrap TinyCC.  This is a minimal C-only
GCC (no C++, no Fortran) that serves as the stepping stone to modern GCC.
It is the first compiler in the chain that produces high-quality optimized
code.  The full provenance chain: hex0 -> mescc-tools -> Mes -> MesCC ->
TinyCC -> this GCC.")
    (license license:gpl3+)))


;;; =========================================================================
;;; Stage 4: GCC 7.5.0 (Intermediate GCC with C++ support)
;;; =========================================================================
;;;
;;; GCC 7.5.0 is built by GCC 4.6.4.  This is significant because:
;;; 1. GCC 7.x is written in C++ (GCC switched from C to C++ in version 4.8)
;;; 2. GCC 4.6.4 compiles the C++ parts of GCC 7.x
;;; 3. GCC 7.5.0 can compile modern GCC (13.x)
;;;
;;; This is the first compiler in the chain with C++ support, which is
;;; required for all subsequent GCC versions and many modern packages.
;;;
;;; Unlike earlier stages, this package uses gnu-build-system because by
;;; this point we have enough of a toolchain (GCC 4.6.4 + bootstrap glibc
;;; + mescc-tools) to run a standard ./configure && make && make install.

(define-public andyl-gcc-mesboot
  (package
    (name "andyl-gcc-mesboot")
    (version (config-version "bootstrap" "gcc-750"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "mirror://gnu/gcc/gcc-" version
                    "/gcc-" version ".tar.xz"))
              (sha256
               ;; TODO: Compute actual hash:
               ;;   guix download mirror://gnu/gcc/gcc-7.5.0/gcc-7.5.0.tar.xz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system gnu-build-system)
    (native-inputs
     (list andyl-gcc-core-mesboot
           andyl-mescc-tools
           andyl-bootstrap-glibc))
    (arguments
     (list
      #:configure-flags
      #~(list
         ;; Enable both C and C++ -- this is the first compiler with C++
         "--enable-languages=c,c++"

         ;; No multilib (x86_64 only)
         "--disable-multilib"

         ;; We performed our own bootstrap chain; don't do GCC's internal
         ;; 3-stage bootstrap
         "--disable-bootstrap"

         ;; Disable optional features not needed at this stage
         "--disable-libsanitizer"
         "--disable-libvtv"
         "--disable-libcilkrts"

         ;; Use the bootstrap glibc headers
         (string-append "--with-native-system-header-dir="
                        #$(this-package-native-input "andyl-bootstrap-glibc")
                        "/include"))

      ;; Modify standard build phases as needed for the bootstrap
      ;; environment
      #:phases
      #~(modify-phases %standard-phases
          (add-before 'configure 'set-paths
            (lambda* (#:key native-inputs #:allow-other-keys)
              ;; Ensure the bootstrap GCC 4.6.4 is on PATH
              (let ((gcc4 (assoc-ref native-inputs
                                     "andyl-gcc-core-mesboot")))
                (when gcc4
                  (setenv "CC" (string-append gcc4 "/bin/gcc"))
                  (setenv "CXX" (string-append gcc4 "/bin/gcc"))))))

          ;; GCC 7.x tests require a more complete environment than we
          ;; have at this bootstrap stage
          (delete 'check))

      ;; Skip tests -- we verify by compiling the next stage
      #:tests? #f))
    (home-page "https://gcc.gnu.org/")
    (synopsis "GCC 7.5.0 with C and C++ support (intermediate bootstrap)")
    (description
     "GCC 7.5.0 compiled by bootstrap GCC 4.6.4.  This is the first compiler
in the ANDYL OS bootstrap chain with C++ support.  It serves as the
intermediate step between the minimal C-only GCC 4.6.4 and the production
GCC 13.x.  The full provenance chain: hex0 -> mescc-tools -> Mes -> MesCC
-> TinyCC -> GCC 4.6.4 -> this GCC 7.5.0.")
    (license license:gpl3+)))
