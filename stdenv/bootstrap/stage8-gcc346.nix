# stdenv/bootstrap/stage8-gcc346.nix — GCC 3.4.6 (C only, RHEL 4) from GCC 2.95.3
#
# Second GCC in the chain. Built by GCC 2.95.3 (a real optimizing compiler).
# C only — next stage adds C++ support. First GCC linked against glibc.
#
# Builder: kaem (from mescc-tools, stage 1). No /bin/sh, no configure.
# Manual per-directory build: libiberty → gcc.
#
{
  gcc295, # Output of stage5-gcc295.nix
  binutils, # Output of stage4-binutils220.nix
  glibc, # Output of stage7-glibc225.nix
  mescc-tools, # Output of stage1-mescc-tools.nix
  make382, # GNU Make 3.82 from TCC
  sed409, # GNU sed 4.0.9 from TCC
  grep24, # GNU grep 2.4 from TCC
  patch259, # GNU patch 2.5.9 from TCC

  system ? "x86_64-linux",
}: let
  fetchSrc = {
    name,
    url,
    hash,
  }:
    builtins.derivation {
      inherit name system;
      builder = "builtin:fetchurl";
      inherit url;
      outputHash = hash;
      outputHashMode = "flat";
      outputHashAlgo = "sha256";
      preferLocalBuild = true;
    };

  gcc-src = fetchSrc {
    name = "gcc-core-3.4.6.tar.bz2";
    url = "https://mirrors.kernel.org/gnu/gcc/gcc-3.4.6/gcc-core-3.4.6.tar.bz2";
    hash = "sha256-OqsXHYblpsFMud41RnoEcqfV7x1beaHfcspTP46CoTM=";
  };

  target = "i686-linux-gnu";

  # Pre-generated config.h for libiberty
  libiberty-config-h = builtins.toFile "libiberty-config.h" ''
    #define HAVE_STDLIB_H 1
    #define HAVE_STRING_H 1
    #define HAVE_UNISTD_H 1
    #define HAVE_SYS_STAT_H 1
    #define HAVE_SYS_TYPES_H 1
    #define HAVE_FCNTL_H 1
    #define HAVE_LIMITS_H 1
    #define HAVE_ERRNO_H 1
    #define HAVE_ALLOCA_H 1
    #define HAVE_SYS_WAIT_H 1
    #define HAVE_SYS_TIME_H 1
    #define HAVE_TIME_H 1
  '';

  # Pre-generated config.h and auto-host.h for gcc 3.4.6
  gcc-config-h = builtins.toFile "gcc346-config.h" ''
    #define HAVE_STDLIB_H 1
    #define HAVE_STRING_H 1
    #define HAVE_UNISTD_H 1
    #define HAVE_SYS_STAT_H 1
    #define HAVE_SYS_TYPES_H 1
    #define HAVE_FCNTL_H 1
    #define HAVE_LIMITS_H 1
    #define HAVE_ERRNO_H 1
    #define HAVE_ALLOCA_H 1
    #define HAVE_SYS_WAIT_H 1
    #define HAVE_SYS_TIME_H 1
    #define HAVE_TIME_H 1
    #define HAVE_STRSIGNAL 1
    #define STDC_HEADERS 1
    #define HOST_BITS_PER_CHAR 8
    #define HOST_BITS_PER_SHORT 16
    #define HOST_BITS_PER_INT 32
    #define HOST_BITS_PER_LONG 32
    #define HOST_BITS_PER_LONGLONG 64
    #define BITS_PER_UNIT 8
    #define BITS_PER_WORD 32
    #define HOST_FLOAT_FORMAT IEEE_FLOAT_FORMAT
    #define REAL_ARITHMETIC 1
    #define PREFIX ""
    #define STANDARD_EXEC_PREFIX ""
    #define STANDARD_STARTFILE_PREFIX ""
    #define TOOLDIR_BASE_PREFIX ""
    #define GPLUSPLUS_INCLUDE_DIR ""
    #define GCC_INCLUDE_DIR ""
    #define CROSS_INCLUDE_DIR ""
    #define TOOL_INCLUDE_DIR ""
    #define STANDARD_INCLUDE_DIR ""
    #define LOCAL_INCLUDE_DIR ""
    #define SYSTEM_INCLUDE_DIR ""
    #define ENABLE_CHECKING 0
    #define HAVE_DECL_ABORT 1
    #define HAVE_DECL_ERRNO 1
    #define HAVE_DECL_GETENV 1
    #define HAVE_DECL_MALLOC 1
    #define HAVE_DECL_REALLOC 1
    #define HAVE_DECL_FREE 1
    #define HAVE_DECL_BASENAME 0
    #define HAVE_DECL_GETOPT 0
    #define HAVE_DECL_GETWD 0
    #define HAVE_DECL_GETRLIMIT 0
    #define HAVE_DECL_SETRLIMIT 0
    #define HAVE_DECL_SBRK 0
    #define HAVE_DECL_SNPRINTF 1
    #define HAVE_DECL_STRSIGNAL 0
    #define HAVE_DECL_VSNPRINTF 1
    #define SIZEOF_INT 4
    #define SIZEOF_SHORT 2
    #define SIZEOF_LONG 4
    #define SIZEOF_LONG_LONG 8
    #define HAVE_LONG_LONG 1
    #define HAVE_CLOCK_T 1
    #define HAVE_WORKING_VFORK 1
    #define HAVE_FORK 1
    #define HAVE_VFORK 1
    #define HAVE_ATOLL 0
    #define HAVE_ATOQ 0
    #define HAVE_STRTOL 1
    #define HAVE_STRTOUL 1
    #define HAVE_PUTENV 1
    #define HAVE_SETENV 1
    #define HAVE_KILL 1
    #define HAVE_DUP2 1
    #define HAVE_POPEN 0
    #define NEED_DECLARATION_CALLOC 0
    #define NEED_DECLARATION_FREE 0
    #define NEED_DECLARATION_MALLOC 0
    #define NEED_DECLARATION_REALLOC 0
    #define NEED_DECLARATION_ENVIRON 1
    #define USED_FOR_TARGET 0
  '';

  # GCC wrapper script (pre-generated)
  gcc-wrapper = builtins.toFile "gcc346-wrapper" ''
    #!/bin/sh
    exec "REAL" \
      -B"LIBEXEC/" -B"LIBDIR/" -B"BINUTILS/bin/" \
      -B"GLIBC/lib/" -isystem "GLIBC/include" -L"GLIBC/lib" \
      -static "$@"
  '';

in
  builtins.derivation {
    name = "gcc-3.4.6";
    inherit system;
    builder = "/bin/sh";
    args = ["-c" ''exec ${mescc-tools}/bin/kaem --verbose --strict --file "$buildScriptPath"''];
    passAsFile = ["buildScript"];
    buildScript = ''
      set -e
      TOOLS=${mescc-tools}/bin
      CC=${gcc295}/bin/gcc
      AR=${binutils}/bin/ar
      RANLIB=${binutils}/bin/ranlib

      cd ''${TMPDIR}
      ''${TOOLS}/unbz2 --file ${gcc-src} --output ''${TMPDIR}/gcc.tar
      ''${TOOLS}/untar --file ''${TMPDIR}/gcc.tar

      SRC=''${TMPDIR}/gcc-3.4.6

      # Install pre-generated config headers
      ''${TOOLS}/cp ${libiberty-config-h} ''${SRC}/libiberty/config.h
      ''${TOOLS}/cp ${gcc-config-h} ''${SRC}/gcc/config.h
      ''${TOOLS}/cp ${gcc-config-h} ''${SRC}/gcc/auto-host.h

      # Create output directories
      LIBEXEC=''${out}/libexec/gcc/${target}/3.4.6
      LIBDIR=''${out}/lib/gcc/${target}/3.4.6
      ''${TOOLS}/mkdir ''${out}
      ''${TOOLS}/mkdir ''${out}/bin
      ''${TOOLS}/mkdir ''${out}/lib
      ''${TOOLS}/mkdir ''${out}/lib/gcc
      ''${TOOLS}/mkdir ''${out}/lib/gcc/${target}
      ''${TOOLS}/mkdir ''${out}/lib/gcc/${target}/3.4.6
      ''${TOOLS}/mkdir ''${LIBDIR}/include
      ''${TOOLS}/mkdir ''${out}/libexec
      ''${TOOLS}/mkdir ''${out}/libexec/gcc
      ''${TOOLS}/mkdir ''${out}/libexec/gcc/${target}
      ''${TOOLS}/mkdir ''${out}/libexec/gcc/${target}/3.4.6

      # Common flags for compilation
      CFLAGS="-O2 -I${glibc}/include -DHAVE_CONFIG_H"

      # ══════════════════════════════════════════════════════════════════════
      # MANUAL BUILD: libiberty
      # ══════════════════════════════════════════════════════════════════════
      cd ''${SRC}/libiberty
      echo "==> Building libiberty"

      ''${CC} -c ''${CFLAGS} -D_GNU_SOURCE -I. -I../include alloca.c
      ''${CC} -c ''${CFLAGS} -D_GNU_SOURCE -I. -I../include argv.c
      ''${CC} -c ''${CFLAGS} -D_GNU_SOURCE -I. -I../include choose-temp.c
      ''${CC} -c ''${CFLAGS} -D_GNU_SOURCE -I. -I../include concat.c
      ''${CC} -c ''${CFLAGS} -D_GNU_SOURCE -I. -I../include cp-demangle.c
      ''${CC} -c ''${CFLAGS} -D_GNU_SOURCE -I. -I../include cplus-dem.c
      ''${CC} -c ''${CFLAGS} -D_GNU_SOURCE -I. -I../include dyn-string.c
      ''${CC} -c ''${CFLAGS} -D_GNU_SOURCE -I. -I../include fibheap.c
      ''${CC} -c ''${CFLAGS} -D_GNU_SOURCE -I. -I../include getopt.c
      ''${CC} -c ''${CFLAGS} -D_GNU_SOURCE -I. -I../include getopt1.c
      ''${CC} -c ''${CFLAGS} -D_GNU_SOURCE -I. -I../include getpwd.c
      ''${CC} -c ''${CFLAGS} -D_GNU_SOURCE -I. -I../include getruntime.c
      ''${CC} -c ''${CFLAGS} -D_GNU_SOURCE -I. -I../include hashtab.c
      ''${CC} -c ''${CFLAGS} -D_GNU_SOURCE -I. -I../include hex.c
      ''${CC} -c ''${CFLAGS} -D_GNU_SOURCE -I. -I../include lbasename.c
      ''${CC} -c ''${CFLAGS} -D_GNU_SOURCE -I. -I../include make-temp-file.c
      ''${CC} -c ''${CFLAGS} -D_GNU_SOURCE -I. -I../include md5.c
      ''${CC} -c ''${CFLAGS} -D_GNU_SOURCE -I. -I../include objalloc.c
      ''${CC} -c ''${CFLAGS} -D_GNU_SOURCE -I. -I../include obstack.c
      ''${CC} -c ''${CFLAGS} -D_GNU_SOURCE -I. -I../include partition.c
      ''${CC} -c ''${CFLAGS} -D_GNU_SOURCE -I. -I../include pex-unix.c
      ''${CC} -c ''${CFLAGS} -D_GNU_SOURCE -I. -I../include physmem.c
      ''${CC} -c ''${CFLAGS} -D_GNU_SOURCE -I. -I../include safe-ctype.c
      ''${CC} -c ''${CFLAGS} -D_GNU_SOURCE -I. -I../include sort.c
      ''${CC} -c ''${CFLAGS} -D_GNU_SOURCE -I. -I../include splay-tree.c
      ''${CC} -c ''${CFLAGS} -D_GNU_SOURCE -I. -I../include xatexit.c
      ''${CC} -c ''${CFLAGS} -D_GNU_SOURCE -I. -I../include xexit.c
      ''${CC} -c ''${CFLAGS} -D_GNU_SOURCE -I. -I../include xmalloc.c
      ''${CC} -c ''${CFLAGS} -D_GNU_SOURCE -I. -I../include xmemdup.c
      ''${CC} -c ''${CFLAGS} -D_GNU_SOURCE -I. -I../include xstrdup.c
      ''${CC} -c ''${CFLAGS} -D_GNU_SOURCE -I. -I../include xstrerror.c
      ''${CC} -c ''${CFLAGS} -D_GNU_SOURCE -I. -I../include xstrndup.c

      ''${AR} cr libiberty.a alloca.o argv.o choose-temp.o concat.o cp-demangle.o cplus-dem.o dyn-string.o fibheap.o getopt.o getopt1.o getpwd.o getruntime.o hashtab.o hex.o lbasename.o make-temp-file.o md5.o objalloc.o obstack.o partition.o pex-unix.o physmem.o safe-ctype.o sort.o splay-tree.o xatexit.o xexit.o xmalloc.o xmemdup.o xstrdup.o xstrerror.o xstrndup.o
      ''${RANLIB} libiberty.a

      echo "==> libiberty.a built"

      # ══════════════════════════════════════════════════════════════════════
      # MANUAL BUILD: gcc 3.4.6 (cc1, xgcc, cpp)
      # ══════════════════════════════════════════════════════════════════════
      cd ''${SRC}/gcc
      echo "==> Building gcc 3.4.6"

      GCCI="-O2 -I${glibc}/include -D_GNU_SOURCE -DHAVE_CONFIG_H -DIN_GCC -I. -Iconfig -I../include -L${glibc}/lib -static"

      # Core compiler files
      ''${CC} -c ''${GCCI} toplev.c
      ''${CC} -c ''${GCCI} version.c
      ''${CC} -c ''${GCCI} tree.c
      ''${CC} -c ''${GCCI} tree-dump.c
      ''${CC} -c ''${GCCI} tree-inline.c
      ''${CC} -c ''${GCCI} print-tree.c
      ''${CC} -c ''${GCCI} stor-layout.c
      ''${CC} -c ''${GCCI} fold-const.c
      ''${CC} -c ''${GCCI} function.c
      ''${CC} -c ''${GCCI} stmt.c
      ''${CC} -c ''${GCCI} expr.c
      ''${CC} -c ''${GCCI} calls.c
      ''${CC} -c ''${GCCI} expmed.c
      ''${CC} -c ''${GCCI} explow.c
      ''${CC} -c ''${GCCI} optabs.c
      ''${CC} -c ''${GCCI} varasm.c
      ''${CC} -c ''${GCCI} rtl.c
      ''${CC} -c ''${GCCI} print-rtl.c
      ''${CC} -c ''${GCCI} rtlanal.c
      ''${CC} -c ''${GCCI} emit-rtl.c
      ''${CC} -c ''${GCCI} real.c
      ''${CC} -c ''${GCCI} dbxout.c
      ''${CC} -c ''${GCCI} sdbout.c
      ''${CC} -c ''${GCCI} dwarf2out.c
      ''${CC} -c ''${GCCI} bitmap.c
      ''${CC} -c ''${GCCI} integrate.c
      ''${CC} -c ''${GCCI} jump.c
      ''${CC} -c ''${GCCI} cse.c
      ''${CC} -c ''${GCCI} loop.c
      ''${CC} -c ''${GCCI} unroll.c
      ''${CC} -c ''${GCCI} flow.c
      ''${CC} -c ''${GCCI} combine.c
      ''${CC} -c ''${GCCI} regclass.c
      ''${CC} -c ''${GCCI} local-alloc.c
      ''${CC} -c ''${GCCI} global.c
      ''${CC} -c ''${GCCI} reload.c
      ''${CC} -c ''${GCCI} reload1.c
      ''${CC} -c ''${GCCI} caller-save.c
      ''${CC} -c ''${GCCI} reorg.c
      ''${CC} -c ''${GCCI} sched-deps.c
      ''${CC} -c ''${GCCI} sched-ebb.c
      ''${CC} -c ''${GCCI} sched-rgn.c
      ''${CC} -c ''${GCCI} sched-vis.c
      ''${CC} -c ''${GCCI} haifa-sched.c
      ''${CC} -c ''${GCCI} final.c
      ''${CC} -c ''${GCCI} recog.c
      ''${CC} -c ''${GCCI} reg-stack.c
      ''${CC} -c ''${GCCI} insn-opinit.c
      ''${CC} -c ''${GCCI} insn-recog.c
      ''${CC} -c ''${GCCI} insn-extract.c
      ''${CC} -c ''${GCCI} insn-output.c
      ''${CC} -c ''${GCCI} insn-emit.c
      ''${CC} -c ''${GCCI} insn-attrtab.c
      ''${CC} -c ''${GCCI} insn-preds.c
      ''${CC} -c ''${GCCI} insn-conditions.c
      ''${CC} -c ''${GCCI} profile.c
      ''${CC} -c ''${GCCI} convert.c
      ''${CC} -c ''${GCCI} alias.c
      ''${CC} -c ''${GCCI} gcse.c
      ''${CC} -c ''${GCCI} prefix.c
      ''${CC} -c ''${GCCI} mkdeps.c
      ''${CC} -c ''${GCCI} except.c
      ''${CC} -c ''${GCCI} graph.c
      ''${CC} -c ''${GCCI} regmove.c
      ''${CC} -c ''${GCCI} lcm.c
      ''${CC} -c ''${GCCI} ggc-page.c
      ''${CC} -c ''${GCCI} stringpool.c
      ''${CC} -c ''${GCCI} genrtl.c
      ''${CC} -c ''${GCCI} timevar.c
      ''${CC} -c ''${GCCI} diagnostic.c
      ''${CC} -c ''${GCCI} builtins.c
      ''${CC} -c ''${GCCI} cfganal.c
      ''${CC} -c ''${GCCI} cfgbuild.c
      ''${CC} -c ''${GCCI} cfgcleanup.c
      ''${CC} -c ''${GCCI} cfglayout.c
      ''${CC} -c ''${GCCI} cfgloop.c
      ''${CC} -c ''${GCCI} cfgrtl.c
      ''${CC} -c ''${GCCI} cfg.c
      ''${CC} -c ''${GCCI} conflict.c
      ''${CC} -c ''${GCCI} coverage.c
      ''${CC} -c ''${GCCI} cselib.c
      ''${CC} -c ''${GCCI} debug.c
      ''${CC} -c ''${GCCI} df.c
      ''${CC} -c ''${GCCI} dominance.c
      ''${CC} -c ''${GCCI} dwarf2asm.c
      ''${CC} -c ''${GCCI} et-forest.c
      ''${CC} -c ''${GCCI} errors.c
      ''${CC} -c ''${GCCI} hooks.c
      ''${CC} -c ''${GCCI} ifcvt.c
      ''${CC} -c ''${GCCI} langhooks.c
      ''${CC} -c ''${GCCI} lists.c
      ''${CC} -c ''${GCCI} params.c
      ''${CC} -c ''${GCCI} predict.c
      ''${CC} -c ''${GCCI} ra.c
      ''${CC} -c ''${GCCI} ra-build.c
      ''${CC} -c ''${GCCI} ra-colorize.c
      ''${CC} -c ''${GCCI} ra-debug.c
      ''${CC} -c ''${GCCI} ra-rewrite.c
      ''${CC} -c ''${GCCI} resource.c
      ''${CC} -c ''${GCCI} sibcall.c
      ''${CC} -c ''${GCCI} simplify-rtx.c
      ''${CC} -c ''${GCCI} value-prof.c
      ''${CC} -c ''${GCCI} varray.c
      ''${CC} -c ''${GCCI} web.c
      ''${CC} -c ''${GCCI} hashtable.c
      ''${CC} -c ''${GCCI} line-map.c
      ''${CC} -c ''${GCCI} i386.c

      # C front-end
      ''${CC} -c ''${GCCI} c-parse.c
      ''${CC} -c ''${GCCI} c-lang.c
      ''${CC} -c ''${GCCI} c-lex.c
      ''${CC} -c ''${GCCI} c-pragma.c
      ''${CC} -c ''${GCCI} c-decl.c
      ''${CC} -c ''${GCCI} c-typeck.c
      ''${CC} -c ''${GCCI} c-convert.c
      ''${CC} -c ''${GCCI} c-aux-info.c
      ''${CC} -c ''${GCCI} c-common.c
      ''${CC} -c ''${GCCI} c-opts.c
      ''${CC} -c ''${GCCI} c-format.c
      ''${CC} -c ''${GCCI} c-semantics.c
      ''${CC} -c ''${GCCI} c-objc-common.c
      ''${CC} -c ''${GCCI} c-cppbuiltin.c
      ''${CC} -c ''${GCCI} c-ppoutput.c
      ''${CC} -c ''${GCCI} c-incpath.c
      ''${CC} -c ''${GCCI} cpplib.c
      ''${CC} -c ''${GCCI} cpplex.c
      ''${CC} -c ''${GCCI} cppmacro.c
      ''${CC} -c ''${GCCI} cppexp.c
      ''${CC} -c ''${GCCI} cppfiles.c
      ''${CC} -c ''${GCCI} cpphash.c
      ''${CC} -c ''${GCCI} cpperror.c
      ''${CC} -c ''${GCCI} cppinit.c
      ''${CC} -c ''${GCCI} cpptrad.c
      ''${CC} -c ''${GCCI} cppspec.c
      ''${CC} -c ''${GCCI} attribs.c

      # Link cc1
      echo "==> Linking cc1"
      ''${CC} -static -L${glibc}/lib -o ''${LIBEXEC}/cc1 toplev.o version.o tree.o tree-dump.o tree-inline.o print-tree.o stor-layout.o fold-const.o function.o stmt.o expr.o calls.o expmed.o explow.o optabs.o varasm.o rtl.o print-rtl.o rtlanal.o emit-rtl.o real.o dbxout.o sdbout.o dwarf2out.o bitmap.o integrate.o jump.o cse.o loop.o unroll.o flow.o combine.o regclass.o local-alloc.o global.o reload.o reload1.o caller-save.o reorg.o sched-deps.o sched-ebb.o sched-rgn.o sched-vis.o haifa-sched.o final.o recog.o reg-stack.o insn-opinit.o insn-recog.o insn-extract.o insn-output.o insn-emit.o insn-attrtab.o insn-preds.o insn-conditions.o profile.o convert.o alias.o gcse.o prefix.o mkdeps.o except.o graph.o regmove.o lcm.o ggc-page.o stringpool.o genrtl.o timevar.o diagnostic.o builtins.o cfganal.o cfgbuild.o cfgcleanup.o cfglayout.o cfgloop.o cfgrtl.o cfg.o conflict.o coverage.o cselib.o debug.o df.o dominance.o dwarf2asm.o et-forest.o errors.o hooks.o ifcvt.o langhooks.o lists.o params.o predict.o ra.o ra-build.o ra-colorize.o ra-debug.o ra-rewrite.o resource.o sibcall.o simplify-rtx.o value-prof.o varray.o web.o hashtable.o line-map.o i386.o c-parse.o c-lang.o c-lex.o c-pragma.o c-decl.o c-typeck.o c-convert.o c-aux-info.o c-common.o c-opts.o c-format.o c-semantics.o c-objc-common.o c-cppbuiltin.o c-ppoutput.o c-incpath.o cpplib.o cpplex.o cppmacro.o cppexp.o cppfiles.o cpphash.o cpperror.o cppinit.o cpptrad.o cppspec.o attribs.o ''${SRC}/libiberty/libiberty.a

      # Build xgcc (the driver)
      ''${CC} -c ''${GCCI} -DSTANDARD_EXEC_PREFIX=\"''${out}/libexec/gcc/\" -DSTANDARD_STARTFILE_PREFIX=\"\" gcc.c
      ''${CC} -static -L${glibc}/lib -o ''${out}/bin/gcc-real gcc.o version.o diagnostic.o errors.o hashtable.o line-map.o prefix.o mkdeps.o ''${SRC}/libiberty/libiberty.a

      # Build cpp (C preprocessor, standalone)
      ''${CC} -c ''${GCCI} -DSTANDARD_EXEC_PREFIX=\"''${out}/libexec/gcc/\" cppdefault.c
      ''${CC} -c ''${GCCI} cppmain.c
      ''${CC} -static -L${glibc}/lib -o ''${out}/bin/cpp cppmain.o cpplib.o cpplex.o cppmacro.o cppexp.o cppfiles.o cpphash.o cpperror.o cppinit.o cpptrad.o cppdefault.o version.o errors.o hashtable.o line-map.o prefix.o mkdeps.o ''${SRC}/libiberty/libiberty.a

      # Install GCC's own standard headers
      ''${TOOLS}/cp ''${SRC}/gcc/ginclude/stddef.h ''${LIBDIR}/include/stddef.h
      ''${TOOLS}/cp ''${SRC}/gcc/ginclude/stdarg.h ''${LIBDIR}/include/stdarg.h
      ''${TOOLS}/cp ''${SRC}/gcc/ginclude/varargs.h ''${LIBDIR}/include/varargs.h
      ''${TOOLS}/cp ''${SRC}/gcc/ginclude/float.h ''${LIBDIR}/include/float.h
      ''${TOOLS}/cp ''${SRC}/gcc/ginclude/iso646.h ''${LIBDIR}/include/iso646.h
      ''${TOOLS}/cp ''${SRC}/gcc/glimits.h ''${LIBDIR}/include/limits.h

      # ── Build libgcc.a ───────────────────────────────────────────────────
      echo "==> Building libgcc.a"
      # Compile libgcc2.c with different defines for each required function
      # This is a minimal libgcc for the bootstrap — just enough for GCC 3.4.6
      # to compile programs that use integer division, etc.
      ''${CC} -c ''${GCCI} -I${glibc}/include -DL_muldi3 -o libgcc2-muldi3.o libgcc2.c
      ''${CC} -c ''${GCCI} -I${glibc}/include -DL_divdi3 -o libgcc2-divdi3.o libgcc2.c
      ''${CC} -c ''${GCCI} -I${glibc}/include -DL_moddi3 -o libgcc2-moddi3.o libgcc2.c
      ''${CC} -c ''${GCCI} -I${glibc}/include -DL_udivdi3 -o libgcc2-udivdi3.o libgcc2.c
      ''${CC} -c ''${GCCI} -I${glibc}/include -DL_umoddi3 -o libgcc2-umoddi3.o libgcc2.c
      ''${CC} -c ''${GCCI} -I${glibc}/include -DL_negdi2 -o libgcc2-negdi2.o libgcc2.c
      ''${CC} -c ''${GCCI} -I${glibc}/include -DL_lshrdi3 -o libgcc2-lshrdi3.o libgcc2.c
      ''${CC} -c ''${GCCI} -I${glibc}/include -DL_ashldi3 -o libgcc2-ashldi3.o libgcc2.c
      ''${CC} -c ''${GCCI} -I${glibc}/include -DL_ashrdi3 -o libgcc2-ashrdi3.o libgcc2.c
      ''${CC} -c ''${GCCI} -I${glibc}/include -DL_cmpdi2 -o libgcc2-cmpdi2.o libgcc2.c
      ''${CC} -c ''${GCCI} -I${glibc}/include -DL_ucmpdi2 -o libgcc2-ucmpdi2.o libgcc2.c
      ''${CC} -c ''${GCCI} -I${glibc}/include -DL_fixunsdfsi -o libgcc2-fixunsdfsi.o libgcc2.c
      ''${CC} -c ''${GCCI} -I${glibc}/include -DL_fixunssfsi -o libgcc2-fixunssfsi.o libgcc2.c
      ''${CC} -c ''${GCCI} -I${glibc}/include -DL_fixdfdi -o libgcc2-fixdfdi.o libgcc2.c
      ''${CC} -c ''${GCCI} -I${glibc}/include -DL_fixsfdi -o libgcc2-fixsfdi.o libgcc2.c
      ''${CC} -c ''${GCCI} -I${glibc}/include -DL_floatdidf -o libgcc2-floatdidf.o libgcc2.c
      ''${CC} -c ''${GCCI} -I${glibc}/include -DL_floatdisf -o libgcc2-floatdisf.o libgcc2.c

      ''${AR} cr ''${LIBDIR}/libgcc.a libgcc2-muldi3.o libgcc2-divdi3.o libgcc2-moddi3.o libgcc2-udivdi3.o libgcc2-umoddi3.o libgcc2-negdi2.o libgcc2-lshrdi3.o libgcc2-ashldi3.o libgcc2-ashrdi3.o libgcc2-cmpdi2.o libgcc2-ucmpdi2.o libgcc2-fixunsdfsi.o libgcc2-fixunssfsi.o libgcc2-fixdfdi.o libgcc2-fixsfdi.o libgcc2-floatdidf.o libgcc2-floatdisf.o
      ''${RANLIB} ''${LIBDIR}/libgcc.a

      echo "==> libgcc.a built"

      # ── Create wrapper ───────────────────────────────────────────────────
      ''${TOOLS}/cp ${gcc-wrapper} ''${out}/bin/gcc
      ''${TOOLS}/replace --file ''${out}/bin/gcc --output ''${out}/bin/gcc --match-on "REAL" --replace-with "''${out}/bin/gcc-real"
      ''${TOOLS}/replace --file ''${out}/bin/gcc --output ''${out}/bin/gcc --match-on "LIBEXEC" --replace-with "''${LIBEXEC}"
      ''${TOOLS}/replace --file ''${out}/bin/gcc --output ''${out}/bin/gcc --match-on "LIBDIR" --replace-with "''${LIBDIR}"
      ''${TOOLS}/replace --file ''${out}/bin/gcc --output ''${out}/bin/gcc --match-on "BINUTILS" --replace-with "${binutils}"
      ''${TOOLS}/replace --file ''${out}/bin/gcc --output ''${out}/bin/gcc --match-on "GLIBC" --replace-with "${glibc}"
      ''${TOOLS}/chmod ''${out}/bin/gcc

      echo "GCC 3.4.6 installed to ''${out}"
    '';
  }
  // {
    meta = {
      description = "GNU Compiler Collection, version 3.4.6";
      homepage = "https://gcc.gnu.org/";
      license = "GPL-3.0-or-later";
      platforms = ["i686-linux" "x86_64-linux"];
    };
  }
