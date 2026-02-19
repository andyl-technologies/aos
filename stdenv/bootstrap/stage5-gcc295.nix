# stdenv/bootstrap/stage5-gcc295.nix — GCC 2.95.3 (C only) from TCC (Mes libc)
#
# First GCC in the bootstrap chain. Built with TCC as CC, using binutils
# from stage 4 for as/ld. C only — no libgcc (next GCC will build its own).
# Linked against Mes libc (static). This GCC will build glibc 2.2.5.
#
# GCC 2.95.3 is the Guix-proven first-GCC-from-TCC target. Its real.c is
# simpler than 3.4.6+, avoiding TCC code-gen bugs in FP emulation.
#
# Builder: kaem (from mescc-tools, stage 1). No /bin/sh, no configure.
# Per-directory manual build: libiberty → gcc.
# cc1 path: lib/gcc-lib/target/2.95.3/ (2.95.x convention, not libexec/gcc/).
#
{
  tinycc, # Output of stage3-tinycc.nix (TCC with Mes libc)
  binutils, # Output of stage4-binutils220.nix
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
    name = "gcc-core-2.95.3.tar.gz";
    url = "https://mirrors.kernel.org/gnu/gcc/gcc-2.95.3/gcc-core-2.95.3.tar.gz";
    hash = "sha256-VoEe5gmQtGYNVMKmb14CU6SH4zDuU7SZ2KVliC/xbvc=";
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
  '';

  # Pre-generated config.h for gcc directory
  gcc-config-h = builtins.toFile "gcc-config.h" ''
    #define HAVE_STDLIB_H 1
    #define HAVE_STRING_H 1
    #define HAVE_UNISTD_H 1
    #define HAVE_SYS_STAT_H 1
    #define HAVE_SYS_TYPES_H 1
    #define HAVE_FCNTL_H 1
    #define HAVE_LIMITS_H 1
    #define HAVE_ERRNO_H 1
    #define HAVE_TIME_H 1
    #define HAVE_SYS_TIME_H 1
    #define STDC_HEADERS 1
    #define HOST_BITS_PER_CHAR 8
    #define HOST_BITS_PER_SHORT 16
    #define HOST_BITS_PER_INT 32
    #define HOST_BITS_PER_LONG 32
    #define HOST_BITS_PER_LONGLONG 64
    #define BITS_PER_UNIT 8
    #define BITS_PER_WORD 32
    #define HOST_FLOAT_FORMAT IEEE_FLOAT_FORMAT
    #define TARGET_FLOAT_FORMAT IEEE_FLOAT_FORMAT
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
    #define LOCAL_INCLUDE_DIR "/usr/local/include"
    #define SYSTEM_INCLUDE_DIR ""
  '';

  # Pre-generated hconfig.h (host config)
  hconfig-h = builtins.toFile "gcc-hconfig.h" ''
    #include "config.h"
  '';

  # Pre-generated tconfig.h (target config)
  tconfig-h = builtins.toFile "gcc-tconfig.h" ''
    /* Target configuration for i386-linux */
    #ifndef GCC_TCONFIG_H
    #define GCC_TCONFIG_H
    #include "i386/xm-i386.h"
    #endif
  '';

  # Pre-generated tm.h (target machine)
  tm-h = builtins.toFile "gcc-tm.h" ''
    #include "i386/i386.h"
    #include "i386/att.h"
    #include "svr4.h"
    #include "i386/linux.h"
    #include "linux.h"
    #include "dbxelf.h"
    #include "elfos.h"
    #include "i386/linux-oldld.h"
    #include "defaults.h"
  '';

  # GCC wrapper script (pre-generated, no heredoc needed)
  gcc-wrapper = builtins.toFile "gcc-wrapper" ''
    #!/bin/sh
    exec "REAL" \
      -B"GCCLIB/" \
      -B"BINUTILS/bin/" \
      "$@"
  '';

in
  builtins.derivation {
    name = "gcc-2.95.3";
    inherit system;
    builder = "/bin/sh";
    args = ["-c" ''exec ${mescc-tools}/bin/kaem --verbose --strict --file "$buildScriptPath"''];
    passAsFile = ["buildScript"];
    buildScript = ''
      set -e
      TOOLS=${mescc-tools}/bin
      CC=${tinycc}/bin/tcc
      AR=${tinycc}/bin/tcc

      cd ''${TMPDIR}
      ''${TOOLS}/ungz --file ${gcc-src} --output ''${TMPDIR}/gcc.tar
      ''${TOOLS}/untar --file ''${TMPDIR}/gcc.tar

      SRC=''${TMPDIR}/gcc-2.95.3
      BUILD=''${TMPDIR}/build

      ''${TOOLS}/mkdir ''${BUILD}

      # ── Create output directories ────────────────────────────────────────
      GCCLIB=''${out}/lib/gcc-lib/${target}/2.95.3
      ''${TOOLS}/mkdir ''${out}
      ''${TOOLS}/mkdir ''${out}/bin
      ''${TOOLS}/mkdir ''${out}/lib
      ''${TOOLS}/mkdir ''${out}/lib/gcc-lib
      ''${TOOLS}/mkdir ''${out}/lib/gcc-lib/${target}
      ''${TOOLS}/mkdir ''${out}/lib/gcc-lib/${target}/2.95.3
      ''${TOOLS}/mkdir ''${GCCLIB}/include

      # ── Install pre-generated config headers ─────────────────────────────
      ''${TOOLS}/cp ${libiberty-config-h} ''${SRC}/libiberty/config.h
      ''${TOOLS}/cp ${gcc-config-h} ''${SRC}/gcc/config.h
      ''${TOOLS}/cp ${gcc-config-h} ''${SRC}/gcc/auto-host.h
      ''${TOOLS}/cp ${hconfig-h} ''${SRC}/gcc/hconfig.h
      ''${TOOLS}/cp ${tconfig-h} ''${SRC}/gcc/tconfig.h

      # ── Patches ──────────────────────────────────────────────────────────
      # Use standard alloca instead of libiberty's C_alloca
      ''${TOOLS}/replace --file ''${SRC}/libiberty/alloca.c --output ''${SRC}/libiberty/alloca.c --match-on "C_alloca" --replace-with "alloca"
      ''${TOOLS}/replace --file ''${SRC}/include/libiberty.h --output ''${SRC}/include/libiberty.h --match-on "C_alloca" --replace-with "alloca"

      # ══════════════════════════════════════════════════════════════════════
      # MANUAL BUILD: libiberty
      # ══════════════════════════════════════════════════════════════════════
      cd ''${SRC}/libiberty
      echo "==> Building libiberty"

      ''${CC} -c -D_GNU_SOURCE -DHAVE_CONFIG_H -I. -I../include alloca.c
      ''${CC} -c -D_GNU_SOURCE -DHAVE_CONFIG_H -I. -I../include argv.c
      ''${CC} -c -D_GNU_SOURCE -DHAVE_CONFIG_H -I. -I../include choose-temp.c
      ''${CC} -c -D_GNU_SOURCE -DHAVE_CONFIG_H -I. -I../include concat.c
      ''${CC} -c -D_GNU_SOURCE -DHAVE_CONFIG_H -I. -I../include cplus-dem.c
      ''${CC} -c -D_GNU_SOURCE -DHAVE_CONFIG_H -I. -I../include getopt.c
      ''${CC} -c -D_GNU_SOURCE -DHAVE_CONFIG_H -I. -I../include getopt1.c
      ''${CC} -c -D_GNU_SOURCE -DHAVE_CONFIG_H -I. -I../include getpwd.c
      ''${CC} -c -D_GNU_SOURCE -DHAVE_CONFIG_H -I. -I../include getruntime.c
      ''${CC} -c -D_GNU_SOURCE -DHAVE_CONFIG_H -I. -I../include hashtab.c
      ''${CC} -c -D_GNU_SOURCE -DHAVE_CONFIG_H -I. -I../include hex.c
      ''${CC} -c -D_GNU_SOURCE -DHAVE_CONFIG_H -I. -I../include lbasename.c
      ''${CC} -c -D_GNU_SOURCE -DHAVE_CONFIG_H -I. -I../include make-temp-file.c
      ''${CC} -c -D_GNU_SOURCE -DHAVE_CONFIG_H -I. -I../include objalloc.c
      ''${CC} -c -D_GNU_SOURCE -DHAVE_CONFIG_H -I. -I../include obstack.c
      ''${CC} -c -D_GNU_SOURCE -DHAVE_CONFIG_H -I. -I../include partition.c
      ''${CC} -c -D_GNU_SOURCE -DHAVE_CONFIG_H -I. -I../include pexecute.c
      ''${CC} -c -D_GNU_SOURCE -DHAVE_CONFIG_H -I. -I../include safe-ctype.c
      ''${CC} -c -D_GNU_SOURCE -DHAVE_CONFIG_H -I. -I../include sort.c
      ''${CC} -c -D_GNU_SOURCE -DHAVE_CONFIG_H -I. -I../include splay-tree.c
      ''${CC} -c -D_GNU_SOURCE -DHAVE_CONFIG_H -I. -I../include xatexit.c
      ''${CC} -c -D_GNU_SOURCE -DHAVE_CONFIG_H -I. -I../include xexit.c
      ''${CC} -c -D_GNU_SOURCE -DHAVE_CONFIG_H -I. -I../include xmalloc.c
      ''${CC} -c -D_GNU_SOURCE -DHAVE_CONFIG_H -I. -I../include xmemdup.c
      ''${CC} -c -D_GNU_SOURCE -DHAVE_CONFIG_H -I. -I../include xstrdup.c
      ''${CC} -c -D_GNU_SOURCE -DHAVE_CONFIG_H -I. -I../include xstrerror.c

      ''${AR} -ar cr libiberty.a alloca.o argv.o choose-temp.o concat.o cplus-dem.o getopt.o getopt1.o getpwd.o getruntime.o hashtab.o hex.o lbasename.o make-temp-file.o objalloc.o obstack.o partition.o pexecute.o safe-ctype.o sort.o splay-tree.o xatexit.o xexit.o xmalloc.o xmemdup.o xstrdup.o xstrerror.o

      echo "==> libiberty.a built"

      # ══════════════════════════════════════════════════════════════════════
      # MANUAL BUILD: gcc (cc1, cpp0, xgcc)
      # ══════════════════════════════════════════════════════════════════════
      cd ''${SRC}/gcc
      echo "==> Building gcc"

      GCCI="-D_GNU_SOURCE -DHAVE_CONFIG_H -DIN_GCC -I. -Iconfig -I../include -static -D__GLIBC_MINOR__=6"

      # Core compiler files
      ''${CC} -c ''${GCCI} toplev.c
      ''${CC} -c ''${GCCI} version.c
      ''${CC} -c ''${GCCI} tree.c
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
      ''${CC} -c ''${GCCI} dwarfout.c
      ''${CC} -c ''${GCCI} dwarf2out.c
      ''${CC} -c ''${GCCI} xcoffout.c
      ''${CC} -c ''${GCCI} bitmap.c
      ''${CC} -c ''${GCCI} integrate.c
      ''${CC} -c ''${GCCI} jump.c
      ''${CC} -c ''${GCCI} cse.c
      ''${CC} -c ''${GCCI} loop.c
      ''${CC} -c ''${GCCI} unroll.c
      ''${CC} -c ''${GCCI} flow.c
      ''${CC} -c ''${GCCI} stupid.c
      ''${CC} -c ''${GCCI} combine.c
      ''${CC} -c ''${GCCI} regclass.c
      ''${CC} -c ''${GCCI} local-alloc.c
      ''${CC} -c ''${GCCI} global.c
      ''${CC} -c ''${GCCI} reload.c
      ''${CC} -c ''${GCCI} reload1.c
      ''${CC} -c ''${GCCI} caller-save.c
      ''${CC} -c ''${GCCI} insn-peep.c
      ''${CC} -c ''${GCCI} reorg.c
      ''${CC} -c ''${GCCI} sched.c
      ''${CC} -c ''${GCCI} final.c
      ''${CC} -c ''${GCCI} recog.c
      ''${CC} -c ''${GCCI} reg-stack.c
      ''${CC} -c ''${GCCI} insn-opinit.c
      ''${CC} -c ''${GCCI} insn-recog.c
      ''${CC} -c ''${GCCI} insn-extract.c
      ''${CC} -c ''${GCCI} insn-output.c
      ''${CC} -c ''${GCCI} insn-emit.c
      ''${CC} -c ''${GCCI} insn-attrtab.c
      ''${CC} -c ''${GCCI} profile.c
      ''${CC} -c ''${GCCI} convert.c
      ''${CC} -c ''${GCCI} alias.c
      ''${CC} -c ''${GCCI} gcse.c
      ''${CC} -c ''${GCCI} obstack.c
      ''${CC} -c ''${GCCI} getpwd.c
      ''${CC} -c ''${GCCI} prefix.c
      ''${CC} -c ''${GCCI} tlink.c
      ''${CC} -c ''${GCCI} mkdeps.c
      ''${CC} -c ''${GCCI} hash.c
      ''${CC} -c ''${GCCI} genrtl.c
      ''${CC} -c ''${GCCI} except.c
      ''${CC} -c ''${GCCI} graph.c
      ''${CC} -c ''${GCCI} haifa-sched.c
      ''${CC} -c ''${GCCI} regmove.c
      ''${CC} -c ''${GCCI} lcm.c
      ''${CC} -c ''${GCCI} ggc-none.c
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
      ''${CC} -c ''${GCCI} c-iterate.c

      # Link cc1
      echo "==> Linking cc1"
      ''${CC} -static -o ''${GCCLIB}/cc1 toplev.o version.o tree.o print-tree.o stor-layout.o fold-const.o function.o stmt.o expr.o calls.o expmed.o explow.o optabs.o varasm.o rtl.o print-rtl.o rtlanal.o emit-rtl.o real.o dbxout.o sdbout.o dwarfout.o dwarf2out.o xcoffout.o bitmap.o integrate.o jump.o cse.o loop.o unroll.o flow.o stupid.o combine.o regclass.o local-alloc.o global.o reload.o reload1.o caller-save.o insn-peep.o reorg.o sched.o final.o recog.o reg-stack.o insn-opinit.o insn-recog.o insn-extract.o insn-output.o insn-emit.o insn-attrtab.o profile.o convert.o alias.o gcse.o obstack.o getpwd.o prefix.o tlink.o mkdeps.o hash.o genrtl.o except.o graph.o haifa-sched.o regmove.o lcm.o ggc-none.o i386.o c-parse.o c-lang.o c-lex.o c-pragma.o c-decl.o c-typeck.o c-convert.o c-aux-info.o c-common.o c-iterate.o ''${SRC}/libiberty/libiberty.a

      # Build xgcc (the driver)
      ''${CC} -c ''${GCCI} -DSTANDARD_EXEC_PREFIX=\"''${out}/lib/gcc-lib/\" -DSTANDARD_STARTFILE_PREFIX=\"\"  gcc.c
      ''${CC} -static -o ''${out}/bin/gcc-real gcc.o version.o obstack.o prefix.o mkdeps.o ''${SRC}/libiberty/libiberty.a

      # Build cpp0 (C preprocessor, standalone)
      ''${CC} -c ''${GCCI} cccp.c
      ''${CC} -c ''${GCCI} cexp.c
      ''${CC} -static -o ''${GCCLIB}/cpp0 cccp.o cexp.o version.o obstack.o prefix.o mkdeps.o ''${SRC}/libiberty/libiberty.a
      ''${TOOLS}/cp ''${GCCLIB}/cpp0 ''${out}/bin/cpp

      # ── Install GCC headers ──────────────────────────────────────────────
      # Install GCC's own standard headers (stddef.h, stdarg.h, varargs.h, etc.)
      ''${TOOLS}/cp ''${SRC}/gcc/ginclude/stddef.h ''${GCCLIB}/include/stddef.h
      ''${TOOLS}/cp ''${SRC}/gcc/ginclude/stdarg.h ''${GCCLIB}/include/stdarg.h
      ''${TOOLS}/cp ''${SRC}/gcc/ginclude/varargs.h ''${GCCLIB}/include/varargs.h
      ''${TOOLS}/cp ''${SRC}/gcc/ginclude/float.h ''${GCCLIB}/include/float.h
      ''${TOOLS}/cp ''${SRC}/gcc/ginclude/limits.h ''${GCCLIB}/include/limits.h
      ''${TOOLS}/cp ''${SRC}/gcc/ginclude/syslimits.h ''${GCCLIB}/include/syslimits.h
      ''${TOOLS}/cp ''${SRC}/gcc/ginclude/iso646.h ''${GCCLIB}/include/iso646.h

      # ── Create wrapper ───────────────────────────────────────────────────
      # Pre-generated wrapper with placeholders, fix with mescc-tools replace
      ''${TOOLS}/cp ${gcc-wrapper} ''${out}/bin/gcc
      ''${TOOLS}/replace --file ''${out}/bin/gcc --output ''${out}/bin/gcc --match-on "REAL" --replace-with "''${out}/bin/gcc-real"
      ''${TOOLS}/replace --file ''${out}/bin/gcc --output ''${out}/bin/gcc --match-on "GCCLIB" --replace-with "''${GCCLIB}"
      ''${TOOLS}/replace --file ''${out}/bin/gcc --output ''${out}/bin/gcc --match-on "BINUTILS" --replace-with "${binutils}"
      ''${TOOLS}/chmod ''${out}/bin/gcc

      echo "GCC 2.95.3 installed to ''${out}"
    '';
  }
  // {
    meta = {
      description = "GNU Compiler Collection, version 2.95.3";
      homepage = "https://gcc.gnu.org/";
      license = "GPL-2.0-or-later";
      platforms = ["i686-linux"];
    };
  }
