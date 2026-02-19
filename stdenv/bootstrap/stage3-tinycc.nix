# stdenv/bootstrap/stage3-tinycc.nix — TinyCC compiled by MesCC
#
# TinyCC (tcc) is a small, fast C compiler that can compile itself.
# MesCC (from stage 2) compiles TinyCC 0.9.26, which then self-hosts
# through 3 boot stages, then compiles TinyCC 0.9.27.
#
# All output binaries are i386 (32-bit). Cross-compilation to x86_64
# and aarch64 happens after GCC is available.
#
# Build chain:
#   MesCC ──compile──> tcc-mes (TCC 0.9.26, very slow)
#   tcc-mes ──compile──> tcc-boot0 (adds float/bitfield/longlong/setjmp)
#   tcc-boot0 ──compile──> tcc-boot1
#   tcc-boot1 ──compile──> tcc-boot2 = tcc-0.9.26 (final)
#   tcc-0.9.26 ──compile──> tcc-0.9.27
#
# After each boot stage, the Mes C library is rebuilt with the new compiler,
# producing progressively better object code.
#
# The output TCC 0.9.27 is linked against Mes libc and can compile
# binutils 2.20.1a (stage 4) and GCC 2.95.3 (stage 5).
#
# Builder: ${mescc-tools}/bin/kaem — the full kaem from stage 1 with ${VAR}
# expansion, cd, echo, if/then/else/fi, and environment variable assignment.
# No /bin/sh dependency.
#
# Reference: https://github.com/fosslinux/live-bootstrap
#   steps/tcc-0.9.26/pass1.kaem, steps/tcc-0.9.27/pass1.kaem
#
{
  mes, # Output of stage2-mes.nix
  mescc-tools, # Output of stage1-mescc-tools.nix
  system ? "x86_64-linux",
}: let
  tcc26version = "0.9.26";
  tcc27version = "0.9.27";

  # x86 (32-bit) architecture parameters — the only target for early bootstrap
  mesCpu = "x86";
  m2Arch = "x86";
  tccTarget = "I386";

  # TCC 0.9.26 — Janneke's bootstrap fork (Guix) with MesCC compatibility
  # Source: https://gitlab.com/janneke/tinycc (commit ee75a10c)
  tcc26src = builtins.derivation {
    name = "tcc-source-${tcc26version}";
    inherit system;
    builder = "builtin:fetchurl";
    url = "https://lilypond.org/janneke/tcc/tcc-0.9.26-1147-gee75a10c.tar.gz";
    outputHash = "sha256-a4y9Cl/tBjbU8PdjpgMke8GTXiBuHMW9pqKBi6tugZ8=";
    outputHashMode = "flat";
    outputHashAlgo = "sha256";
    preferLocalBuild = true;
  };

  # TCC 0.9.27 — upstream release
  tcc27src = builtins.derivation {
    name = "tcc-source-${tcc27version}";
    inherit system;
    builder = "builtin:fetchurl";
    url = "https://download.savannah.gnu.org/releases/tinycc/tcc-${tcc27version}.tar.bz2";
    outputHash = "sha256-3iOvePypDOMt/y3UWzQysjNHQLubt7Bb9g/b/Dls65w=";
    outputHashMode = "flat";
    outputHashAlgo = "sha256";
    preferLocalBuild = true;
  };

  # ── simple-patch tool (compiled by tcc-0.9.26 during the build) ────
  # Reads a file, finds exact "before" text, replaces with "after" text.
  # Equivalent to live-bootstrap's simple-patch from mescc-tools-extra.
  simple-patch-src = builtins.toFile "simple-patch.c" ''
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    char *readfile(const char *path, int *len) {
      int c, sz = 0, cap = 65536;
      char *buf;
      FILE *f = fopen(path, "r");
      if (!f) { fprintf(stderr, "simple-patch: cannot open %s\n", path); exit(1); }
      buf = malloc(cap);
      while ((c = fgetc(f)) != EOF) {
        if (sz >= cap - 1) { cap = cap * 2; buf = realloc(buf, cap); }
        buf[sz++] = c;
      }
      buf[sz] = 0;
      fclose(f);
      *len = sz;
      return buf;
    }
    int main(int argc, char **argv) {
      char *content, *before, *after, *p;
      int clen, blen, alen;
      FILE *f;
      if (argc != 4) {
        fprintf(stderr, "Usage: simple-patch <file> <before-file> <after-file>\n");
        return 1;
      }
      content = readfile(argv[1], &clen);
      before = readfile(argv[2], &blen);
      after = readfile(argv[3], &alen);
      p = strstr(content, before);
      if (!p) {
        fprintf(stderr, "simple-patch: pattern not found in %s\n", argv[1]);
        return 1;
      }
      f = fopen(argv[1], "w");
      if (!f) { fprintf(stderr, "simple-patch: cannot write %s\n", argv[1]); return 1; }
      fwrite(content, 1, p - content, f);
      fwrite(after, 1, alen, f);
      fwrite(p + blen, 1, clen - (p - content) - blen, f);
      fclose(f);
      return 0;
    }
  '';

  # ── Live-bootstrap patches for TCC 0.9.27 ─────────────────────────
  # Each patch is a before/after text pair, applied via simple-patch.

  # 1. check-reloc-null: Fix SIGSEGV in fill_local_got_entries()
  check-reloc-null-before = builtins.toFile "check-reloc-null.before" "static void fill_local_got_entries(TCCState *s1)\n{\n    ElfW_Rel *rel;\n    for_each_elem(s1->got->reloc, 0, rel, ElfW_Rel) {\n";
  check-reloc-null-after = builtins.toFile "check-reloc-null.after" "static void fill_local_got_entries(TCCState *s1)\n{\n    ElfW_Rel *rel;\n    if (!s1->got->reloc)\n        return;\n    for_each_elem(s1->got->reloc, 0, rel, ElfW_Rel) {\n";

  # 2. remove-fileopen + addback-fileopen: Move fopen() in tcc -ar
  remove-fileopen-before = builtins.toFile "remove-fileopen.before" "    if (ret == 1)\n        return ar_usage(ret);\n\n    if ((fh = fopen(argv[i_lib], \"wb\")) == NULL)\n    {\n        fprintf(stderr, \"tcc: ar: can't open file %s \\n\", argv[i_lib]);\n        goto the_end;\n    }\n";
  remove-fileopen-after = builtins.toFile "remove-fileopen.after" "    if (ret == 1)\n        return ar_usage(ret);\n";
  addback-fileopen-before = builtins.toFile "addback-fileopen.before" "    // write header\n";
  addback-fileopen-after = builtins.toFile "addback-fileopen.after" "    if ((fh = fopen(argv[i_lib], \"wb\")) == NULL)\n    {\n        fprintf(stderr, \"tcc: ar: can't open file %s \\n\", argv[i_lib]);\n        goto the_end;\n    }\n\n    // write header\n";

  # 3. static-link: Default to static linking (Mes libc is static-only)
  static-link-before = builtins.toFile "static-link.before" "    s->alacarte_link = 1;\n";
  static-link-after = builtins.toFile "static-link.after" "    s->alacarte_link = 1;\n    s->static_link = 1;\n";

  # 4. ignore-static-inside-array: Handle C99 qualifiers in array declarations
  ignore-static-before = builtins.toFile "ignore-static.before" "        if (tok == TOK_RESTRICT1)\n            next();\n";
  ignore-static-after = builtins.toFile "ignore-static.after" "        while (1) {\n            switch (tok) {\n            case TOK_RESTRICT1: case TOK_RESTRICT2: case TOK_RESTRICT3:\n            case TOK_CONST1:\n            case TOK_VOLATILE1:\n            case TOK_STATIC:\n            case '*':\n                next();\n                continue;\n            default:\n                break;\n            }\n            break;\n        }\n";

  # 5. dont-skip-weak-symbols-ar: Index weak symbols in tcc -ar archives
  weak-syms-before = builtins.toFile "weak-syms.before" "                    (sym->st_info == 0x10\n                    || sym->st_info == 0x11\n                    || sym->st_info == 0x12\n                    )) {\n";
  weak-syms-after = builtins.toFile "weak-syms.after" "                    (sym->st_info == 0x10\n                    || sym->st_info == 0x11\n                    || sym->st_info == 0x12\n                    || sym->st_info == 0x20\n                    || sym->st_info == 0x21\n                    || sym->st_info == 0x22\n                    )) {\n";

  # Mes libc source files — the unified-libc.c list matching live-bootstrap.
  # All paths are relative to lib/ within the Mes output; the MES env var
  # (set by the derivation) is expanded by kaem at build time.
  # Listed as a Nix list of strings, then joined for catm.
  libcSources = [
    "ctype/isalnum.c" "ctype/isalpha.c" "ctype/isascii.c" "ctype/iscntrl.c"
    "ctype/isdigit.c" "ctype/isgraph.c" "ctype/islower.c" "ctype/isnumber.c"
    "ctype/isprint.c" "ctype/ispunct.c" "ctype/isspace.c" "ctype/isupper.c"
    "ctype/isxdigit.c" "ctype/tolower.c" "ctype/toupper.c"
    "dirent/closedir.c" "dirent/__getdirentries.c" "dirent/opendir.c"
    "linux/readdir.c" "linux/access.c" "linux/brk.c" "linux/chdir.c"
    "linux/chmod.c" "linux/clock_gettime.c" "linux/close.c" "linux/dup2.c"
    "linux/dup.c" "linux/execve.c" "linux/fcntl.c" "linux/fork.c"
    "linux/fsync.c" "linux/fstat.c" "linux/_getcwd.c" "linux/getdents.c"
    "linux/getegid.c" "linux/geteuid.c" "linux/getgid.c" "linux/getpid.c"
    "linux/getppid.c" "linux/getrusage.c" "linux/gettimeofday.c" "linux/getuid.c"
    "linux/ioctl.c" "linux/ioctl3.c" "linux/kill.c" "linux/link.c"
    "linux/lseek.c" "linux/lstat.c" "linux/malloc.c" "linux/mkdir.c"
    "linux/mknod.c" "linux/nanosleep.c" "linux/_open3.c" "linux/pipe.c"
    "linux/_read.c" "linux/readlink.c" "linux/rename.c" "linux/rmdir.c"
    "linux/setgid.c" "linux/settimer.c" "linux/setuid.c" "linux/signal.c"
    "linux/sigprogmask.c" "linux/symlink.c" "linux/stat.c" "linux/time.c"
    "linux/unlink.c" "linux/waitpid.c" "linux/wait4.c"
    "linux/${mesCpu}-mes-gcc/_exit.c" "linux/${mesCpu}-mes-gcc/syscall.c"
    "linux/${mesCpu}-mes-gcc/_write.c"
    "math/ceil.c" "math/fabs.c" "math/floor.c"
    "mes/abtod.c" "mes/abtol.c" "mes/__assert_fail.c" "mes/assert_msg.c"
    "mes/__buffered_read.c" "mes/__init_io.c" "mes/cast.c" "mes/dtoab.c"
    "mes/eputc.c" "mes/eputs.c" "mes/fdgetc.c" "mes/fdgets.c"
    "mes/fdputc.c" "mes/fdputs.c" "mes/fdungetc.c" "mes/globals.c"
    "mes/itoa.c" "mes/ltoab.c" "mes/ltoa.c" "mes/__mes_debug.c"
    "mes/mes_open.c" "mes/ntoab.c" "mes/oputc.c" "mes/oputs.c"
    "mes/search-path.c" "mes/ultoa.c" "mes/utoa.c"
    "posix/alarm.c" "posix/buffered-read.c" "posix/execl.c" "posix/execlp.c"
    "posix/execv.c" "posix/execvp.c" "posix/getcwd.c" "posix/getenv.c"
    "posix/isatty.c" "posix/mktemp.c" "posix/open.c" "posix/pathconf.c"
    "posix/raise.c" "posix/sbrk.c" "posix/setenv.c" "posix/sleep.c"
    "posix/unsetenv.c" "posix/wait.c" "posix/write.c"
    "stdio/clearerr.c" "stdio/fclose.c" "stdio/fdopen.c" "stdio/feof.c"
    "stdio/ferror.c" "stdio/fflush.c" "stdio/fgetc.c" "stdio/fgets.c"
    "stdio/fileno.c" "stdio/fopen.c" "stdio/fprintf.c" "stdio/fputc.c"
    "stdio/fputs.c" "stdio/fread.c" "stdio/freopen.c" "stdio/fscanf.c"
    "stdio/fseek.c" "stdio/ftell.c" "stdio/fwrite.c" "stdio/getc.c"
    "stdio/getchar.c" "stdio/perror.c" "stdio/printf.c" "stdio/putc.c"
    "stdio/putchar.c" "stdio/remove.c" "stdio/snprintf.c" "stdio/sprintf.c"
    "stdio/sscanf.c" "stdio/ungetc.c" "stdio/vfprintf.c" "stdio/vfscanf.c"
    "stdio/vprintf.c" "stdio/vsnprintf.c" "stdio/vsprintf.c" "stdio/vsscanf.c"
    "stdlib/abort.c" "stdlib/abs.c" "stdlib/alloca.c" "stdlib/atexit.c"
    "stdlib/atof.c" "stdlib/atoi.c" "stdlib/atol.c" "stdlib/calloc.c"
    "stdlib/__exit.c" "stdlib/exit.c" "stdlib/free.c" "stdlib/mbstowcs.c"
    "stdlib/puts.c" "stdlib/qsort.c" "stdlib/realloc.c" "stdlib/strtod.c"
    "stdlib/strtof.c" "stdlib/strtol.c" "stdlib/strtold.c" "stdlib/strtoll.c"
    "stdlib/strtoul.c" "stdlib/strtoull.c"
    "string/bcmp.c" "string/bcopy.c" "string/bzero.c" "string/index.c"
    "string/memchr.c" "string/memcmp.c" "string/memcpy.c" "string/memmem.c"
    "string/memmove.c" "string/memset.c" "string/rindex.c" "string/strcat.c"
    "string/strchr.c" "string/strcmp.c" "string/strcpy.c" "string/strcspn.c"
    "string/strdup.c" "string/strerror.c" "string/strlen.c" "string/strlwr.c"
    "string/strncat.c" "string/strncmp.c" "string/strncpy.c" "string/strpbrk.c"
    "string/strrchr.c" "string/strspn.c" "string/strstr.c" "string/strupr.c"
    "stub/atan2.c" "stub/bsearch.c" "stub/chown.c" "stub/__cleanup.c"
    "stub/cos.c" "stub/ctime.c" "stub/exp.c" "stub/fpurge.c"
    "stub/freadahead.c" "stub/frexp.c" "stub/getgrgid.c" "stub/getgrnam.c"
    "stub/getlogin.c" "stub/getpgid.c" "stub/getpgrp.c" "stub/getpwnam.c"
    "stub/getpwuid.c" "stub/gmtime.c" "stub/ldexp.c" "stub/localtime.c"
    "stub/log.c" "stub/mktime.c" "stub/modf.c" "stub/mprotect.c"
    "stub/pclose.c" "stub/popen.c" "stub/pow.c" "stub/putenv.c"
    "stub/rand.c" "stub/realpath.c" "stub/rewind.c" "stub/setbuf.c"
    "stub/setgrent.c" "stub/setlocale.c" "stub/setvbuf.c" "stub/sigaction.c"
    "stub/sigaddset.c" "stub/sigblock.c" "stub/sigdelset.c" "stub/sigemptyset.c"
    "stub/sigsetmask.c" "stub/sin.c" "stub/sys_siglist.c" "stub/system.c"
    "stub/sqrt.c" "stub/strftime.c" "stub/times.c" "stub/ttyname.c"
    "stub/umask.c" "stub/utime.c"
    "${mesCpu}-mes-gcc/setjmp.c"
  ];

  # Generate the catm arguments for unified-libc.c: each source prefixed by ${mes}/lib/
  libcCatmArgs = builtins.concatStringsSep " " (map (s: "${mes}/lib/${s}") libcSources);

  # Generate the rebuild_mes_libc commands for a given compiler variable name.
  # This produces a sequence of kaem commands to rebuild crt objects, unified
  # libc, libtcc1, and libgetopt with the specified compiler.
  # $CC is a kaem variable that must be set before calling this.
  mkRebuildLibcScript = ccVar: ''
    # Rebuild Mes libc with ${ccVar}
    echo "  crt objects..."
    ''${${ccVar}} -c -D HAVE_CONFIG_H=1 -I ${mes}/include -I ${mes}/include/linux/${mesCpu} -o ''${LIBDIR}/crt1.o ${mes}/lib/linux/${mesCpu}-mes-gcc/crt1.c
    ''${${ccVar}} -c -D HAVE_CONFIG_H=1 -I ${mes}/include -I ${mes}/include/linux/${mesCpu} -o ''${LIBDIR}/crtn.o ${mes}/lib/linux/${mesCpu}-mes-gcc/crtn.c
    ''${${ccVar}} -c -D HAVE_CONFIG_H=1 -I ${mes}/include -I ${mes}/include/linux/${mesCpu} -o ''${LIBDIR}/crti.o ${mes}/lib/linux/${mesCpu}-mes-gcc/crti.c

    echo "  unified libc..."
    ''${${ccVar}} -c -D HAVE_CONFIG_H=1 -I ${mes}/include -I ${mes}/include/linux/${mesCpu} -o ''${WORK}/unified-libc.o ''${WORK}/unified-libc.c
    ''${${ccVar}} -ar cr ''${LIBDIR}/libc.a ''${WORK}/unified-libc.o

    echo "  libtcc1..."
    ''${${ccVar}} -c -D HAVE_CONFIG_H=1 -D HAVE_LONG_LONG=1 -D HAVE_FLOAT=1 -I ${mes}/include -I ${mes}/include/linux/${mesCpu} -o ''${WORK}/libtcc1.o ${mes}/lib/libtcc1.c
    ''${${ccVar}} -ar cr ''${LIBDIR}/tcc/libtcc1.a ''${WORK}/libtcc1.o
  '';

  # The complete TCC bootstrap chain
  tinycc = builtins.derivation {
    name = "tinycc-${tcc27version}";
    inherit system;
    builder = "/bin/sh";
    args = ["-c" ''exec ${mescc-tools}/bin/kaem --verbose --strict --file "$buildScriptPath"''];
    passAsFile = ["buildScript"];
    buildScript = ''
      # Stage 3: TinyCC bootstrap chain
      # All Nix store paths are pre-interpolated at eval time.
      # ''${TMPDIR}, ''${out} are expanded by kaem at build time.

      PATH=${mescc-tools}/bin

      # Mes paths from stage 2
      MES_BIN=${mes}/bin/mes-m2
      MESCC=${mes}/bin/mescc.scm
      MES_INCDIR=${mes}/include
      MES_LIBDIR=${mes}/lib/${mesCpu}-mes
      MES_MODDIR=${mes}/mes/module

      GUILE_LOAD_PATH=${mes}/mes/module:${mes}/share/mes/module:${mes}/share/nyacc
      MES_STACK=15000000
      MES_ARENA=30000000
      MES_MAX_ARENA=30000000
      MES_PREFIX=${mes}
      MES_LIB=${mes}/lib
      MES_SOURCE=${mes}

      M1=${mescc-tools}/bin/M1
      HEX2=${mescc-tools}/bin/hex2
      BLOOD_ELF=${mescc-tools}/bin/blood-elf

      WORK=''${TMPDIR}/build
      mkdir ''${WORK}

      # Working lib directory
      LIBDIR=''${WORK}/lib/${mesCpu}-mes
      INCDIR=${mes}/include
      PREFIX=''${WORK}/prefix
      BINDIR=''${PREFIX}/bin

      mkdir ''${WORK}/lib
      mkdir ''${WORK}/lib/${mesCpu}-mes
      mkdir ''${WORK}/lib/${mesCpu}-mes/tcc
      mkdir ''${PREFIX}
      mkdir ''${BINDIR}

      # Copy Mes libc from stage 2
      cp ${mes}/lib/${mesCpu}-mes/crt1.o ''${LIBDIR}/crt1.o
      cp ${mes}/lib/${mesCpu}-mes/libc.a ''${LIBDIR}/libc.a
      cp ${mes}/lib/${mesCpu}-mes/libc+tcc.a ''${LIBDIR}/libc+tcc.a

      # ── Extract TCC 0.9.26 source ─────────────────────────────────────
      cd ''${WORK}
      ungz --file ${tcc26src} --output ''${WORK}/tcc26.tar
      untar --non-strict --file ''${WORK}/tcc26.tar
      rm ''${WORK}/tcc26.tar

      TCC26_SRC=''${WORK}/tcc-0.9.26-1147-gee75a10c
      cd ''${TCC26_SRC}

      # tcc.h includes config.h unconditionally — empty one suffices
      catm config.h

      # Architecture M1 definition files
      DEFS_M1=${mes}/lib/m2/${mesCpu}/${mesCpu}_defs.M1
      ARCH_M1=${mes}/lib/${mesCpu}-mes/${mesCpu}.M1

      # Create unified-libc.c for reuse across boot stages (matching live-bootstrap)
      cd ${mes}/lib
      catm ''${WORK}/unified-libc.c ${libcCatmArgs}
      cd ''${TCC26_SRC}

      # ══════════════════════════════════════════════════════════════════
      # PASS 1: MesCC compiles TCC 0.9.26 -> tcc-mes
      # ══════════════════════════════════════════════════════════════════
      echo "==> Pass 1: MesCC compiling TCC 0.9.26..."

      # HAVE_LONG_LONG=0 for this pass: NYACC cannot handle long long types
      ''${MES_BIN} --no-auto-compile -e main ''${MESCC} -- -S -o tcc.s -I ''${INCDIR} -D BOOTSTRAP=1 -D HAVE_LONG_LONG=0 -I . -D TCC_TARGET_${tccTarget}=1 -D inline= -D CONFIG_TCCDIR=\"''${LIBDIR}/tcc\" -D CONFIG_SYSROOT=\"/\" -D CONFIG_TCC_CRTPREFIX=\"''${LIBDIR}\" -D CONFIG_TCC_ELFINTERP=\"/mes/loader\" -D CONFIG_TCC_SYSINCLUDEPATHS=\"''${INCDIR}\" -D TCC_LIBGCC=\"''${LIBDIR}/libc.a\" -D CONFIG_TCC_LIBTCC1_MES=0 -D CONFIG_TCCBOOT=1 -D CONFIG_TCC_STATIC=1 -D CONFIG_USE_LIBGCC=1 -D TCC_VERSION=\"0.9.26\" -D ONE_SOURCE=1 tcc.c

      echo "==> tcc.s produced, linking..."
      ''${MES_BIN} --no-auto-compile -e main ''${MESCC} -- --base-address 0x08048000 -o ''${BINDIR}/tcc-mes -L ''${LIBDIR} tcc.s -l c+tcc

      chmod ''${BINDIR}/tcc-mes
      echo "==> tcc-mes built"

      # Test tcc-mes
      ''${BINDIR}/tcc-mes -version

      # ── Rebuild Mes libc with tcc-mes ────────────────────────────────
      echo "==> Rebuilding Mes libc with tcc-mes..."
      CC=''${BINDIR}/tcc-mes
      ${mkRebuildLibcScript "CC"}

      # ══════════════════════════════════════════════════════════════════
      # BOOT 0: tcc-mes compiles tcc-boot0
      # ══════════════════════════════════════════════════════════════════
      echo "==> Boot 0: tcc-mes compiling tcc-boot0..."
      cd ''${TCC26_SRC}

      ''${BINDIR}/tcc-mes -g -v -static -o ''${BINDIR}/tcc-boot0 -D BOOTSTRAP=1 -D HAVE_FLOAT=1 -D HAVE_BITFIELD=1 -D HAVE_LONG_LONG=1 -D HAVE_SETJMP=1 -I . -I ''${INCDIR} -D TCC_TARGET_${tccTarget}=1 -D CONFIG_TCCDIR=\"''${LIBDIR}/tcc\" -D CONFIG_TCC_CRTPREFIX=\"''${LIBDIR}\" -D CONFIG_TCC_ELFINTERP=\"/mes/loader\" -D CONFIG_TCC_LIBPATHS=\"''${LIBDIR}:''${LIBDIR}/tcc\" -D CONFIG_TCC_SYSINCLUDEPATHS=\"''${INCDIR}\" -D TCC_LIBGCC=\"''${LIBDIR}/libc.a\" -D TCC_LIBTCC1=\"libtcc1.a\" -D CONFIG_TCCBOOT=1 -D CONFIG_TCC_STATIC=1 -D CONFIG_USE_LIBGCC=1 -D TCC_VERSION=\"0.9.26\" -D ONE_SOURCE=1 -L . -L ''${LIBDIR} tcc.c

      chmod ''${BINDIR}/tcc-boot0
      echo "==> tcc-boot0 built"

      # Rebuild libc with tcc-boot0
      echo "==> Rebuilding Mes libc with tcc-boot0..."
      CC=''${BINDIR}/tcc-boot0
      ${mkRebuildLibcScript "CC"}

      # Test boot0
      ''${BINDIR}/tcc-boot0 -version

      # ══════════════════════════════════════════════════════════════════
      # BOOT 1: tcc-boot0 compiles tcc-boot1
      # ══════════════════════════════════════════════════════════════════
      echo "==> Boot 1: tcc-boot0 compiling tcc-boot1..."
      cd ''${TCC26_SRC}

      ''${BINDIR}/tcc-boot0 -g -v -static -o ''${BINDIR}/tcc-boot1 -D BOOTSTRAP=1 -D HAVE_FLOAT=1 -D HAVE_BITFIELD=1 -D HAVE_LONG_LONG=1 -D HAVE_SETJMP=1 -I . -I ''${INCDIR} -D TCC_TARGET_${tccTarget}=1 -D CONFIG_TCCDIR=\"''${LIBDIR}/tcc\" -D CONFIG_TCC_CRTPREFIX=\"''${LIBDIR}\" -D CONFIG_TCC_ELFINTERP=\"/mes/loader\" -D CONFIG_TCC_LIBPATHS=\"''${LIBDIR}:''${LIBDIR}/tcc\" -D CONFIG_TCC_SYSINCLUDEPATHS=\"''${INCDIR}\" -D TCC_LIBGCC=\"''${LIBDIR}/libc.a\" -D TCC_LIBTCC1=\"libtcc1.a\" -D CONFIG_TCCBOOT=1 -D CONFIG_TCC_STATIC=1 -D CONFIG_USE_LIBGCC=1 -D TCC_VERSION=\"0.9.26\" -D ONE_SOURCE=1 -L . -L ''${LIBDIR} tcc.c

      chmod ''${BINDIR}/tcc-boot1
      echo "==> tcc-boot1 built"

      # Rebuild libc with tcc-boot1
      echo "==> Rebuilding Mes libc with tcc-boot1..."
      CC=''${BINDIR}/tcc-boot1
      ${mkRebuildLibcScript "CC"}

      # Test boot1
      ''${BINDIR}/tcc-boot1 -version

      # ══════════════════════════════════════════════════════════════════
      # BOOT 2: tcc-boot1 compiles tcc-boot2 (= tcc-0.9.26 final)
      # ══════════════════════════════════════════════════════════════════
      echo "==> Boot 2: tcc-boot1 compiling tcc-boot2 (final 0.9.26)..."
      cd ''${TCC26_SRC}

      ''${BINDIR}/tcc-boot1 -g -v -static -o ''${BINDIR}/tcc-0.9.26 -D BOOTSTRAP=1 -D HAVE_FLOAT=1 -D HAVE_BITFIELD=1 -D HAVE_LONG_LONG=1 -D HAVE_SETJMP=1 -I . -I ''${INCDIR} -D TCC_TARGET_${tccTarget}=1 -D CONFIG_TCCDIR=\"''${LIBDIR}/tcc\" -D CONFIG_TCC_CRTPREFIX=\"''${LIBDIR}\" -D CONFIG_TCC_ELFINTERP=\"/mes/loader\" -D CONFIG_TCC_LIBPATHS=\"''${LIBDIR}:''${LIBDIR}/tcc\" -D CONFIG_TCC_SYSINCLUDEPATHS=\"''${INCDIR}\" -D TCC_LIBGCC=\"''${LIBDIR}/libc.a\" -D TCC_LIBTCC1=\"libtcc1.a\" -D CONFIG_TCCBOOT=1 -D CONFIG_TCC_STATIC=1 -D CONFIG_USE_LIBGCC=1 -D TCC_VERSION=\"0.9.26\" -D ONE_SOURCE=1 -L . -L ''${LIBDIR} tcc.c

      chmod ''${BINDIR}/tcc-0.9.26
      echo "==> tcc-0.9.26 (boot2) built"

      # Rebuild libc + libtcc1 with the final 0.9.26
      echo "==> Rebuilding Mes libc with tcc-0.9.26..."
      CC=''${BINDIR}/tcc-0.9.26
      ${mkRebuildLibcScript "CC"}

      # Build libgetopt.a
      ''${BINDIR}/tcc-0.9.26 -c -D HAVE_CONFIG_H=1 -I ${mes}/include -I ${mes}/include/linux/${mesCpu} -o ''${WORK}/getopt.o ${mes}/lib/posix/getopt.c
      ''${BINDIR}/tcc-0.9.26 -ar cr ''${LIBDIR}/libgetopt.a ''${WORK}/getopt.o

      # Compile simple-patch tool for applying multi-line patches
      ''${BINDIR}/tcc-0.9.26 -o ''${BINDIR}/simple-patch ${simple-patch-src}
      echo "==> simple-patch tool built"

      # ══════════════════════════════════════════════════════════════════
      # TCC 0.9.27: Built by TCC 0.9.26
      # ══════════════════════════════════════════════════════════════════
      echo "==> Building TCC 0.9.27 with TCC 0.9.26..."

      cd ''${WORK}
      unbz2 --file ${tcc27src} --output ''${WORK}/tcc27.tar
      untar --file ''${WORK}/tcc27.tar
      rm ''${WORK}/tcc27.tar

      TCC27_SRC=''${WORK}/tcc-${tcc27version}
      cd ''${TCC27_SRC}

      # TCC 0.9.27's tcc.h includes config.h — create empty one
      catm config.h

      # ── Patches from live-bootstrap ──────────────────────────────────
      ''${BINDIR}/simple-patch tccelf.c ${check-reloc-null-before} ${check-reloc-null-after}
      echo "  Applied check-reloc-null (SIGSEGV fix for static binaries)"

      ''${BINDIR}/simple-patch tcctools.c ${remove-fileopen-before} ${remove-fileopen-after}
      ''${BINDIR}/simple-patch tcctools.c ${addback-fileopen-before} ${addback-fileopen-after}
      echo "  Applied fileopen-reorder (tcc -ar fix)"

      ''${BINDIR}/simple-patch libtcc.c ${static-link-before} ${static-link-after}
      echo "  Applied static-link (default static linking)"

      ''${BINDIR}/simple-patch tccgen.c ${ignore-static-before} ${ignore-static-after}
      echo "  Applied ignore-static-inside-array (C99 array quals)"

      ''${BINDIR}/simple-patch tcctools.c ${weak-syms-before} ${weak-syms-after}
      echo "  Applied dont-skip-weak-symbols-ar (weak symbol indexing)"

      # Use $out paths so the installed binary finds its libs in the Nix store
      ''${BINDIR}/tcc-0.9.26 -v -static -o ''${BINDIR}/tcc -D TCC_TARGET_${tccTarget}=1 -D CONFIG_TCCDIR=\"''${out}/lib/${mesCpu}-mes/tcc\" -D CONFIG_TCC_CRTPREFIX=\"''${out}/lib/${mesCpu}-mes\" -D CONFIG_TCC_ELFINTERP=\"/mes/loader\" -D CONFIG_TCC_LIBPATHS=\"''${out}/lib/${mesCpu}-mes:''${out}/lib/${mesCpu}-mes/tcc\" -D CONFIG_TCC_SYSINCLUDEPATHS=\"''${out}/include\" -D TCC_LIBGCC=\"''${out}/lib/${mesCpu}-mes/libc.a\" -D CONFIG_TCC_STATIC=1 -D CONFIG_USE_LIBGCC=1 -D TCC_VERSION=\"0.9.27\" -D ONE_SOURCE=1 tcc.c

      chmod ''${BINDIR}/tcc
      echo "==> tcc-0.9.27 built"

      # Build libtcc1.a — use TCC's own lib/libtcc1.c which provides
      # __fixdfdi, __fixsfdi, __divdi3 etc. (guarded by #ifdef __i386__)
      ''${BINDIR}/tcc -c -o ''${WORK}/libtcc1-27.o lib/libtcc1.c
      ''${BINDIR}/tcc -ar cr ''${LIBDIR}/tcc/libtcc1.a ''${WORK}/libtcc1-27.o

      # Rebuild crt objects and libc with TCC 0.9.27
      echo "==> Rebuilding Mes libc with tcc-0.9.27..."
      CC=''${BINDIR}/tcc
      ${mkRebuildLibcScript "CC"}

      # Rebuild libgetopt with final TCC
      ''${BINDIR}/tcc -c -D HAVE_CONFIG_H=1 -I ${mes}/include -I ${mes}/include/linux/${mesCpu} -o ''${WORK}/getopt.o ${mes}/lib/posix/getopt.c
      ''${BINDIR}/tcc -ar cr ''${LIBDIR}/libgetopt.a ''${WORK}/getopt.o

      # ── Install to output ──────────────────────────────────────────────
      mkdir ''${out}
      mkdir ''${out}/bin
      mkdir ''${out}/lib
      mkdir ''${out}/lib/${mesCpu}-mes
      mkdir ''${out}/lib/${mesCpu}-mes/tcc
      mkdir ''${out}/include

      cp ''${BINDIR}/tcc ''${out}/bin/tcc
      cp ''${BINDIR}/tcc-0.9.26 ''${out}/bin/tcc-0.9.26
      cp ''${BINDIR}/simple-patch ''${out}/bin/simple-patch
      cp ''${LIBDIR}/crt1.o ''${out}/lib/${mesCpu}-mes/crt1.o
      cp ''${LIBDIR}/crtn.o ''${out}/lib/${mesCpu}-mes/crtn.o
      cp ''${LIBDIR}/crti.o ''${out}/lib/${mesCpu}-mes/crti.o
      cp ''${LIBDIR}/libc.a ''${out}/lib/${mesCpu}-mes/libc.a
      cp ''${LIBDIR}/libgetopt.a ''${out}/lib/${mesCpu}-mes/libgetopt.a
      cp ''${LIBDIR}/tcc/libtcc1.a ''${out}/lib/${mesCpu}-mes/tcc/libtcc1.a

      # Install Mes C headers (needed for compiling C programs)
      # Enumerate all headers from stage 2 output
      mkdir ''${out}/include/mes
      mkdir ''${out}/include/sys
      mkdir ''${out}/include/linux
      mkdir ''${out}/include/linux/${mesCpu}
      mkdir ''${out}/include/arch
      mkdir ''${out}/include/m2

      cp ${mes}/include/alloca.h ''${out}/include/alloca.h
      cp ${mes}/include/ar.h ''${out}/include/ar.h
      cp ${mes}/include/argz.h ''${out}/include/argz.h
      cp ${mes}/include/assert.h ''${out}/include/assert.h
      cp ${mes}/include/ctype.h ''${out}/include/ctype.h
      cp ${mes}/include/dirent.h ''${out}/include/dirent.h
      cp ${mes}/include/dirstream.h ''${out}/include/dirstream.h
      cp ${mes}/include/dlfcn.h ''${out}/include/dlfcn.h
      cp ${mes}/include/endian.h ''${out}/include/endian.h
      cp ${mes}/include/errno.h ''${out}/include/errno.h
      cp ${mes}/include/fcntl.h ''${out}/include/fcntl.h
      cp ${mes}/include/features.h ''${out}/include/features.h
      cp ${mes}/include/float.h ''${out}/include/float.h
      cp ${mes}/include/getopt.h ''${out}/include/getopt.h
      cp ${mes}/include/grp.h ''${out}/include/grp.h
      cp ${mes}/include/inttypes.h ''${out}/include/inttypes.h
      cp ${mes}/include/libgen.h ''${out}/include/libgen.h
      cp ${mes}/include/limits.h ''${out}/include/limits.h
      cp ${mes}/include/locale.h ''${out}/include/locale.h
      cp ${mes}/include/math.h ''${out}/include/math.h
      cp ${mes}/include/memory.h ''${out}/include/memory.h
      cp ${mes}/include/pwd.h ''${out}/include/pwd.h
      cp ${mes}/include/setjmp.h ''${out}/include/setjmp.h
      cp ${mes}/include/signal.h ''${out}/include/signal.h
      cp ${mes}/include/stdarg.h ''${out}/include/stdarg.h
      cp ${mes}/include/stdbool.h ''${out}/include/stdbool.h
      cp ${mes}/include/stddef.h ''${out}/include/stddef.h
      cp ${mes}/include/stdint.h ''${out}/include/stdint.h
      cp ${mes}/include/stdio.h ''${out}/include/stdio.h
      cp ${mes}/include/stdlib.h ''${out}/include/stdlib.h
      cp ${mes}/include/stdnoreturn.h ''${out}/include/stdnoreturn.h
      cp ${mes}/include/string.h ''${out}/include/string.h
      cp ${mes}/include/strings.h ''${out}/include/strings.h
      cp ${mes}/include/termio.h ''${out}/include/termio.h
      cp ${mes}/include/time.h ''${out}/include/time.h
      cp ${mes}/include/unistd.h ''${out}/include/unistd.h

      cp ${mes}/include/arch/kernel-stat.h ''${out}/include/arch/kernel-stat.h
      cp ${mes}/include/arch/syscall.h ''${out}/include/arch/syscall.h
      cp ${mes}/include/arch/signal.h ''${out}/include/arch/signal.h

      cp ${mes}/include/linux/syscall.h ''${out}/include/linux/syscall.h
      cp ${mes}/include/linux/${mesCpu}/syscall.h ''${out}/include/linux/${mesCpu}/syscall.h

      cp ${mes}/include/mes/builtins.h ''${out}/include/mes/builtins.h
      cp ${mes}/include/mes/cc.h ''${out}/include/mes/cc.h
      catm ''${out}/include/mes/config.h
      cp ${mes}/include/mes/constants.h ''${out}/include/mes/constants.h
      cp ${mes}/include/mes/lib.h ''${out}/include/mes/lib.h
      cp ${mes}/include/mes/lib-cc.h ''${out}/include/mes/lib-cc.h
      cp ${mes}/include/mes/lib-mini.h ''${out}/include/mes/lib-mini.h
      cp ${mes}/include/mes/mes.h ''${out}/include/mes/mes.h
      cp ${mes}/include/mes/symbols.h ''${out}/include/mes/symbols.h

      cp ${mes}/include/sys/cdefs.h ''${out}/include/sys/cdefs.h
      cp ${mes}/include/sys/dir.h ''${out}/include/sys/dir.h
      cp ${mes}/include/sys/file.h ''${out}/include/sys/file.h
      cp ${mes}/include/sys/ioctl.h ''${out}/include/sys/ioctl.h
      cp ${mes}/include/sys/mman.h ''${out}/include/sys/mman.h
      cp ${mes}/include/sys/param.h ''${out}/include/sys/param.h
      cp ${mes}/include/sys/resource.h ''${out}/include/sys/resource.h
      cp ${mes}/include/sys/select.h ''${out}/include/sys/select.h
      cp ${mes}/include/sys/stat.h ''${out}/include/sys/stat.h
      cp ${mes}/include/sys/timeb.h ''${out}/include/sys/timeb.h
      cp ${mes}/include/sys/time.h ''${out}/include/sys/time.h
      cp ${mes}/include/sys/times.h ''${out}/include/sys/times.h
      cp ${mes}/include/sys/types.h ''${out}/include/sys/types.h
      cp ${mes}/include/sys/ucontext.h ''${out}/include/sys/ucontext.h
      cp ${mes}/include/sys/user.h ''${out}/include/sys/user.h
      cp ${mes}/include/sys/wait.h ''${out}/include/sys/wait.h

      cp ${mes}/include/m2/types.h ''${out}/include/m2/types.h

      # Test final tcc
      ''${BINDIR}/tcc -version

      echo "Stage 3 complete: TinyCC ${tcc27version} built successfully (i386)"
      echo "Compiler: ''${out}/bin/tcc"
      echo "Libraries: ''${out}/lib/${mesCpu}-mes/"
    '';
  };
in
  tinycc
  // {
    version = tcc27version;
    meta = {
      description = "TinyCC (TCC) is a small and fast C compiler";
      homepage = "https://bellard.org/tcc/";
      license = "LGPL-2.1-or-later";
      platforms = ["i686-linux"];
    };
  }
