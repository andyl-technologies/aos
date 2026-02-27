# stdenv/bootstrap/stage3-tinycc.nix — TinyCC compiled by MesCC
#
# TinyCC (tcc) is a small, fast C compiler that can compile itself.
# MesCC (from stage 2) compiles janneke's TinyCC fork, which then
# self-hosts through 3 boot stages to produce the final tcc.
#
# All output binaries are i386 (32-bit). Cross-compilation to x86_64
# and aarch64 happens after GCC is available.
#
# Build chain (all passes use the same janneke/tinycc source):
#   MesCC ──compile──> tcc-mes (very slow, limited features)
#   tcc-mes ──compile──> tcc-boot0 (adds float/bitfield/longlong/setjmp)
#   tcc-boot0 ──compile──> tcc-boot1
#   tcc-boot1 ──compile──> tcc-boot2 (= final tcc)
#
# After each boot stage, the Mes C library is rebuilt with the new compiler,
# producing progressively better object code.
#
# Builder: kaem -> full kaem. kaem reads $buildScriptPath, then
# invokes full kaem to run the real build script (builtins.toFile).
# No /bin/sh dependency.
#
# Source: janneke's TinyCC fork (https://gitlab.com/janneke/tinycc)
# which includes all live-bootstrap patches merged upstream.
#
{
  mes, # Output of stage2-mes.nix
  posix-tools, # Output of stage1-posix-tools.nix
  seeds, # Output of stage0-seeds.nix (provides kaem)
  buildPlatform,
  ...
}:
let
  system = buildPlatform.system;
  # Guix's TCC fork — janneke's tinycc with 30 MesCC-compatibility patches.
  # Upstream TCC cannot be compiled by MesCC; this fork has the fixes baked in.
  # Same source Guix uses in their bootstrap (gnu/packages/commencement.scm).
  tccsrc = builtins.derivation {
    name = "tinycc-source";
    inherit system;
    builder = "builtin:fetchurl";
    url = "https://lilypond.org/janneke/tcc/tcc-0.9.26-1149-g46a75d0c.tar.gz";
    outputHash = "sha256-9PbOEhrGMaI0rwgHU/udZF0jNNIBYLN6u+dbV0oeHRk=";
    outputHashMode = "flat";
    outputHashAlgo = "sha256";
    preferLocalBuild = true;
  };

  # x86 (32-bit) architecture parameters — the only target for early bootstrap
  mesCpu = "x86";

  # Mes libc source files — the unified-libc.c list matching live-bootstrap.
  libcSources = [
    "ctype/isalnum.c"
    "ctype/isalpha.c"
    "ctype/isascii.c"
    "ctype/iscntrl.c"
    "ctype/isdigit.c"
    "ctype/isgraph.c"
    "ctype/islower.c"
    "ctype/isnumber.c"
    "ctype/isprint.c"
    "ctype/ispunct.c"
    "ctype/isspace.c"
    "ctype/isupper.c"
    "ctype/isxdigit.c"
    "ctype/tolower.c"
    "ctype/toupper.c"
    "dirent/closedir.c"
    "dirent/__getdirentries.c"
    "dirent/opendir.c"
    "linux/readdir.c"
    "linux/access.c"
    "linux/brk.c"
    "linux/chdir.c"
    "linux/chmod.c"
    "linux/clock_gettime.c"
    "linux/close.c"
    "linux/dup2.c"
    "linux/dup.c"
    "linux/execve.c"
    "linux/fcntl.c"
    "linux/fork.c"
    "linux/fsync.c"
    "linux/fstat.c"
    "linux/_getcwd.c"
    "linux/getdents.c"
    "linux/getegid.c"
    "linux/geteuid.c"
    "linux/getgid.c"
    "linux/getpid.c"
    "linux/getppid.c"
    "linux/getrusage.c"
    "linux/gettimeofday.c"
    "linux/getuid.c"
    "linux/ioctl.c"
    "linux/ioctl3.c"
    "linux/kill.c"
    "linux/link.c"
    "linux/lseek.c"
    "linux/lstat.c"
    "linux/malloc.c"
    "linux/mkdir.c"
    "linux/mknod.c"
    "linux/nanosleep.c"
    "linux/_open3.c"
    "linux/pipe.c"
    "linux/_read.c"
    "linux/readlink.c"
    "linux/rename.c"
    "linux/rmdir.c"
    "linux/setgid.c"
    "linux/settimer.c"
    "linux/setuid.c"
    "linux/signal.c"
    "linux/sigprogmask.c"
    "linux/symlink.c"
    "linux/stat.c"
    "linux/time.c"
    "linux/unlink.c"
    "linux/waitpid.c"
    "linux/wait4.c"
    "linux/${mesCpu}-mes-gcc/_exit.c"
    "linux/${mesCpu}-mes-gcc/syscall.c"
    "linux/${mesCpu}-mes-gcc/_write.c"
    "math/ceil.c"
    "math/fabs.c"
    "math/floor.c"
    "mes/abtod.c"
    "mes/abtol.c"
    "mes/__assert_fail.c"
    "mes/assert_msg.c"
    "mes/__buffered_read.c"
    "mes/__init_io.c"
    "mes/cast.c"
    "mes/dtoab.c"
    "mes/eputc.c"
    "mes/eputs.c"
    "mes/fdgetc.c"
    "mes/fdgets.c"
    "mes/fdputc.c"
    "mes/fdputs.c"
    "mes/fdungetc.c"
    "mes/globals.c"
    "mes/itoa.c"
    "mes/ltoab.c"
    "mes/ltoa.c"
    "mes/__mes_debug.c"
    "mes/mes_open.c"
    "mes/ntoab.c"
    "mes/oputc.c"
    "mes/oputs.c"
    "mes/search-path.c"
    "mes/ultoa.c"
    "mes/utoa.c"
    "posix/alarm.c"
    "posix/buffered-read.c"
    "posix/execl.c"
    "posix/execlp.c"
    "posix/execv.c"
    "posix/execvp.c"
    "posix/getcwd.c"
    "posix/getenv.c"
    "posix/isatty.c"
    "posix/mktemp.c"
    "posix/open.c"
    "posix/pathconf.c"
    "posix/raise.c"
    "posix/sbrk.c"
    "posix/setenv.c"
    "posix/sleep.c"
    "posix/unsetenv.c"
    "posix/wait.c"
    "posix/write.c"
    "stdio/clearerr.c"
    "stdio/fclose.c"
    "stdio/fdopen.c"
    "stdio/feof.c"
    "stdio/ferror.c"
    "stdio/fflush.c"
    "stdio/fgetc.c"
    "stdio/fgets.c"
    "stdio/fileno.c"
    "stdio/fopen.c"
    "stdio/fprintf.c"
    "stdio/fputc.c"
    "stdio/fputs.c"
    "stdio/fread.c"
    "stdio/freopen.c"
    "stdio/fscanf.c"
    "stdio/fseek.c"
    "stdio/ftell.c"
    "stdio/fwrite.c"
    "stdio/getc.c"
    "stdio/getchar.c"
    "stdio/perror.c"
    "stdio/printf.c"
    "stdio/putc.c"
    "stdio/putchar.c"
    "stdio/remove.c"
    "stdio/snprintf.c"
    "stdio/sprintf.c"
    "stdio/sscanf.c"
    "stdio/ungetc.c"
    "stdio/vfprintf.c"
    "stdio/vfscanf.c"
    "stdio/vprintf.c"
    "stdio/vsnprintf.c"
    "stdio/vsprintf.c"
    "stdio/vsscanf.c"
    "stdlib/abort.c"
    "stdlib/abs.c"
    "stdlib/alloca.c"
    "stdlib/atexit.c"
    "stdlib/atof.c"
    "stdlib/atoi.c"
    "stdlib/atol.c"
    "stdlib/calloc.c"
    "stdlib/__exit.c"
    "stdlib/exit.c"
    "stdlib/free.c"
    "stdlib/mbstowcs.c"
    "stdlib/puts.c"
    "stdlib/qsort.c"
    "stdlib/realloc.c"
    "stdlib/strtod.c"
    "stdlib/strtof.c"
    "stdlib/strtol.c"
    "stdlib/strtold.c"
    "stdlib/strtoll.c"
    "stdlib/strtoul.c"
    "stdlib/strtoull.c"
    "string/bcmp.c"
    "string/bcopy.c"
    "string/bzero.c"
    "string/index.c"
    "string/memchr.c"
    "string/memcmp.c"
    "string/memcpy.c"
    "string/memmem.c"
    "string/memmove.c"
    "string/memset.c"
    "string/rindex.c"
    "string/strcat.c"
    "string/strchr.c"
    "string/strcmp.c"
    "string/strcpy.c"
    "string/strcspn.c"
    "string/strdup.c"
    "string/strerror.c"
    "string/strlen.c"
    "string/strlwr.c"
    "string/strncat.c"
    "string/strncmp.c"
    "string/strncpy.c"
    "string/strpbrk.c"
    "string/strrchr.c"
    "string/strspn.c"
    "string/strstr.c"
    "string/strupr.c"
    "stub/atan2.c"
    "stub/bsearch.c"
    "stub/chown.c"
    "stub/__cleanup.c"
    "stub/cos.c"
    "stub/ctime.c"
    "stub/exp.c"
    "stub/fpurge.c"
    "stub/freadahead.c"
    "stub/frexp.c"
    "stub/getgrgid.c"
    "stub/getgrnam.c"
    "stub/getlogin.c"
    "stub/getpgid.c"
    "stub/getpgrp.c"
    "stub/getpwnam.c"
    "stub/getpwuid.c"
    "stub/gmtime.c"
    "stub/ldexp.c"
    "stub/localtime.c"
    "stub/log.c"
    "stub/mktime.c"
    "stub/modf.c"
    "stub/mprotect.c"
    "stub/pclose.c"
    "stub/popen.c"
    "stub/pow.c"
    "stub/putenv.c"
    "stub/rand.c"
    "stub/realpath.c"
    "stub/rewind.c"
    "stub/setbuf.c"
    "stub/setgrent.c"
    "stub/setlocale.c"
    "stub/setvbuf.c"
    "stub/sigaction.c"
    "stub/sigaddset.c"
    "stub/sigblock.c"
    "stub/sigdelset.c"
    "stub/sigemptyset.c"
    "stub/sigsetmask.c"
    "stub/sin.c"
    "stub/sys_siglist.c"
    "stub/system.c"
    "stub/sqrt.c"
    "stub/strftime.c"
    "stub/times.c"
    "stub/ttyname.c"
    "stub/umask.c"
    "stub/utime.c"
    "${mesCpu}-mes-gcc/setjmp.c"
  ];

  # Generate the rebuild_mes_libc commands for a given compiler variable name.
  # All references use ''${VAR} for kaem expansion at build time.
  mkRebuildLibcScript = ccVar: ''
    # Rebuild Mes libc with ''${${ccVar}}
    echo "  crt objects..."
    ''${${ccVar}} -c -D HAVE_CONFIG_H=1 -I ''${MES_INC} -I ''${MES_INC}/linux/${mesCpu} -o ''${LIBDIR}/crt1.o ''${MES_LIB}/linux/${mesCpu}-mes-gcc/crt1.c
    ''${${ccVar}} -c -D HAVE_CONFIG_H=1 -I ''${MES_INC} -I ''${MES_INC}/linux/${mesCpu} -o ''${LIBDIR}/crtn.o ''${MES_LIB}/linux/${mesCpu}-mes-gcc/crtn.c
    ''${${ccVar}} -c -D HAVE_CONFIG_H=1 -I ''${MES_INC} -I ''${MES_INC}/linux/${mesCpu} -o ''${LIBDIR}/crti.o ''${MES_LIB}/linux/${mesCpu}-mes-gcc/crti.c

    echo "  unified libc..."
    ''${${ccVar}} -c -D HAVE_CONFIG_H=1 -I ''${MES_INC} -I ''${MES_INC}/linux/${mesCpu} -o ''${WORK}/unified-libc.o ''${WORK}/unified-libc.c
    ''${${ccVar}} -ar cr ''${LIBDIR}/libc.a ''${WORK}/unified-libc.o

    echo "  libtcc1..."
    ''${${ccVar}} -c -D HAVE_CONFIG_H=1 -D HAVE_LONG_LONG=1 -D HAVE_FLOAT=1 -I ''${MES_INC} -I ''${MES_INC}/linux/${mesCpu} -o ''${WORK}/libtcc1.o ''${MES_LIB}/libtcc1.c
    ''${${ccVar}} -ar cr ''${LIBDIR}/tcc/libtcc1.a ''${WORK}/libtcc1.o
  '';

  # The catm arguments for unified-libc.c — each source prefixed by MES_LIB env var.
  # These use ''${MES_LIB} for kaem expansion at build time.
  libcCatmArgs = builtins.concatStringsSep " " (map (s: "\${MES_LIB}/${s}") libcSources);

  # ── Build script (run by full kaem) ──────────────────────────────────
  # builtins.toFile — cannot reference derivation outputs directly.
  # Derivation paths are passed via env vars.
  buildKaem = builtins.toFile "build-tinycc.kaem" ''
    # Stage 3: TinyCC bootstrap chain
    # ''${POSIX_TOOLS}, ''${MES_OUT}, ''${MES_SRC_TAR}, ''${NYACC_TAR},
    # ''${TCC_TAR}, ''${MES_INC}, ''${MES_LIB}
    # are env vars set by the Nix derivation.

    PATH=''${POSIX_TOOLS}/bin

    WORK=''${TMPDIR}/build
    mkdir ''${WORK}
    cd ''${WORK}

    # Unpack Mes source for Scheme modules (boot-5.scm etc.)
    ungz --file ''${MES_SRC_TAR} --output ''${WORK}/mes-src.tar
    untar --non-strict --file ''${WORK}/mes-src.tar
    rm ''${WORK}/mes-src.tar
    MES_SRC_DIR=''${WORK}/mes-0.27.1

    # Prepare Mes source tree (same as stage 2)
    cp ''${MES_SRC_DIR}/mes/module/srfi/srfi-9-struct.mes ''${MES_SRC_DIR}/mes/module/srfi/srfi-9.mes
    cp ''${MES_SRC_DIR}/mes/module/srfi/srfi-9/gnu-struct.mes ''${MES_SRC_DIR}/mes/module/srfi/srfi-9/gnu.mes
    rm ''${MES_SRC_DIR}/mes/module/mes/psyntax.pp
    rm ''${MES_SRC_DIR}/mes/module/mes/psyntax.pp.header

    # Unpack NYACC for C99 parser modules
    ungz --file ''${NYACC_TAR} --output ''${WORK}/nyacc.tar
    untar --file ''${WORK}/nyacc.tar
    rm ''${WORK}/nyacc.tar
    NYACC_DIR=''${WORK}/nyacc-1.00.2

    # Mes paths from stage 2
    MES_BIN=''${MES_OUT}/bin/mes-m2
    MESCC=''${MES_OUT}/bin/mescc.scm
    MES_LIBDIR=''${MES_OUT}/lib/x86-mes

    # GUILE_LOAD_PATH: use unpacked source trees for Scheme modules
    GUILE_LOAD_PATH=''${NYACC_DIR}/module:''${MES_SRC_DIR}/mes/module:''${MES_SRC_DIR}/module
    MES_STACK=15000000
    MES_ARENA=30000000
    MES_MAX_ARENA=30000000
    MES_PREFIX=''${MES_SRC_DIR}
    MES_SOURCE=''${MES_SRC_DIR}

    M1=''${POSIX_TOOLS}/bin/M1
    HEX2=''${POSIX_TOOLS}/bin/hex2
    BLOOD_ELF=''${POSIX_TOOLS}/bin/blood-elf

    # Working lib directory
    LIBDIR=''${WORK}/lib/x86-mes
    INCDIR=''${MES_INC}
    PREFIX=''${WORK}/prefix
    BINDIR=''${PREFIX}/bin

    mkdir ''${WORK}/lib
    mkdir ''${WORK}/lib/x86-mes
    mkdir ''${WORK}/lib/x86-mes/tcc
    mkdir ''${PREFIX}
    mkdir ''${BINDIR}

    # Copy Mes libc from stage 2
    cp ''${MES_LIBDIR}/crt1.o ''${LIBDIR}/crt1.o
    cp ''${MES_LIBDIR}/libc.a ''${LIBDIR}/libc.a
    cp ''${MES_LIBDIR}/libc+tcc.a ''${LIBDIR}/libc+tcc.a

    # ── Extract TCC source ──────────────────────────────────────────────
    cd ''${WORK}
    ungz --file ''${TCC_TAR} --output ''${WORK}/tcc.tar
    untar --non-strict --file ''${WORK}/tcc.tar
    rm ''${WORK}/tcc.tar

    TCC_SRC=''${WORK}/tcc-0.9.26-1149-g46a75d0c
    cd ''${TCC_SRC}

    # tcc.h includes config.h unconditionally — empty one suffices
    catm config.h

    # Architecture M1 definition files
    DEFS_M1=''${MES_OUT}/lib/m2/x86/x86_defs.M1
    ARCH_M1=''${MES_OUT}/lib/x86-mes/x86.M1

    # Create unified-libc.c for reuse across boot stages
    cd ''${MES_LIB}
    catm ''${WORK}/unified-libc.c ${libcCatmArgs}
    cd ''${TCC_SRC}

    # ══════════════════════════════════════════════════════════════════
    # PASS 1: MesCC compiles TCC -> tcc-mes
    # ══════════════════════════════════════════════════════════════════
    echo "==> Pass 1: MesCC compiling TCC..."

    # Patch TCC source for MesCC Pass 1 — NYACC cannot parse
    # "typedef __jmp_buf jmp_buf[1]" from setjmp.h (array typedefs).
    # Remove setjmp usage entirely for Pass 1; Boot 0/1/2 restore unpatched source.
    cp ''${TCC_SRC}/tcc.h ''${WORK}/tcc.h.orig
    cp ''${TCC_SRC}/libtcc.c ''${WORK}/libtcc.c.orig
    replace --file ''${TCC_SRC}/tcc.h --output ''${TCC_SRC}/tcc.h --match-on "#include <setjmp.h>" --replace-with "/* setjmp removed for MesCC */"
    replace --file ''${TCC_SRC}/tcc.h --output ''${TCC_SRC}/tcc.h --match-on "jmp_buf error_jmp_buf;" --replace-with "long error_jmp_buf;"
    replace --file ''${TCC_SRC}/libtcc.c --output ''${TCC_SRC}/libtcc.c --match-on "longjmp(s1->error_jmp_buf, 1);" --replace-with "exit(1);"
    replace --file ''${TCC_SRC}/libtcc.c --output ''${TCC_SRC}/libtcc.c --match-on "if (setjmp(s1->error_jmp_buf) == 0) {" --replace-with "if (1) {"

    ''${MES_BIN} --no-auto-compile -e main ''${MESCC} -- -S -o tcc.s -I ''${INCDIR} -D BOOTSTRAP=1 -I . -D TCC_TARGET_I386=1 -D inline= -D CONFIG_TCCDIR=\"''${LIBDIR}/tcc\" -D CONFIG_SYSROOT=\"/\" -D CONFIG_TCC_CRTPREFIX=\"''${LIBDIR}\" -D CONFIG_TCC_ELFINTERP=\"/mes/loader\" -D CONFIG_TCC_SYSINCLUDEPATHS=\"''${INCDIR}\" -D TCC_LIBGCC=\"''${LIBDIR}/libc.a\" -D CONFIG_TCC_LIBTCC1_MES=0 -D CONFIG_TCCBOOT=1 -D CONFIG_TCC_STATIC=1 -D CONFIG_USE_LIBGCC=1 -D TCC_VERSION=\"0.9.26\" -D ONE_SOURCE=1 tcc.c

    echo "==> tcc.s produced, linking..."
    ''${MES_BIN} --no-auto-compile -e main ''${MESCC} -- --base-address 0x08048000 -o ''${BINDIR}/tcc-mes -L ''${WORK}/lib -L ''${MES_OUT}/lib tcc.s -l c+tcc

    chmod 750 ''${BINDIR}/tcc-mes
    echo "==> tcc-mes built"

    ''${BINDIR}/tcc-mes -version

    # ── Rebuild Mes libc with tcc-mes ────────────────────────────────
    echo "==> Rebuilding Mes libc with tcc-mes..."
    CC=''${BINDIR}/tcc-mes
    ${mkRebuildLibcScript "CC"}

    # Restore original TCC source for Boot passes (TCC can parse real setjmp.h)
    cp ''${WORK}/tcc.h.orig ''${TCC_SRC}/tcc.h
    cp ''${WORK}/libtcc.c.orig ''${TCC_SRC}/libtcc.c

    # ══════════════════════════════════════════════════════════════════
    # BOOT 0: tcc-mes compiles tcc-boot0
    # ══════════════════════════════════════════════════════════════════
    echo "==> Boot 0: tcc-mes compiling tcc-boot0..."
    cd ''${TCC_SRC}

    ''${BINDIR}/tcc-mes -g -v -static -o ''${BINDIR}/tcc-boot0 -D BOOTSTRAP=1 -D HAVE_FLOAT=1 -D HAVE_BITFIELD=1 -D HAVE_LONG_LONG=1 -D HAVE_SETJMP=1 -I . -I ''${INCDIR} -D TCC_TARGET_I386=1 -D CONFIG_TCCDIR=\"''${LIBDIR}/tcc\" -D CONFIG_TCC_CRTPREFIX=\"''${LIBDIR}\" -D CONFIG_TCC_ELFINTERP=\"/mes/loader\" -D CONFIG_TCC_LIBPATHS=\"''${LIBDIR}:''${LIBDIR}/tcc\" -D CONFIG_TCC_SYSINCLUDEPATHS=\"''${INCDIR}\" -D TCC_LIBGCC=\"''${LIBDIR}/libc.a\" -D TCC_LIBTCC1=\"libtcc1.a\" -D CONFIG_TCCBOOT=1 -D CONFIG_TCC_STATIC=1 -D CONFIG_USE_LIBGCC=1 -D TCC_VERSION=\"0.9.26\" -D ONE_SOURCE=1 -L . -L ''${LIBDIR} tcc.c

    chmod 750 ''${BINDIR}/tcc-boot0
    echo "==> tcc-boot0 built"

    echo "==> Rebuilding Mes libc with tcc-boot0..."
    CC=''${BINDIR}/tcc-boot0
    ${mkRebuildLibcScript "CC"}

    ''${BINDIR}/tcc-boot0 -version

    # ══════════════════════════════════════════════════════════════════
    # BOOT 1: tcc-boot0 compiles tcc-boot1
    # ══════════════════════════════════════════════════════════════════
    echo "==> Boot 1: tcc-boot0 compiling tcc-boot1..."
    cd ''${TCC_SRC}

    ''${BINDIR}/tcc-boot0 -g -v -static -o ''${BINDIR}/tcc-boot1 -D BOOTSTRAP=1 -D HAVE_FLOAT=1 -D HAVE_BITFIELD=1 -D HAVE_LONG_LONG=1 -D HAVE_SETJMP=1 -I . -I ''${INCDIR} -D TCC_TARGET_I386=1 -D CONFIG_TCCDIR=\"''${LIBDIR}/tcc\" -D CONFIG_TCC_CRTPREFIX=\"''${LIBDIR}\" -D CONFIG_TCC_ELFINTERP=\"/mes/loader\" -D CONFIG_TCC_LIBPATHS=\"''${LIBDIR}:''${LIBDIR}/tcc\" -D CONFIG_TCC_SYSINCLUDEPATHS=\"''${INCDIR}\" -D TCC_LIBGCC=\"''${LIBDIR}/libc.a\" -D TCC_LIBTCC1=\"libtcc1.a\" -D CONFIG_TCCBOOT=1 -D CONFIG_TCC_STATIC=1 -D CONFIG_USE_LIBGCC=1 -D TCC_VERSION=\"0.9.26\" -D ONE_SOURCE=1 -L . -L ''${LIBDIR} tcc.c

    chmod 750 ''${BINDIR}/tcc-boot1
    echo "==> tcc-boot1 built"

    echo "==> Rebuilding Mes libc with tcc-boot1..."
    CC=''${BINDIR}/tcc-boot1
    ${mkRebuildLibcScript "CC"}

    ''${BINDIR}/tcc-boot1 -version

    # ══════════════════════════════════════════════════════════════════
    # BOOT 2: tcc-boot1 compiles tcc (final)
    # ══════════════════════════════════════════════════════════════════
    echo "==> Boot 2: tcc-boot1 compiling final tcc..."
    cd ''${TCC_SRC}

    # Use $out paths so the installed binary finds its libs in the Nix store
    ''${BINDIR}/tcc-boot1 -g -v -static -o ''${BINDIR}/tcc -D BOOTSTRAP=1 -D HAVE_FLOAT=1 -D HAVE_BITFIELD=1 -D HAVE_LONG_LONG=1 -D HAVE_SETJMP=1 -I . -I ''${INCDIR} -D TCC_TARGET_I386=1 -D CONFIG_TCCDIR=\"''${out}/lib/x86-mes/tcc\" -D CONFIG_TCC_CRTPREFIX=\"''${out}/lib/x86-mes\" -D CONFIG_TCC_ELFINTERP=\"/mes/loader\" -D CONFIG_TCC_LIBPATHS=\"''${out}/lib/x86-mes:''${out}/lib/x86-mes/tcc\" -D CONFIG_TCC_SYSINCLUDEPATHS=\"''${out}/include\" -D TCC_LIBGCC=\"''${out}/lib/x86-mes/libc.a\" -D TCC_LIBTCC1=\"libtcc1.a\" -D CONFIG_TCCBOOT=1 -D CONFIG_TCC_STATIC=1 -D CONFIG_USE_LIBGCC=1 -D TCC_VERSION=\"0.9.26\" -D ONE_SOURCE=1 -L . -L ''${LIBDIR} tcc.c

    chmod 750 ''${BINDIR}/tcc
    echo "==> tcc (boot2) built"

    echo "==> Rebuilding Mes libc with final tcc..."
    CC=''${BINDIR}/tcc
    ${mkRebuildLibcScript "CC"}

    # Build libgetopt.a
    ''${BINDIR}/tcc -c -D HAVE_CONFIG_H=1 -I ''${MES_INC} -I ''${MES_INC}/linux/x86 -o ''${WORK}/getopt.o ''${MES_LIB}/posix/getopt.c
    ''${BINDIR}/tcc -ar cr ''${LIBDIR}/libgetopt.a ''${WORK}/getopt.o

    # ── Install to output ──────────────────────────────────────────────
    mkdir ''${out}
    mkdir ''${out}/bin
    mkdir ''${out}/lib
    mkdir ''${out}/lib/x86-mes
    mkdir ''${out}/lib/x86-mes/tcc
    mkdir ''${out}/include

    cp ''${BINDIR}/tcc ''${out}/bin/tcc
    chmod 750 ''${out}/bin/tcc
    cp ''${LIBDIR}/crt1.o ''${out}/lib/x86-mes/crt1.o
    cp ''${LIBDIR}/crtn.o ''${out}/lib/x86-mes/crtn.o
    cp ''${LIBDIR}/crti.o ''${out}/lib/x86-mes/crti.o
    cp ''${LIBDIR}/libc.a ''${out}/lib/x86-mes/libc.a
    cp ''${LIBDIR}/libgetopt.a ''${out}/lib/x86-mes/libgetopt.a
    cp ''${LIBDIR}/tcc/libtcc1.a ''${out}/lib/x86-mes/tcc/libtcc1.a

    # Install Mes C headers
    mkdir ''${out}/include/mes
    mkdir ''${out}/include/sys
    mkdir ''${out}/include/linux
    mkdir ''${out}/include/linux/x86
    mkdir ''${out}/include/arch
    mkdir ''${out}/include/m2

    cp ''${MES_INC}/alloca.h ''${out}/include/alloca.h
    cp ''${MES_INC}/ar.h ''${out}/include/ar.h
    cp ''${MES_INC}/argz.h ''${out}/include/argz.h
    cp ''${MES_INC}/assert.h ''${out}/include/assert.h
    cp ''${MES_INC}/ctype.h ''${out}/include/ctype.h
    cp ''${MES_INC}/dirent.h ''${out}/include/dirent.h
    cp ''${MES_INC}/dirstream.h ''${out}/include/dirstream.h
    cp ''${MES_INC}/dlfcn.h ''${out}/include/dlfcn.h
    cp ''${MES_INC}/endian.h ''${out}/include/endian.h
    cp ''${MES_INC}/errno.h ''${out}/include/errno.h
    cp ''${MES_INC}/fcntl.h ''${out}/include/fcntl.h
    cp ''${MES_INC}/features.h ''${out}/include/features.h
    cp ''${MES_INC}/float.h ''${out}/include/float.h
    cp ''${MES_INC}/getopt.h ''${out}/include/getopt.h
    cp ''${MES_INC}/grp.h ''${out}/include/grp.h
    cp ''${MES_INC}/inttypes.h ''${out}/include/inttypes.h
    cp ''${MES_INC}/libgen.h ''${out}/include/libgen.h
    cp ''${MES_INC}/limits.h ''${out}/include/limits.h
    cp ''${MES_INC}/locale.h ''${out}/include/locale.h
    cp ''${MES_INC}/math.h ''${out}/include/math.h
    cp ''${MES_INC}/memory.h ''${out}/include/memory.h
    cp ''${MES_INC}/pwd.h ''${out}/include/pwd.h
    cp ''${MES_INC}/setjmp.h ''${out}/include/setjmp.h
    cp ''${MES_INC}/signal.h ''${out}/include/signal.h
    cp ''${MES_INC}/stdarg.h ''${out}/include/stdarg.h
    cp ''${MES_INC}/stdbool.h ''${out}/include/stdbool.h
    cp ''${MES_INC}/stddef.h ''${out}/include/stddef.h
    cp ''${MES_INC}/stdint.h ''${out}/include/stdint.h
    cp ''${MES_INC}/stdio.h ''${out}/include/stdio.h
    cp ''${MES_INC}/stdlib.h ''${out}/include/stdlib.h
    cp ''${MES_INC}/stdnoreturn.h ''${out}/include/stdnoreturn.h
    cp ''${MES_INC}/string.h ''${out}/include/string.h
    cp ''${MES_INC}/strings.h ''${out}/include/strings.h
    cp ''${MES_INC}/termio.h ''${out}/include/termio.h
    cp ''${MES_INC}/time.h ''${out}/include/time.h
    cp ''${MES_INC}/unistd.h ''${out}/include/unistd.h

    cp ''${MES_INC}/arch/kernel-stat.h ''${out}/include/arch/kernel-stat.h
    cp ''${MES_INC}/arch/syscall.h ''${out}/include/arch/syscall.h
    cp ''${MES_INC}/arch/signal.h ''${out}/include/arch/signal.h

    cp ''${MES_INC}/linux/syscall.h ''${out}/include/linux/syscall.h
    cp ''${MES_INC}/linux/x86/syscall.h ''${out}/include/linux/x86/syscall.h

    cp ''${MES_INC}/mes/builtins.h ''${out}/include/mes/builtins.h
    cp ''${MES_INC}/mes/cc.h ''${out}/include/mes/cc.h
    catm ''${out}/include/mes/config.h
    cp ''${MES_INC}/mes/constants.h ''${out}/include/mes/constants.h
    cp ''${MES_INC}/mes/lib.h ''${out}/include/mes/lib.h
    cp ''${MES_INC}/mes/lib-cc.h ''${out}/include/mes/lib-cc.h
    cp ''${MES_INC}/mes/lib-mini.h ''${out}/include/mes/lib-mini.h
    cp ''${MES_INC}/mes/mes.h ''${out}/include/mes/mes.h
    cp ''${MES_INC}/mes/symbols.h ''${out}/include/mes/symbols.h

    cp ''${MES_INC}/sys/cdefs.h ''${out}/include/sys/cdefs.h
    cp ''${MES_INC}/sys/dir.h ''${out}/include/sys/dir.h
    cp ''${MES_INC}/sys/file.h ''${out}/include/sys/file.h
    cp ''${MES_INC}/sys/ioctl.h ''${out}/include/sys/ioctl.h
    cp ''${MES_INC}/sys/mman.h ''${out}/include/sys/mman.h
    cp ''${MES_INC}/sys/param.h ''${out}/include/sys/param.h
    cp ''${MES_INC}/sys/resource.h ''${out}/include/sys/resource.h
    cp ''${MES_INC}/sys/select.h ''${out}/include/sys/select.h
    cp ''${MES_INC}/sys/stat.h ''${out}/include/sys/stat.h
    cp ''${MES_INC}/sys/timeb.h ''${out}/include/sys/timeb.h
    cp ''${MES_INC}/sys/time.h ''${out}/include/sys/time.h
    cp ''${MES_INC}/sys/times.h ''${out}/include/sys/times.h
    cp ''${MES_INC}/sys/types.h ''${out}/include/sys/types.h
    cp ''${MES_INC}/sys/ucontext.h ''${out}/include/sys/ucontext.h
    cp ''${MES_INC}/sys/user.h ''${out}/include/sys/user.h
    cp ''${MES_INC}/sys/wait.h ''${out}/include/sys/wait.h

    cp ''${MES_INC}/m2/types.h ''${out}/include/m2/types.h

    # Test final tcc
    ''${BINDIR}/tcc -version

    echo "Stage 3 complete: TinyCC built successfully (i386)"
    echo "Compiler: ''${out}/bin/tcc"
    echo "Libraries: ''${out}/lib/x86-mes/"
  '';

  # The complete TCC bootstrap chain
  tinycc = builtins.derivation {
    name = "tinycc-0.9.26";
    inherit system;
    builder = "${seeds.kaemNix}";
    passAsFile = [ "buildScript" ];
    # Single-line buildScript: kaem invokes full kaem
    buildScript = "${posix-tools}/bin/kaem --verbose --strict --file ${buildKaem}\n";
    # Derivation paths passed as env vars for full kaem ${VAR} expansion
    POSIX_TOOLS = "${posix-tools}";
    MES_OUT = "${mes}";
    MES_SRC_TAR = "${mes.passthru.src.mes}";
    NYACC_TAR = "${mes.passthru.src.nyacc}";
    TCC_TAR = "${tccsrc}";
    MES_INC = "${mes}/include";
    MES_LIB = "${mes}/lib";
  };
in
tinycc
// {
  version = "0.9.26";
  meta = {
    description = "TinyCC (TCC) is a small and fast C compiler (janneke's fork)";
    homepage = "https://gitlab.com/janneke/tinycc";
    license = "LGPL-2.1-or-later";
    build = {
      os = "linux";
      cpu = [
        "x86_64"
        "i686"
      ];
    };
    execute = {
      os = "linux";
      cpu = "i686";
    };
  };
}
