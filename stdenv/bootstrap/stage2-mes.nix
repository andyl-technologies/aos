# stdenv/bootstrap/stage2-mes027.nix — GNU Mes (Scheme interpreter + MesCC C compiler)
#
# GNU Mes is a Scheme interpreter that includes MesCC, a C compiler written
# in Scheme. MesCC can compile a subset of C sufficient to build TinyCC.
#
# Built by M2-Planet from posix-tools (stage 1). Targets x86 (32-bit) only.
# Cross-compilation to x86_64/aarch64 happens after GCC is available.
#
# The build process:
#   1. M2-Planet compiles mes.c -> mes.M1 (M1 macro assembly)
#   2. blood-elf generates ELF debug info -> mes.blood-elf-M1
#   3. M1 assembles all .M1 files -> mes.hex2
#   4. hex2 links ELF header + code -> bin/mes-m2 (static ELF binary)
#   5. mescc.scm is prepared from template
#   6. mes-m2 runs mescc to build the Mes C library (crt1.o, libc.a, etc.)
#
# The output provides everything stage 3 (TinyCC) needs:
#   - bin/mes-m2: Scheme interpreter (i386 ELF)
#   - bin/mescc.scm: C compiler driver (Scheme script)
#   - include/: C headers
#   - lib/: crt1.o, library archives, and source files for libc rebuild
#
# Builder: kaemNix -> full kaem (from posix-tools). kaemNix reads the
# passAsFile build script which invokes full kaem to run the real build
# script (a builtins.toFile that uses ${VAR} expansion for derivation paths).
#
# Reference: https://github.com/fosslinux/live-bootstrap (steps/mes-0.27.1/)
#
{
  posix-tools, # Output of stage1-posix-tools.nix
  seeds, # Output of stage0-seeds.nix (provides kaemNix)
  buildPlatform,
  ...
}: let
  system = buildPlatform.system;
  mesSrc = builtins.derivation {
    name = "mes-source-0.27.1";
    inherit system;
    builder = "builtin:fetchurl";
    url = "https://mirrors.kernel.org/gnu/mes/mes-0.27.1.tar.gz";
    outputHash = "sha256-GDpA6kfqSfih470bnRLmdjdNZNY7x557wa59Zz398l0=";
    outputHashMode = "flat";
    outputHashAlgo = "sha256";
    preferLocalBuild = true;
  };

  nyaccSrc = builtins.derivation {
    name = "nyacc-source-1.00.2";
    inherit system;
    builder = "builtin:fetchurl";
    # download-mirror serves the file directly; the plain
    # download.savannah host 302s into a volunteer mirror pool
    # whose members intermittently answer HTTP 200 with an HTML
    # error page — builtin:fetchurl has no retry, so a bad mirror
    # poisons this FOD with a hash mismatch.
    url = "https://download-mirror.savannah.gnu.org/releases/nyacc/nyacc-1.00.2.tar.gz";
    outputHash = "sha256-825Pt91STcP0s1TT1TE/aefOWmrpNxHoz21R6qjSsxg=";
    outputHashMode = "flat";
    outputHashAlgo = "sha256";
    preferLocalBuild = true;
  };

  # Pre-baked config.h — avoids needing heredoc/redirect in kaem
  configH = builtins.toFile "config.h" ''
    #undef SYSTEM_LIBC
    #define MES_VERSION "0.27.1"
  '';

  # ── Build script (run by full kaem) ──────────────────────────────────
  # This script is a builtins.toFile, so it CANNOT reference derivation
  # outputs directly. Instead, derivation paths are passed as environment
  # variables (set as string attributes on the derivation), and full kaem's
  # ${VAR} expansion reads them at build time.
  #
  # In Nix's '' '' strings: ''${...} escapes Nix interpolation, passing
  # the literal ${...} through. These are expanded by full kaem at runtime.
  #
  # The configH toFile CAN be referenced directly (toFile -> toFile is OK).
  buildKaem = builtins.toFile "build-mes.kaem" ''
    # Build GNU Mes 0.27.1
    # ''${POSIX_TOOLS}, ''${MES_SRC_TAR}, ''${NYACC_TAR} are env vars set
    # by the Nix derivation, expanded by full kaem at build time.

    PATH=''${POSIX_TOOLS}/bin

    WORK=''${TMPDIR}/build
    mkdir ''${WORK}
    cd ''${WORK}

    # ── Extract sources ────────────────────────────────────────────────
    ungz --file ''${MES_SRC_TAR} --output ''${WORK}/mes.tar
    untar --non-strict --file ''${WORK}/mes.tar
    rm ''${WORK}/mes.tar

    ungz --file ''${NYACC_TAR} --output ''${WORK}/nyacc.tar
    untar --file ''${WORK}/nyacc.tar
    rm ''${WORK}/nyacc.tar

    MES_SRC=''${WORK}/mes-0.27.1
    NYACC_DIR=''${WORK}/nyacc-1.00.2

    cd ''${MES_SRC}

    PREFIX=''${out}
    BINDIR=''${out}/bin
    LIBDIR=''${out}/lib/x86-mes
    INCDIR=''${out}/include
    MODDIR=''${out}/mes/module

    # Create output directories (kaem mkdir is not -p, chain them)
    mkdir ''${out}
    mkdir ''${out}/bin
    mkdir ''${out}/lib
    mkdir ''${out}/lib/x86-mes
    mkdir ''${out}/include
    mkdir ''${out}/mes
    mkdir ''${out}/mes/module

    # ── Patches and configuration ──────────────────────────────────────

    # Create config.h from pre-baked file
    cp ${configH} ''${MES_SRC}/include/mes/config.h

    # Copy architecture-specific headers to arch/ directory
    mkdir ''${MES_SRC}/include/arch
    cp ''${MES_SRC}/include/linux/x86/kernel-stat.h ''${MES_SRC}/include/arch/kernel-stat.h
    cp ''${MES_SRC}/include/linux/x86/signal.h ''${MES_SRC}/include/arch/signal.h
    cp ''${MES_SRC}/include/linux/x86/syscall.h ''${MES_SRC}/include/arch/syscall.h

    # Fix symlinks that may not have been preserved by tar
    cp ''${MES_SRC}/mes/module/srfi/srfi-9-struct.mes ''${MES_SRC}/mes/module/srfi/srfi-9.mes
    cp ''${MES_SRC}/mes/module/srfi/srfi-9/gnu-struct.mes ''${MES_SRC}/mes/module/srfi/srfi-9/gnu.mes

    # Remove pregenerated files (will be regenerated)
    rm ''${MES_SRC}/mes/module/mes/psyntax.pp
    rm ''${MES_SRC}/mes/module/mes/psyntax.pp.header

    # ── Phase 1: Build mes-m2 with M2-Planet ──────────────────────────
    # M2-Planet compiles all source files passed via -f flags into a
    # single M1 assembly output. There is no #include mechanism.

    echo "==> Compiling mes.c with M2-Planet..."
    mkdir ''${MES_SRC}/m2

    M2-Planet --debug --architecture x86 -D __i386__=1 -D __linux__=1 -f include/mes/config.h -f include/mes/lib-mini.h -f include/mes/lib.h -f lib/linux/x86-mes-m2/crt1.c -f lib/mes/__init_io.c -f lib/linux/x86-mes-m2/_exit.c -f lib/linux/x86-mes-m2/_write.c -f lib/mes/globals.c -f lib/m2/cast.c -f lib/stdlib/exit.c -f lib/mes/write.c -f include/linux/x86/syscall.h -f lib/linux/x86-mes-m2/syscall.c -f lib/stub/__raise.c -f lib/linux/brk.c -f lib/linux/malloc.c -f lib/string/memset.c -f lib/linux/read.c -f lib/mes/fdgetc.c -f lib/stdio/getchar.c -f lib/stdio/putchar.c -f lib/stub/__buffered_read.c -f include/errno.h -f include/fcntl.h -f lib/linux/_open3.c -f lib/linux/open.c -f lib/mes/mes_open.c -f lib/string/strlen.c -f lib/mes/eputs.c -f lib/mes/fdputc.c -f lib/mes/eputc.c -f include/time.h -f include/sys/time.h -f include/m2/types.h -f include/sys/types.h -f include/sys/utsname.h -f include/mes/mes.h -f include/mes/builtins.h -f include/mes/constants.h -f include/mes/symbols.h -f lib/mes/__assert_fail.c -f lib/mes/assert_msg.c -f lib/mes/fdputc.c -f lib/string/strncmp.c -f lib/posix/getenv.c -f lib/mes/fdputs.c -f lib/mes/ntoab.c -f lib/ctype/isdigit.c -f lib/ctype/isxdigit.c -f lib/ctype/isspace.c -f lib/ctype/isnumber.c -f lib/mes/abtol.c -f lib/stdlib/atoi.c -f lib/string/memcpy.c -f lib/stdlib/free.c -f lib/stdlib/realloc.c -f lib/string/strcpy.c -f lib/mes/itoa.c -f lib/mes/ltoa.c -f lib/mes/fdungetc.c -f lib/posix/setenv.c -f lib/linux/access.c -f include/linux/m2/kernel-stat.h -f include/sys/stat.h -f lib/linux/chmod.c -f lib/linux/ioctl3.c -f include/sys/ioctl.h -f lib/m2/isatty.c -f include/signal.h -f lib/linux/fork.c -f lib/m2/execve.c -f lib/m2/execv.c -f include/sys/resource.h -f lib/linux/wait4.c -f lib/linux/waitpid.c -f lib/linux/gettimeofday.c -f lib/linux/clock_gettime.c -f lib/m2/time.c -f lib/linux/_getcwd.c -f include/limits.h -f lib/m2/getcwd.c -f lib/linux/dup.c -f lib/linux/dup2.c -f lib/string/strcmp.c -f lib/string/memcmp.c -f lib/linux/uname.c -f lib/linux/unlink.c -f src/builtins.c -f src/core.c -f src/display.c -f src/eval-apply.c -f src/gc.c -f src/hash.c -f src/lib.c -f src/m2.c -f src/math.c -f src/mes.c -f src/module.c -f src/posix.c -f src/reader.c -f src/stack.c -f src/string.c -f src/struct.c -f src/symbol.c -f src/variable.c -f src/vector.c -o m2/mes.M1

    echo "==> Running blood-elf..."
    blood-elf --little-endian -f m2/mes.M1 -o m2/mes.blood-elf-M1

    echo "==> Assembling with M1..."
    M1 --architecture x86 --little-endian -f lib/m2/x86/x86_defs.M1 -f lib/x86-mes/x86.M1 -f lib/linux/x86-mes-m2/crt1.M1 -f m2/mes.M1 -f m2/mes.blood-elf-M1 -o m2/mes.hex2

    echo "==> Linking with hex2..."
    mkdir ''${MES_SRC}/bin
    hex2 --architecture x86 --little-endian --base-address 0x08048000 -f lib/m2/x86/ELF-x86.hex2 -f m2/mes.hex2 -o bin/mes-m2

    chmod 750 bin/mes-m2
    cp bin/mes-m2 ''${BINDIR}/mes-m2
    chmod 750 ''${BINDIR}/mes-m2

    echo "==> mes-m2 binary built successfully"

    # ── Phase 2: Set up mescc (C compiler in Scheme) ──────────────────

    # Create mescc.scm from template
    cp scripts/mescc.scm.in ''${BINDIR}/mescc.scm
    replace --file ''${BINDIR}/mescc.scm --output ''${BINDIR}/mescc.scm --match-on @prefix@ --replace-with ''${PREFIX}
    replace --file ''${BINDIR}/mescc.scm --output ''${BINDIR}/mescc.scm --match-on @VERSION@ --replace-with 0.27.1
    replace --file ''${BINDIR}/mescc.scm --output ''${BINDIR}/mescc.scm --match-on @mes_cpu@ --replace-with x86
    replace --file ''${BINDIR}/mescc.scm --output ''${BINDIR}/mescc.scm --match-on @mes_kernel@ --replace-with linux

    # Install NYACC modules FIRST (so mes stubs can override them)
    mkdir ''${MODDIR}/nyacc
    mkdir ''${MODDIR}/nyacc/lang
    mkdir ''${MODDIR}/nyacc/lang/c99
    mkdir ''${MODDIR}/nyacc/lang/c99/mach.d
    mkdir ''${MODDIR}/nyacc/lex
    mkdir ''${MODDIR}/nyacc/parse

    # Install Mes-specific Scheme modules
    mkdir ''${out}/share
    mkdir ''${out}/share/nyacc
    mkdir ''${out}/share/mes
    mkdir ''${out}/share/mes/module

    # Install C headers
    mkdir ''${INCDIR}/mes
    mkdir ''${INCDIR}/sys
    mkdir ''${INCDIR}/linux
    mkdir ''${INCDIR}/linux/x86
    mkdir ''${INCDIR}/arch
    mkdir ''${INCDIR}/m2

    cp include/alloca.h ''${INCDIR}/alloca.h
    cp include/ar.h ''${INCDIR}/ar.h
    cp include/argz.h ''${INCDIR}/argz.h
    cp include/assert.h ''${INCDIR}/assert.h
    cp include/ctype.h ''${INCDIR}/ctype.h
    cp include/dirent.h ''${INCDIR}/dirent.h
    cp include/dirstream.h ''${INCDIR}/dirstream.h
    cp include/dlfcn.h ''${INCDIR}/dlfcn.h
    cp include/endian.h ''${INCDIR}/endian.h
    cp include/errno.h ''${INCDIR}/errno.h
    cp include/fcntl.h ''${INCDIR}/fcntl.h
    cp include/features.h ''${INCDIR}/features.h
    cp include/float.h ''${INCDIR}/float.h
    cp include/getopt.h ''${INCDIR}/getopt.h
    cp include/grp.h ''${INCDIR}/grp.h
    cp include/inttypes.h ''${INCDIR}/inttypes.h
    cp include/libgen.h ''${INCDIR}/libgen.h
    cp include/limits.h ''${INCDIR}/limits.h
    cp include/locale.h ''${INCDIR}/locale.h
    cp include/math.h ''${INCDIR}/math.h
    cp include/memory.h ''${INCDIR}/memory.h
    cp include/pwd.h ''${INCDIR}/pwd.h
    cp include/setjmp.h ''${INCDIR}/setjmp.h
    cp include/signal.h ''${INCDIR}/signal.h
    cp include/stdarg.h ''${INCDIR}/stdarg.h
    cp include/stdbool.h ''${INCDIR}/stdbool.h
    cp include/stddef.h ''${INCDIR}/stddef.h
    cp include/stdint.h ''${INCDIR}/stdint.h
    cp include/stdio.h ''${INCDIR}/stdio.h
    cp include/stdlib.h ''${INCDIR}/stdlib.h
    cp include/stdnoreturn.h ''${INCDIR}/stdnoreturn.h
    cp include/string.h ''${INCDIR}/string.h
    cp include/strings.h ''${INCDIR}/strings.h
    cp include/termio.h ''${INCDIR}/termio.h
    cp include/time.h ''${INCDIR}/time.h
    cp include/unistd.h ''${INCDIR}/unistd.h

    cp include/arch/kernel-stat.h ''${INCDIR}/arch/kernel-stat.h
    cp include/arch/syscall.h ''${INCDIR}/arch/syscall.h
    cp include/linux/x86/signal.h ''${INCDIR}/arch/signal.h

    cp include/linux/syscall.h ''${INCDIR}/linux/syscall.h
    cp include/linux/x86/syscall.h ''${INCDIR}/linux/x86/syscall.h

    cp include/mes/builtins.h ''${INCDIR}/mes/builtins.h
    cp include/mes/cc.h ''${INCDIR}/mes/cc.h
    catm ''${INCDIR}/mes/config.h
    cp include/mes/constants.h ''${INCDIR}/mes/constants.h
    cp include/mes/lib.h ''${INCDIR}/mes/lib.h
    cp include/mes/lib-cc.h ''${INCDIR}/mes/lib-cc.h
    cp include/mes/lib-mini.h ''${INCDIR}/mes/lib-mini.h
    cp include/mes/mes.h ''${INCDIR}/mes/mes.h
    cp include/mes/symbols.h ''${INCDIR}/mes/symbols.h

    cp include/sys/cdefs.h ''${INCDIR}/sys/cdefs.h
    cp include/sys/dir.h ''${INCDIR}/sys/dir.h
    cp include/sys/file.h ''${INCDIR}/sys/file.h
    cp include/sys/ioctl.h ''${INCDIR}/sys/ioctl.h
    cp include/sys/mman.h ''${INCDIR}/sys/mman.h
    cp include/sys/param.h ''${INCDIR}/sys/param.h
    cp include/sys/resource.h ''${INCDIR}/sys/resource.h
    cp include/sys/select.h ''${INCDIR}/sys/select.h
    cp include/sys/stat.h ''${INCDIR}/sys/stat.h
    cp include/sys/timeb.h ''${INCDIR}/sys/timeb.h
    cp include/sys/time.h ''${INCDIR}/sys/time.h
    cp include/sys/times.h ''${INCDIR}/sys/times.h
    cp include/sys/types.h ''${INCDIR}/sys/types.h
    cp include/sys/ucontext.h ''${INCDIR}/sys/ucontext.h
    cp include/sys/user.h ''${INCDIR}/sys/user.h
    cp include/sys/wait.h ''${INCDIR}/sys/wait.h

    cp include/m2/types.h ''${INCDIR}/m2/types.h

    echo "==> mescc.scm installed"

    # ── Phase 3: Build Mes C library with mescc ───────────────────────

    MES_STACK=15000000
    MES_ARENA=30000000
    MES_MAX_ARENA=30000000
    MES_PREFIX=''${MES_SRC}
    MES_SOURCE=''${MES_SRC}
    MES_LIB=''${MES_SRC}/lib

    GUILE_LOAD_PATH=''${NYACC_DIR}/module:''${MES_SRC}/mes/module:''${MES_SRC}/module

    M1=''${POSIX_TOOLS}/bin/M1
    HEX2=''${POSIX_TOOLS}/bin/hex2
    BLOOD_ELF=''${POSIX_TOOLS}/bin/blood-elf

    MES=''${BINDIR}/mes-m2
    MESCC=''${BINDIR}/mescc.scm

    DEFS_M1=''${MES_SRC}/lib/m2/x86/x86_defs.M1
    ARCH_M1=''${MES_SRC}/lib/x86-mes/x86.M1

    cd ''${MES_SRC}

    # ── crt1.o ──
    echo "==> Building crt1.o..."
    ''${MES} --no-auto-compile -e main ''${MESCC} -- -D HAVE_CONFIG_H=1 -I ''${INCDIR} -I ''${INCDIR}/linux/x86 -c lib/linux/x86-mes-mescc/crt1.c -o lib/x86-mes/crt1.o

    ''${POSIX_TOOLS}/bin/M1 --little-endian --architecture x86 -f ''${DEFS_M1} -f ''${ARCH_M1} -f lib/x86-mes/crt1.s -o ''${LIBDIR}/crt1.o
    cp lib/x86-mes/crt1.s ''${LIBDIR}/crt1.s

    # ── libc-mini.a ──
    echo "==> Building libc-mini.a..."
    catm ''${TMPDIR}/libc-mini.c lib/mes/__init_io.c lib/mes/eputs.c lib/mes/oputs.c lib/mes/globals.c lib/stdlib/exit.c lib/linux/x86-mes-mescc/syscall.c lib/linux/x86-mes-mescc/_exit.c lib/linux/x86-mes-mescc/_write.c lib/stdlib/puts.c lib/string/strlen.c

    ''${MES} --no-auto-compile -e main ''${MESCC} -- -D HAVE_CONFIG_H=1 -I ''${INCDIR} -I ''${INCDIR}/linux/x86 -c ''${TMPDIR}/libc-mini.c

    ''${POSIX_TOOLS}/bin/M1 --little-endian --architecture x86 -f ''${DEFS_M1} -f ''${ARCH_M1} -f libc-mini.s -o ''${LIBDIR}/libc-mini.a
    cp libc-mini.s ''${LIBDIR}/libc-mini.s

    # ── libmescc.a ──
    echo "==> Building libmescc.a..."
    catm ''${TMPDIR}/libmescc.c lib/mes/globals.c lib/linux/x86-mes-mescc/syscall-internal.c

    ''${MES} --no-auto-compile -e main ''${MESCC} -- -D HAVE_CONFIG_H=1 -I ''${INCDIR} -I ''${INCDIR}/linux/x86 -c ''${TMPDIR}/libmescc.c

    ''${POSIX_TOOLS}/bin/M1 --little-endian --architecture x86 -f ''${DEFS_M1} -f ''${ARCH_M1} -f libmescc.s -o ''${LIBDIR}/libmescc.a
    cp libmescc.s ''${LIBDIR}/libmescc.s

    # ── libc.a ──
    echo "==> Building libc.a..."
    catm ''${TMPDIR}/libc.c lib/ctype/isnumber.c lib/mes/abtol.c lib/mes/cast.c lib/mes/eputc.c lib/mes/fdgetc.c lib/mes/fdputc.c lib/mes/fdputs.c lib/mes/fdungetc.c lib/mes/itoa.c lib/mes/ltoa.c lib/mes/ltoab.c lib/mes/mes_open.c lib/mes/ntoab.c lib/mes/oputc.c lib/mes/ultoa.c lib/mes/utoa.c lib/ctype/isdigit.c lib/ctype/isspace.c lib/ctype/isxdigit.c lib/mes/assert_msg.c lib/posix/write.c lib/stdlib/atoi.c lib/linux/lseek.c lib/mes/__assert_fail.c lib/mes/__buffered_read.c lib/mes/__mes_debug.c lib/posix/execv.c lib/posix/getcwd.c lib/posix/getenv.c lib/posix/isatty.c lib/posix/open.c lib/posix/buffered-read.c lib/posix/setenv.c lib/posix/wait.c lib/dirent/closedir.c lib/dirent/opendir.c lib/stdio/fgetc.c lib/stdio/fputc.c lib/stdio/fputs.c lib/stdio/getc.c lib/stdio/getchar.c lib/stdio/putc.c lib/stdio/putchar.c lib/stdio/ungetc.c lib/stdlib/calloc.c lib/stdlib/free.c lib/stdlib/realloc.c lib/string/memchr.c lib/string/memcmp.c lib/string/memcpy.c lib/string/memmove.c lib/string/memset.c lib/string/strcmp.c lib/string/strcpy.c lib/string/strncmp.c lib/posix/raise.c lib/linux/access.c lib/linux/brk.c lib/linux/chdir.c lib/linux/chmod.c lib/linux/clock_gettime.c lib/linux/dup.c lib/linux/dup2.c lib/linux/execve.c lib/linux/fork.c lib/linux/fsync.c lib/linux/_getcwd.c lib/linux/gettimeofday.c lib/linux/ioctl3.c lib/linux/malloc.c lib/linux/_open3.c lib/linux/_read.c lib/linux/readdir.c lib/linux/rename.c lib/linux/time.c lib/linux/umask.c lib/linux/uname.c lib/linux/unlink.c lib/linux/utimensat.c lib/linux/wait4.c lib/linux/waitpid.c lib/linux/x86-mes-mescc/syscall.c lib/linux/getpid.c lib/linux/kill.c lib/linux/pipe.c lib/linux/stat.c lib/linux/lstat.c lib/linux/mkdir.c lib/linux/rmdir.c lib/linux/link.c lib/linux/symlink.c lib/linux/close.c lib/linux/nanosleep.c lib/linux/fcntl.c lib/linux/fstat.c lib/linux/getdents.c

    ''${MES} --no-auto-compile -e main ''${MESCC} -- -D HAVE_CONFIG_H=1 -I ''${INCDIR} -I ''${INCDIR}/linux/x86 -c ''${TMPDIR}/libc.c

    ''${POSIX_TOOLS}/bin/M1 --little-endian --architecture x86 -f ''${DEFS_M1} -f ''${ARCH_M1} -f libc.s -o ''${TMPDIR}/libc.o
    catm ''${LIBDIR}/libc.a ''${LIBDIR}/libc-mini.a ''${TMPDIR}/libc.o
    catm ''${LIBDIR}/libc.s ''${LIBDIR}/libc-mini.s libc.s

    # ── libc+tcc.a ──
    echo "==> Building libc+tcc.a..."
    catm ''${TMPDIR}/libc+tcc.c lib/ctype/islower.c lib/ctype/isupper.c lib/ctype/tolower.c lib/ctype/toupper.c lib/mes/abtod.c lib/mes/dtoab.c lib/mes/search-path.c lib/posix/execvp.c lib/stdio/fclose.c lib/stdio/fdopen.c lib/stdio/ferror.c lib/stdio/fflush.c lib/stdio/fopen.c lib/stdio/fprintf.c lib/stdio/fread.c lib/stdio/fseek.c lib/stdio/ftell.c lib/stdio/fwrite.c lib/stdio/printf.c lib/stdio/remove.c lib/stdio/snprintf.c lib/stdio/sprintf.c lib/stdio/sscanf.c lib/stdio/vfprintf.c lib/stdio/vprintf.c lib/stdio/vsnprintf.c lib/stdio/vsprintf.c lib/stdio/vsscanf.c lib/stdlib/abort.c lib/stdlib/qsort.c lib/stdlib/strtod.c lib/stdlib/strtof.c lib/stdlib/strtol.c lib/stdlib/strtold.c lib/stdlib/strtoll.c lib/stdlib/strtoul.c lib/stdlib/strtoull.c lib/string/memmem.c lib/string/strcat.c lib/string/strchr.c lib/string/strlwr.c lib/string/strncpy.c lib/string/strrchr.c lib/string/strstr.c lib/string/strupr.c lib/stub/sigaction.c lib/stub/ldexp.c lib/stub/mprotect.c lib/stub/localtime.c lib/stub/sigemptyset.c lib/x86-mes-mescc/setjmp.c lib/linux/close.c lib/linux/rmdir.c lib/linux/stat.c

    ''${MES} --no-auto-compile -e main ''${MESCC} -- -D HAVE_CONFIG_H=1 -I ''${INCDIR} -I ''${INCDIR}/linux/x86 -c ''${TMPDIR}/libc+tcc.c

    ''${POSIX_TOOLS}/bin/M1 --little-endian --architecture x86 -f ''${DEFS_M1} -f ''${ARCH_M1} -f libc+tcc.s -o ''${TMPDIR}/libc+tcc.o
    catm ''${LIBDIR}/libc+tcc.a ''${LIBDIR}/libc.a ''${TMPDIR}/libc+tcc.o
    catm ''${LIBDIR}/libc+tcc.s ''${LIBDIR}/libc.s libc+tcc.s

    # ── Install M1/hex2 architecture files ─────────────────────────────
    mkdir ''${out}/lib/linux
    mkdir ''${out}/lib/linux/x86-mes
    mkdir ''${out}/lib/linux/x86-mes-mescc
    mkdir ''${out}/lib/linux/x86-mes-m2
    mkdir ''${out}/lib/linux/x86-mes-gcc
    mkdir ''${out}/lib/linux/m2
    mkdir ''${out}/lib/m2
    mkdir ''${out}/lib/m2/x86
    mkdir ''${out}/lib/x86-mes-mescc
    mkdir ''${out}/lib/x86-mes-gcc
    mkdir ''${out}/lib/mes
    mkdir ''${out}/lib/ctype
    mkdir ''${out}/lib/dirent
    mkdir ''${out}/lib/math
    mkdir ''${out}/lib/posix
    mkdir ''${out}/lib/stdio
    mkdir ''${out}/lib/stdlib
    mkdir ''${out}/lib/string
    mkdir ''${out}/lib/stub

    cp lib/linux/x86-mes/elf32-footer-single-main.hex2 ''${out}/lib/linux/x86-mes/elf32-footer-single-main.hex2
    cp lib/linux/x86-mes/elf32-header.hex2 ''${out}/lib/linux/x86-mes/elf32-header.hex2
    cp lib/x86-mes/x86.M1 ''${LIBDIR}/x86.M1

    # ── Install library source files ───────────────────────────────────
    # ctype/
    cp lib/ctype/isalnum.c ''${out}/lib/ctype/isalnum.c
    cp lib/ctype/isalpha.c ''${out}/lib/ctype/isalpha.c
    cp lib/ctype/isascii.c ''${out}/lib/ctype/isascii.c
    cp lib/ctype/iscntrl.c ''${out}/lib/ctype/iscntrl.c
    cp lib/ctype/isdigit.c ''${out}/lib/ctype/isdigit.c
    cp lib/ctype/isgraph.c ''${out}/lib/ctype/isgraph.c
    cp lib/ctype/islower.c ''${out}/lib/ctype/islower.c
    cp lib/ctype/isnumber.c ''${out}/lib/ctype/isnumber.c
    cp lib/ctype/isprint.c ''${out}/lib/ctype/isprint.c
    cp lib/ctype/ispunct.c ''${out}/lib/ctype/ispunct.c
    cp lib/ctype/isspace.c ''${out}/lib/ctype/isspace.c
    cp lib/ctype/isupper.c ''${out}/lib/ctype/isupper.c
    cp lib/ctype/isxdigit.c ''${out}/lib/ctype/isxdigit.c
    cp lib/ctype/tolower.c ''${out}/lib/ctype/tolower.c
    cp lib/ctype/toupper.c ''${out}/lib/ctype/toupper.c

    # dirent/
    cp lib/dirent/closedir.c ''${out}/lib/dirent/closedir.c
    cp lib/dirent/__getdirentries.c ''${out}/lib/dirent/__getdirentries.c
    cp lib/dirent/opendir.c ''${out}/lib/dirent/opendir.c

    # math/
    cp lib/math/ceil.c ''${out}/lib/math/ceil.c
    cp lib/math/fabs.c ''${out}/lib/math/fabs.c
    cp lib/math/floor.c ''${out}/lib/math/floor.c

    # mes/
    cp lib/mes/__assert_fail.c ''${out}/lib/mes/__assert_fail.c
    cp lib/mes/__buffered_read.c ''${out}/lib/mes/__buffered_read.c
    cp lib/mes/__init_io.c ''${out}/lib/mes/__init_io.c
    cp lib/mes/__mes_debug.c ''${out}/lib/mes/__mes_debug.c
    cp lib/mes/abtod.c ''${out}/lib/mes/abtod.c
    cp lib/mes/abtol.c ''${out}/lib/mes/abtol.c
    cp lib/mes/assert_msg.c ''${out}/lib/mes/assert_msg.c
    cp lib/mes/cast.c ''${out}/lib/mes/cast.c
    cp lib/mes/dtoab.c ''${out}/lib/mes/dtoab.c
    cp lib/mes/eputc.c ''${out}/lib/mes/eputc.c
    cp lib/mes/eputs.c ''${out}/lib/mes/eputs.c
    cp lib/mes/fdgetc.c ''${out}/lib/mes/fdgetc.c
    cp lib/mes/fdgets.c ''${out}/lib/mes/fdgets.c
    cp lib/mes/fdputc.c ''${out}/lib/mes/fdputc.c
    cp lib/mes/fdputs.c ''${out}/lib/mes/fdputs.c
    cp lib/mes/fdungetc.c ''${out}/lib/mes/fdungetc.c
    cp lib/mes/globals.c ''${out}/lib/mes/globals.c
    cp lib/mes/itoa.c ''${out}/lib/mes/itoa.c
    cp lib/mes/ltoab.c ''${out}/lib/mes/ltoab.c
    cp lib/mes/ltoa.c ''${out}/lib/mes/ltoa.c
    cp lib/mes/mes_open.c ''${out}/lib/mes/mes_open.c
    cp lib/mes/ntoab.c ''${out}/lib/mes/ntoab.c
    cp lib/mes/oputc.c ''${out}/lib/mes/oputc.c
    cp lib/mes/oputs.c ''${out}/lib/mes/oputs.c
    cp lib/mes/search-path.c ''${out}/lib/mes/search-path.c
    cp lib/mes/ultoa.c ''${out}/lib/mes/ultoa.c
    cp lib/mes/utoa.c ''${out}/lib/mes/utoa.c

    # posix/
    cp lib/posix/alarm.c ''${out}/lib/posix/alarm.c
    cp lib/posix/buffered-read.c ''${out}/lib/posix/buffered-read.c
    cp lib/posix/execl.c ''${out}/lib/posix/execl.c
    cp lib/posix/execlp.c ''${out}/lib/posix/execlp.c
    cp lib/posix/execv.c ''${out}/lib/posix/execv.c
    cp lib/posix/execvp.c ''${out}/lib/posix/execvp.c
    cp lib/posix/getcwd.c ''${out}/lib/posix/getcwd.c
    cp lib/posix/getenv.c ''${out}/lib/posix/getenv.c
    cp lib/posix/getopt.c ''${out}/lib/posix/getopt.c
    cp lib/posix/isatty.c ''${out}/lib/posix/isatty.c
    cp lib/posix/mktemp.c ''${out}/lib/posix/mktemp.c
    cp lib/posix/open.c ''${out}/lib/posix/open.c
    cp lib/posix/pathconf.c ''${out}/lib/posix/pathconf.c
    cp lib/posix/raise.c ''${out}/lib/posix/raise.c
    cp lib/posix/sbrk.c ''${out}/lib/posix/sbrk.c
    cp lib/posix/setenv.c ''${out}/lib/posix/setenv.c
    cp lib/posix/sleep.c ''${out}/lib/posix/sleep.c
    cp lib/posix/unsetenv.c ''${out}/lib/posix/unsetenv.c
    cp lib/posix/wait.c ''${out}/lib/posix/wait.c
    cp lib/posix/write.c ''${out}/lib/posix/write.c

    # stdio/
    cp lib/stdio/clearerr.c ''${out}/lib/stdio/clearerr.c
    cp lib/stdio/fclose.c ''${out}/lib/stdio/fclose.c
    cp lib/stdio/fdopen.c ''${out}/lib/stdio/fdopen.c
    cp lib/stdio/feof.c ''${out}/lib/stdio/feof.c
    cp lib/stdio/ferror.c ''${out}/lib/stdio/ferror.c
    cp lib/stdio/fflush.c ''${out}/lib/stdio/fflush.c
    cp lib/stdio/fgetc.c ''${out}/lib/stdio/fgetc.c
    cp lib/stdio/fgets.c ''${out}/lib/stdio/fgets.c
    cp lib/stdio/fileno.c ''${out}/lib/stdio/fileno.c
    cp lib/stdio/fopen.c ''${out}/lib/stdio/fopen.c
    cp lib/stdio/fprintf.c ''${out}/lib/stdio/fprintf.c
    cp lib/stdio/fputc.c ''${out}/lib/stdio/fputc.c
    cp lib/stdio/fputs.c ''${out}/lib/stdio/fputs.c
    cp lib/stdio/fread.c ''${out}/lib/stdio/fread.c
    cp lib/stdio/freopen.c ''${out}/lib/stdio/freopen.c
    cp lib/stdio/fscanf.c ''${out}/lib/stdio/fscanf.c
    cp lib/stdio/fseek.c ''${out}/lib/stdio/fseek.c
    cp lib/stdio/ftell.c ''${out}/lib/stdio/ftell.c
    cp lib/stdio/fwrite.c ''${out}/lib/stdio/fwrite.c
    cp lib/stdio/getc.c ''${out}/lib/stdio/getc.c
    cp lib/stdio/getchar.c ''${out}/lib/stdio/getchar.c
    cp lib/stdio/perror.c ''${out}/lib/stdio/perror.c
    cp lib/stdio/printf.c ''${out}/lib/stdio/printf.c
    cp lib/stdio/putc.c ''${out}/lib/stdio/putc.c
    cp lib/stdio/putchar.c ''${out}/lib/stdio/putchar.c
    cp lib/stdio/remove.c ''${out}/lib/stdio/remove.c
    cp lib/stdio/snprintf.c ''${out}/lib/stdio/snprintf.c
    cp lib/stdio/sprintf.c ''${out}/lib/stdio/sprintf.c
    cp lib/stdio/sscanf.c ''${out}/lib/stdio/sscanf.c
    cp lib/stdio/ungetc.c ''${out}/lib/stdio/ungetc.c
    cp lib/stdio/vfprintf.c ''${out}/lib/stdio/vfprintf.c
    cp lib/stdio/vfscanf.c ''${out}/lib/stdio/vfscanf.c
    cp lib/stdio/vprintf.c ''${out}/lib/stdio/vprintf.c
    cp lib/stdio/vsnprintf.c ''${out}/lib/stdio/vsnprintf.c
    cp lib/stdio/vsprintf.c ''${out}/lib/stdio/vsprintf.c
    cp lib/stdio/vsscanf.c ''${out}/lib/stdio/vsscanf.c

    # stdlib/
    cp lib/stdlib/abort.c ''${out}/lib/stdlib/abort.c
    cp lib/stdlib/abs.c ''${out}/lib/stdlib/abs.c
    cp lib/stdlib/alloca.c ''${out}/lib/stdlib/alloca.c
    cp lib/stdlib/atexit.c ''${out}/lib/stdlib/atexit.c
    cp lib/stdlib/atof.c ''${out}/lib/stdlib/atof.c
    cp lib/stdlib/atoi.c ''${out}/lib/stdlib/atoi.c
    cp lib/stdlib/atol.c ''${out}/lib/stdlib/atol.c
    cp lib/stdlib/calloc.c ''${out}/lib/stdlib/calloc.c
    cp lib/stdlib/__exit.c ''${out}/lib/stdlib/__exit.c
    cp lib/stdlib/exit.c ''${out}/lib/stdlib/exit.c
    cp lib/stdlib/free.c ''${out}/lib/stdlib/free.c
    cp lib/stdlib/mbstowcs.c ''${out}/lib/stdlib/mbstowcs.c
    cp lib/stdlib/puts.c ''${out}/lib/stdlib/puts.c
    cp lib/stdlib/qsort.c ''${out}/lib/stdlib/qsort.c
    cp lib/stdlib/realloc.c ''${out}/lib/stdlib/realloc.c
    cp lib/stdlib/strtod.c ''${out}/lib/stdlib/strtod.c
    cp lib/stdlib/strtof.c ''${out}/lib/stdlib/strtof.c
    cp lib/stdlib/strtol.c ''${out}/lib/stdlib/strtol.c
    cp lib/stdlib/strtold.c ''${out}/lib/stdlib/strtold.c
    cp lib/stdlib/strtoll.c ''${out}/lib/stdlib/strtoll.c
    cp lib/stdlib/strtoul.c ''${out}/lib/stdlib/strtoul.c
    cp lib/stdlib/strtoull.c ''${out}/lib/stdlib/strtoull.c

    # string/
    cp lib/string/bcmp.c ''${out}/lib/string/bcmp.c
    cp lib/string/bcopy.c ''${out}/lib/string/bcopy.c
    cp lib/string/bzero.c ''${out}/lib/string/bzero.c
    cp lib/string/index.c ''${out}/lib/string/index.c
    cp lib/string/memchr.c ''${out}/lib/string/memchr.c
    cp lib/string/memcmp.c ''${out}/lib/string/memcmp.c
    cp lib/string/memcpy.c ''${out}/lib/string/memcpy.c
    cp lib/string/memmem.c ''${out}/lib/string/memmem.c
    cp lib/string/memmove.c ''${out}/lib/string/memmove.c
    cp lib/string/memset.c ''${out}/lib/string/memset.c
    cp lib/string/rindex.c ''${out}/lib/string/rindex.c
    cp lib/string/strcat.c ''${out}/lib/string/strcat.c
    cp lib/string/strchr.c ''${out}/lib/string/strchr.c
    cp lib/string/strcmp.c ''${out}/lib/string/strcmp.c
    cp lib/string/strcpy.c ''${out}/lib/string/strcpy.c
    cp lib/string/strcspn.c ''${out}/lib/string/strcspn.c
    cp lib/string/strdup.c ''${out}/lib/string/strdup.c
    cp lib/string/strerror.c ''${out}/lib/string/strerror.c
    cp lib/string/strlen.c ''${out}/lib/string/strlen.c
    cp lib/string/strlwr.c ''${out}/lib/string/strlwr.c
    cp lib/string/strncat.c ''${out}/lib/string/strncat.c
    cp lib/string/strncmp.c ''${out}/lib/string/strncmp.c
    cp lib/string/strncpy.c ''${out}/lib/string/strncpy.c
    cp lib/string/strpbrk.c ''${out}/lib/string/strpbrk.c
    cp lib/string/strrchr.c ''${out}/lib/string/strrchr.c
    cp lib/string/strspn.c ''${out}/lib/string/strspn.c
    cp lib/string/strstr.c ''${out}/lib/string/strstr.c
    cp lib/string/strupr.c ''${out}/lib/string/strupr.c

    # linux syscalls
    cp lib/linux/x86-mes-gcc/syscall.c ''${out}/lib/linux/x86-mes-gcc/syscall.c
    cp lib/linux/x86-mes-gcc/_exit.c ''${out}/lib/linux/x86-mes-gcc/_exit.c
    cp lib/linux/x86-mes-gcc/_write.c ''${out}/lib/linux/x86-mes-gcc/_write.c
    cp lib/linux/x86-mes-gcc/crt1.c ''${out}/lib/linux/x86-mes-gcc/crt1.c
    cp lib/linux/x86-mes-gcc/crtn.c ''${out}/lib/linux/x86-mes-gcc/crtn.c
    cp lib/linux/x86-mes-gcc/crti.c ''${out}/lib/linux/x86-mes-gcc/crti.c

    # linux syscalls (generic)
    cp lib/linux/_open3.c ''${out}/lib/linux/_open3.c
    cp lib/linux/_read.c ''${out}/lib/linux/_read.c
    cp lib/linux/access.c ''${out}/lib/linux/access.c
    cp lib/linux/brk.c ''${out}/lib/linux/brk.c
    cp lib/linux/chdir.c ''${out}/lib/linux/chdir.c
    cp lib/linux/chmod.c ''${out}/lib/linux/chmod.c
    cp lib/linux/clock_gettime.c ''${out}/lib/linux/clock_gettime.c
    cp lib/linux/close.c ''${out}/lib/linux/close.c
    cp lib/linux/dup.c ''${out}/lib/linux/dup.c
    cp lib/linux/dup2.c ''${out}/lib/linux/dup2.c
    cp lib/linux/execve.c ''${out}/lib/linux/execve.c
    cp lib/linux/fcntl.c ''${out}/lib/linux/fcntl.c
    cp lib/linux/fork.c ''${out}/lib/linux/fork.c
    cp lib/linux/fstat.c ''${out}/lib/linux/fstat.c
    cp lib/linux/fsync.c ''${out}/lib/linux/fsync.c
    cp lib/linux/_getcwd.c ''${out}/lib/linux/_getcwd.c
    cp lib/linux/getdents.c ''${out}/lib/linux/getdents.c
    cp lib/linux/getegid.c ''${out}/lib/linux/getegid.c
    cp lib/linux/geteuid.c ''${out}/lib/linux/geteuid.c
    cp lib/linux/getgid.c ''${out}/lib/linux/getgid.c
    cp lib/linux/getpid.c ''${out}/lib/linux/getpid.c
    cp lib/linux/getppid.c ''${out}/lib/linux/getppid.c
    cp lib/linux/getrusage.c ''${out}/lib/linux/getrusage.c
    cp lib/linux/gettimeofday.c ''${out}/lib/linux/gettimeofday.c
    cp lib/linux/getuid.c ''${out}/lib/linux/getuid.c
    cp lib/linux/ioctl.c ''${out}/lib/linux/ioctl.c
    cp lib/linux/ioctl3.c ''${out}/lib/linux/ioctl3.c
    cp lib/linux/kill.c ''${out}/lib/linux/kill.c
    cp lib/linux/link.c ''${out}/lib/linux/link.c
    cp lib/linux/lseek.c ''${out}/lib/linux/lseek.c
    cp lib/linux/lstat.c ''${out}/lib/linux/lstat.c
    cp lib/linux/malloc.c ''${out}/lib/linux/malloc.c
    cp lib/linux/mkdir.c ''${out}/lib/linux/mkdir.c
    cp lib/linux/mknod.c ''${out}/lib/linux/mknod.c
    cp lib/linux/nanosleep.c ''${out}/lib/linux/nanosleep.c
    cp lib/linux/pipe.c ''${out}/lib/linux/pipe.c
    cp lib/linux/readdir.c ''${out}/lib/linux/readdir.c
    cp lib/linux/readlink.c ''${out}/lib/linux/readlink.c
    cp lib/linux/rename.c ''${out}/lib/linux/rename.c
    cp lib/linux/rmdir.c ''${out}/lib/linux/rmdir.c
    cp lib/linux/setgid.c ''${out}/lib/linux/setgid.c
    cp lib/linux/settimer.c ''${out}/lib/linux/settimer.c
    cp lib/linux/setuid.c ''${out}/lib/linux/setuid.c
    cp lib/linux/signal.c ''${out}/lib/linux/signal.c
    cp lib/linux/sigprogmask.c ''${out}/lib/linux/sigprogmask.c
    cp lib/linux/stat.c ''${out}/lib/linux/stat.c
    cp lib/linux/symlink.c ''${out}/lib/linux/symlink.c
    cp lib/linux/time.c ''${out}/lib/linux/time.c
    cp lib/linux/unlink.c ''${out}/lib/linux/unlink.c
    cp lib/linux/wait4.c ''${out}/lib/linux/wait4.c
    cp lib/linux/waitpid.c ''${out}/lib/linux/waitpid.c

    # stub functions
    cp lib/stub/atan2.c ''${out}/lib/stub/atan2.c
    cp lib/stub/bsearch.c ''${out}/lib/stub/bsearch.c
    cp lib/stub/chown.c ''${out}/lib/stub/chown.c
    cp lib/stub/__cleanup.c ''${out}/lib/stub/__cleanup.c
    cp lib/stub/cos.c ''${out}/lib/stub/cos.c
    cp lib/stub/ctime.c ''${out}/lib/stub/ctime.c
    cp lib/stub/exp.c ''${out}/lib/stub/exp.c
    cp lib/stub/fpurge.c ''${out}/lib/stub/fpurge.c
    cp lib/stub/freadahead.c ''${out}/lib/stub/freadahead.c
    cp lib/stub/frexp.c ''${out}/lib/stub/frexp.c
    cp lib/stub/getgrgid.c ''${out}/lib/stub/getgrgid.c
    cp lib/stub/getgrnam.c ''${out}/lib/stub/getgrnam.c
    cp lib/stub/getlogin.c ''${out}/lib/stub/getlogin.c
    cp lib/stub/getpgid.c ''${out}/lib/stub/getpgid.c
    cp lib/stub/getpgrp.c ''${out}/lib/stub/getpgrp.c
    cp lib/stub/getpwnam.c ''${out}/lib/stub/getpwnam.c
    cp lib/stub/getpwuid.c ''${out}/lib/stub/getpwuid.c
    cp lib/stub/gmtime.c ''${out}/lib/stub/gmtime.c
    cp lib/stub/ldexp.c ''${out}/lib/stub/ldexp.c
    cp lib/stub/localtime.c ''${out}/lib/stub/localtime.c
    cp lib/stub/log.c ''${out}/lib/stub/log.c
    cp lib/stub/mktime.c ''${out}/lib/stub/mktime.c
    cp lib/stub/modf.c ''${out}/lib/stub/modf.c
    cp lib/stub/mprotect.c ''${out}/lib/stub/mprotect.c
    cp lib/stub/pclose.c ''${out}/lib/stub/pclose.c
    cp lib/stub/popen.c ''${out}/lib/stub/popen.c
    cp lib/stub/pow.c ''${out}/lib/stub/pow.c
    cp lib/stub/putenv.c ''${out}/lib/stub/putenv.c
    cp lib/stub/rand.c ''${out}/lib/stub/rand.c
    cp lib/stub/realpath.c ''${out}/lib/stub/realpath.c
    cp lib/stub/rewind.c ''${out}/lib/stub/rewind.c
    cp lib/stub/setbuf.c ''${out}/lib/stub/setbuf.c
    cp lib/stub/setgrent.c ''${out}/lib/stub/setgrent.c
    cp lib/stub/setlocale.c ''${out}/lib/stub/setlocale.c
    cp lib/stub/setvbuf.c ''${out}/lib/stub/setvbuf.c
    cp lib/stub/sigaction.c ''${out}/lib/stub/sigaction.c
    cp lib/stub/sigaddset.c ''${out}/lib/stub/sigaddset.c
    cp lib/stub/sigblock.c ''${out}/lib/stub/sigblock.c
    cp lib/stub/sigdelset.c ''${out}/lib/stub/sigdelset.c
    cp lib/stub/sigemptyset.c ''${out}/lib/stub/sigemptyset.c
    cp lib/stub/sigsetmask.c ''${out}/lib/stub/sigsetmask.c
    cp lib/stub/sin.c ''${out}/lib/stub/sin.c
    cp lib/stub/sys_siglist.c ''${out}/lib/stub/sys_siglist.c
    cp lib/stub/system.c ''${out}/lib/stub/system.c
    cp lib/stub/sqrt.c ''${out}/lib/stub/sqrt.c
    cp lib/stub/strftime.c ''${out}/lib/stub/strftime.c
    cp lib/stub/times.c ''${out}/lib/stub/times.c
    cp lib/stub/ttyname.c ''${out}/lib/stub/ttyname.c
    cp lib/stub/umask.c ''${out}/lib/stub/umask.c
    cp lib/stub/utime.c ''${out}/lib/stub/utime.c

    # arch-specific
    cp lib/x86-mes-gcc/setjmp.c ''${out}/lib/x86-mes-gcc/setjmp.c

    # libtcc1.c (Mes's pure-C version)
    cp lib/libtcc1.c ''${out}/lib/libtcc1.c

    # M1 architecture definitions
    cp lib/m2/x86/x86_defs.M1 ''${out}/lib/m2/x86/x86_defs.M1
    cp lib/x86-mes/x86.M1 ''${out}/lib/x86-mes/x86.M1

    echo "GNU Mes 0.27.1 built successfully (x86/i386)"
    echo "mes-m2 binary: ''${BINDIR}/mes-m2"
    echo "mescc driver: ''${BINDIR}/mescc.scm"
    echo "Libraries in: ''${LIBDIR}"
  '';

  mes = builtins.derivation {
    name = "mes-0.27.1";
    inherit system;
    builder = "${seeds.kaemNix}";
    passAsFile = ["buildScript"];
    # Single-line buildScript: kaemNix reads this via $buildScriptPath,
    # forks/execs full kaem to run the real build script.
    buildScript = "${posix-tools}/bin/kaem --verbose --strict --file ${buildKaem}\n";
    # Derivation paths passed as env vars for full kaem ${VAR} expansion
    POSIX_TOOLS = "${posix-tools}";
    MES_SRC_TAR = "${mesSrc}";
    NYACC_TAR = "${nyaccSrc}";
  };
in
  mes
  // {
    version = "0.27.1";

    passthru = {
      src.mes = mesSrc;
      src.nyacc = nyaccSrc;
    };

    meta = {
      description = "GNU Mes -- Scheme interpreter and MesCC C compiler";
      homepage = "https://www.gnu.org/software/mes/";
      license = "GPL-3.0-or-later";
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
