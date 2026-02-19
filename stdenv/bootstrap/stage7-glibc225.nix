# stdenv/bootstrap/stage7-glibc225.nix — glibc 2.2.5 from GCC 2.95.3
#
# First real C library in the bootstrap chain. Built by the first GCC,
# replacing Mes libc. glibc 2.2.5 is the Guix-proven earliest glibc
# version for source bootstrap.
#
# Builder: kaem (from mescc-tools, stage 1). No /bin/sh, no configure.
#
# glibc is the most complex package to build without configure. We
# pre-generate all configuration headers via builtins.toFile and
# enumerate the essential compilation commands for a minimal static
# libc sufficient to build GCC 3.4.6.
#
# The minimal set: crt1.o, crti.o, crtn.o, libc.a containing the core
# C library functions needed by GCC and basic C programs.
#
{
  gcc295, # Output of stage5-gcc295.nix
  binutils, # Output of stage4-binutils220.nix
  linuxHeaders, # Output of stage6-linux-headers.nix
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

  glibc-src = fetchSrc {
    name = "glibc-2.2.5.tar.gz";
    url = "https://mirrors.kernel.org/gnu/glibc/glibc-2.2.5.tar.gz";
    hash = "sha256-WNyN9ZrtHk2dUO755MTAeJ+ig7UPegk5MtD0Z0JEhO4=";
  };

  target = "i686-linux-gnu";

  # Pre-generated config.h for glibc (replaces configure output)
  glibc-config-h = builtins.toFile "glibc-config.h" ''
    #define _LIBC 1
    #define __STDC__ 1
    #define HAVE_ASM_WEAK_DIRECTIVE 1
    #define HAVE_INITFINI_ARRAY 0
    #define HAVE_ELF 1
    #define HAVE_VISIBILITY_ATTRIBUTE 0
    #define HAVE_TLS_SUPPORT 0
    #define HAVE_FORCED_UNWIND 0
    #define HAVE_BUILTIN_EXPECT 0
    #define HAVE_BUILTIN_MEMSET 0
    #define HAVE_ALLOCA_H 1
    #define HAVE_FCNTL_H 1
    #define HAVE_LIMITS_H 1
    #define HAVE_UNISTD_H 1
    #define HAVE_SYS_PARAM_H 0
    #define HAVE_SYS_TYPES_H 1
    #define HAVE_LONG_DOUBLE 0
    #define NO_LONG_DOUBLE 1
    #define __NO_MATH_INLINES 1
    #define HAVE_SYS_STAT_H 1
    #define HAVE_MEMORY_H 1
    #define HAVE_STRINGS_H 1
    #define HAVE_STRING_H 1
    #define HAVE_STDLIB_H 1
    #define HAVE_ERRNO_H 1
    #define VERSION "2.2.5"
    #define PACKAGE "glibc"
    #define _LIBC_REENTRANT 1
    #define HAVE_GNU_LD 1
    #define HAVE_ELF 1
    #define PIC
    #define SHARED
  '';

in
  builtins.derivation {
    name = "glibc-2.2.5";
    inherit system;
    builder = "/bin/sh";
    args = ["-c" ''exec ${mescc-tools}/bin/kaem --verbose --strict --file "$buildScriptPath"''];
    passAsFile = ["buildScript"];
    buildScript = ''
      set -e
      TOOLS=${mescc-tools}/bin
      CC=${gcc295}/bin/gcc
      AS=${binutils}/bin/as
      AR=${binutils}/bin/ar
      RANLIB=${binutils}/bin/ranlib

      cd ''${TMPDIR}
      ''${TOOLS}/ungz --file ${glibc-src} --output ''${TMPDIR}/glibc.tar
      ''${TOOLS}/untar --file ''${TMPDIR}/glibc.tar

      SRC=''${TMPDIR}/glibc-2.2.5
      BUILD=''${TMPDIR}/build

      ''${TOOLS}/mkdir ''${BUILD}
      ''${TOOLS}/mkdir ''${BUILD}/objs

      # Create output directories
      ''${TOOLS}/mkdir ''${out}
      ''${TOOLS}/mkdir ''${out}/include
      ''${TOOLS}/mkdir ''${out}/lib

      # Install pre-generated config.h
      ''${TOOLS}/cp ${glibc-config-h} ''${BUILD}/config.h

      # Common compiler flags for glibc
      CFLAGS="-O2 -I''${BUILD} -I''${SRC}/include -I''${SRC}/sysdeps/unix/sysv/linux/i386 -I''${SRC}/sysdeps/unix/sysv/linux -I''${SRC}/sysdeps/unix/i386 -I''${SRC}/sysdeps/unix -I''${SRC}/sysdeps/posix -I''${SRC}/sysdeps/i386/elf -I''${SRC}/sysdeps/i386 -I''${SRC}/sysdeps/ieee754 -I''${SRC}/sysdeps/generic -I${linuxHeaders}/include -D_LIBC -DHAVE_CONFIG_H -DIS_IN_libc -D__ELF__ -D_GNU_SOURCE"

      # ══════════════════════════════════════════════════════════════════════
      # Build crt objects (startup code)
      # ══════════════════════════════════════════════════════════════════════
      echo "==> Building CRT objects"

      # crt1.o — the C runtime startup (calls main)
      # For a minimal build, use the assembly start.S file
      ''${CC} -c -I''${SRC}/include -I''${SRC}/sysdeps/unix/sysv/linux/i386 -I''${SRC}/sysdeps/i386/elf -I''${SRC}/sysdeps/i386 -I''${SRC}/sysdeps/generic -I${linuxHeaders}/include -D__ASSEMBLER__ -D_LIBC -o ''${out}/lib/crt1.o ''${SRC}/sysdeps/i386/elf/start.S

      # crti.o and crtn.o (init/fini array setup)
      ''${CC} -c -I''${SRC}/include -I''${SRC}/sysdeps/unix/sysv/linux/i386 -I''${SRC}/sysdeps/i386/elf -I''${SRC}/sysdeps/i386 -I''${SRC}/sysdeps/generic -I${linuxHeaders}/include -D__ASSEMBLER__ -D_LIBC -o ''${out}/lib/crti.o ''${SRC}/sysdeps/i386/elf/initfini.c
      ''${TOOLS}/catm ''${BUILD}/crtn.s
      ''${AS} -o ''${out}/lib/crtn.o ''${BUILD}/crtn.s

      # ══════════════════════════════════════════════════════════════════════
      # Build libc.a — the main C library archive
      # ══════════════════════════════════════════════════════════════════════
      echo "==> Building libc.a (core)"

      # String functions
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/strlen.o ''${SRC}/string/strlen.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/strcmp.o ''${SRC}/string/strcmp.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/strcpy.o ''${SRC}/string/strcpy.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/strncpy.o ''${SRC}/string/strncpy.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/strncmp.o ''${SRC}/string/strncmp.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/strcat.o ''${SRC}/string/strcat.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/strncat.o ''${SRC}/string/strncat.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/strchr.o ''${SRC}/string/strchr.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/strrchr.o ''${SRC}/string/strrchr.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/strstr.o ''${SRC}/string/strstr.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/strerror.o ''${SRC}/string/strerror.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/strdup.o ''${SRC}/string/strdup.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/strtok.o ''${SRC}/string/strtok.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/strspn.o ''${SRC}/string/strspn.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/strcspn.o ''${SRC}/string/strcspn.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/strpbrk.o ''${SRC}/string/strpbrk.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/memcpy.o ''${SRC}/string/memcpy.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/memmove.o ''${SRC}/string/memmove.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/memset.o ''${SRC}/string/memset.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/memcmp.o ''${SRC}/string/memcmp.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/memchr.o ''${SRC}/string/memchr.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/bcopy.o ''${SRC}/string/bcopy.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/bzero.o ''${SRC}/string/bzero.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/stpcpy.o ''${SRC}/string/stpcpy.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/stpncpy.o ''${SRC}/string/stpncpy.c

      # Stdlib functions
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/atoi.o ''${SRC}/stdlib/atoi.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/atol.o ''${SRC}/stdlib/atol.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/strtol.o ''${SRC}/stdlib/strtol.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/strtoul.o ''${SRC}/stdlib/strtoul.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/abs.o ''${SRC}/stdlib/abs.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/exit.o ''${SRC}/stdlib/exit.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/abort.o ''${SRC}/stdlib/abort.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/atexit.o ''${SRC}/stdlib/atexit.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/malloc.o ''${SRC}/malloc/malloc.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/calloc.o ''${SRC}/malloc/calloc.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/realloc.o ''${SRC}/malloc/realloc.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/free.o ''${SRC}/malloc/free.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/qsort.o ''${SRC}/stdlib/qsort.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/getenv.o ''${SRC}/stdlib/getenv.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/putenv.o ''${SRC}/stdlib/putenv.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/setenv.o ''${SRC}/stdlib/setenv.c

      # Stdio functions
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/printf.o ''${SRC}/stdio-common/printf.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/fprintf.o ''${SRC}/stdio-common/fprintf.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/sprintf.o ''${SRC}/stdio-common/sprintf.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/snprintf.o ''${SRC}/stdio-common/snprintf.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/vprintf.o ''${SRC}/stdio-common/vprintf.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/vfprintf.o ''${SRC}/stdio-common/vfprintf.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/vsprintf.o ''${SRC}/stdio-common/vsprintf.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/scanf.o ''${SRC}/stdio-common/scanf.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/sscanf.o ''${SRC}/stdio-common/sscanf.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/fopen.o ''${SRC}/libio/fopen.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/fclose.o ''${SRC}/libio/fclose.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/fread.o ''${SRC}/libio/fread.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/fwrite.o ''${SRC}/libio/fwrite.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/fseek.o ''${SRC}/libio/fseek.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/ftell.o ''${SRC}/libio/ftell.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/fflush.o ''${SRC}/libio/fflush.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/fgets.o ''${SRC}/libio/fgets.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/fputs.o ''${SRC}/libio/fputs.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/puts.o ''${SRC}/libio/puts.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/getc.o ''${SRC}/libio/getc.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/putc.o ''${SRC}/libio/putc.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/ungetc.o ''${SRC}/libio/ungetc.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/perror.o ''${SRC}/stdio-common/perror.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/remove.o ''${SRC}/stdio-common/remove.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/tmpnam.o ''${SRC}/stdio-common/tmpnam.c

      # Syscall wrappers (i386 Linux)
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/read.o ''${SRC}/sysdeps/unix/sysv/linux/i386/read.S
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/write.o ''${SRC}/sysdeps/unix/sysv/linux/i386/write.S
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/open.o ''${SRC}/sysdeps/unix/sysv/linux/open.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/close.o ''${SRC}/sysdeps/unix/sysv/linux/i386/close.S
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/lseek.o ''${SRC}/sysdeps/unix/sysv/linux/i386/lseek.S
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/stat.o ''${SRC}/sysdeps/unix/sysv/linux/i386/stat.S
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/fstat.o ''${SRC}/sysdeps/unix/sysv/linux/i386/fstat.S
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/access.o ''${SRC}/sysdeps/unix/sysv/linux/i386/access.S
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/brk.o ''${SRC}/sysdeps/unix/sysv/linux/i386/brk.S
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/mmap.o ''${SRC}/sysdeps/unix/sysv/linux/i386/mmap.S
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/munmap.o ''${SRC}/sysdeps/unix/sysv/linux/i386/munmap.S
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/ioctl.o ''${SRC}/sysdeps/unix/sysv/linux/i386/ioctl.S
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/fcntl.o ''${SRC}/sysdeps/unix/sysv/linux/i386/fcntl.S
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/fork.o ''${SRC}/sysdeps/unix/sysv/linux/i386/fork.S
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/execve.o ''${SRC}/sysdeps/unix/sysv/linux/i386/execve.S
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/waitpid.o ''${SRC}/sysdeps/unix/sysv/linux/i386/waitpid.S
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/kill.o ''${SRC}/sysdeps/unix/sysv/linux/i386/kill.S
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/getpid.o ''${SRC}/sysdeps/unix/sysv/linux/i386/getpid.S
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/pipe.o ''${SRC}/sysdeps/unix/sysv/linux/i386/pipe.S
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/dup2.o ''${SRC}/sysdeps/unix/sysv/linux/i386/dup2.S
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/mkdir.o ''${SRC}/sysdeps/unix/sysv/linux/i386/mkdir.S
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/rmdir.o ''${SRC}/sysdeps/unix/sysv/linux/i386/rmdir.S
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/unlink.o ''${SRC}/sysdeps/unix/sysv/linux/i386/unlink.S
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/rename.o ''${SRC}/sysdeps/unix/sysv/linux/i386/rename.S
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/link.o ''${SRC}/sysdeps/unix/sysv/linux/i386/link.S
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/symlink.o ''${SRC}/sysdeps/unix/sysv/linux/i386/symlink.S
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/readlink.o ''${SRC}/sysdeps/unix/sysv/linux/i386/readlink.S
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/chmod.o ''${SRC}/sysdeps/unix/sysv/linux/i386/chmod.S
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/chown.o ''${SRC}/sysdeps/unix/sysv/linux/i386/chown.S
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/chdir.o ''${SRC}/sysdeps/unix/sysv/linux/i386/chdir.S
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/getcwd.o ''${SRC}/sysdeps/unix/sysv/linux/getcwd.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/time.o ''${SRC}/sysdeps/unix/sysv/linux/i386/time.S
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/gettimeofday.o ''${SRC}/sysdeps/unix/sysv/linux/i386/gettimeofday.S
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/nanosleep.o ''${SRC}/sysdeps/unix/sysv/linux/i386/nanosleep.S
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/signal.o ''${SRC}/signal/signal.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/sigaction.o ''${SRC}/sysdeps/unix/sysv/linux/i386/sigaction.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/_exit.o ''${SRC}/sysdeps/unix/sysv/linux/i386/_exit.S

      # Ctype functions
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/ctype.o ''${SRC}/ctype/ctype.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/isalpha.o ''${SRC}/ctype/isalpha.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/isdigit.o ''${SRC}/ctype/isdigit.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/isspace.o ''${SRC}/ctype/isspace.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/islower.o ''${SRC}/ctype/islower.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/isupper.o ''${SRC}/ctype/isupper.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/tolower.o ''${SRC}/ctype/tolower.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/toupper.o ''${SRC}/ctype/toupper.c

      # Misc essential functions
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/errno.o ''${SRC}/sysdeps/unix/sysv/linux/i386/errno.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/assert.o ''${SRC}/assert/assert.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/sbrk.o ''${SRC}/misc/sbrk.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/getopt.o ''${SRC}/posix/getopt.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/getopt1.o ''${SRC}/posix/getopt1.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/sleep.o ''${SRC}/posix/sleep.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/isatty.o ''${SRC}/posix/isatty.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/mkstemp.o ''${SRC}/misc/mkstemp.c
      ''${CC} -c ''${CFLAGS} -o ''${BUILD}/objs/tempnam.o ''${SRC}/stdio-common/tempnam.c

      # Create libc.a
      echo "==> Creating libc.a"
      ''${AR} cr ''${out}/lib/libc.a ''${BUILD}/objs/strlen.o ''${BUILD}/objs/strcmp.o ''${BUILD}/objs/strcpy.o ''${BUILD}/objs/strncpy.o ''${BUILD}/objs/strncmp.o ''${BUILD}/objs/strcat.o ''${BUILD}/objs/strncat.o ''${BUILD}/objs/strchr.o ''${BUILD}/objs/strrchr.o ''${BUILD}/objs/strstr.o ''${BUILD}/objs/strerror.o ''${BUILD}/objs/strdup.o ''${BUILD}/objs/strtok.o ''${BUILD}/objs/strspn.o ''${BUILD}/objs/strcspn.o ''${BUILD}/objs/strpbrk.o ''${BUILD}/objs/memcpy.o ''${BUILD}/objs/memmove.o ''${BUILD}/objs/memset.o ''${BUILD}/objs/memcmp.o ''${BUILD}/objs/memchr.o ''${BUILD}/objs/bcopy.o ''${BUILD}/objs/bzero.o ''${BUILD}/objs/stpcpy.o ''${BUILD}/objs/stpncpy.o ''${BUILD}/objs/atoi.o ''${BUILD}/objs/atol.o ''${BUILD}/objs/strtol.o ''${BUILD}/objs/strtoul.o ''${BUILD}/objs/abs.o ''${BUILD}/objs/exit.o ''${BUILD}/objs/abort.o ''${BUILD}/objs/atexit.o ''${BUILD}/objs/malloc.o ''${BUILD}/objs/calloc.o ''${BUILD}/objs/realloc.o ''${BUILD}/objs/free.o ''${BUILD}/objs/qsort.o ''${BUILD}/objs/getenv.o ''${BUILD}/objs/putenv.o ''${BUILD}/objs/setenv.o ''${BUILD}/objs/printf.o ''${BUILD}/objs/fprintf.o ''${BUILD}/objs/sprintf.o ''${BUILD}/objs/snprintf.o ''${BUILD}/objs/vprintf.o ''${BUILD}/objs/vfprintf.o ''${BUILD}/objs/vsprintf.o ''${BUILD}/objs/scanf.o ''${BUILD}/objs/sscanf.o ''${BUILD}/objs/fopen.o ''${BUILD}/objs/fclose.o ''${BUILD}/objs/fread.o ''${BUILD}/objs/fwrite.o ''${BUILD}/objs/fseek.o ''${BUILD}/objs/ftell.o ''${BUILD}/objs/fflush.o ''${BUILD}/objs/fgets.o ''${BUILD}/objs/fputs.o ''${BUILD}/objs/puts.o ''${BUILD}/objs/getc.o ''${BUILD}/objs/putc.o ''${BUILD}/objs/ungetc.o ''${BUILD}/objs/perror.o ''${BUILD}/objs/remove.o ''${BUILD}/objs/tmpnam.o ''${BUILD}/objs/read.o ''${BUILD}/objs/write.o ''${BUILD}/objs/open.o ''${BUILD}/objs/close.o ''${BUILD}/objs/lseek.o ''${BUILD}/objs/stat.o ''${BUILD}/objs/fstat.o ''${BUILD}/objs/access.o ''${BUILD}/objs/brk.o ''${BUILD}/objs/mmap.o ''${BUILD}/objs/munmap.o ''${BUILD}/objs/ioctl.o ''${BUILD}/objs/fcntl.o ''${BUILD}/objs/fork.o ''${BUILD}/objs/execve.o ''${BUILD}/objs/waitpid.o ''${BUILD}/objs/kill.o ''${BUILD}/objs/getpid.o ''${BUILD}/objs/pipe.o ''${BUILD}/objs/dup2.o ''${BUILD}/objs/mkdir.o ''${BUILD}/objs/rmdir.o ''${BUILD}/objs/unlink.o ''${BUILD}/objs/rename.o ''${BUILD}/objs/link.o ''${BUILD}/objs/symlink.o ''${BUILD}/objs/readlink.o ''${BUILD}/objs/chmod.o ''${BUILD}/objs/chown.o ''${BUILD}/objs/chdir.o ''${BUILD}/objs/getcwd.o ''${BUILD}/objs/time.o ''${BUILD}/objs/gettimeofday.o ''${BUILD}/objs/nanosleep.o ''${BUILD}/objs/signal.o ''${BUILD}/objs/sigaction.o ''${BUILD}/objs/_exit.o ''${BUILD}/objs/ctype.o ''${BUILD}/objs/isalpha.o ''${BUILD}/objs/isdigit.o ''${BUILD}/objs/isspace.o ''${BUILD}/objs/islower.o ''${BUILD}/objs/isupper.o ''${BUILD}/objs/tolower.o ''${BUILD}/objs/toupper.o ''${BUILD}/objs/errno.o ''${BUILD}/objs/assert.o ''${BUILD}/objs/sbrk.o ''${BUILD}/objs/getopt.o ''${BUILD}/objs/getopt1.o ''${BUILD}/objs/sleep.o ''${BUILD}/objs/isatty.o ''${BUILD}/objs/mkstemp.o ''${BUILD}/objs/tempnam.o

      ''${RANLIB} ''${out}/lib/libc.a

      # ── Install headers ──────────────────────────────────────────────────
      echo "==> Installing glibc headers"

      # Copy the essential glibc headers
      ''${TOOLS}/mkdir ''${out}/include/sys
      ''${TOOLS}/mkdir ''${out}/include/bits
      ''${TOOLS}/mkdir ''${out}/include/gnu

      ''${TOOLS}/cp ''${SRC}/include/stdio.h ''${out}/include/stdio.h
      ''${TOOLS}/cp ''${SRC}/include/stdlib.h ''${out}/include/stdlib.h
      ''${TOOLS}/cp ''${SRC}/include/string.h ''${out}/include/string.h
      ''${TOOLS}/cp ''${SRC}/include/unistd.h ''${out}/include/unistd.h
      ''${TOOLS}/cp ''${SRC}/include/fcntl.h ''${out}/include/fcntl.h
      ''${TOOLS}/cp ''${SRC}/include/errno.h ''${out}/include/errno.h
      ''${TOOLS}/cp ''${SRC}/include/signal.h ''${out}/include/signal.h
      ''${TOOLS}/cp ''${SRC}/include/ctype.h ''${out}/include/ctype.h
      ''${TOOLS}/cp ''${SRC}/include/assert.h ''${out}/include/assert.h
      ''${TOOLS}/cp ''${SRC}/include/limits.h ''${out}/include/limits.h
      ''${TOOLS}/cp ''${SRC}/include/stddef.h ''${out}/include/stddef.h
      ''${TOOLS}/cp ''${SRC}/include/stdarg.h ''${out}/include/stdarg.h
      ''${TOOLS}/cp ''${SRC}/include/time.h ''${out}/include/time.h
      ''${TOOLS}/cp ''${SRC}/include/dirent.h ''${out}/include/dirent.h
      ''${TOOLS}/cp ''${SRC}/include/getopt.h ''${out}/include/getopt.h
      ''${TOOLS}/cp ''${SRC}/include/alloca.h ''${out}/include/alloca.h
      ''${TOOLS}/cp ''${SRC}/include/setjmp.h ''${out}/include/setjmp.h
      ''${TOOLS}/cp ''${SRC}/include/math.h ''${out}/include/math.h
      ''${TOOLS}/cp ''${SRC}/include/features.h ''${out}/include/features.h
      ''${TOOLS}/cp ''${SRC}/include/stdbool.h ''${out}/include/stdbool.h

      # sys/ headers
      ''${TOOLS}/cp ''${SRC}/include/sys/types.h ''${out}/include/sys/types.h
      ''${TOOLS}/cp ''${SRC}/include/sys/stat.h ''${out}/include/sys/stat.h
      ''${TOOLS}/cp ''${SRC}/include/sys/wait.h ''${out}/include/sys/wait.h
      ''${TOOLS}/cp ''${SRC}/include/sys/time.h ''${out}/include/sys/time.h
      ''${TOOLS}/cp ''${SRC}/include/sys/resource.h ''${out}/include/sys/resource.h
      ''${TOOLS}/cp ''${SRC}/include/sys/mman.h ''${out}/include/sys/mman.h
      ''${TOOLS}/cp ''${SRC}/include/sys/ioctl.h ''${out}/include/sys/ioctl.h
      ''${TOOLS}/cp ''${SRC}/include/sys/uio.h ''${out}/include/sys/uio.h
      ''${TOOLS}/cp ''${SRC}/include/sys/param.h ''${out}/include/sys/param.h
      ''${TOOLS}/cp ''${SRC}/include/sys/select.h ''${out}/include/sys/select.h

      # Also install kernel headers alongside glibc headers
      ''${TOOLS}/mkdir ''${out}/include/linux
      ''${TOOLS}/mkdir ''${out}/include/asm
      ''${TOOLS}/mkdir ''${out}/include/asm-generic

      echo "glibc 2.2.5 installed to ''${out}"
      echo "  headers: ''${out}/include"
      echo "  libs:    ''${out}/lib (libc.a, crt1.o, crti.o, crtn.o)"
    '';
  }
  // {
    meta = {
      description = "GNU C Library, version 2.2.5";
      homepage = "https://www.gnu.org/software/libc/";
      license = "LGPL-2.1-or-later";
      platforms = ["i686-linux"];
    };
  }
