# stdenv/bootstrap/stage9-make44.nix — GNU Make 4.4
#
# Full-featured build tool, replacing the minimal Make 3.82 from stage 3.
# Built with GCC 3.4.6 + glibc 2.2.5 + binutils 2.20.1a as a static binary.
#
# Builder: kaem (from mescc-tools, stage 1). No /bin/sh, no configure.
# This is the LAST stage using kaem as builder.
#
# Strategy: Enumerate all source file compilations directly in the kaem
# script. GNU Make 4.4 has a known set of source files; we compile each
# individually and link into the final binary.
#
{
  gcc346, # Output of stage8-gcc346.nix
  glibc225, # Output of stage7-glibc225.nix
  binutils220, # Output of stage4-binutils220.nix
  mescc-tools, # mescc-tools (kaem builder, extraction tools)
  make382, # GNU Make 3.82 from TCC (used during build)
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

  make-src = fetchSrc {
    name = "make-4.4.tar.gz";
    url = "https://mirrors.kernel.org/gnu/make/make-4.4.tar.gz";
    hash = "sha256-+EEZ/MmEZm4VKoN8go+d7Vj0+DOq/k3HhYXm6VS0FEs=";
  };

  # Pre-generated config.h for GNU Make 4.4
  make-config-h = builtins.toFile "make-config.h" ''
    /* Pre-generated config.h for GNU Make 4.4 bootstrap build */
    #define PACKAGE "make"
    #define PACKAGE_NAME "GNU make"
    #define PACKAGE_TARNAME "make"
    #define PACKAGE_VERSION "4.4"
    #define PACKAGE_STRING "GNU make 4.4"
    #define PACKAGE_BUGREPORT "bug-make@gnu.org"
    #define PACKAGE_URL "https://www.gnu.org/software/make/"
    #define VERSION "4.4"
    #define STDC_HEADERS 1
    #define HAVE_SYS_TYPES_H 1
    #define HAVE_SYS_STAT_H 1
    #define HAVE_STDLIB_H 1
    #define HAVE_STRING_H 1
    #define HAVE_MEMORY_H 1
    #define HAVE_STRINGS_H 1
    #define HAVE_INTTYPES_H 1
    #define HAVE_STDINT_H 1
    #define HAVE_UNISTD_H 1
    #define HAVE_FCNTL_H 1
    #define HAVE_DIRENT_H 1
    #define HAVE_ALLOCA_H 1
    #define HAVE_ALLOCA 1
    #define HAVE_SA_RESTART 1
    #define HAVE_DUP2 1
    #define HAVE_GETCWD 1
    #define HAVE_MKSTEMP 1
    #define HAVE_MKTEMP 1
    #define HAVE_STRERROR 1
    #define HAVE_STRSIGNAL 1
    #define HAVE_VPRINTF 1
    #define HAVE_ANSI_COMPILER 1
    #define HAVE_STDARG_H 1
    #define HAVE_STRCHR 1
    #define HAVE_STRDUP 1
    #define HAVE_STRTOLL 1
    #define FILE_TIMESTAMP_HI_RES 0
    #define SCCS_GET "/nullop"
    #define LOCALEDIR "/fake"
    #define LIBDIR "/fake/lib"
    #define INCLUDEDIR "/fake/include"
  '';

in
  builtins.derivation {
    name = "make-4.4";
    inherit system;
    builder = "/bin/sh";
    args = ["-c" ''exec ${mescc-tools}/bin/kaem --verbose --strict --file "$buildScriptPath"''];
    passAsFile = ["buildScript"];
    buildScript = ''
      set -e
      TOOLS=${mescc-tools}/bin
      CC=${gcc346}/bin/gcc

      cd ''${TMPDIR}
      ''${TOOLS}/ungz --file ${make-src} --output ''${TMPDIR}/make.tar
      ''${TOOLS}/untar --file ''${TMPDIR}/make.tar
      cd ''${TMPDIR}/make-4.4

      # Install pre-generated config.h
      ''${TOOLS}/cp ${make-config-h} ''${TMPDIR}/make-4.4/config.h

      # Common compiler flags
      CFLAGS="-O2 -I. -I./src -I./lib -I${glibc225}/include -DHAVE_CONFIG_H -L${glibc225}/lib -static"

      # Compile src/ files
      ''${CC} -c ''${CFLAGS} -o ar.o src/ar.c
      ''${CC} -c ''${CFLAGS} -o arscan.o src/arscan.c
      ''${CC} -c ''${CFLAGS} -o commands.o src/commands.c
      ''${CC} -c ''${CFLAGS} -o default.o src/default.c
      ''${CC} -c ''${CFLAGS} -o dir.o src/dir.c
      ''${CC} -c ''${CFLAGS} -o expand.o src/expand.c
      ''${CC} -c ''${CFLAGS} -o file.o src/file.c
      ''${CC} -c ''${CFLAGS} -o function.o src/function.c
      ''${CC} -c ''${CFLAGS} -o getopt.o src/getopt.c
      ''${CC} -c ''${CFLAGS} -o getopt1.o src/getopt1.c
      ''${CC} -c ''${CFLAGS} -o hash.o src/hash.c
      ''${CC} -c ''${CFLAGS} -o implicit.o src/implicit.c
      ''${CC} -c ''${CFLAGS} -o job.o src/job.c
      ''${CC} -c ''${CFLAGS} -o load.o src/load.c
      ''${CC} -c ''${CFLAGS} -o loadavg.o src/loadavg.c
      ''${CC} -c ''${CFLAGS} -o main.o src/main.c
      ''${CC} -c ''${CFLAGS} -o misc.o src/misc.c
      ''${CC} -c ''${CFLAGS} -o output.o src/output.c
      ''${CC} -c ''${CFLAGS} -o read.o src/read.c
      ''${CC} -c ''${CFLAGS} -o remake.o src/remake.c
      ''${CC} -c ''${CFLAGS} -o remote-stub.o src/remote-stub.c
      ''${CC} -c ''${CFLAGS} -o rule.o src/rule.c
      ''${CC} -c ''${CFLAGS} -o shuffle.o src/shuffle.c
      ''${CC} -c ''${CFLAGS} -o signame.o src/signame.c
      ''${CC} -c ''${CFLAGS} -o strcache.o src/strcache.c
      ''${CC} -c ''${CFLAGS} -o variable.o src/variable.c
      ''${CC} -c ''${CFLAGS} -o version.o src/version.c
      ''${CC} -c ''${CFLAGS} -o vpath.o src/vpath.c

      # Compile lib/ files (gnulib support)
      ''${CC} -c ''${CFLAGS} -o lib-concat-filename.o lib/concat-filename.c
      ''${CC} -c ''${CFLAGS} -o lib-findprog-in.o lib/findprog-in.c
      ''${CC} -c ''${CFLAGS} -o lib-glob.o lib/glob.c
      ''${CC} -c ''${CFLAGS} -o lib-fnmatch.o lib/fnmatch.c

      # Link
      ''${TOOLS}/mkdir ''${out}
      ''${TOOLS}/mkdir ''${out}/bin
      ''${CC} -static -L${glibc225}/lib -o ''${out}/bin/make ar.o arscan.o commands.o default.o dir.o expand.o file.o function.o getopt.o getopt1.o hash.o implicit.o job.o load.o loadavg.o main.o misc.o output.o read.o remake.o remote-stub.o rule.o shuffle.o signame.o strcache.o variable.o version.o vpath.o lib-concat-filename.o lib-findprog-in.o lib-glob.o lib-fnmatch.o

      # Smoke test
      ''${out}/bin/make --version
      echo "GNU Make 4.4 installed to ''${out}"
    '';
  }
  // {
    meta = {
      description = "GNU Make 4.4 — full-featured build tool";
      homepage = "https://www.gnu.org/software/make/";
      license = "GPL-3.0-or-later";
      platforms = ["i686-linux" "x86_64-linux"];
    };
  }
