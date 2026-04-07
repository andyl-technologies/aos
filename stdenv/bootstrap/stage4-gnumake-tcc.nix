# stdenv/bootstrap/stage4-gnumake-tcc.nix — GNU Make 3.79.1 from TCC (Mes libc)
#
# First make in the bootstrap chain. Built with TCC as CC, linked against
# Mes libc (static). This make is used by later stage-4 builds (binutils,
# GCC 2.95.3) to drive compilation.
#
# GNU Make 3.79.1 (2000) is simple enough to compile file-by-file with TCC.
# No configure — we pre-define the needed HAVE_* macros on the command line.
#
# Builder: bash-tcc + coreutils-tcc (stage 4)
#
{
  tinycc, # Output of stage3-tinycc.nix (TCC with Mes libc)
  bash, # Output of stage4-bash-tcc.nix (bash shell)
  coreutils, # Output of stage4-coreutils-tcc.nix (cp, mkdir, etc.)
  buildPlatform,
  ...
}:
let
  inherit (import ../../lib/derivations.nix { system = builtins.currentSystem; }) fetchTarball;

  system = buildPlatform.system;
  sources = import ./sources.nix;

  src = fetchTarball {
    url = sources.gnumake.url;
    hash = sources.gnumake.hash;
  };
in
builtins.derivation {
  name = "gnumake-${sources.gnumake.version}";
  inherit system;
  builder = "${bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu

      export PATH="${
        builtins.concatStringsSep ":" (
          builtins.map (p: "${p}/bin") [
            bash
            coreutils
            tinycc
          ]
        )
      }"
      CC=${tinycc}/bin/tcc

      # Copy source to writable directory (store files are read-only)
      cp -r ${src} $TMPDIR/src
      chmod -R u+w $TMPDIR/src
      cd $TMPDIR/src

      # ── Create output directories ────────────────────────────────────────
      mkdir $out
      mkdir $out/bin

      # ── Create empty config.h ────────────────────────────────────────────
      > config.h

      # ══════════════════════════════════════════════════════════════════════
      # MANUAL BUILD: compile each source file individually
      # ══════════════════════════════════════════════════════════════════════
      echo "==> Building GNU Make 3.79.1"

      # ── Common flags ─────────────────────────────────────────────────────
      # -Dsys_siglist=_make_siglist: Mes libc exports sys_siglist as a FUNCTION
      # (not an array), causing segfault when gnumake indexes into it. Rename
      # to avoid the Mes libc symbol collision.
      CFLAGS_BASE="-c -I. -DHAVE_INTTYPES_H -DHAVE_SA_RESTART -Dsys_siglist=_make_siglist"

      # ── getopt (no extra flags needed) ───────────────────────────────────
      $CC -c -I. getopt.c
      $CC -c -I. getopt1.c

      # ── Core source files with standard flags ────────────────────────────
      for f in expand.c implicit.c rule.c signame.c variable.c vpath.c remote-stub.c; do
        $CC $CFLAGS_BASE $f
      done

      # ── Files needing -Iglob ─────────────────────────────────────────────
      $CC $CFLAGS_BASE -Iglob ar.c
      $CC $CFLAGS_BASE -Iglob -DHAVE_DIRENT_H dir.c
      $CC $CFLAGS_BASE -Iglob -DINCLUDEDIR=\"\" read.c

      # ── Files needing -DHAVE_FCNTL_H ────────────────────────────────────
      $CC $CFLAGS_BASE -DHAVE_FCNTL_H arscan.c
      $CC $CFLAGS_BASE -DFILE_TIMESTAMP_HI_RES=0 -DHAVE_FCNTL_H -DLIBDIR=\"\" remake.c

      # ── Files needing -DFILE_TIMESTAMP_HI_RES=0 ─────────────────────────
      $CC $CFLAGS_BASE -DFILE_TIMESTAMP_HI_RES=0 commands.c
      $CC $CFLAGS_BASE -DFILE_TIMESTAMP_HI_RES=0 file.c

      # ── Files with unique extra flags ────────────────────────────────────
      $CC $CFLAGS_BASE -DSCCS_GET=\"get\" default.c
      $CC $CFLAGS_BASE -Dvfork=fork function.c
      $CC $CFLAGS_BASE -DHAVE_DUP2 -DHAVE_STRCHR -Dvfork=fork job.c
      $CC $CFLAGS_BASE -DLOCALEDIR=\"\" -DPACKAGE=\"make\" -DHAVE_MKTEMP -DHAVE_GETCWD main.c
      $CC $CFLAGS_BASE -DHAVE_STRERROR -DHAVE_VPRINTF -DHAVE_ANSI_COMPILER -DHAVE_STDARG_H misc.c
      $CC -c -I. -DVERSION=\"3.79.1\" version.c
      $CC -c -DHAVE_FCNTL_H getloadavg.c

      # ── glob library ─────────────────────────────────────────────────────
      $CC -c -Iglob -DSTDC_HEADERS -DHAVE_UNISTD_H -DHAVE_DIRENT_H glob/fnmatch.c
      $CC -c -Iglob -DHAVE_STRDUP -DHAVE_DIRENT_H glob/glob.c

      # ── Link ─────────────────────────────────────────────────────────────
      echo "==> Linking make"
      $CC -static -o $out/bin/make ar.o arscan.o commands.o default.o dir.o expand.o file.o function.o implicit.o job.o main.o misc.o read.o remake.o rule.o signame.o variable.o version.o vpath.o remote-stub.o getloadavg.o getopt.o getopt1.o fnmatch.o glob.o

      echo "GNU Make 3.79.1 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU Make, version 3.79.1";
    homepage = "https://www.gnu.org/software/make/";
    license = "GPL-2.0-or-later";
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
