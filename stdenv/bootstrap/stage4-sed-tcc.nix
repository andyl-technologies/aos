# stdenv/bootstrap/stage4-sed-tcc.nix — GNU sed 4.0.9 from TCC (Mes libc)
#
# File-by-file compilation with TCC, statically linked against Mes libc.
# Provides sed with -i support for later bootstrap stages.
#
# Builder: bash-tcc (stage 4)
#
{
  tinycc, # Output of stage3-tinycc.nix (TCC with Mes libc)
  bash, # Output of stage4-bash-tcc.nix
  posix-tools, # Output of stage1-posix-tools.nix (mkdir, cp, chmod)
  buildPlatform,
  ...
}:
let
  inherit (import ../../lib/derivations.nix { system = builtins.currentSystem; }) fetchTarball;

  system = buildPlatform.system;
  sources = import ./sources.nix;

  src = fetchTarball {
    url = sources.sed.url;
    hash = sources.sed.hash;
  };
in
builtins.derivation {
  name = "sed-${sources.sed.version}-tcc";
  inherit system;
  builder = "${bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu

      export PATH="${bash}/bin:${tinycc}/bin:${posix-tools}/bin"
      CC="${tinycc}/bin/tcc"
      SRC=${src}

      mkdir $out
      mkdir $out/bin

      CFLAGS="-c -I$SRC -I$SRC/lib -I$SRC/sed -DHAVE_CONFIG_H"

      # ── Create empty config.h in TMPDIR ──────────────────────────────
      > $TMPDIR/config.h

      # ── Copy regex_.h -> regex.h ─────────────────────────────────────
      cp $SRC/lib/regex_.h $TMPDIR/regex.h

      # Common defines for Mes libc compatibility
      DEFS="-DREGEX_MALLOC=1 -Dmbstate_t=void* -Dvfork=fork -DRETSIGTYPE=int"
      DEFS="$DEFS -DHAVE_STRING_H -DHAVE_STDLIB_H -DHAVE_UNISTD_H"
      DEFS="$DEFS -DHAVE_LIMITS_H -DHAVE_ALLOCA_H -DHAVE_ALLOCA"
      DEFS="$DEFS -DSTDC_HEADERS -DHAVE_FCNTL_H -DHAVE_DIRENT_H"
      DEFS="$DEFS -DHAVE_ERRNO_H -DHAVE_MEMCPY -DHAVE_MEMSET"
      DEFS="$DEFS -DHAVE_STRERROR -DHAVE_ISASCII -DHAVE_VPRINTF"
      DEFS="$DEFS -DPACKAGE=\"sed\" -DVERSION=\"4.0.9\""
      DEFS="$DEFS -DSED_FEATURE_VERSION=\"4.0\""

      echo "==> Building GNU sed 4.0.9"

      # ── lib/ source files → libsed.a ─────────────────────────────────
      echo "==> Compiling lib/ files"
      for f in getline getopt1 getopt utils regex obstack strverscmp mkstemp; do
        $CC -c -I$TMPDIR -I$SRC -I$SRC/lib $DEFS -o $TMPDIR/$f.o $SRC/lib/$f.c
      done

      $CC -ar cr $TMPDIR/libsed.a $TMPDIR/getline.o $TMPDIR/getopt1.o $TMPDIR/getopt.o $TMPDIR/utils.o $TMPDIR/regex.o $TMPDIR/obstack.o $TMPDIR/strverscmp.o $TMPDIR/mkstemp.o

      # ── sed/ source files ────────────────────────────────────────────
      echo "==> Compiling sed/ files"
      for f in compile execute regexp fmt sed; do
        $CC -c -I$TMPDIR -I$SRC -I$SRC/lib -I$SRC/sed $DEFS -o $TMPDIR/$f.o $SRC/sed/$f.c
      done

      # ── Link ─────────────────────────────────────────────────────────
      echo "==> Linking sed"
      $CC -static -o $out/bin/sed $TMPDIR/compile.o $TMPDIR/execute.o $TMPDIR/regexp.o $TMPDIR/fmt.o $TMPDIR/sed.o $TMPDIR/libsed.a

      echo "GNU sed 4.0.9 (TCC/Mes libc) installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU sed 4.0.9 — TCC-compiled with Mes libc for bootstrap";
    homepage = "https://www.gnu.org/software/sed/";
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
