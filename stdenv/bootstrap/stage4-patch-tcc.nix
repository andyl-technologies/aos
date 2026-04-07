# stdenv/bootstrap/stage4-patch-tcc.nix — GNU patch 2.5.9 from TCC (Mes libc)
#
# File-by-file compilation with TCC, statically linked against Mes libc.
# patch 2.5.9 has a flat source layout (all .c files in top level).
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
    url = sources.patch.url;
    hash = sources.patch.hash;
  };
in
builtins.derivation {
  name = "patch-${sources.patch.version}-tcc";
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

      # ── Create empty config.h and patchlevel.h ──────────────────────
      > $TMPDIR/config.h
      > $TMPDIR/patchlevel.h

      # Defines for Mes libc compatibility
      DEFS="-I$TMPDIR -I$SRC"
      DEFS="$DEFS -DHAVE_DECL_GETENV -DHAVE_DECL_MALLOC -DHAVE_DECL_STRERROR"
      DEFS="$DEFS -DHAVE_DIRENT_H -DHAVE_DUP2 -DHAVE_ERRNO_H"
      DEFS="$DEFS -DHAVE_FCNTL_H -DHAVE_FSEEKO -DHAVE_GETEUID"
      DEFS="$DEFS -DHAVE_LIMITS_H -DHAVE_MALLOC -DHAVE_MEMCMP"
      DEFS="$DEFS -DHAVE_MKDIR -DHAVE_MKTEMP -DHAVE_PATHCONF"
      DEFS="$DEFS -DHAVE_RAISE -DHAVE_STRERROR -DHAVE_STRING_H"
      DEFS="$DEFS -DHAVE_STDLIB_H -DHAVE_UNISTD_H"
      DEFS="$DEFS -DSTDC_HEADERS -DHAVE_INTTYPES_H"
      DEFS="$DEFS -Dmbstate_t=void* -Dvfork=fork -DRETSIGTYPE=int"
      DEFS="$DEFS -DPACKAGE=\"patch\" -DVERSION=\"2.5.9\""
      DEFS="$DEFS -DPACKAGE_BUGREPORT=\"\" -DPACKAGE_NAME=\"patch\""
      DEFS="$DEFS -DPACKAGE_VERSION=\"2.5.9\" -Ded_PROGRAM=\"ed\""
      DEFS="$DEFS -Dftello=ftell -Dfseeko=fseek"
      DEFS="$DEFS -DHAVE_MALLOC -DHAVE_REALLOC"

      echo "==> Building GNU patch 2.5.9"

      # ── Compile all source files ─────────────────────────────────────
      OBJS=""
      for f in addext argmatch backupfile basename dirname error \
               getopt getopt1 inp maketime partime \
               patch pch quote quotearg quotesys \
               util version xmalloc; do
        $CC -c $DEFS -o $TMPDIR/$f.o $SRC/$f.c
        OBJS="$OBJS $TMPDIR/$f.o"
      done

      # ── Link ─────────────────────────────────────────────────────────
      echo "==> Linking patch"
      $CC -static -o $out/bin/patch $OBJS

      echo "GNU patch 2.5.9 (TCC/Mes libc) installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU patch 2.5.9 — TCC-compiled with Mes libc for bootstrap";
    homepage = "https://www.gnu.org/software/patch/";
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
