# stdenv/bootstrap/stage4-findutils-tcc.nix — GNU findutils 4.1 from TCC (Mes libc)
#
# File-by-file compilation with TCC, statically linked against Mes libc.
# Builds find and xargs. The locate/updatedb utilities are skipped
# (they need a database which isn't useful in bootstrap).
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
  system = buildPlatform.system;
  sources = import ./sources.nix;

  src = builtins.fetchTarball {
    url = sources.findutils.url;
    sha256 = sources.findutils.sha256;
  };
in
builtins.derivation {
  name = "findutils-${sources.findutils.version}-tcc";
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

      # Defines for Mes libc compatibility
      DEFS="-I$TMPDIR -I$SRC -I$SRC/lib -I$SRC/find -I$SRC/xargs"
      DEFS="$DEFS -DHAVE_CONFIG_H"
      DEFS="$DEFS -DHAVE_STRING_H -DHAVE_STDLIB_H -DHAVE_UNISTD_H"
      DEFS="$DEFS -DHAVE_LIMITS_H -DHAVE_FCNTL_H -DHAVE_DIRENT_H"
      DEFS="$DEFS -DHAVE_ERRNO_H -DHAVE_STRERROR"
      DEFS="$DEFS -DSTDC_HEADERS -DHAVE_SYS_TYPES_H -DHAVE_SYS_STAT_H"
      DEFS="$DEFS -DHAVE_SYS_WAIT_H -DHAVE_ALLOCA_H -DHAVE_ALLOCA"
      DEFS="$DEFS -Dvfork=fork -DRETSIGTYPE=int"
      DEFS="$DEFS -DPACKAGE=\"findutils\" -DVERSION=\"4.1\""

      # ── Create empty config.h ────────────────────────────────────────
      > $TMPDIR/config.h

      echo "==> Building GNU findutils 4.1"

      # ── Compile lib/ files ──────────────────────────────────────────
      echo "==> Compiling lib/ files"
      LIB_OBJS=""
      for f in nextelem regex savedir stpcpy error fnmatch getopt getopt1 \
               idcache modechange filemode xmalloc xstrdup modetype listfile; do
        if test -f $SRC/lib/$f.c; then
          $CC -c $DEFS -o $TMPDIR/lib_$f.o $SRC/lib/$f.c 2>/dev/null && \
            LIB_OBJS="$LIB_OBJS $TMPDIR/lib_$f.o" || \
            echo "  warning: skipped lib/$f.c"
        fi
      done

      $CC -ar cr $TMPDIR/libfind.a $LIB_OBJS

      # ── Build find ──────────────────────────────────────────────────
      echo "==> Compiling find"
      FIND_OBJS=""
      for f in find tree pred parser util fstype; do
        if test -f $SRC/find/$f.c; then
          $CC -c $DEFS -DHAVE_DIRENT_H -o $TMPDIR/find_$f.o $SRC/find/$f.c 2>/dev/null && \
            FIND_OBJS="$FIND_OBJS $TMPDIR/find_$f.o" || \
            echo "  warning: skipped find/$f.c"
        fi
      done

      echo "==> Linking find"
      $CC -static -o $out/bin/find $FIND_OBJS $TMPDIR/libfind.a

      # ── Build xargs ─────────────────────────────────────────────────
      echo "==> Compiling xargs"
      $CC -c $DEFS -o $TMPDIR/xargs.o $SRC/xargs/xargs.c

      echo "==> Linking xargs"
      $CC -static -o $out/bin/xargs $TMPDIR/xargs.o $TMPDIR/libfind.a

      echo "GNU findutils 4.1 (TCC/Mes libc) installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU findutils 4.1 — TCC-compiled with Mes libc for bootstrap";
    homepage = "https://www.gnu.org/software/findutils/";
    license = "GPL-2.0-or-later";
    build = { os = "linux"; cpu = ["x86_64" "i686"]; };
    execute = { os = "linux"; cpu = "i686"; };
  };
}
