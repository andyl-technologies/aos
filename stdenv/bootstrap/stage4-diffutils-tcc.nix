# stdenv/bootstrap/stage4-diffutils-tcc.nix — GNU diffutils 2.7 from TCC (Mes libc)
#
# File-by-file compilation with TCC, statically linked against Mes libc.
# Builds two separate binaries: diff and cmp.
#
# Builder: bash-tcc (stage 4)
#
{
  tinycc, # Output of stage3-tinycc.nix (TCC with Mes libc)
  bash, # Output of stage4-bash-tcc.nix
  posix-tools, # Output of stage1-posix-tools.nix (mkdir, cp, chmod)
  buildPlatform,
  ...
}: let
  system = buildPlatform.system;
  sources = import ./sources.nix;

  src = builtins.fetchTarball {
    url = sources.diffutils.url;
    sha256 = sources.diffutils.sha256;
  };
in
  builtins.derivation {
    name = "diffutils-${sources.diffutils.version}-tcc";
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

        # ── Create empty config.h ─────────────────────────────────────────
        > $TMPDIR/config.h

        # Defines for Mes libc compatibility
        DEFS="-I$TMPDIR -I$SRC -DREGEX_MALLOC=1"
        DEFS="$DEFS -DHAVE_UNISTD_H -DHAVE_STRING_H -DHAVE_STDLIB_H"
        DEFS="$DEFS -DHAVE_FCNTL_H -DHAVE_LIMITS_H -DHAVE_ERRNO_H"
        DEFS="$DEFS -DHAVE_STRERROR -DHAVE_DUP2"
        DEFS="$DEFS -DSTDC_HEADERS -DHAVE_DIRENT_H"
        DEFS="$DEFS -Dvfork=fork -DRETSIGTYPE=int"
        DEFS="$DEFS -DPACKAGE=\"diffutils\" -DVERSION=\"2.7\""
        DEFS="$DEFS -DNULL_DEVICE=\"/dev/null\""

        echo "==> Building GNU diffutils 2.7"

        # ── Build diff ───────────────────────────────────────────────────
        echo "==> Compiling diff"
        for f in diff analyze cmpbuf context ed ifdef io normal side util dir fnmatch getopt getopt1 regex version; do
          $CC -c $DEFS -o $TMPDIR/diff_$f.o $SRC/$f.c
        done

        echo "==> Linking diff"
        $CC -static -o $out/bin/diff $TMPDIR/diff_diff.o $TMPDIR/diff_analyze.o $TMPDIR/diff_cmpbuf.o $TMPDIR/diff_context.o $TMPDIR/diff_ed.o $TMPDIR/diff_ifdef.o $TMPDIR/diff_io.o $TMPDIR/diff_normal.o $TMPDIR/diff_side.o $TMPDIR/diff_util.o $TMPDIR/diff_dir.o $TMPDIR/diff_fnmatch.o $TMPDIR/diff_getopt.o $TMPDIR/diff_getopt1.o $TMPDIR/diff_regex.o $TMPDIR/diff_version.o

        # ── Build cmp ────────────────────────────────────────────────────
        echo "==> Compiling cmp"
        for f in cmp cmpbuf getopt getopt1 error xmalloc version; do
          $CC -c $DEFS -o $TMPDIR/cmp_$f.o $SRC/$f.c
        done

        echo "==> Linking cmp"
        $CC -static -o $out/bin/cmp $TMPDIR/cmp_cmp.o $TMPDIR/cmp_cmpbuf.o $TMPDIR/cmp_getopt.o $TMPDIR/cmp_getopt1.o $TMPDIR/cmp_error.o $TMPDIR/cmp_xmalloc.o $TMPDIR/cmp_version.o

        echo "GNU diffutils 2.7 (TCC/Mes libc) installed to $out"
      ''
    ];
  }
  // {
    meta = {
      description = "GNU diffutils 2.7 — TCC-compiled with Mes libc for bootstrap";
      homepage = "https://www.gnu.org/software/diffutils/";
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
