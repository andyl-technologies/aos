# stdenv/bootstrap/stage4-grep-tcc.nix — GNU grep 2.4 from TCC (Mes libc)
#
# File-by-file compilation with TCC, statically linked against Mes libc.
# Provides grep, egrep, and fgrep for the bootstrap chain.
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
    url = sources.grep.url;
    sha256 = sources.grep.sha256;
  };
in
builtins.derivation {
  name = "grep-${sources.grep.version}-tcc";
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

      # Defines for Mes libc compatibility — no config.h needed
      DEFS="-I$SRC -I$SRC/src"
      DEFS="$DEFS -DREGEX_MALLOC=1"
      DEFS="$DEFS -DHAVE_DIRENT_H -DHAVE_UNISTD_H -DHAVE_STRERROR"
      DEFS="$DEFS -DHAVE_STRING_H -DHAVE_STDLIB_H -DHAVE_MEMCHR"
      DEFS="$DEFS -DSTDC_HEADERS"
      DEFS="$DEFS -DPACKAGE=\"grep\" -DVERSION=\"2.4\""

      echo "==> Building GNU grep 2.4"

      # ── Compile source files ─────────────────────────────────────────
      for f in grep dfa kwset obstack regex stpcpy savedir getopt getopt1 search grepmat; do
        $CC -c $DEFS -o $TMPDIR/$f.o $SRC/src/$f.c
      done

      # ── Link grep ────────────────────────────────────────────────────
      echo "==> Linking grep"
      $CC -static -o $out/bin/grep $TMPDIR/grep.o $TMPDIR/dfa.o $TMPDIR/kwset.o $TMPDIR/obstack.o $TMPDIR/regex.o $TMPDIR/stpcpy.o $TMPDIR/savedir.o $TMPDIR/getopt.o $TMPDIR/getopt1.o $TMPDIR/search.o $TMPDIR/grepmat.o

      # Create egrep and fgrep copies
      cp $out/bin/grep $out/bin/egrep
      chmod 755 $out/bin/egrep
      cp $out/bin/grep $out/bin/fgrep
      chmod 755 $out/bin/fgrep

      echo "GNU grep 2.4 (TCC/Mes libc) installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU grep 2.4 — TCC-compiled with Mes libc for bootstrap";
    homepage = "https://www.gnu.org/software/grep/";
    license = "GPL-2.0-or-later";
    build = { os = "linux"; cpu = ["x86_64" "i686"]; };
    execute = { os = "linux"; cpu = "i686"; };
  };
}
