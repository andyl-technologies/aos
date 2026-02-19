# stdenv/bootstrap/stage3-grep24.nix — GNU grep 2.4 from TCC
#
# Simple grep, compiled directly with TCC. No make needed.
#
# Builder: kaem (from mescc-tools, stage 1). No /bin/sh.
#
{
  tinycc, # Output of stage2 (TCC 0.9.27 with Mes libc)
  mescc-tools, # Output of stage0 (provides untar, ungz, etc.)
  system ? "x86_64-linux",
}: let
  src = builtins.derivation {
    name = "grep-2.4.tar.gz";
    inherit system;
    builder = "builtin:fetchurl";
    url = "https://mirrors.kernel.org/gnu/grep/grep-2.4.tar.gz";
    outputHash = "sha256-n95RDSVBiYkmQqKFg09s4zN3JKM6IMXpKXj7YnTe2Oc=";
    outputHashMode = "flat";
    outputHashAlgo = "sha256";
    preferLocalBuild = true;
  };

in
  builtins.derivation {
    name = "grep-2.4";
    inherit system;
    builder = "/bin/sh";
    args = ["-c" ''exec ${mescc-tools}/bin/kaem --verbose --strict --file "$buildScriptPath"''];
    passAsFile = ["buildScript"];
    buildScript = ''
      set -e
      TOOLS=${mescc-tools}/bin
      CC=${tinycc}/bin/tcc

      cd ''${TMPDIR}
      ''${TOOLS}/ungz --file ${src} --output ''${TMPDIR}/grep.tar
      ''${TOOLS}/untar --file ''${TMPDIR}/grep.tar
      cd ''${TMPDIR}/grep-2.4

      # Compile directly with TCC (no configure needed)
      ''${CC} -c -DHAVE_DIRENT_H -DSTDC_HEADERS -DHAVE_MEMCHR -DHAVE_STRERROR -DPACKAGE=\"grep\" -DVERSION=\"2.4\" src/grep.c
      ''${CC} -c src/dfa.c
      ''${CC} -c -DSTDC_HEADERS src/kwset.c
      ''${CC} -c src/obstack.c
      ''${CC} -c src/regex.c
      ''${CC} -c src/search.c
      ''${CC} -c -DHAVE_STRERROR src/grepmat.c
      ''${CC} -c src/savedir.c
      ''${CC} -c -DHAVE_STRERROR src/getopt.c
      ''${CC} -c src/getopt1.c

      # Link
      ''${TOOLS}/mkdir ''${out}
      ''${TOOLS}/mkdir ''${out}/bin
      ''${CC} -static -o ''${out}/bin/grep grep.o dfa.o kwset.o obstack.o regex.o search.o grepmat.o savedir.o getopt.o getopt1.o

      echo "grep 2.4 built successfully"
    '';
  }
  // {
    meta = {
      description = "GNU grep 2.4 — built from TCC for bootstrap";
      license = "GPL-3.0-or-later";
      platforms = ["i686-linux"];
    };
  }
