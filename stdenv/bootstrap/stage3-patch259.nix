# stdenv/bootstrap/stage3-patch259.nix — GNU patch 2.5.9 from TCC
#
# Compiled directly with TCC. No make needed.
#
# Builder: kaem (from mescc-tools, stage 1). No /bin/sh.
#
{
  tinycc, # Output of stage2 (TCC 0.9.27 with Mes libc)
  mescc-tools, # Output of stage0 (provides untar, ungz, etc.)
  system ? "x86_64-linux",
}: let
  src = builtins.derivation {
    name = "patch-2.5.9.tar.gz";
    inherit system;
    builder = "builtin:fetchurl";
    url = "https://mirrors.kernel.org/gnu/patch/patch-2.5.9.tar.gz";
    outputHash = "sha256-7LXGRp1zK88B1uwa/p5k8WaMq6W/2xA8KNf1N7o824o=";
    outputHashMode = "flat";
    outputHashAlgo = "sha256";
    preferLocalBuild = true;
  };

in
  builtins.derivation {
    name = "patch-2.5.9";
    inherit system;
    builder = "/bin/sh";
    args = ["-c" ''exec ${mescc-tools}/bin/kaem --verbose --strict --file "$buildScriptPath"''];
    passAsFile = ["buildScript"];
    buildScript = ''
      set -e
      TOOLS=${mescc-tools}/bin
      CC=${tinycc}/bin/tcc

      cd ''${TMPDIR}
      ''${TOOLS}/ungz --file ${src} --output ''${TMPDIR}/patch.tar
      ''${TOOLS}/untar --file ''${TMPDIR}/patch.tar
      cd ''${TMPDIR}/patch-2.5.9

      # Compile directly with TCC
      ''${CC} -c -DHAVE_DECL_GETENV -DHAVE_DECL_MALLOC -DHAVE_DIRENT_H -DHAVE_LIMITS_H -DHAVE_GETEUID -DHAVE_MKTEMP -DPACKAGE_BUGREPORT=\"\" -Ded_PROGRAM=\"/nullop\" -DPACKAGE_NAME=\"patch\" -DVERSION=\"2.5.9\" -DSTDC_HEADERS patch.c
      ''${CC} -c -DHAVE_LIMITS_H inp.c
      ''${CC} -c -DHAVE_LIMITS_H pch.c
      ''${CC} -c util.c
      ''${CC} -c -DHAVE_GETEUID backupfile.c
      ''${CC} -c version.c
      ''${CC} -c getopt.c
      ''${CC} -c getopt1.c
      ''${CC} -c -DHAVE_DECL_MALLOC -DHAVE_LIMITS_H quotesys.c
      ''${CC} -c basename.c
      ''${CC} -c dirname.c
      ''${CC} -c addext.c
      ''${CC} -c argmatch.c
      ''${CC} -c error.c
      ''${CC} -c xmalloc.c
      ''${CC} -c maketime.c
      ''${CC} -c -DHAVE_LIMITS_H partime.c
      ''${CC} -c quotearg.c

      ''${TOOLS}/mkdir ''${out}
      ''${TOOLS}/mkdir ''${out}/bin
      ''${CC} -static -o ''${out}/bin/patch patch.o inp.o pch.o util.o backupfile.o version.o getopt.o getopt1.o quotesys.o basename.o dirname.o addext.o argmatch.o error.o xmalloc.o maketime.o partime.o quotearg.o

      echo "patch 2.5.9 built successfully"
    '';
  }
  // {
    meta = {
      description = "GNU patch 2.5.9 — built from TCC for bootstrap";
      license = "GPL-3.0-or-later";
      platforms = ["i686-linux"];
    };
  }
