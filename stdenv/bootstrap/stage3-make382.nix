# stdenv/bootstrap/stage3-make382.nix — GNU Make 3.82 from TCC
#
# Built directly from TCC: compile each .c file individually, then link.
# No configure or existing make needed — following live-bootstrap pass1.kaem.
#
# Builder: kaem (from mescc-tools, stage 1). No /bin/sh.
#
{
  tinycc, # Output of stage2 (TCC 0.9.27 with Mes libc)
  mescc-tools, # Output of stage0 (provides untar, ungz, unbz2, etc.)
  system ? "x86_64-linux",
}: let
  src = builtins.derivation {
    name = "make-3.82.tar.bz2";
    inherit system;
    builder = "builtin:fetchurl";
    url = "https://mirrors.kernel.org/gnu/make/make-3.82.tar.bz2";
    outputHash = "sha256-i2JRWAG6SNBi0CEjhfbMa/Bfl/0IjnLzxFhJVICEII4=";
    outputHashMode = "flat";
    outputHashAlgo = "sha256";
    preferLocalBuild = true;
  };

in
  builtins.derivation {
    name = "make-3.82";
    inherit system;
    builder = "/bin/sh";
    args = ["-c" ''exec ${mescc-tools}/bin/kaem --verbose --strict --file "$buildScriptPath"''];
    passAsFile = ["buildScript"];
    buildScript = ''
      set -e
      TOOLS=${mescc-tools}/bin
      CC=${tinycc}/bin/tcc

      cd ''${TMPDIR}
      ''${TOOLS}/unbz2 --file ${src} --output ''${TMPDIR}/make.tar
      ''${TOOLS}/untar --file ''${TMPDIR}/make.tar
      cd ''${TMPDIR}/make-3.82

      # Empty config.h (defines are passed via -D flags)
      ''${TOOLS}/catm config.h

      # Compile each source file individually (live-bootstrap pass1.kaem)
      ''${CC} -c getopt.c
      ''${CC} -c getopt1.c
      ''${CC} -c -I. -Iglob -DHAVE_INTTYPES_H -DHAVE_SA_RESTART -DHAVE_STDINT_H ar.c
      ''${CC} -c -I. -DHAVE_INTTYPES_H -DHAVE_SA_RESTART -DHAVE_FCNTL_H arscan.c
      ''${CC} -c -I. -DHAVE_INTTYPES_H -DHAVE_SA_RESTART -DFILE_TIMESTAMP_HI_RES=0 commands.c
      ''${CC} -c -I. -DHAVE_INTTYPES_H -DHAVE_SA_RESTART -DSCCS_GET=\"/nullop\" default.c
      ''${CC} -c -I. -Iglob -DHAVE_INTTYPES_H -DHAVE_SA_RESTART -DHAVE_DIRENT_H dir.c
      ''${CC} -c -I. -DHAVE_INTTYPES_H -DHAVE_SA_RESTART expand.c
      ''${CC} -c -I. -DHAVE_INTTYPES_H -DHAVE_SA_RESTART -DFILE_TIMESTAMP_HI_RES=0 file.c
      ''${CC} -c -I. -DHAVE_INTTYPES_H -DHAVE_SA_RESTART -Dvfork=fork function.c
      ''${CC} -c -I. -DHAVE_INTTYPES_H -DHAVE_SA_RESTART implicit.c
      ''${CC} -c -I. -DHAVE_INTTYPES_H -DHAVE_SA_RESTART -DHAVE_DUP2 -DHAVE_STRCHR -Dvfork=fork job.c
      ''${CC} -c -I. -DHAVE_INTTYPES_H -DHAVE_SA_RESTART -DLOCALEDIR=\"/fake\" -DPACKAGE=\"make\" -DHAVE_MKTEMP -DHAVE_GETCWD main.c
      ''${CC} -c -I. -DHAVE_INTTYPES_H -DHAVE_SA_RESTART -DHAVE_STRERROR -DHAVE_VPRINTF -DHAVE_ANSI_COMPILER -DHAVE_STDARG_H misc.c
      ''${CC} -c -I. -Iglob -DHAVE_INTTYPES_H -DHAVE_SA_RESTART -DINCLUDEDIR=\"''${out}/include\" read.c
      ''${CC} -c -I. -DHAVE_INTTYPES_H -DHAVE_SA_RESTART -DFILE_TIMESTAMP_HI_RES=0 -DHAVE_FCNTL_H -DLIBDIR=\"''${out}/lib\" remake.c
      ''${CC} -c -I. -DHAVE_INTTYPES_H -DHAVE_SA_RESTART rule.c
      ''${CC} -c -I. -DHAVE_INTTYPES_H -DHAVE_SA_RESTART signame.c
      ''${CC} -c -I. -DHAVE_INTTYPES_H -DHAVE_SA_RESTART strcache.c
      ''${CC} -c -I. -DHAVE_INTTYPES_H -DHAVE_SA_RESTART variable.c
      ''${CC} -c -I. -DVERSION=\"3.82\" version.c
      ''${CC} -c -I. -DHAVE_INTTYPES_H -DHAVE_SA_RESTART vpath.c
      ''${CC} -c -I. -DHAVE_INTTYPES_H -DHAVE_SA_RESTART hash.c
      ''${CC} -c -I. -DHAVE_INTTYPES_H -DHAVE_SA_RESTART remote-stub.c
      ''${CC} -c -DHAVE_FCNTL_H getloadavg.c
      ''${CC} -c -Iglob -DSTDC_HEADERS glob/fnmatch.c
      ''${CC} -c -Iglob -DHAVE_STRDUP -DHAVE_DIRENT_H glob/glob.c

      # Link
      ''${TOOLS}/mkdir ''${out}
      ''${TOOLS}/mkdir ''${out}/bin
      ''${CC} -static -o ''${out}/bin/make getopt.o getopt1.o ar.o arscan.o commands.o default.o dir.o expand.o file.o function.o implicit.o job.o main.o misc.o read.o remake.o rule.o signame.o strcache.o variable.o version.o vpath.o hash.o remote-stub.o getloadavg.o fnmatch.o glob.o

      ''${out}/bin/make --version
      echo "GNU Make 3.82 built successfully"
    '';
  }
  // {
    meta = {
      description = "GNU Make 3.82 — built from TCC for bootstrap";
      license = "GPL-3.0-or-later";
      platforms = ["i686-linux"];
    };
  }
