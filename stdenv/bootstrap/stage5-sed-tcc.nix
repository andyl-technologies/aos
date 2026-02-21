# stdenv/bootstrap/stage5-sed.nix — GNU sed 3.02 from TCC (Mes libc)
#
# Minimal sed for the bootstrap chain. Built with TCC as CC, linked against
# Mes libc (static). Used by later stage-4 builds (binutils, GCC) for
# simple text transformations.
#
# GNU sed 3.02 (1998) is simple enough to build with a hand-written Makefile.
# No configure — we pre-define the needed macros on the command line.
# Can't use ./configure because it requires sed (circular dependency).
#
# Builder: bash 2.05b (TCC-compiled, stage 4)
#
{
  tinycc, # Output of stage3-tinycc.nix (TCC with Mes libc)
  posix-tools, # Output of stage1-posix-tools.nix
  bash, # Output of stage4-bash.nix (bash 2.05b from TCC)
  gnumake, # GNU Make 3.79.1 from TCC
  buildPlatform,
  ...
}:
let
  system = buildPlatform.system;

  src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/sed/sed-3.02.tar.gz";
    sha256 = "sha256-yykplNr4R3PuJIbgNpD/WhKpMByw8fbt3UYwjERr5yU=";
  };

  # Inline Makefile for sed 3.02 — configure can't be used (circular dep on sed)
  makefile = builtins.toFile "Makefile.sed" ''
    CC = tcc
    CFLAGS = -DENABLE_NLS=0 -DHAVE_FCNTL_H -DHAVE_STRING_H -DHAVE_STDLIB_H \
             -DHAVE_UNISTD_H -DPACKAGE=\"sed\" -DVERSION=\"3.02\" \
             -DHAVE_ALLOCA_H -DHAVE_ALLOCA -DSTDC_HEADERS -I. -Ilib
    LDFLAGS = -static

    OBJS = sed.o compile.o execute.o utils.o regex.o getopt.o getopt1.o

    all: sed

    sed: $(OBJS)
    	$(CC) $(LDFLAGS) -o $@ $(OBJS)

    sed.o: sed/sed.c
    	$(CC) -c $(CFLAGS) -o $@ $<

    compile.o: sed/compile.c
    	$(CC) -c $(CFLAGS) -o $@ $<

    execute.o: sed/execute.c
    	$(CC) -c $(CFLAGS) -o $@ $<

    utils.o: sed/utils.c
    	$(CC) -c $(CFLAGS) -o $@ $<

    regex.o: lib/regex.c
    	$(CC) -c $(CFLAGS) -o $@ $<

    getopt.o: lib/getopt.c
    	$(CC) -c $(CFLAGS) -o $@ $<

    getopt1.o: lib/getopt1.c
    	$(CC) -c $(CFLAGS) -o $@ $<
  '';

  # Recursive copy helper for bootstrap (posix-tools cp handles single files)
  cpdir = ''
    cpdir() {
      for item in "$1"/*; do
        [ -e "$item" ] || continue
        base="''${item##*/}"
        if [ -d "$item" ]; then
          [ -d "$2/$base" ] || mkdir "$2/$base"
          cpdir "$item" "$2/$base"
        else
          cp "$item" "$2/$base"
        fi
      done
    }
  '';

in
builtins.derivation {
  name = "sed-3.02";
  inherit system;
  builder = "${bash}/bin/bash";
  args = [
    "-c"
    ''
      ${cpdir}
      set -eu

      export PATH="${
        builtins.concatStringsSep ":" (
          builtins.map (p: "${p}/bin") [
            bash
            tinycc
            gnumake
            posix-tools
          ]
        )
      }"

      # Copy source to writable directory
      mkdir $TMPDIR/src
      cpdir ${src} $TMPDIR/src
      cd $TMPDIR/src

      # ── Create output directories ────────────────────────────────────────
      mkdir $out
      mkdir $out/bin

      # ── Create empty config.h ────────────────────────────────────────────
      > config.h

      # Copy regex-gnu.h to regex.h (normally done by configure)
      cp lib/regex-gnu.h lib/regex.h

      # ── Copy inline Makefile ─────────────────────────────────────────────
      cp ${makefile} Makefile.aos

      # ══════════════════════════════════════════════════════════════════════
      # BUILD with make
      # ══════════════════════════════════════════════════════════════════════
      echo "==> Building GNU sed 3.02"
      make -f Makefile.aos

      # ── Install ──────────────────────────────────────────────────────────
      cp sed $out/bin/sed

      echo "GNU sed 3.02 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU sed (stream editor), version 3.02";
    homepage = "https://www.gnu.org/software/sed/";
    license = "GPL-2.0-or-later";
    platforms = [ "i686-linux" ];
  };
}
