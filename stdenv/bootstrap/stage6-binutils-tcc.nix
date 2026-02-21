# stdenv/bootstrap/stage6-binutils.nix — binutils 2.20.1a via configure+make
#
# Provides GNU as, ld, ar, nm, objcopy, objdump, ranlib, readelf, strip.
# Built with TCC 0.9.27 against Mes libc using configure+make, matching
# the Guix/live-bootstrap approach. The configure script detects TCC's
# capabilities and generates appropriate config.h files, avoiding TCC
# codegen bugs that manifest with incorrect #define combinations in
# hand-written config.h files.
#
# Builder: bash 2.05b (TCC-compiled, stage 4).
#
{
  tinycc, # Output of stage3-tinycc.nix (TCC with Mes libc)
  posix-tools, # Output of stage1-posix-tools.nix
  bash, # bash 2.05b from TCC (stage 4)
  gnumake, # GNU Make 3.79.1 from TCC
  sed, # GNU sed 3.02 from TCC
  grep, # GNU grep 2.4 from TCC
  patch, # GNU patch 2.5.9 from TCC
  buildPlatform,
  ...
}:
let
  system = buildPlatform.system;

  src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/binutils/binutils-2.20.1a.tar.bz2";
    sha256 = "sha256-CZWJSyqtTcbeB9I4Htimq4qTM7AiZlu2qV4x3xlnGH4=";
  };

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
  name = "binutils-2.20.1";
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
            sed
            grep
            patch
            posix-tools
          ]
        )
      }"
      export CONFIG_SHELL="${bash}/bin/bash"
      export SHELL="${bash}/bin/bash"

      # Copy source to writable directory
      mkdir $TMPDIR/src
      cpdir ${src} $TMPDIR/src
      cd $TMPDIR/src

      # ── Apply TCC compatibility patch (from Guix, verified upstream) ──
      ${patch}/bin/patch -p1 < ${./patches/binutils-boot-2.20.1a.patch}

      # ── Configure ──────────────────────────────────────────────────────
      $CONFIG_SHELL ./configure \
        CC=tcc \
        CPPFLAGS="-D__GLIBC_MINOR__=6 -DMES_BOOTSTRAP=1" \
        AR="tcc -ar" \
        RANLIB=true \
        LDFLAGS="-static" \
        --build=i686-unknown-linux-gnu \
        --host=i686-unknown-linux-gnu \
        --disable-nls \
        --disable-shared \
        --disable-werror \
        --prefix=$out

      # ── Build ──────────────────────────────────────────────────────────
      make

      # ── Install ────────────────────────────────────────────────────────
      make install

      echo "binutils 2.20.1 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU tools for manipulating binaries (linker, assembler, etc.), version 2.20.1a";
    homepage = "https://www.gnu.org/software/binutils/";
    license = "GPL-3.0-or-later";
    platforms = [ "i686-linux" ];
  };
}
