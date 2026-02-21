# stdenv/bootstrap/stage7-binutils.nix — binutils 2.20.1a from GCC 2.95.3 (glibc)
#
# Recompiles binutils with GCC 2.95.3 (self-hosted) linked against glibc 2.2.5.
# Provides: as, ld, ar, nm, objcopy, objdump, ranlib, readelf, strip, size, strings.
#
# Uses the same 2.20.1a tarball as stage6-binutils-tcc for consistency.
#
# Builder: bash 2.05b. Uses ./configure && make && make install.
#
{
  gcc, # Output of stage7-gcc.nix (self-hosted GCC 2.95.3)
  glibc, # Output of stage7-glibc.nix
  linuxHeaders, # Output of stage5-linux-headers.nix
  posix-tools, # Output of stage1-posix-tools.nix
  bash, # Output of stage4-bash.nix (bash 2.05b)
  gnumake, # gnumake-tcc from stage 5
  sed, # sed-tcc from stage 5
  grep, # grep-tcc from stage 5
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
  name = "binutils-2.20.1a";
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
            gcc
            gnumake
            sed
            grep
            posix-tools
            bash
          ]
        )
      }"
      export CONFIG_SHELL="${bash}/bin/bash"
      export SHELL="${bash}/bin/bash"

      # ── Copy source to writable directory ─────────────────────────────
      mkdir $TMPDIR/src
      cpdir ${src} $TMPDIR/src
      cd $TMPDIR/src

      # ── Configure ──────────────────────────────────────────────────────
      echo "==> Configuring binutils 2.20.1a"

      CC="${gcc}/bin/gcc" \
      CFLAGS="-I${glibc}/include -I${linuxHeaders}/include" \
      LDFLAGS="-static -L${glibc}/lib" \
      $CONFIG_SHELL ./configure \
        --prefix=$out \
        --build=i686-unknown-linux-gnu \
        --host=i686-unknown-linux-gnu \
        --disable-shared \
        --disable-nls \
        --disable-werror

      # ── Build ──────────────────────────────────────────────────────────
      echo "==> Building binutils 2.20.1a"
      make

      # ── Install ────────────────────────────────────────────────────────
      echo "==> Installing binutils 2.20.1a"
      make install

      echo "binutils 2.20.1a installed to $out"
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
