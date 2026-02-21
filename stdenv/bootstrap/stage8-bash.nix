# stdenv/bootstrap/stage8-bash.nix — bash 2.05b from GCC 2.95.3 (glibc)
#
# Compiled with self-hosted GCC 2.95.3 linked against glibc 2.2.5.
# Uses configure/make (via TCC-compiled tools from stage 5) instead of
# hand-compiling every .c file.
#
# Static binary — no dynamic linker issues. At stage 8 we have a full
# GCC + glibc + all POSIX tools, so configure+make works cleanly.
#
# Builder: bash 2.05b (TCC-compiled, stage 4)
#
{
  gcc, # Self-hosted GCC 2.95.3
  binutils, # Binutils (rebuilt with GCC)
  glibc, # glibc 2.2.5
  linuxHeaders, # Linux kernel headers
  posix-tools, # Output of stage1-posix-tools.nix
  bash, # TCC-compiled bash 2.05b (stage 4, used as builder)
  gnumake, # gnumake-tcc from stage 5
  sed, # sed-tcc from stage 5 (needed by configure)
  grep, # grep-tcc from stage 5 (needed by configure)
  buildPlatform,
  ...
}:
let
  system = buildPlatform.system;

  src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/bash/bash-2.05b.tar.gz";
    sha256 = "sha256-TsSxfIbg+xOIMfOVzjszOKbEG7Hj4b19D8oqMg0ek0g=";
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
  name = "bash-2.05b";
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
            binutils
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

      # Copy source to writable directory
      mkdir $TMPDIR/src
      cpdir ${src} $TMPDIR/src
      cd $TMPDIR/src

      CC="${gcc}/bin/gcc" \
      CFLAGS="-I${glibc}/include -I${linuxHeaders}/include" \
      LDFLAGS="-static -L${glibc}/lib" \
      CONFIG_SHELL="${bash}/bin/bash" \
      ./configure \
        --prefix=$out \
        --build=i686-unknown-linux-gnu \
        --host=i686-unknown-linux-gnu \
        --without-bash-malloc

      make
      make install

      # Create sh symlink
      ln -s bash $out/bin/sh

      echo "bash 2.05b built successfully"
    ''
  ];
}
// {
  meta = {
    description = "GNU Bourne-Again SHell, version 2.05b";
    homepage = "https://www.gnu.org/software/bash/";
    license = "GPL-2.0-or-later";
    platforms = [ "i686-linux" ];
  };
}
