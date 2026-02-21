# stdenv/bootstrap/stage8-gawk.nix — GNU awk 3.0.6 from GCC 2.95.3 (glibc)
#
# Compiled with self-hosted GCC 2.95.3 linked against glibc 2.2.5.
# Uses configure/make (via TCC-compiled tools from stage 5).
#
# GNU awk 3.0.6 (November 2000) is era-appropriate for GCC 2.95.3.
#
# Builder: bash 2.05b (TCC-compiled, stage 4)
#
{
  gcc, # Self-hosted GCC 2.95.3
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
    url = "https://mirrors.kernel.org/gnu/gawk/gawk-3.0.6.tar.gz";
    sha256 = "sha256-KxjOpC2yN3DtY3HOcoe+/Ze71nE+BegC8mYxld6qu7c=";
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
  name = "gawk-3.0.6";
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
        --disable-nls

      make
      make install

      # Create awk symlink if not present
      test -f "$out/bin/gawk" && test ! -f "$out/bin/awk" && ln -s gawk "$out/bin/awk"

      echo "GNU awk 3.0.6 built successfully"
    ''
  ];
}
// {
  meta = {
    description = "GNU awk pattern scanning and processing language, version 3.0.6";
    homepage = "https://www.gnu.org/software/gawk/";
    license = "GPL-2.0-or-later";
    platforms = [ "i686-linux" ];
  };
}
