# stdenv/toolchains/gcc3_4/patch.nix — GNU patch 2.5.4 (RHEL 4)
#
# Phase 5: full POSIX tool rebuild.
# Built with this tier's full toolchain.
# All i686-linux.
#
{
  prev,
  buildPlatform,
  hostPlatform,
  this,
  ...
}:
let
  inherit (import ../../../lib/derivations.nix { system = builtins.currentSystem; }) fetchTarball;

  src = fetchTarball {
    url = "https://mirrors.kernel.org/gnu/patch/patch-2.5.4.tar.gz";
    hash = "0wrlwv5qz02ln3m90yxmwrnv7mgdp2yidarrih1ah9ig5lcdjhmg";
  };
in
builtins.derivation {
  name = "patch-2.5.4";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export PATH="${prev.coreutils}/bin:${this.gcc}/bin:${this.binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${this.tar}/bin:${this.gzip}/bin:${prev.diffutils}/bin:${prev.patch}/bin:${prev.bash}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      cd ${src}

      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      CC="${this.gcc}/bin/gcc" \
      CFLAGS="-O2 -I${this.glibc}/include" \
      LDFLAGS="-L${this.glibc}/lib -static" \
      ${src}/configure \
        --prefix="$out"

      make -j"$NIX_BUILD_CORES"
      make install

      echo "GNU patch 2.5.4 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU patch file patching utility, version 2.5.4";
    homepage = "https://www.gnu.org/software/patch/";
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
      cpu = [
        "x86_64"
        "i686"
      ];
    };
  };
}
