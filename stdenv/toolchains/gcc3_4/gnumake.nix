# stdenv/toolchains/gcc3_4/gnumake.nix — GNU Make 3.80 (RHEL 4)
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
    url = "https://mirrors.kernel.org/gnu/make/make-3.80.tar.bz2";
    hash = "050qpdwd85y7f9lhkj0i19av2nybn248m26zkl2as47wp2y1daki";
  };
in
builtins.derivation {
  name = "gnumake-3.80";
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
        --prefix="$out" \
        --build=${buildPlatform.config} --host=${hostPlatform.config} --target=${hostPlatform.config} \
        --disable-nls

      make -j"$NIX_BUILD_CORES"
      make install

      echo "GNU Make 3.80 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU Make build automation tool, version 3.80";
    homepage = "https://www.gnu.org/software/make/";
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
