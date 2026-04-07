# stdenv/toolchains/gcc3_4/gawk.nix — GNU awk 3.1.3 (RHEL 4)
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
    url = "https://mirrors.kernel.org/gnu/gawk/gawk-3.1.3.tar.bz2";
    hash = "1yhi1nzpwl206jxfm3jxyk377bmyj9lkhiyiwphfmcrg1fyzzrlz";
  };
in
builtins.derivation {
  name = "gawk-3.1.3";
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

      test -f "$out/bin/gawk" && test ! -f "$out/bin/awk" && ln -sf gawk "$out/bin/awk"

      echo "GNU awk 3.1.3 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU awk pattern scanning and processing language, version 3.1.3";
    homepage = "https://www.gnu.org/software/gawk/";
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
