# stdenv/toolchains/gcc3_4/gzip.nix — GNU gzip 1.3.5 (RHEL 4)
#
# Phase 4: compression utility needed for tar.gz extraction.
# Built with this tier's GCC 3.4.6 + binutils 2.15 + glibc 2.3.4.
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
  src = builtins.fetchTarball {
    url = "https://alpha.gnu.org/gnu/gzip/gzip-1.3.5.tar.gz";
    sha256 = "1pkqayhb6rs3aj858wxyga4q3nha8x9y7bn5lbqad4985y5a0hm7";
  };
in
builtins.derivation {
  name = "gzip-1.3.5";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export PATH="${prev.coreutils}/bin:${this.gcc}/bin:${this.binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.patch}/bin:${prev.bash}/bin"
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

      echo "GNU gzip 1.3.5 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU gzip compression utility, version 1.3.5";
    homepage = "https://www.gnu.org/software/gzip/";
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
