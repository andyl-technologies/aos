# stdenv/toolchains/gcc8/gzip.nix — GNU gzip 1.9 (RHEL 8)
#
# Built with THIS tier's GCC 8.5.0 + binutils 2.30 + glibc 2.28.
#
{
  prev,
  gcc,
  binutils,
  glibc,
  buildPlatform,
  hostPlatform,
}:
let
  src = builtins.fetchTarball {
    url = "https://ftp.gnu.org/gnu/gzip/gzip-1.9.tar.xz";
    sha256 = "0hjbnzqyhbnphcz5z5dwkbkcynjcn32mwqyj5p6ispn0jga31i2n";
  };

in
builtins.derivation {
  name = "gzip-1.9";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      cd "$TMPDIR"
      cp -r ${src} gzip-1.9
      cd gzip-1.9
      chmod -R u+w .

      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      CC="${gcc}/bin/gcc" \
      CFLAGS="-O2 -I${glibc}/include" \
      LDFLAGS="-L${glibc}/lib -static" \
      "$TMPDIR/gzip-1.9/configure" \
        --prefix="$out"

      make -j"$(nproc)"
      make install

      echo "GNU gzip 1.9 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU gzip compression utility, version 1.9";
    homepage = "https://www.gnu.org/software/gzip/";
    license = "GPL-3.0-or-later";
    platforms = [
      "i686-linux"
      "x86_64-linux"
      "aarch64-linux"
    ];
  };
}
