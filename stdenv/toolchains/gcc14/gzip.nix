# stdenv/toolchains/gcc14/gzip.nix — GNU gzip 1.13 (RHEL 10)
#
# Production GNU gzip built with THIS tier's GCC 14.3.0 + binutils 2.41 + glibc 2.39.
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
    url = "https://mirrors.kernel.org/gnu/gzip/gzip-1.13.tar.xz";
    sha256 = "093w3a12220gzy00qi9zy52mhjlgyyh7kiimsz5xa00fgf81rbp9";
  };
in
builtins.derivation {
  name = "gzip-1.13";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      cd "$TMPDIR"
      cp -r ${src} gzip-1.13
      cd gzip-1.13
      chmod -R u+w .

      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      CC="${gcc}/bin/gcc" \
      CFLAGS="-O2 -I${glibc}/include" \
      LDFLAGS="-L${glibc}/lib -static" \
      "$TMPDIR/gzip-1.13/configure" \
        --prefix="$out"

      make -j"$(nproc)"
      make install

      echo "GNU gzip 1.13 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU gzip 1.13 compression utility";
    homepage = "https://www.gnu.org/software/gzip/";
    license = "GPL-3.0-or-later";
    platforms = [
      "i686-linux"
      "x86_64-linux"
      "aarch64-linux"
    ];
  };
}
