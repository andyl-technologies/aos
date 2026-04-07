# stdenv/toolchains/gcc4_8/bzip2.nix — bzip2 1.0.6 (RHEL 7)
#
# Built with THIS tier's GCC 4.8.5 + glibc 2.17, static linking.
# bzip2 has a simple Makefile — no autoconf, no configure script.
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
    url = "https://sourceware.org/pub/bzip2/bzip2-1.0.6.tar.gz";
    sha256 = "1avxlchs84q09h8njldbhg4h5andjbfvsdcdz9r6d0ahlpznfyhs";
  };
in
builtins.derivation {
  name = "bzip2-1.0.6";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin"

      cd "$TMPDIR"
      mkdir -p bzip2-1.0.6 && (cd ${src} && tar cf - .) | (cd bzip2-1.0.6 && tar xf -)
      cd bzip2-1.0.6
      chmod -R u+w .

      make \
        CC="${gcc}/bin/gcc" \
        CFLAGS="-O2 -isystem ${glibc}/include -D_FILE_OFFSET_BITS=64" \
        LDFLAGS="-L${glibc}/lib -static" \
        PREFIX="$out" \
        -j"$NIX_BUILD_CORES" \
        bzip2 bzip2recover

      mkdir -p "$out/bin" "$out/lib" "$out/include"
      cp bzip2 "$out/bin/"
      cp bzip2recover "$out/bin/"
      ln -sf bzip2 "$out/bin/bunzip2"
      ln -sf bzip2 "$out/bin/bzcat"
      cp libbz2.a "$out/lib/"
      cp bzlib.h "$out/include/"

      echo "bzip2 1.0.6 installed to $out"
    ''
  ];
}
// {
  meta = {
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
