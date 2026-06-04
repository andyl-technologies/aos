# stdenv/toolchains/gcc14/bzip2.nix — bzip2 1.0.8 (RHEL 10)
#
# bzip2 compression tool built with THIS tier's GCC 14.3.0. Required so that
# GNU tar can decompress .tar.bz2 source tarballs in the production stdenv.
#
{
  prev,
  gcc,
  binutils,
  glibc,
  buildPlatform,
  hostPlatform,
}: let
  src = builtins.fetchTarball {
    url = "https://sourceware.org/pub/bzip2/bzip2-1.0.8.tar.gz";
    sha256 = "1a0pl9gq1iny210b0vkrf4lp0hjcks3cmf19hfvi44fgjcjviy2j";
  };
in
  builtins.derivation {
    name = "bzip2-1.0.8";
    system = buildPlatform.system;
    builder = "${prev.bash}/bin/bash";
    args = [
      "-c"
      ''
        set -eu
        export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin"

        cd "$TMPDIR"
        mkdir bzip2-1.0.8 && (cd ${src} && ${prev.tar}/bin/tar cf - .) | (cd bzip2-1.0.8 && ${prev.tar}/bin/tar xf -)
        cd bzip2-1.0.8
        chmod -R u+w .

        make \
          CC="${gcc}/bin/gcc" \
          CFLAGS="-O2 -fPIC -isystem ${glibc.dev}/include -D_FILE_OFFSET_BITS=64" \
          LDFLAGS="-L${glibc}/lib -Wl,-rpath,${glibc}/lib -Wl,--dynamic-linker,${glibc}/lib/ld-linux-x86-64.so.2" \
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

        echo "bzip2 1.0.8 installed to $out"
      ''
    ];
  }
  // {
    meta = {
      description = "bzip2 1.0.8 — block-sorting file compressor";
      homepage = "https://sourceware.org/bzip2/";
      license = "bzip2-1.0.6";
      build = {
        os = "linux";
      };
      execute = {
        os = "linux";
      };
    };
  }
