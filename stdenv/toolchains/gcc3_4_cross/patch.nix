# stdenv/toolchains/gcc3_4_cross/patch.nix — Phase 7
#
# Native x86_64 GNU patch 2.5.4, cross-compiled from i686.
#
{
  prev,
  crossGccStage2,
  crossBinutils,
  crossGlibc,
  buildPlatform,
  hostPlatform,
  ...
}: let
  src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/patch/patch-2.5.4.tar.gz";
    sha256 = "0wrlwv5qz02ln3m90yxmwrnv7mgdp2yidarrih1ah9ig5lcdjhmg";
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
        export PATH="${prev.coreutils}/bin:${crossGccStage2}/bin:${crossBinutils}/bin:${prev.gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.patch}/bin:${prev.bash}/bin"
        export CONFIG_SHELL="${prev.bash}/bin/bash"

        mkdir -p "$TMPDIR/build"
        cd "$TMPDIR/build"

        CC="${crossGccStage2}/bin/${hostPlatform.config}-gcc" \
        AR="${crossBinutils}/bin/${hostPlatform.config}-ar" \
        RANLIB="${crossBinutils}/bin/${hostPlatform.config}-ranlib" \
        CFLAGS="-O2 -isystem ${crossGlibc}/include" \
        LDFLAGS="-L${crossGlibc}/lib -static -Wl,--whole-archive -lnss_files -lnss_dns -lresolv -Wl,--no-whole-archive" \
        ${src}/configure \
          --prefix="$out"

        make -j"$NIX_BUILD_CORES"
        make install

        echo "GNU patch 2.5.4 (${hostPlatform.config}) installed to $out"
      ''
    ];
  }
