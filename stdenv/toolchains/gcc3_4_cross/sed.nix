# stdenv/toolchains/gcc3_4_cross/sed.nix — Phase 7
#
# Native x86_64 GNU sed 4.1.2, cross-compiled from i686.
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
    url = "https://mirrors.kernel.org/gnu/sed/sed-4.1.2.tar.gz";
    sha256 = "11rkzxnqjz226ifblx3y003y06kaqnw45ph6jxq2d3dpyliavq2h";
  };
in
  builtins.derivation {
    name = "sed-4.1.2";
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
          --prefix="$out" \
          --build=${buildPlatform.config} --host=${hostPlatform.config} \
          --disable-nls

        make -j"$NIX_BUILD_CORES"
        make install

        echo "GNU sed 4.1.2 (${hostPlatform.config}) installed to $out"
      ''
    ];
  }
