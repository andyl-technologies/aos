# stdenv/toolchains/gcc3_4_cross/gawk.nix — Phase 7
#
# Native x86_64 GNU awk 3.1.3, cross-compiled from i686.
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
    url = "https://mirrors.kernel.org/gnu/gawk/gawk-3.1.3.tar.bz2";
    sha256 = "1yhi1nzpwl206jxfm3jxyk377bmyj9lkhiyiwphfmcrg1fyzzrlz";
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

        test -f "$out/bin/gawk" && test ! -f "$out/bin/awk" && ln -sf gawk "$out/bin/awk"

        echo "GNU awk 3.1.3 (${hostPlatform.config}) installed to $out"
      ''
    ];
  }
