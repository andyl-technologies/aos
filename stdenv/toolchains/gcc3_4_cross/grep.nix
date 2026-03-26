# stdenv/toolchains/gcc3_4_cross/grep.nix — Phase 7
#
# Native x86_64 GNU grep 2.5.1, cross-compiled from i686.
#
{
  prev,
  crossGccStage2,
  crossBinutils,
  crossGlibc,
  buildPlatform,
  hostPlatform,
  ...
}:
let
  src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/grep/grep-2.5.1.tar.bz2";
    sha256 = "0in49mhmxsl52jyzp0qwz31xz8yvyfxsjxx17x1az01d5kvkk11l";
  };
in
builtins.derivation {
  name = "grep-2.5.1";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export PATH="${prev.coreutils}/bin:${crossGccStage2}/bin:${crossBinutils}/bin:${prev.gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.patch}/bin:${prev.bash}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      # grep build tries to update doc/version.texi — needs writable source
      cp -r ${src} "$TMPDIR/src"
      chmod -R u+w "$TMPDIR/src"

      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      CC="${crossGccStage2}/bin/${hostPlatform.config}-gcc" \
      AR="${crossBinutils}/bin/${hostPlatform.config}-ar" \
      RANLIB="${crossBinutils}/bin/${hostPlatform.config}-ranlib" \
      CFLAGS="-O2 -isystem ${crossGlibc}/include" \
      LDFLAGS="-L${crossGlibc}/lib -static -Wl,--whole-archive -lnss_files -lnss_dns -lresolv -Wl,--no-whole-archive" \
      "$TMPDIR/src/configure" \
        --prefix="$out" \
        --build=${buildPlatform.config} --host=${hostPlatform.config} \
        --disable-nls \
        --disable-perl-regexp

      make -j"$NIX_BUILD_CORES"
      make install

      echo "GNU grep 2.5.1 (${hostPlatform.config}) installed to $out"
    ''
  ];
}
