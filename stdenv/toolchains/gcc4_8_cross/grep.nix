# stdenv/toolchains/gcc4_8_cross/grep.nix — Phase 7
#
# Native target-arch GNU grep 2.20, cross-compiled from x86_64.
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
    url = "https://mirrors.kernel.org/gnu/grep/grep-2.20.tar.xz";
    sha256 = "10kwh7l1gnnycsignmi13b5nl8f0xbg86dzayx4ara3lmnj98x26";
  };
in
  builtins.derivation {
    name = "grep-2.20";
    system = buildPlatform.system;
    builder = "${prev.bash}/bin/bash";
    args = [
      "-c"
      ''
        set -eu
        export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
        export PATH="${prev.coreutils}/bin:${crossGccStage2}/bin:${crossBinutils}/bin:${prev.gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.bzip2}/bin:${prev.xz}/bin:${prev.diffutils}/bin:${prev.patch}/bin:${prev.bash}/bin"
        export CONFIG_SHELL="${prev.bash}/bin/bash"

        cp -r ${src} "$TMPDIR/src"
        chmod -R u+w "$TMPDIR/src"
        find "$TMPDIR/src" -name configure -exec chmod +x {} + 2>/dev/null || true
        find "$TMPDIR/src" -name '*.sh' -exec chmod +x {} + 2>/dev/null || true
        chmod +x "$TMPDIR/src/install-sh" "$TMPDIR/src/missing" "$TMPDIR/src/build-aux/install-sh" 2>/dev/null || true
        find "$TMPDIR/src" -type f \( -name '*.c' -o -name '*.h' \) -exec touch {} + 2>/dev/null || true
        sleep 1
        find "$TMPDIR/src" \( -name 'configure' -o -name 'Makefile.in' -o -name 'aclocal.m4' -o -name 'config.h.in' \) -exec touch {} + 2>/dev/null || true

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

        echo "GNU grep 2.20 (${hostPlatform.config}) installed to $out"
      ''
    ];
  }
