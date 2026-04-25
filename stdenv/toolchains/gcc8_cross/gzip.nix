# stdenv/toolchains/gcc8_cross/gzip.nix — Phase 7
#
# Native target-arch GNU gzip 1.9, cross-compiled from x86_64.
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
    url = "https://mirrors.kernel.org/gnu/gzip/gzip-1.9.tar.xz";
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
        export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
        export PATH="${prev.coreutils}/bin:${crossGccStage2}/bin:${crossBinutils}/bin:${prev.gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.patch}/bin:${prev.bash}/bin"
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
        CPPFLAGS="-isystem ${crossGlibc}/include -D_IO_ftrylockfile -D_IO_IN_BACKUP=0x100" \
        LDFLAGS="-L${crossGlibc}/lib -static -Wl,--whole-archive -lnss_files -lnss_dns -lresolv -Wl,--no-whole-archive" \
        "$TMPDIR/src/configure" \
          --prefix="$out" \
          --build=${buildPlatform.config} --host=${hostPlatform.config}

        make -j"$NIX_BUILD_CORES"
        make install

        echo "GNU gzip 1.9 (${hostPlatform.config}) installed to $out"
      ''
    ];
  }
