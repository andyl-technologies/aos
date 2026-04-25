# stdenv/toolchains/gcc4_8_cross/binutils.nix — Phase 6a
#
# Native target-arch binutils 2.25, cross-compiled from x86_64.
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
    url = "https://mirrors.kernel.org/gnu/binutils/binutils-2.25.tar.bz2";
    sha256 = "sha256:12axyrxx1f74zd338l40s6033vjxm3ifx94lx2sxg4mbksq9xrca";
  };
in
  builtins.derivation {
    name = "binutils-2.25";
    system = buildPlatform.system;
    builder = "${prev.bash}/bin/bash";
    args = [
      "-c"
      ''
        set -eu
        export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
        export PATH="${prev.coreutils}/bin:${crossGccStage2}/bin:${crossBinutils}/bin:${prev.gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.bzip2}/bin:${prev.diffutils}/bin:${prev.patch}/bin:${prev.bash}/bin:${prev.m4}/bin:${prev.flex}/bin:${prev.bison}/bin:${prev.texinfo}/bin"
        export CONFIG_SHELL="${prev.bash}/bin/bash"

        cp -r ${src} "$TMPDIR/src"
        chmod -R u+w "$TMPDIR/src"

        # Touch all files first, then touch generated .c/.h to prevent regeneration
        find "$TMPDIR/src" -type f -exec touch {} + 2>/dev/null || true
        sleep 1
        find "$TMPDIR/src" -type f \( -name '*.c' -o -name '*.h' \) -exec touch {} + 2>/dev/null || true
        sleep 1
        find "$TMPDIR/src" \( -name 'configure' -o -name 'Makefile.in' -o -name 'aclocal.m4' -o -name 'config.h.in' \) -exec touch {} + 2>/dev/null || true

        mkdir -p "$TMPDIR/build"
        cd "$TMPDIR/build"

        CC="${crossGccStage2}/bin/${hostPlatform.config}-gcc" \
        CXX="${crossGccStage2}/bin/${hostPlatform.config}-g++" \
        AR="${crossBinutils}/bin/${hostPlatform.config}-ar" \
        RANLIB="${crossBinutils}/bin/${hostPlatform.config}-ranlib" \
        CFLAGS="-O2 -isystem ${crossGlibc}/include" \
        CXXFLAGS="-O2 -isystem ${crossGlibc}/include" \
        LDFLAGS="-L${crossGlibc}/lib -static" \
        "$TMPDIR/src/configure" \
          --prefix="$out" \
          --build=${buildPlatform.config} \
          --host=${hostPlatform.config} \
          --target=${hostPlatform.config} \
          --disable-shared --disable-nls \
          --disable-gdb --disable-gdbserver --disable-libdecnumber --disable-readline --disable-sim \
          --with-sysroot=/ \
          --program-transform-name=

        make -j"$NIX_BUILD_CORES"
        make install

        echo "Native binutils 2.25 (${hostPlatform.config}) installed to $out"
      ''
    ];
  }
