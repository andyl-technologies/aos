# stdenv/toolchains/gcc8_cross/cross-gcc-stage1.nix — Phase 2
#
# Cross GCC 8.5.0 stage 1: runs on x86_64, targets target arch, no libc.
# Minimal C-only compiler for building glibc. Produces libgcc.
#
{
  prev,
  crossBinutils,
  buildPlatform,
  hostPlatform,
  ...
}: let
  gccSrc = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/gcc/gcc-8.5.0/gcc-8.5.0.tar.xz";
    sha256 = "1d4xjxwvxd4zi4hy7z2fqbd8mfddj32x4w5cqw163lz0q1yf1ak4";
  };

  gmpSrc = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/gmp/gmp-6.3.0.tar.xz";
    sha256 = "1kc3dy4jxand0y118yb9715g9xy1fnzqgkwxy02vd57y2fhg2pcw";
  };

  mpfrSrc = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/mpfr/mpfr-4.2.1.tar.xz";
    sha256 = "1irpgc9aqyhgkwqk7cvib1dgr5v5hf4m0vaaknssyfpkjmab9ydq";
  };

  mpcSrc = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/mpc/mpc-1.3.1.tar.gz";
    sha256 = "1b6layaybj039fajx8dpy2zvcfy7s02y3y4lficz16vac0fsd0jk";
  };
in
  builtins.derivation {
    name = "cross-gcc-stage1-8.5.0";
    system = buildPlatform.system;
    builder = "${prev.bash}/bin/bash";
    args = [
      "-c"
      ''
        set -eu
        export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
        export PATH="${prev.coreutils}/bin:${prev.gcc}/bin:${prev.binutils}/bin:${crossBinutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.patch}/bin:${prev.bash}/bin:${prev.m4}/bin:${prev.flex}/bin:${prev.bison}/bin:${prev.texinfo}/bin"
        export CONFIG_SHELL="${prev.bash}/bin/bash"

        cp -r ${gccSrc} "$TMPDIR/gcc-8.5.0"
        chmod -R u+w "$TMPDIR/gcc-8.5.0"

        # In-tree GMP, MPFR, MPC
        cp -r ${gmpSrc} "$TMPDIR/gcc-8.5.0/gmp"
        chmod -R u+w "$TMPDIR/gcc-8.5.0/gmp"
        cp -r ${mpfrSrc} "$TMPDIR/gcc-8.5.0/mpfr"
        chmod -R u+w "$TMPDIR/gcc-8.5.0/mpfr"
        cp -r ${mpcSrc} "$TMPDIR/gcc-8.5.0/mpc"
        chmod -R u+w "$TMPDIR/gcc-8.5.0/mpc"

        SRC="$TMPDIR/gcc-8.5.0"
        cd "$SRC"

        find . -name configure -exec chmod +x {} + 2>/dev/null || true
        find . -name '*.sh' -exec chmod +x {} + 2>/dev/null || true
        chmod +x move-if-change mkinstalldirs install-sh missing depcomp ylwrap 2>/dev/null || true
        # Touch autotools outputs first, then source files
        for dir in . gmp mpfr mpc; do
          find "$dir" \( -name 'configure' -o -name 'Makefile.in' -o -name 'aclocal.m4' -o -name 'config.h.in' \) -exec touch {} + 2>/dev/null || true
        done
        sleep 1
        for dir in . gmp mpfr mpc; do
          find "$dir" -type f \( -name '*.c' -o -name '*.h' \) -exec touch {} + 2>/dev/null || true
        done

        # CC wrapper: add -std=gnu99 + static linking
        mkdir -p "$TMPDIR/ccwrap"
        printf '#!${prev.bash}/bin/bash\nexec ${prev.gcc}/bin/gcc -std=gnu99 -L${prev.glibc}/lib -static "$@"\n' > "$TMPDIR/ccwrap/gcc"
        printf '#!${prev.bash}/bin/bash\nexec ${prev.gcc}/bin/g++ -L${prev.glibc}/lib -static "$@"\n' > "$TMPDIR/ccwrap/g++"
        chmod +x "$TMPDIR/ccwrap/gcc" "$TMPDIR/ccwrap/g++"
        ln -sf gcc "$TMPDIR/ccwrap/cc"
        ln -sf g++ "$TMPDIR/ccwrap/c++"
        export PATH="$TMPDIR/ccwrap:$PATH"

        # Disable fixincludes
        ${prev.sed}/bin/sed -i \
          -e 's@\./fixinc\.sh@-c true@' \
          -e 's|then sleep 1; else exit 1; fi;|then sleep 1; else sleep 1; fi;|' \
          gcc/Makefile.in

        # Patch out hardcoded /usr/include
        ${prev.sed}/bin/sed -i \
          "s|native_system_header_dir=/usr/include|native_system_header_dir=/nonexistent|g" \
          gcc/configure

        mkdir -p "$TMPDIR/build"
        cd "$TMPDIR/build"

        CC="$TMPDIR/ccwrap/gcc" CXX="$TMPDIR/ccwrap/g++" \
        CFLAGS="-O2" CXXFLAGS="-O2" \
        "$SRC/configure" \
          --prefix="$out" \
          --build=${buildPlatform.config} \
          --host=${buildPlatform.config} \
          --target=${hostPlatform.config} \
          --enable-languages=c,c++ \
          --without-headers --with-newlib \
          --disable-shared --disable-nls --disable-threads \
          --disable-multilib --disable-bootstrap \
          --disable-libssp --disable-libgomp \
          --disable-libsanitizer --disable-libmpx --disable-libvtv \
          --disable-lto --disable-plugin \
          --program-transform-name=

        # Patch SYSTEM_HEADER_DIR to avoid /usr/include
        mkdir -p "$TMPDIR/empty-headers"
        make configure-gcc
        ${prev.sed}/bin/sed -i \
          "s|^SYSTEM_HEADER_DIR.*|SYSTEM_HEADER_DIR = $TMPDIR/empty-headers|" \
          gcc/Makefile

        # Create $prefix/$target/bin/ with cross-tool symlinks so xgcc
        # can find the target assembler/linker when building CRT files
        mkdir -p "$out/${hostPlatform.config}/bin"
        for tool in as ld ar ranlib nm objcopy objdump strip; do
          ln -sf ${crossBinutils}/bin/${hostPlatform.config}-$tool \
            "$out/${hostPlatform.config}/bin/$tool" 2>/dev/null || true
        done

        make -j"$NIX_BUILD_CORES" all-gcc \
          BOOT_CFLAGS="-O2"

        make -j"$NIX_BUILD_CORES" all-target-libgcc \
          CFLAGS_FOR_TARGET="-O2"

        make install-gcc
        make install-target-libgcc

        # GCC's install for cross builds doesn't always create $target-gcc
        test -f "$out/bin/gcc" && test ! -f "$out/bin/${hostPlatform.config}-gcc" && \
          ln -sf gcc "$out/bin/${hostPlatform.config}-gcc"
        test -f "$out/bin/g++" && test ! -f "$out/bin/${hostPlatform.config}-g++" && \
          ln -sf g++ "$out/bin/${hostPlatform.config}-g++"

        # Create libgcc_eh.a and re-index libgcc.a
        GCCLIB="$out/lib/gcc/${hostPlatform.config}/8.5.0"
        mkdir -p "$GCCLIB"
        test -f "$GCCLIB/libgcc.a" || { echo "FATAL: libgcc.a not installed"; exit 1; }
        if [ ! -f "$GCCLIB/libgcc_eh.a" ]; then
          "${crossBinutils}/bin/${hostPlatform.config}-ar" crs "$GCCLIB/libgcc_eh.a"
        fi
        "${crossBinutils}/bin/${hostPlatform.config}-ranlib" \
          "$GCCLIB/libgcc.a" 2>/dev/null || true

        echo "Cross GCC stage 1 (${buildPlatform.config} → ${hostPlatform.config}) installed to $out"
      ''
    ];
  }
