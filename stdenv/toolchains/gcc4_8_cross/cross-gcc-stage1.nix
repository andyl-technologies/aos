# stdenv/toolchains/gcc4_8_cross/cross-gcc-stage1.nix — Phase 2
#
# Cross GCC 4.8.5 stage 1: runs on x86_64, targets target arch, no libc.
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
    url = "https://mirrors.kernel.org/gnu/gcc/gcc-4.8.5/gcc-4.8.5.tar.bz2";
    sha256 = "0d9dzzhp8v0wbiiyy13jymq0dh23qdk8zkh1i3kfqjqb5b96rjf6";
  };

  gmpSrc = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/gmp/gmp-5.1.3.tar.bz2";
    sha256 = "1ywxm99myn8qny788sb7b2vq7kvmqhmc808na2a0v08nvz5sfx97";
  };

  mpfrSrc = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/mpfr/mpfr-3.1.2.tar.bz2";
    sha256 = "1rk77zyqykqh6m425ig547lc8b1wd5z3jsb1046g5mpmv7904gr3";
  };

  mpcSrc = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/mpc/mpc-1.0.3.tar.gz";
    sha256 = "1scdw4gm8hfgkxpnhh33wvgcvh26zzkhza37wxilwwl8kkhn867p";
  };
in
  builtins.derivation {
    name = "cross-gcc-stage1-4.8.5";
    system = buildPlatform.system;
    builder = "${prev.bash}/bin/bash";
    args = [
      "-c"
      ''
        set -eu
        export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
        export PATH="${prev.coreutils}/bin:${prev.gcc}/bin:${prev.binutils}/bin:${crossBinutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.bzip2}/bin:${prev.diffutils}/bin:${prev.patch}/bin:${prev.bash}/bin:${prev.m4}/bin:${prev.flex}/bin:${prev.bison}/bin:${prev.texinfo}/bin"
        export CONFIG_SHELL="${prev.bash}/bin/bash"

        mkdir -p "$TMPDIR/gcc-4.8.5"
        (cd ${gccSrc} && tar cf - .) | (cd "$TMPDIR/gcc-4.8.5" && tar xf -)
        chmod -R u+w "$TMPDIR/gcc-4.8.5"

        # In-tree GMP, MPFR, MPC
        mkdir -p "$TMPDIR/gcc-4.8.5/gmp"
        (cd ${gmpSrc} && tar cf - .) | (cd "$TMPDIR/gcc-4.8.5/gmp" && tar xf -)
        chmod -R u+w "$TMPDIR/gcc-4.8.5/gmp"
        mkdir -p "$TMPDIR/gcc-4.8.5/mpfr"
        (cd ${mpfrSrc} && tar cf - .) | (cd "$TMPDIR/gcc-4.8.5/mpfr" && tar xf -)
        chmod -R u+w "$TMPDIR/gcc-4.8.5/mpfr"
        mkdir -p "$TMPDIR/gcc-4.8.5/mpc"
        (cd ${mpcSrc} && tar cf - .) | (cd "$TMPDIR/gcc-4.8.5/mpc" && tar xf -)
        chmod -R u+w "$TMPDIR/gcc-4.8.5/mpc"

        SRC="$TMPDIR/gcc-4.8.5"
        cd "$SRC"

        find . -name configure -exec chmod +x {} + 2>/dev/null || true
        find . -name '*.sh' -exec chmod +x {} + 2>/dev/null || true
        chmod +x move-if-change mkinstalldirs install-sh missing depcomp ylwrap 2>/dev/null || true
        # Touch all files first, then touch generated .c/.h to prevent regeneration
        find . -type f -exec touch {} + 2>/dev/null || true
        sleep 1
        find . -type f \( -name '*.c' -o -name '*.h' \) -exec touch {} + 2>/dev/null || true
        sleep 1
        find . \( -name 'configure' -o -name 'Makefile.in' -o -name 'aclocal.m4' -o -name 'config.h.in' \) -exec touch {} + 2>/dev/null || true

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

        CC="${prev.gcc}/bin/gcc" \
        CXX="${prev.gcc}/bin/g++" \
        CFLAGS="-O2 -isystem ${prev.glibc}/include" \
        CXXFLAGS="-O2 -isystem ${prev.glibc}/include" \
        LDFLAGS="-L${prev.glibc}/lib -static" \
        "$SRC/configure" \
          --prefix="$out" \
          --build=${buildPlatform.config} \
          --host=${buildPlatform.config} \
          --target=${hostPlatform.config} \
          --enable-languages=c,c++ \
          --without-headers --with-newlib \
          --disable-shared --disable-nls --disable-threads \
          --disable-multilib --disable-bootstrap \
          --disable-libssp --disable-libgomp --disable-libmudflap \
          --disable-libsanitizer \
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

        make install-gcc

        # GCC's install for cross builds doesn't always create $target-gcc
        test -f "$out/bin/gcc" && test ! -f "$out/bin/${hostPlatform.config}-gcc" && \
          ln -sf gcc "$out/bin/${hostPlatform.config}-gcc"
        test -f "$out/bin/g++" && test ! -f "$out/bin/${hostPlatform.config}-g++" && \
          ln -sf g++ "$out/bin/${hostPlatform.config}-g++"

        # Create empty libgcc_eh.a and re-index libgcc.a
        GCCLIB="$out/lib/gcc/${hostPlatform.config}/4.8.5"
        mkdir -p "$GCCLIB"
        "${prev.binutils}/bin/ar" crs "$GCCLIB/libgcc_eh.a"
        "${crossBinutils}/bin/${hostPlatform.config}-ranlib" \
          "$GCCLIB/libgcc.a" 2>/dev/null || true

        echo "Cross GCC stage 1 (${buildPlatform.config} → ${hostPlatform.config}) installed to $out"
      ''
    ];
  }
