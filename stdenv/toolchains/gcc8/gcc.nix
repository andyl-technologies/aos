# stdenv/toolchains/gcc8/gcc.nix — GCC 8.5.0 (C+C++, RHEL 8)
#
# Requires C++11 (provided by GCC 4.8.5 from the previous tier).
# In-tree GMP/MPFR/MPC.
#
{
  prev,
  buildPlatform,
  hostPlatform,
  targetPlatform,
}: let
  src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/gcc/gcc-8.5.0/gcc-8.5.0.tar.xz";
    sha256 = "1d4xjxwvxd4zi4hy7z2fqbd8mfddj32x4w5cqw163lz0q1yf1ak4";
  };

  gmp-src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/gmp/gmp-6.3.0.tar.xz";
    sha256 = "1kc3dy4jxand0y118yb9715g9xy1fnzqgkwxy02vd57y2fhg2pcw";
  };

  mpfr-src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/mpfr/mpfr-4.2.1.tar.xz";
    sha256 = "1irpgc9aqyhgkwqk7cvib1dgr5v5hf4m0vaaknssyfpkjmab9ydq";
  };

  mpc-src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/mpc/mpc-1.3.1.tar.gz";
    sha256 = "1b6layaybj039fajx8dpy2zvcfy7s02y3y4lficz16vac0fsd0jk";
  };
in
  builtins.derivation {
    name = "gcc-8.5.0";
    system = buildPlatform.system;
    builder = "${prev.bash}/bin/bash";
    args = [
      "-c"
      ''
        set -eu
        export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
        export PATH="${prev.coreutils}/bin:${prev.gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin:${prev.m4}/bin:${prev.flex}/bin:${prev.bison}/bin:${prev.autoconf}/bin:${prev.automake}/bin:${prev.texinfo}/bin:${prev.help2man}/bin"
        export CONFIG_SHELL="${prev.bash}/bin/bash"

        cd "$TMPDIR"
        # cp -r from coreutils-8.22/glibc-2.17 fails with "Function not implemented"
        # (fchmodat AT_SYMLINK_NOFOLLOW bug). Use tar pipe workaround instead.
        mkdir gcc-8.5.0 && (cd ${src} && ${prev.tar}/bin/tar cf - .) | (cd gcc-8.5.0 && ${prev.tar}/bin/tar xf -)
        cd gcc-8.5.0
        chmod -R u+w .

        # In-tree GMP/MPFR/MPC
        mkdir gmp && (cd ${gmp-src} && ${prev.tar}/bin/tar cf - .) | (cd gmp && ${prev.tar}/bin/tar xf -)
        chmod -R u+w gmp
        mkdir mpfr && (cd ${mpfr-src} && ${prev.tar}/bin/tar cf - .) | (cd mpfr && ${prev.tar}/bin/tar xf -)
        chmod -R u+w mpfr
        mkdir mpc && (cd ${mpc-src} && ${prev.tar}/bin/tar cf - .) | (cd mpc && ${prev.tar}/bin/tar xf -)
        chmod -R u+w mpc

        # Touch autotools-generated files to prevent regeneration
        for dir in . gmp mpfr mpc; do
          find "$dir" \( -name 'configure' -o -name 'Makefile.in' -o -name 'aclocal.m4' -o -name 'config.h.in' \) -exec touch {} + 2>/dev/null || true
        done
        sleep 1
        for dir in . gmp mpfr mpc; do
          find "$dir" -type f \( -name '*.c' -o -name '*.h' \) -exec touch {} + 2>/dev/null || true
        done

        # CC wrapper: add -std=gnu99 (GCC 4.8.5 defaults to C89)
        mkdir -p "$TMPDIR/ccwrap"
        printf '#!/bin/sh\nexec ${prev.gcc}/bin/gcc -std=gnu99 "$@"\n' > "$TMPDIR/ccwrap/gcc"
        printf '#!/bin/sh\nexec ${prev.gcc}/bin/g++ "$@"\n' > "$TMPDIR/ccwrap/g++"
        chmod +x "$TMPDIR/ccwrap/gcc" "$TMPDIR/ccwrap/g++"
        ln -sf gcc "$TMPDIR/ccwrap/cc"
        ln -sf g++ "$TMPDIR/ccwrap/c++"
        # Prefixed variants (GMP configure may look for these)
        ln -sf gcc "$TMPDIR/ccwrap/${targetPlatform.config}-gcc"
        ln -sf g++ "$TMPDIR/ccwrap/${targetPlatform.config}-g++"
        ln -sf gcc "$TMPDIR/ccwrap/${targetPlatform.config}-cc"
        export PATH="$TMPDIR/ccwrap:$PATH"

        # Set up target sysroot so xgcc can find glibc headers + libs
        mkdir -p "$TMPDIR/sysroot/usr"
        ln -sf ${prev.glibc}/include "$TMPDIR/sysroot/usr/include"
        ln -sf ${prev.glibc}/lib "$TMPDIR/sysroot/usr/lib"
        ln -sf ${prev.glibc}/lib "$TMPDIR/sysroot/lib"

        mkdir -p "$TMPDIR/build"
        cd "$TMPDIR/build"

        CC="$TMPDIR/ccwrap/gcc" CXX="$TMPDIR/ccwrap/g++" \
        CFLAGS="-O2 -static" CXXFLAGS="-O2 -static" \
        LDFLAGS="-static" \
        "$TMPDIR/gcc-8.5.0/configure" \
          --prefix="$out" \
          --build=${hostPlatform.config} --host=${hostPlatform.config} --target=${targetPlatform.config} \
          --enable-languages=c,c++ \
          --disable-shared --disable-nls --disable-threads \
          --disable-multilib --disable-bootstrap \
          --disable-libssp --disable-libgomp --disable-libsanitizer \
          --disable-libmpx --disable-libvtv \
          --with-native-system-header-dir="/usr/include" \
          --with-build-sysroot="$TMPDIR/sysroot" \
          --program-transform-name=

        make -j"$NIX_BUILD_CORES" \
          AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true \
          BOOT_CFLAGS="-O2 -static" \
          CFLAGS_FOR_TARGET="-O2" \
          LDFLAGS_FOR_TARGET="-static"

        make install \
          AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true

        [ -f "$out/bin/gcc" ] && [ ! -f "$out/bin/cc" ] && ln -sf gcc "$out/bin/cc"
        [ -f "$out/bin/g++" ] && [ ! -f "$out/bin/c++" ] && ln -sf g++ "$out/bin/c++"

        # Symlink binutils tools so gcc can find as/ld
        mkdir -p "$out/${targetPlatform.config}/bin"
        for tool in as ld ar ranlib nm objcopy objdump strip; do
          ln -sf ${prev.binutils}/bin/$tool "$out/${targetPlatform.config}/bin/$tool" 2>/dev/null || true
          ln -sf ${prev.binutils}/bin/$tool "$out/bin/$tool" 2>/dev/null || true
        done

        # Set up so gcc finds glibc headers + startfiles + libraries
        SPEC_DIR="$out/lib/gcc/${targetPlatform.config}/8.5.0"
        # Symlink glibc startfiles into gcc lib dir
        for f in ${prev.glibc}/lib/crt*.o; do
          bn="$(basename "$f")"
          ln -sf "$f" "$SPEC_DIR/$bn" 2>/dev/null || true
        done
        ln -sf ${prev.glibc}/lib/libc.a "$SPEC_DIR/libc.a" 2>/dev/null || true
        ln -sf ${prev.glibc}/lib/libm.a "$SPEC_DIR/libm.a" 2>/dev/null || true
        ln -sf ${prev.glibc}/lib/libpthread.a "$SPEC_DIR/libpthread.a" 2>/dev/null || true
        # Install specs file: add glibc paths, default -static, always --start-group
        "$out/bin/gcc" -dumpspecs > "$SPEC_DIR/specs"
        # Add -idirafter for glibc headers (not -isystem, which goes before C++ headers
        # and breaks #include_next <stdlib.h> in cstdlib)
        ${prev.sed}/bin/sed -i '/^\*cpp:$/{n; s|^|-idirafter ${prev.glibc}/include |}' \
          "$SPEC_DIR/specs" 2>/dev/null || true
        # Default to -static unless -shared or -nostdlib is given.
        # NOTE: we intentionally do NOT add -L${prev.glibc}/lib here — that would
        # conflict with later tiers that compile against a newer glibc but link via
        # this gcc (specs -L comes before user LDFLAGS).  Consumers must pass their
        # own -L<glibc>/lib explicitly.
        ${prev.sed}/bin/sed -i '/^\*link:$/{n; s|^|%{!shared:%{!nostdlib:-static}} |}' \
          "$SPEC_DIR/specs" 2>/dev/null || true
        # Use --start-group for -lgcc/-lc in static linking (resolves circular deps)
        ${prev.sed}/bin/sed -i '/^\*link_gcc_c_sequence:$/{n; s|.*|%{!shared:%{!nostdlib:--start-group}} %G %L %{!shared:%{!nostdlib:--end-group}}|}' \
          "$SPEC_DIR/specs" 2>/dev/null || true

        echo "GCC 8.5.0 installed to $out"
      ''
    ];
  }
  // {
    meta = {
      description = "GNU Compiler Collection, version 8.5.0 (C, C++)";
      homepage = "https://gcc.gnu.org/";
      license = "GPL-3.0-or-later";
      build = {
        os = "linux";
        cpu = [
          "x86_64"
          "aarch64"
          "riscv64"
        ];
      };
      execute = {
        os = "linux";
        cpu = [
          "x86_64"
          "aarch64"
          "riscv64"
        ];
      };
      target = {
        os = "linux";
        cpu = [
          "x86_64"
          "aarch64"
          "riscv64"
        ];
      };
    };
  }
