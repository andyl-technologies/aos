# stdenv/toolchains/gcc11/gcc.nix — GCC 11.5.0 (RHEL 9)
#
# Built by GCC 8.5.0 from the previous tier. Requires C++14 host compiler.
# In-tree GMP/MPFR/MPC/ISL for Graphite loop optimizations.
#
{
  prev,
  buildPlatform,
  hostPlatform,
  targetPlatform,
}:
let
  inherit (import ../../../lib/derivations.nix { system = builtins.currentSystem; }) fetchTarball;

  src = fetchTarball {
    url = "https://mirrors.kernel.org/gnu/gcc/gcc-11.5.0/gcc-11.5.0.tar.xz";
    hash = "1gd9gix3jgbmav964rrp8c8h2dp1mkszwyawvxgik6cw4r2hx9s3";
  };

  gmp-src = fetchTarball {
    url = "https://mirrors.kernel.org/gnu/gmp/gmp-6.3.0.tar.xz";
    hash = "1kc3dy4jxand0y118yb9715g9xy1fnzqgkwxy02vd57y2fhg2pcw";
  };

  mpfr-src = fetchTarball {
    url = "https://mirrors.kernel.org/gnu/mpfr/mpfr-4.2.1.tar.xz";
    hash = "1irpgc9aqyhgkwqk7cvib1dgr5v5hf4m0vaaknssyfpkjmab9ydq";
  };

  mpc-src = fetchTarball {
    url = "https://mirrors.kernel.org/gnu/mpc/mpc-1.3.1.tar.gz";
    hash = "1b6layaybj039fajx8dpy2zvcfy7s02y3y4lficz16vac0fsd0jk";
  };

  isl-src = fetchTarball {
    url = "https://libisl.sourceforge.io/isl-0.24.tar.bz2";
    hash = "05rkpcwxm1cq0pp10vzkaadppyqylkx79p306js2xm869pibjfl9";
  };
in
builtins.derivation {
  name = "gcc-11.5.0";
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
      # cp -r from coreutils/glibc may fail with "Function not implemented"
      # (fchmodat AT_SYMLINK_NOFOLLOW bug). Use tar pipe workaround instead.
      mkdir gcc-11.5.0 && (cd ${src} && ${prev.tar}/bin/tar cf - .) | (cd gcc-11.5.0 && ${prev.tar}/bin/tar xf -)
      cd gcc-11.5.0
      chmod -R u+w .

      # In-tree GMP/MPFR/MPC/ISL
      mkdir gmp && (cd ${gmp-src} && ${prev.tar}/bin/tar cf - .) | (cd gmp && ${prev.tar}/bin/tar xf -)
      chmod -R u+w gmp
      mkdir mpfr && (cd ${mpfr-src} && ${prev.tar}/bin/tar cf - .) | (cd mpfr && ${prev.tar}/bin/tar xf -)
      chmod -R u+w mpfr
      mkdir mpc && (cd ${mpc-src} && ${prev.tar}/bin/tar cf - .) | (cd mpc && ${prev.tar}/bin/tar xf -)
      chmod -R u+w mpc
      mkdir isl && (cd ${isl-src} && ${prev.tar}/bin/tar cf - .) | (cd isl && ${prev.tar}/bin/tar xf -)
      chmod -R u+w isl

      # Set up target sysroot so xgcc can find glibc + linux headers + libs
      mkdir -p "$TMPDIR/sysroot/usr/include"
      # Glibc headers first
      ln -sf ${prev.glibc}/include/* "$TMPDIR/sysroot/usr/include/"
      # Linux kernel headers second — remove existing directory symlinks first,
      # because ln -sf can't replace a symlink-to-directory (it creates inside it)
      for d in ${prev.linuxHeaders}/include/*; do
        bn=$(basename "$d")
        rm -f "$TMPDIR/sysroot/usr/include/$bn"
        ln -sf "$d" "$TMPDIR/sysroot/usr/include/$bn"
      done
      ln -sf ${prev.glibc}/lib "$TMPDIR/sysroot/usr/lib"
      ln -sf ${prev.glibc}/lib "$TMPDIR/sysroot/lib"

      # Touch autotools inputs first, then .c/.h, then autotools outputs
      for dir in . gmp mpfr mpc isl; do
        find "$dir" -type f \( -name '*.y' -o -name '*.l' -o -name 'Makefile.am' -o -name 'configure.ac' -o -name 'configure.in' -o -name 'acinclude.m4' \) -exec touch {} + 2>/dev/null || true
      done
      sleep 1
      for dir in . gmp mpfr mpc isl; do
        find "$dir" -type f \( -name '*.c' -o -name '*.h' \) -exec touch {} + 2>/dev/null || true
      done
      sleep 1
      for dir in . gmp mpfr mpc isl; do
        find "$dir" \( -name 'configure' -o -name 'Makefile.in' -o -name 'aclocal.m4' -o -name 'config.h.in' \) -exec touch {} + 2>/dev/null || true
      done

      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      CC="${prev.gcc}/bin/gcc" CXX="${prev.gcc}/bin/g++" \
      CFLAGS="-O2 -static" CXXFLAGS="-O2 -static" \
      LDFLAGS="-L${prev.glibc}/lib -static" \
      "$TMPDIR/gcc-11.5.0/configure" \
        --prefix="$out" \
        --build=${buildPlatform.config} --host=${hostPlatform.config} --target=${targetPlatform.config} \
        --enable-languages=c,c++ \
        --disable-shared --disable-nls --disable-threads \
        --disable-multilib --disable-bootstrap \
        --disable-libssp --disable-libgomp --disable-libsanitizer \
        --disable-libvtv --disable-libquadmath --disable-lto \
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

      # Set up so gcc finds glibc startfiles + libraries
      SPEC_DIR="$out/lib/gcc/${targetPlatform.config}/11.5.0"
      for f in ${prev.glibc}/lib/crt*.o; do
        bn="$(basename "$f")"
        ln -sf "$f" "$SPEC_DIR/$bn" 2>/dev/null || true
      done
      ln -sf ${prev.glibc}/lib/libc.a "$SPEC_DIR/libc.a" 2>/dev/null || true
      ln -sf ${prev.glibc}/lib/libm.a "$SPEC_DIR/libm.a" 2>/dev/null || true
      ln -sf ${prev.glibc}/lib/libpthread.a "$SPEC_DIR/libpthread.a" 2>/dev/null || true
      # Install specs file: add glibc header path, default -static, --start-group
      "$out/bin/gcc" -dumpspecs > "$SPEC_DIR/specs"
      # Add -idirafter for glibc + linux kernel headers (not -isystem, which goes
      # before C++ headers and breaks #include_next <stdlib.h> in cstdlib).
      # Two -idirafter entries: glibc first, then linux-headers (for linux/*.h).
      # Consumers using -nostdinc override this; consumers without -nostdinc get headers.
      ${prev.sed}/bin/sed -i '/^\*cpp:$/{n; s|^|-idirafter ${prev.glibc}/include -idirafter ${prev.linuxHeaders}/include |}' \
        "$SPEC_DIR/specs" 2>/dev/null || true
      # NOTE: we do NOT add -L${prev.glibc}/lib here — that would conflict
      # with later tiers that compile against a newer glibc.  Consumers must
      # pass their own -L<glibc>/lib explicitly.
      ${prev.sed}/bin/sed -i '/^\*link:$/{n; s|^|%{!shared:%{!nostdlib:-static}} |}' \
        "$SPEC_DIR/specs" 2>/dev/null || true
      ${prev.sed}/bin/sed -i '/^\*link_gcc_c_sequence:$/{n; s|.*|%{!shared:%{!nostdlib:--start-group}} %G %L %{!shared:%{!nostdlib:--end-group}}|}' \
        "$SPEC_DIR/specs" 2>/dev/null || true

      echo "GCC 11.5.0 installed to $out"
    ''
  ];
}
// {
  meta = {
    build = {
      os = "linux";
      cpu = [
        "x86_64"
        "aarch64"
      ];
    };
    execute = {
      os = "linux";
      cpu = [
        "x86_64"
        "aarch64"
      ];
    };
    target = {
      os = "linux";
      cpu = [
        "x86_64"
        "aarch64"
      ];
    };
  };
}
