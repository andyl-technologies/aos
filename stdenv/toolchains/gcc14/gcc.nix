# stdenv/toolchains/gcc14/gcc.nix — GCC 14.3.0 (RHEL 10)
#
# GCC built by GCC 11.5.0 from the previous tier. In-tree
# GMP/MPFR/MPC/ISL. Enables PIE and SSP by default (hardening flags).
#
{
  prev,
  buildPlatform,
  hostPlatform,
  targetPlatform,
}:
let
  inherit (import ../../../lib/derivations.nix { system = builtins.currentSystem; }) fetchTarball;

  gcc-src = fetchTarball {
    url = "https://mirrors.kernel.org/gnu/gcc/gcc-14.3.0/gcc-14.3.0.tar.xz";
    hash = "18slj57b3zizzmc1bn4b6x8rygijfjjmwfzipdvyyzrbspaa5x21";
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
    url = "https://libisl.sourceforge.io/isl-0.26.tar.xz";
    hash = "01krva4ax8zvi365akpzdv8r3a3gdl8sqcdgsg2kxmcy810gay0k";
  };
in
builtins.derivation {
  name = "gcc-14.3.0";
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
      mkdir gcc-14.3.0 && (cd ${gcc-src} && ${prev.tar}/bin/tar cf - .) | (cd gcc-14.3.0 && ${prev.tar}/bin/tar xf -)
      cd gcc-14.3.0
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
      # Linux kernel headers — installed at $linuxHeaders/ root (no include/ prefix)
      # Remove existing directory symlinks first (ln -sf can't replace symlink-to-directory)
      for d in ${prev.linuxHeaders}/*; do
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
      CFLAGS="-O2 -static -isystem ${prev.glibc}/include" \
      CXXFLAGS="-O2 -static -isystem ${prev.glibc}/include" \
      LDFLAGS="-L${prev.glibc}/lib -static" \
      "$TMPDIR/gcc-14.3.0/configure" \
        --prefix="$out" \
        --build=${buildPlatform.config} --host=${hostPlatform.config} --target=${targetPlatform.config} \
        --enable-languages=c,c++ \
        --disable-shared --disable-nls --enable-threads=posix \
        --disable-multilib --disable-bootstrap \
        --disable-libsanitizer --disable-libvtv \
        --enable-default-pie --enable-default-ssp \
        --with-native-system-header-dir="/usr/include" \
        --with-build-sysroot="$TMPDIR/sysroot" \
        --program-transform-name=

      # Build the compiler first
      make -j"$NIX_BUILD_CORES" all-gcc \
        AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true \
        BOOT_CFLAGS="-O2 -static" \
        CFLAGS_FOR_TARGET="-O2" \
        LDFLAGS_FOR_TARGET="-static"

      # fixincludes in GCC 14 doesn't always generate include-fixed/limits.h,
      # which is needed to chain #include_next from GCC's limits.h to the
      # system's limits.h. Create it manually.
      mkdir -p "$TMPDIR/build/gcc/include-fixed"
      cat > "$TMPDIR/build/gcc/include-fixed/limits.h" <<'LIMITS_EOF'
/* Generated for GCC 14 bootstrap — chains to system limits.h */
#ifndef _GCC_LIMITS_H_
#define _GCC_NEXT_LIMITS_H
#include_next <limits.h>
#undef _GCC_NEXT_LIMITS_H
#endif
LIMITS_EOF

      # Now build target libraries (libgcc + libstdc++)
      # libstdc++ is needed so this GCC can be used as the host compiler
      # for the self-recompile step (g++ must be able to create executables).
      make -j"$NIX_BUILD_CORES" all-target-libgcc \
        AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true \
        CFLAGS_FOR_TARGET="-O2 -fPIC" \
        LDFLAGS_FOR_TARGET="-static"
      make -j"$NIX_BUILD_CORES" all-target-libstdc++-v3 \
        AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true \
        CFLAGS_FOR_TARGET="-O2 -fPIC" \
        CXXFLAGS_FOR_TARGET="-O2 -fPIC" \
        LDFLAGS_FOR_TARGET="-static"
      make -j"$NIX_BUILD_CORES" all-target-libatomic \
        AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true \
        CFLAGS_FOR_TARGET="-O2 -fPIC" \
        LDFLAGS_FOR_TARGET="-static"

      make install-gcc \
        AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
      make install-target-libgcc \
        AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
      make install-target-libstdc++-v3 \
        AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
      make install-target-libatomic \
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
      SPEC_DIR="$out/lib/gcc/${targetPlatform.config}/14.3.0"
      for f in ${prev.glibc}/lib/crt*.o ${prev.glibc}/lib/Scrt1.o ${prev.glibc}/lib/rcrt1.o ${prev.glibc}/lib/gcrt1.o; do
        bn="$(basename "$f")"
        ln -sf "$f" "$SPEC_DIR/$bn" 2>/dev/null || true
      done
      ln -sf ${prev.glibc}/lib/libc.a "$SPEC_DIR/libc.a" 2>/dev/null || true
      ln -sf ${prev.glibc}/lib/libm.a "$SPEC_DIR/libm.a" 2>/dev/null || true
      ln -sf ${prev.glibc}/lib/libpthread.a "$SPEC_DIR/libpthread.a" 2>/dev/null || true
      # Install specs file: add glibc header path.
      # Do NOT add forced -static to link specs — it conflicts with the PIE default
      # (GCC 14 has --enable-default-pie). The spec `%{!static:` condition checks
      # user flags, not spec-generated ones, so spec-injected -static still adds
      # -dynamic-linker, producing a broken static PIE. Tier tools pass -static
      # and -no-pie explicitly in their own LDFLAGS instead.
      "$out/bin/gcc" -dumpspecs > "$SPEC_DIR/specs"
      # Add -idirafter for glibc + linux kernel headers (not -isystem, which goes
      # before C++ headers and breaks #include_next <stdlib.h> in cstdlib).
      ${prev.sed}/bin/sed -i '/^\*cpp:$/{n; s|^|-idirafter ${prev.glibc}/include -idirafter ${prev.linuxHeaders} |}' \
        "$SPEC_DIR/specs" 2>/dev/null || true

      # Create libgcc_s.so linker script stub.
      # GCC was built with --disable-shared so libgcc_s.so doesn't exist,
      # but GCC's default link sequence for dynamic executables references
      # -lgcc_s. This linker script redirects it to the static libgcc.a.
      echo "/* Stub: redirect -lgcc_s to static libgcc */" > "$SPEC_DIR/libgcc_s.so"
      echo "INPUT(-lgcc)" >> "$SPEC_DIR/libgcc_s.so"
      # Also create libgcc_s.a for explicit static linking
      echo "/* Stub: redirect -lgcc_s to static libgcc */" > "$SPEC_DIR/libgcc_s.a"
      echo "INPUT(-lgcc)" >> "$SPEC_DIR/libgcc_s.a"

      echo "GCC 14.3.0 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU Compiler Collection 14.3.0 — production compiler with PIE+SSP";
    homepage = "https://gcc.gnu.org/";
    license = "GPL-3.0-or-later";
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
