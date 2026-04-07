# stdenv/toolchains/gcc8_cross/gcc.nix — Phase 6b
#
# Native target-arch GCC 8.5.0 via Canadian cross.
# Build=x86_64, Host=target, Target=target.
# CC_FOR_BUILD = x86_64 native compiler (build-time generators)
# CC = x86_64→target cross-compiler (compiles GCC into target binary)
#
{
  prev,
  crossGccStage2,
  crossBinutils,
  crossGlibc,
  binutils,
  linuxHeaders,
  buildPlatform,
  hostPlatform,
  targetPlatform,
  ...
}:
let
  inherit (import ../../../lib/derivations.nix { system = builtins.currentSystem; }) fetchTarball;

  gccSrc = fetchTarball {
    url = "https://mirrors.kernel.org/gnu/gcc/gcc-8.5.0/gcc-8.5.0.tar.xz";
    hash = "1d4xjxwvxd4zi4hy7z2fqbd8mfddj32x4w5cqw163lz0q1yf1ak4";
  };

  gmpSrc = fetchTarball {
    url = "https://mirrors.kernel.org/gnu/gmp/gmp-6.3.0.tar.xz";
    hash = "1kc3dy4jxand0y118yb9715g9xy1fnzqgkwxy02vd57y2fhg2pcw";
  };

  mpfrSrc = fetchTarball {
    url = "https://mirrors.kernel.org/gnu/mpfr/mpfr-4.2.1.tar.xz";
    hash = "1irpgc9aqyhgkwqk7cvib1dgr5v5hf4m0vaaknssyfpkjmab9ydq";
  };

  mpcSrc = fetchTarball {
    url = "https://mirrors.kernel.org/gnu/mpc/mpc-1.3.1.tar.gz";
    hash = "1b6layaybj039fajx8dpy2zvcfy7s02y3y4lficz16vac0fsd0jk";
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
      export PATH="${prev.coreutils}/bin:${crossGccStage2}/bin:${crossBinutils}/bin:${prev.gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.patch}/bin:${prev.bash}/bin:${prev.m4}/bin:${prev.flex}/bin:${prev.bison}/bin:${prev.texinfo}/bin:${prev.autoconf}/bin:${prev.automake}/bin:${prev.help2man}/bin"
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
      for dir in . gmp mpfr mpc; do
        find "$dir" \( -name 'configure' -o -name 'Makefile.in' -o -name 'aclocal.m4' -o -name 'config.h.in' \) -exec touch {} + 2>/dev/null || true
      done
      sleep 1
      for dir in . gmp mpfr mpc; do
        find "$dir" -type f \( -name '*.c' -o -name '*.h' \) -exec touch {} + 2>/dev/null || true
      done

      # Disable fixincludes
      ${prev.sed}/bin/sed -i \
        -e 's@\./fixinc\.sh@-c true@' \
        -e 's|then sleep 1; else exit 1; fi;|then sleep 1; else sleep 1; fi;|' \
        gcc/Makefile.in

      # Patch out hardcoded /usr/include
      ${prev.sed}/bin/sed -i \
        "s|native_system_header_dir=/usr/include|native_system_header_dir=${crossGlibc}/include|g" \
        gcc/configure

      # Set up target sys-include with glibc + linux headers
      mkdir -p "$out/${targetPlatform.config}/sys-include"
      for item in "${crossGlibc}/include"/*; do
        ln -sf "$item" "$out/${targetPlatform.config}/sys-include/"
      done
      # Copy linux headers
      cp -r ${linuxHeaders}/include/linux "$out/${targetPlatform.config}/sys-include/" 2>/dev/null || true
      cp -r ${linuxHeaders}/include/asm "$out/${targetPlatform.config}/sys-include/" 2>/dev/null || true
      cp -r ${linuxHeaders}/include/asm-generic "$out/${targetPlatform.config}/sys-include/" 2>/dev/null || true
      ln -sf "$out/${targetPlatform.config}/sys-include" "$out/${targetPlatform.config}/include"

      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      # Canadian cross: build=x86_64, host=target, target=target
      CC_FOR_BUILD="${prev.gcc}/bin/gcc" \
      CXX_FOR_BUILD="${prev.gcc}/bin/g++" \
      CC="${crossGccStage2}/bin/${hostPlatform.config}-gcc" \
      CXX="${crossGccStage2}/bin/${hostPlatform.config}-g++" \
      AR="${crossBinutils}/bin/${hostPlatform.config}-ar" \
      RANLIB="${crossBinutils}/bin/${hostPlatform.config}-ranlib" \
      CFLAGS="-O2 -isystem ${crossGlibc}/include" \
      CXXFLAGS="-O2 -isystem ${crossGlibc}/include" \
      CFLAGS_FOR_BUILD="-O2" \
      CXXFLAGS_FOR_BUILD="-O2" \
      LDFLAGS="-L${crossGlibc}/lib -static" \
      LDFLAGS_FOR_BUILD="-L${prev.glibc}/lib -static" \
      "$SRC/configure" \
        --prefix="$out" \
        --build=${buildPlatform.config} \
        --host=${hostPlatform.config} \
        --target=${targetPlatform.config} \
        --enable-languages=c,c++ \
        --disable-shared --disable-nls --disable-threads \
        --disable-multilib --disable-bootstrap \
        --disable-libssp --disable-libgomp \
        --disable-libsanitizer --disable-libmpx --disable-libvtv \
        --program-transform-name=

      # Patch SYSTEM_HEADER_DIR
      make configure-gcc
      ${prev.sed}/bin/sed -i \
        "s|^SYSTEM_HEADER_DIR.*|SYSTEM_HEADER_DIR = ${crossGlibc}/include|" \
        gcc/Makefile

      # Canadian cross: xgcc is target-arch and can't run on x86_64 build machine,
      # so build only gcc (not target libraries like libgcc).
      make -j"$NIX_BUILD_CORES" all-gcc \
        BOOT_CFLAGS="-O2" \
        CFLAGS_FOR_TARGET="-O2 -isystem ${crossGlibc}/include" \
        CXXFLAGS_FOR_TARGET="-O2 -isystem ${crossGlibc}/include" \
        LDFLAGS_FOR_TARGET="-L${crossGlibc}/lib -static"

      make install-gcc

      test -f "$out/bin/gcc" && test ! -f "$out/bin/cc" && ln -sf gcc "$out/bin/cc"
      test -f "$out/bin/g++" && test ! -f "$out/bin/c++" && ln -sf g++ "$out/bin/c++"

      # Create syslimits.h — normally generated by fixincludes
      cat > "$out/lib/gcc/${targetPlatform.config}/8.5.0/include/syslimits.h" <<'SYSLIM'
/* syslimits.h — wrapper to get the system limits.h */
#ifndef _GCC_LIMITS_H_
#include_next <limits.h>
#endif
SYSLIM

      # Copy libgcc.a from cross-compiler (can't build it in Canadian cross —
      # xgcc is target-arch, can't run on x86_64 build machine)
      GCCLIB="$out/lib/gcc/${targetPlatform.config}/8.5.0"
      mkdir -p "$GCCLIB"
      cp "${crossGccStage2}/lib/gcc/${hostPlatform.config}/8.5.0/libgcc.a" "$GCCLIB/" 2>/dev/null || true
      "${crossBinutils}/bin/${hostPlatform.config}-ar" crs "$GCCLIB/libgcc_eh.a"

      # Symlink binutils tools so native gcc can find as/ld
      mkdir -p "$out/${targetPlatform.config}/bin"
      for tool in as ld ar ranlib nm objcopy objdump strip; do
        ln -sf ${binutils}/bin/$tool "$out/${targetPlatform.config}/bin/$tool" 2>/dev/null || true
        ln -sf ${binutils}/bin/$tool "$out/bin/$tool" 2>/dev/null || true
      done

      # Symlink glibc CRT files and libraries into GCC's lib directory
      for f in "${crossGlibc}/lib/"*.o "${crossGlibc}/lib/"*.a; do
        test -f "$f" && ln -sf "$f" "$GCCLIB/" && ln -sf "$f" "$out/lib/"
      done

      echo "Native GCC 8.5.0 (${hostPlatform.config}) installed to $out"
    ''
  ];
}
