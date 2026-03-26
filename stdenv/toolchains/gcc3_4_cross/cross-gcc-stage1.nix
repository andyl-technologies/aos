# stdenv/toolchains/gcc3_4_cross/cross-gcc-stage1.nix — Phase 2
#
# Cross GCC 3.4.6 stage 1: runs on i686, targets x86_64, no libc.
# Minimal C-only compiler for building glibc. Produces libgcc.
#
{
  prev,
  crossBinutils,
  buildPlatform,
  hostPlatform,
  ...
}:
let
  src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/gcc/gcc-3.4.6/gcc-3.4.6.tar.bz2";
    sha256 = "09v2s3ij1pxng9k3z4w98058lvd2m98jywiv5xfiwzxvnp1n5jwq";
  };
in
builtins.derivation {
  name = "cross-gcc-stage1-3.4.6";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export PATH="${prev.coreutils}/bin:${prev.gcc}/bin:${prev.binutils}/bin:${crossBinutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.patch}/bin:${prev.bash}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      cp -r ${src} "$TMPDIR/src"
      chmod -R u+w "$TMPDIR/src"

      # Pre-generated yacc/lex files must be newer than sources
      touch "$TMPDIR/src/gcc/gengtype-yacc.c" \
            "$TMPDIR/src/gcc/gengtype-yacc.h" \
            "$TMPDIR/src/gcc/gengtype-lex.c" \
            "$TMPDIR/src/gcc/c-parse.c" \
            "$TMPDIR/src/gcc/c-parse.h" \
            "$TMPDIR/src/gcc/tradcif.c"

      # Patch out hardcoded /usr/include
      sed -i \
        "s|native_system_header_dir=/usr/include|native_system_header_dir=/nonexistent|g" \
        "$TMPDIR/src/gcc/configure"

      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      CC="${prev.gcc}/bin/gcc" \
      CFLAGS="-O2 -static -DSSIZE_MAX=0x7fffffff" \
      LDFLAGS="-static" \
      "$TMPDIR/src/configure" \
        --prefix="$out" \
        --build=${buildPlatform.config} \
        --host=${buildPlatform.config} \
        --target=${hostPlatform.config} \
        --enable-languages=c \
        --without-headers --with-newlib \
        --enable-tls \
        --disable-shared --disable-nls --disable-threads \
        --disable-multilib --disable-bootstrap \
        --disable-libssp --disable-libgomp --disable-libmudflap \
        --program-transform-name=

      # Patch SYSTEM_HEADER_DIR to avoid /usr/include — use an empty
      # directory so fixincludes doesn't error on missing path
      mkdir -p "$TMPDIR/empty-headers"
      make configure-gcc
      sed -i \
        "s|^SYSTEM_HEADER_DIR.*|SYSTEM_HEADER_DIR = $TMPDIR/empty-headers|" \
        gcc/Makefile

      # Copy pre-generated parser files to build dir — VPATH doesn't
      # find them in out-of-tree builds when yacc/bison is missing
      cp "$TMPDIR/src/gcc/c-parse.c" "$TMPDIR/build/gcc/"
      cp "$TMPDIR/src/gcc/c-parse.h" "$TMPDIR/build/gcc/"
      cp "$TMPDIR/src/gcc/tradcif.c" "$TMPDIR/build/gcc/"
      cp "$TMPDIR/src/gcc/gengtype-yacc.c" "$TMPDIR/build/gcc/"
      cp "$TMPDIR/src/gcc/gengtype-yacc.h" "$TMPDIR/build/gcc/"
      cp "$TMPDIR/src/gcc/gengtype-lex.c" "$TMPDIR/build/gcc/"

      # Create $prefix/$target/bin/ with cross-tool symlinks so xgcc
      # can find the x86_64 assembler/linker when building CRT files
      mkdir -p "$out/${hostPlatform.config}/bin"
      for tool in as ld ar ranlib nm objcopy objdump strip; do
        ln -sf ${crossBinutils}/bin/${hostPlatform.config}-$tool \
          "$out/${hostPlatform.config}/bin/$tool" 2>/dev/null || true
      done

      make -j"$NIX_BUILD_CORES" all-gcc \
        BOOT_CFLAGS="-O2 -static"

      make install-gcc

      # GCC's install for cross builds doesn't create $target-gcc when
      # gcc-cross exists — create the expected symlink
      test -f "$out/bin/gcc" && test ! -f "$out/bin/${hostPlatform.config}-gcc" && \
        ln -sf gcc "$out/bin/${hostPlatform.config}-gcc"

      # Create empty libgcc_eh.a and re-index libgcc.a
      "${prev.binutils}/bin/ar" crs "$out/lib/gcc/${hostPlatform.config}/3.4.6/libgcc_eh.a"
      "${crossBinutils}/bin/${hostPlatform.config}-ranlib" \
        "$out/lib/gcc/${hostPlatform.config}/3.4.6/libgcc.a" 2>/dev/null || true

      echo "Cross GCC stage 1 (${buildPlatform.config} → ${hostPlatform.config}) installed to $out"
    ''
  ];
}
