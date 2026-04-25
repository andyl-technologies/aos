# stdenv/toolchains/gcc3_4_cross/gcc.nix — Phase 6b
#
# Native x86_64 GCC 3.4.6 via Canadian cross.
# Build=i686, Host=x86_64, Target=x86_64.
# CC_FOR_BUILD = i686 native compiler (build-time generators)
# CC = i686→x86_64 cross-compiler (compiles GCC into x86_64 binary)
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
}: let
  src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/gcc/gcc-3.4.6/gcc-3.4.6.tar.bz2";
    sha256 = "09v2s3ij1pxng9k3z4w98058lvd2m98jywiv5xfiwzxvnp1n5jwq";
  };

  linuxSrc = builtins.fetchTarball {
    url = "https://cdn.kernel.org/pub/linux/kernel/v2.6/linux-2.6.9.tar.bz2";
    sha256 = "1hrnvjlgr4alcs1xcvc98c4vx3bmnc42idp3bav8jnvd0n4kwmq2";
  };
in
  builtins.derivation {
    name = "gcc-3.4.6";
    system = buildPlatform.system;
    builder = "${prev.bash}/bin/bash";
    args = [
      "-c"
      ''
              set -eu
              export PATH="${prev.coreutils}/bin:${crossGccStage2}/bin:${crossBinutils}/bin:${prev.gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.patch}/bin:${prev.bash}/bin"
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
                "s|native_system_header_dir=/usr/include|native_system_header_dir=${crossGlibc}/include|g" \
                "$TMPDIR/src/gcc/configure"

              # Set up target sys-include with glibc + linux headers
              # The resulting native gcc looks here for system headers.
              mkdir -p "$out/${targetPlatform.config}/sys-include"
              for item in "${crossGlibc}/include"/*; do
                ln -sf "$item" "$out/${targetPlatform.config}/sys-include/"
              done
              cp -r ${linuxSrc}/include/linux "$out/${targetPlatform.config}/sys-include/" 2>/dev/null || true
              cp -r ${linuxSrc}/include/asm-x86_64 "$out/${targetPlatform.config}/sys-include/asm" 2>/dev/null || true
              cp -r ${linuxSrc}/include/asm-generic "$out/${targetPlatform.config}/sys-include/" 2>/dev/null || true
              ln -sf "$out/${targetPlatform.config}/sys-include" "$out/${targetPlatform.config}/include"

              mkdir -p "$TMPDIR/build"
              cd "$TMPDIR/build"

              # Canadian cross: build=i686, host=x86_64, target=x86_64
              CC_FOR_BUILD="${prev.gcc}/bin/gcc" \
              CC="${crossGccStage2}/bin/${hostPlatform.config}-gcc" \
              AR="${crossBinutils}/bin/${hostPlatform.config}-ar" \
              RANLIB="${crossBinutils}/bin/${hostPlatform.config}-ranlib" \
              CFLAGS="-O2 -static -isystem ${crossGlibc}/include" \
              CFLAGS_FOR_BUILD="-O2 -static -DSSIZE_MAX=0x7fffffff" \
              LDFLAGS="-L${crossGlibc}/lib -static" \
              LDFLAGS_FOR_BUILD="-static" \
              "$TMPDIR/src/configure" \
                --prefix="$out" \
                --build=${buildPlatform.config} \
                --host=${hostPlatform.config} \
                --target=${targetPlatform.config} \
                --enable-languages=c \
                --disable-shared --disable-nls --disable-threads \
                --disable-multilib --disable-bootstrap \
                --disable-libssp --disable-libgomp --disable-libmudflap \
                --program-transform-name=

              # Patch SYSTEM_HEADER_DIR
              make configure-gcc
              sed -i \
                "s|^SYSTEM_HEADER_DIR.*|SYSTEM_HEADER_DIR = ${crossGlibc}/include|" \
                gcc/Makefile

              # Copy pre-generated parser files to build dir — VPATH doesn't
              # find them in out-of-tree builds when yacc/bison is missing
              cp "$TMPDIR/src/gcc/c-parse.c" "$TMPDIR/build/gcc/"
              cp "$TMPDIR/src/gcc/c-parse.h" "$TMPDIR/build/gcc/"
              cp "$TMPDIR/src/gcc/tradcif.c" "$TMPDIR/build/gcc/"
              cp "$TMPDIR/src/gcc/gengtype-yacc.c" "$TMPDIR/build/gcc/"
              cp "$TMPDIR/src/gcc/gengtype-yacc.h" "$TMPDIR/build/gcc/"
              cp "$TMPDIR/src/gcc/gengtype-lex.c" "$TMPDIR/build/gcc/"

              # Canadian cross: xgcc is x86_64 and can't run on i686 build machine,
              # so build only gcc (not target libraries like libgcc).
              make -j"$NIX_BUILD_CORES" all-gcc \
                BOOT_CFLAGS="-O2 -static" \
                CFLAGS_FOR_TARGET="-O2 -I${crossGlibc}/include" \
                LDFLAGS_FOR_TARGET="-L${crossGlibc}/lib -static"

              make install-gcc

              test -f "$out/bin/gcc" && test ! -f "$out/bin/cc" && ln -sf gcc "$out/bin/cc"

              # Create syslimits.h — normally generated by fixincludes, which was
              # skipped in the Canadian cross. Without it, #include <limits.h> fails.
              cat > "$out/lib/gcc/${targetPlatform.config}/3.4.6/include/syslimits.h" <<'SYSLIM'
        /* syslimits.h — wrapper to get the system limits.h */
        #ifndef _GCC_LIMITS_H_
        #include_next <limits.h>
        #endif
        SYSLIM

              # Copy libgcc.a from cross-compiler (can't build it in Canadian cross —
              # xgcc is x86_64, can't run on i686 build machine)
              GCCLIB="$out/lib/gcc/${targetPlatform.config}/3.4.6"
              mkdir -p "$GCCLIB"
              cp "${crossGccStage2}/lib/gcc/${hostPlatform.config}/3.4.6/libgcc.a" "$GCCLIB/" 2>/dev/null || true
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

              echo "Native GCC 3.4.6 (${hostPlatform.config}) installed to $out"
      ''
    ];
  }
  // {
    meta = {
      description = "GNU Compiler Collection, version 3.4.6 (C only, cross-compiled to x86_64)";
      homepage = "https://gcc.gnu.org/";
      license = "GPL-2.0-or-later";
      build = {
        os = "linux";
        cpu = [
          "x86_64"
          "i686"
        ];
      };
      execute = {
        os = "linux";
        cpu = "x86_64";
      };
      target = {
        os = "linux";
        cpu = "x86_64";
      };
    };
  }
