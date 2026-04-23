# stdenv/toolchains/gcc3_4/gcc.nix — GCC 3.4.6 (C only, RHEL 4)
#
# First toolchain GCC, built by bootstrap GCC 2.95.3.
# No GMP/MPFR needed (only required starting in GCC 4.3).
# All i686-linux.
#
{
  prev,
  buildPlatform,
  hostPlatform,
  targetPlatform,
  ...
}: let
  src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/gcc/gcc-3.4.6/gcc-3.4.6.tar.bz2";
    sha256 = "09v2s3ij1pxng9k3z4w98058lvd2m98jywiv5xfiwzxvnp1n5jwq";
  };

  # Linux kernel headers for CRT compilation — glibc headers reference
  # linux/*.h which must be available when xgcc compiles crtstuff.c.
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
        export PATH="${prev.coreutils}/bin:${prev.gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.patch}/bin:${prev.bash}/bin"
        export CONFIG_SHELL="${prev.bash}/bin/bash"

        # GCC 3.4 hardcodes /usr/include as the system header dir.
        # Patch the source to use our glibc headers instead.
        cp -r ${src} "$TMPDIR/src"
        chmod -R u+w "$TMPDIR/src"
        # Ensure pre-generated yacc/lex .c/.h files are newer than
        # .l/.y sources so make doesn't try to re-run flex/bison.
        touch "$TMPDIR/src/gcc/gengtype-yacc.c" \
              "$TMPDIR/src/gcc/gengtype-yacc.h" \
              "$TMPDIR/src/gcc/gengtype-lex.c" \
              "$TMPDIR/src/gcc/c-parse.c" \
              "$TMPDIR/src/gcc/c-parse.h" \
              "$TMPDIR/src/gcc/tradcif.c"
        sed -i \
          "s|native_system_header_dir=/usr/include|native_system_header_dir=${prev.glibc}/include|g" \
          "$TMPDIR/src/gcc/configure"

        mkdir -p "$TMPDIR/build"
        cd "$TMPDIR/build"

        CC="${prev.gcc}/bin/gcc" \
        CFLAGS="-O2 -static -DSSIZE_MAX=0x7fffffff" \
        LDFLAGS="-static" \
        "$TMPDIR/src/configure" \
          --prefix="$out" \
          --build=${buildPlatform.config} --host=${hostPlatform.config} --target=${targetPlatform.config} \
          --enable-languages=c \
          --disable-shared --disable-nls --disable-threads \
          --disable-multilib --disable-bootstrap \
          --disable-libssp --disable-libgomp --disable-libmudflap \
          --program-transform-name=

        # Also patch SYSTEM_HEADER_DIR in the generated gcc/Makefile
        # to prevent fixincludes from looking at /usr/include.
        make configure-gcc
        sed -i \
          "s|^SYSTEM_HEADER_DIR.*|SYSTEM_HEADER_DIR = ${prev.glibc}/include|" \
          gcc/Makefile

        # xgcc searches $prefix/$target/sys-include for system headers.
        # Create merged include dir with glibc + linux kernel headers
        # (glibc headers reference linux/*.h which must be present).
        mkdir -p "$out/${targetPlatform.config}/sys-include"
        for item in "${prev.glibc}/include"/*; do
          ln -sf "$item" "$out/${targetPlatform.config}/sys-include/"
        done
        cp -r ${linuxSrc}/include/linux "$out/${targetPlatform.config}/sys-include/"
        cp -r ${linuxSrc}/include/asm-i386 "$out/${targetPlatform.config}/sys-include/asm"
        cp -r ${linuxSrc}/include/asm-generic "$out/${targetPlatform.config}/sys-include/"
        ln -sf "$out/${targetPlatform.config}/sys-include" "$out/${targetPlatform.config}/include"

        make -j"$NIX_BUILD_CORES" \
          BOOT_CFLAGS="-O2 -static" \
          CFLAGS_FOR_TARGET="-O2 -I${prev.glibc}/include" \
          LDFLAGS_FOR_TARGET="-L${prev.glibc}/lib -static"

        make install

        test -f "$out/bin/gcc" && test ! -f "$out/bin/cc" && ln -sf gcc "$out/bin/cc"

        # Create empty libgcc_eh.a — glibc expects it but --disable-shared
        # means GCC doesn't build it. An empty archive satisfies the linker.
        "${prev.binutils}/bin/ar" crs "$out/lib/gcc/${targetPlatform.config}/3.4.6/libgcc_eh.a"

        # Symlink all glibc CRT files and libraries into GCC's lib directory
        # so GCC can find crt1.o, crti.o, crtn.o, libc.a, libm.a etc.
        for f in "${prev.glibc}/lib/"*.o "${prev.glibc}/lib/"*.a; do
          test -f "$f" && ln -sf "$f" "$out/lib/"
        done

        echo "GCC 3.4.6 installed to $out"
      ''
    ];
  }
  // {
    meta = {
      description = "GNU Compiler Collection, version 3.4.6 (C only)";
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
        cpu = [
          "x86_64"
          "i686"
        ];
      };
      target = {
        os = "linux";
        cpu = [
          "x86_64"
          "i686"
        ];
      };
    };
  }
