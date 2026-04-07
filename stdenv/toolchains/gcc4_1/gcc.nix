# stdenv/toolchains/gcc4_1/gcc.nix — GCC 4.1.2 (C only, RHEL 5)
#
# Built by GCC 3.4.6 from the previous tier. No GMP/MPFR needed (only
# required starting with GCC 4.3).
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
    url = "https://mirrors.kernel.org/gnu/gcc/gcc-4.1.2/gcc-core-4.1.2.tar.bz2";
    hash = "0fzi14bjj39lx9s8ppkrlarbmga8j51p7f4qnm3w4rh13z6gnz87";
  };

  # Linux kernel headers for CRT compilation — glibc headers reference
  # linux/*.h which must be available when xgcc compiles crtstuff.c.
  linuxSrc = fetchTarball {
    url = "https://cdn.kernel.org/pub/linux/kernel/v2.6/linux-2.6.18.tar.bz2";
    hash = "0ad6d97c1z5z79gafbxsd9d9wq4f21hmvp52s91dysqk24fkbdbx";
  };

  # Linux 2.6.18 uses asm-<arch> directory names (pre-2.6.24 unification)
  asmDirMap = {
    x86_64 = "asm-x86_64";
    i686 = "asm-i386";
  };
  asmDir =
    asmDirMap.${hostPlatform.constraints.cpu}
      or (throw "unsupported CPU for linux headers: ${hostPlatform.constraints.cpu}");
in
builtins.derivation {
  name = "gcc-4.1.2";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export PATH="${prev.coreutils}/bin:${prev.gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"
      export LIBRARY_PATH="${prev.glibc}/lib"

      cd "$TMPDIR"
      cp -r ${src} gcc-4.1.2
      cd gcc-4.1.2
      chmod -R u+w .

      # Touch pre-generated lex/yacc output files so make doesn't try to
      # regenerate them (flex/bison aren't available). cp -r from the Nix
      # store creates files with current timestamps, and the .l/.y files
      # may end up with slightly newer mtimes than the .c files.
      touch gcc/gengtype-lex.c gcc/gengtype-yacc.c gcc/gengtype-yacc.h

      # Fix known build issues with modern host compilers
      sed -i 's/ix86_attribute_table\[\]/ix86_attribute_table[10]/' gcc/config/i386/i386.c 2>/dev/null || true
      sed -i 's/C_alloca/alloca/g' libiberty/alloca.c include/libiberty.h

      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      CC="${prev.gcc}/bin/gcc" \
      CPP="${prev.gcc}/bin/gcc -E" \
      CFLAGS="-O2 -static -I${prev.glibc}/include" \
      LDFLAGS="-static -L${prev.glibc}/lib" \
      "$TMPDIR/gcc-4.1.2/configure" \
        --prefix="$out" \
        --build=${hostPlatform.config} --host=${hostPlatform.config} --target=${targetPlatform.config} \
        --enable-languages=c \
        --disable-shared --disable-nls --disable-threads \
        --disable-multilib --disable-bootstrap \
        --disable-libssp --disable-libgomp --disable-libmudflap \
        --with-native-system-header-dir="${prev.glibc}/include" \
        --without-headers --program-transform-name=

      # Patch SYSTEM_HEADER_DIR in gcc/Makefile to prevent fixincludes
      # from looking at /usr/include.
      make configure-gcc
      sed -i \
        "s|^SYSTEM_HEADER_DIR.*|SYSTEM_HEADER_DIR = ${prev.glibc}/include|" \
        gcc/Makefile

      # xgcc searches $prefix/$target/sys-include for system headers.
      # Create merged include dir with glibc + linux kernel headers.
      mkdir -p "$out/${targetPlatform.config}/sys-include"
      for item in "${prev.glibc}/include"/*; do
        ln -sf "$item" "$out/${targetPlatform.config}/sys-include/"
      done
      # Remove conflicting symlinks before copying kernel headers as real dirs
      rm -f "$out/${targetPlatform.config}/sys-include/linux" \
            "$out/${targetPlatform.config}/sys-include/asm" \
            "$out/${targetPlatform.config}/sys-include/asm-generic"
      cp -r ${linuxSrc}/include/linux "$out/${targetPlatform.config}/sys-include/"
      cp -r ${linuxSrc}/include/${asmDir} "$out/${targetPlatform.config}/sys-include/asm"
      cp -r ${linuxSrc}/include/asm-generic "$out/${targetPlatform.config}/sys-include/"
      ln -sf "$out/${targetPlatform.config}/sys-include" "$out/${targetPlatform.config}/include"

      make -j"$NIX_BUILD_CORES" \
        BOOT_CFLAGS="-O2 -static" \
        CFLAGS_FOR_TARGET="-O2 -I${prev.glibc}/include" \
        LDFLAGS_FOR_TARGET="-L${prev.glibc}/lib -static"

      make install

      [ -f "$out/bin/gcc" ] && [ ! -f "$out/bin/cc" ] && ln -sf gcc "$out/bin/cc"

      # Create empty libgcc_eh.a — glibc expects it but --disable-shared
      # means GCC doesn't build it. An empty archive satisfies the linker.
      "${prev.binutils}/bin/ar" crs "$out/lib/gcc/${targetPlatform.config}/4.1.2/libgcc_eh.a"

      # Symlink all glibc CRT files and libraries into GCC's lib directory
      # so GCC can find crt1.o, crti.o, crtn.o, libc.a, libm.a etc.
      for f in "${prev.glibc}/lib/"*.o "${prev.glibc}/lib/"*.a; do
        test -f "$f" && ln -sf "$f" "$out/lib/"
      done

      # Symlink binutils tools into GCC's target bin directory so GCC
      # can find as/ld without relying on PATH.
      mkdir -p "$out/${targetPlatform.config}/bin"
      for tool in as ld ar nm ranlib strip objcopy objdump; do
        test -f "${prev.binutils}/bin/$tool" && \
          ln -sf "${prev.binutils}/bin/$tool" "$out/${targetPlatform.config}/bin/$tool"
      done

      echo "GCC 4.1.2 installed to $out"
    ''
  ];
}
// {
  meta = {
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
