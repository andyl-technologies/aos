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
}: let
  src = builtins.fetchTarball {
    url = "https://ftp.gnu.org/gnu/gcc/gcc-4.1.2/gcc-core-4.1.2.tar.bz2";
    sha256 = "0fzi14bjj39lx9s8ppkrlarbmga8j51p7f4qnm3w4rh13z6gnz87";
  };
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

        cd "$TMPDIR"
        cp -r ${src} gcc-4.1.2
        cd gcc-4.1.2
        chmod -R u+w .

        # Fix known build issues with modern host compilers
        sed -i 's/ix86_attribute_table\[\]/ix86_attribute_table[10]/' gcc/config/i386/i386.c 2>/dev/null || true
        sed -i 's/C_alloca/alloca/g' libiberty/alloca.c include/libiberty.h

        mkdir -p "$TMPDIR/build"
        cd "$TMPDIR/build"

        CC="${prev.gcc}/bin/gcc" \
        CFLAGS="-O2 -static" \
        LDFLAGS="-static" \
        "$TMPDIR/gcc-4.1.2/configure" \
          --prefix="$out" \
          --build=${hostPlatform.config} --host=${hostPlatform.config} --target=${targetPlatform.config} \
          --enable-languages=c \
          --disable-shared --disable-nls --disable-threads \
          --disable-multilib --disable-bootstrap \
          --disable-libssp --disable-libgomp --disable-libmudflap \
          --with-native-system-header-dir="${prev.glibc}/include" \
          --without-headers --program-transform-name=

        make -j"$(nproc)" \
          BOOT_CFLAGS="-O2 -static" \
          CFLAGS_FOR_TARGET="-O2 -I${prev.glibc}/include" \
          LDFLAGS_FOR_TARGET="-L${prev.glibc}/lib -static"

        make install

        [ -f "$out/bin/gcc" ] && [ ! -f "$out/bin/cc" ] && ln -sf gcc "$out/bin/cc"

        echo "GCC 4.1.2 installed to $out"
      ''
    ];
  }
  // {
    meta = {
      build = {
        os = "linux";
        cpu = ["x86_64" "i686"];
      };
      execute = {
        os = "linux";
        cpu = ["x86_64" "i686"];
      };
      target = {
        os = "linux";
        cpu = ["x86_64" "i686"];
      };
    };
  }
