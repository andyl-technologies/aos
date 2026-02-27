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
}:
let
  src = builtins.fetchTarball {
    url = "https://ftp.gnu.org/gnu/gcc/gcc-3.4.6/gcc-3.4.6.tar.bz2";
    sha256 = "09v2s3ij1pxng9k3z4w98058lvd2m98jywiv5xfiwzxvnp1n5jwq";
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
      export PATH="${prev.gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.patch}/bin:${prev.bash}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      cd ${src}

      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      CC="${prev.gcc}/bin/gcc" \
      CFLAGS="-O2 -static" \
      LDFLAGS="-static" \
      ${src}/configure \
        --prefix="$out" \
        --build=${buildPlatform.config} --host=${hostPlatform.config} --target=${targetPlatform.config} \
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

      test -f "$out/bin/gcc" && test ! -f "$out/bin/cc" && ln -sf gcc "$out/bin/cc"

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
