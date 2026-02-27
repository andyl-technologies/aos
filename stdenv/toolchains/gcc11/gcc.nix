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
  src = builtins.fetchTarball {
    url = "https://ftp.gnu.org/gnu/gcc/gcc-11.5.0/gcc-11.5.0.tar.xz";
    sha256 = "1gd9gix3jgbmav964rrp8c8h2dp1mkszwyawvxgik6cw4r2hx9s3";
  };

  gmp-src = builtins.fetchTarball {
    url = "https://ftp.gnu.org/gnu/gmp/gmp-6.3.0.tar.xz";
    sha256 = "1kc3dy4jxand0y118yb9715g9xy1fnzqgkwxy02vd57y2fhg2pcw";
  };

  mpfr-src = builtins.fetchTarball {
    url = "https://ftp.gnu.org/gnu/mpfr/mpfr-4.2.1.tar.xz";
    sha256 = "1irpgc9aqyhgkwqk7cvib1dgr5v5hf4m0vaaknssyfpkjmab9ydq";
  };

  mpc-src = builtins.fetchTarball {
    url = "https://ftp.gnu.org/gnu/mpc/mpc-1.3.1.tar.gz";
    sha256 = "1b6layaybj039fajx8dpy2zvcfy7s02y3y4lficz16vac0fsd0jk";
  };

  isl-src = builtins.fetchTarball {
    url = "https://libisl.sourceforge.io/isl-0.26.tar.xz";
    sha256 = "01krva4ax8zvi365akpzdv8r3a3gdl8sqcdgsg2kxmcy810gay0k";
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
      export PATH="${prev.coreutils}/bin:${prev.gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      cd "$TMPDIR"
      cp -r ${src} gcc-11.5.0
      cd gcc-11.5.0
      chmod -R u+w .

      # Place in-tree dependencies
      cp -r ${gmp-src} gmp
      chmod -R u+w gmp
      cp -r ${mpfr-src} mpfr
      chmod -R u+w mpfr
      cp -r ${mpc-src} mpc
      chmod -R u+w mpc
      cp -r ${isl-src} isl
      chmod -R u+w isl

      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      CC="${prev.gcc}/bin/gcc" CXX="${prev.gcc}/bin/g++" \
      CFLAGS="-O2 -static" CXXFLAGS="-O2 -static" \
      LDFLAGS="-static" \
      "$TMPDIR/gcc-11.5.0/configure" \
        --prefix="$out" \
        --build=${buildPlatform.config} --host=${hostPlatform.config} --target=${targetPlatform.config} \
        --enable-languages=c,c++ \
        --disable-shared --disable-nls --disable-threads \
        --disable-multilib --disable-bootstrap \
        --disable-libssp --disable-libgomp --disable-libsanitizer \
        --disable-libvtv --disable-libquadmath \
        --with-native-system-header-dir="${prev.glibc}/include" \
        --program-transform-name=

      make -j"$(nproc)" \
        BOOT_CFLAGS="-O2 -static" \
        CFLAGS_FOR_TARGET="-O2 -I${prev.glibc}/include" \
        LDFLAGS_FOR_TARGET="-L${prev.glibc}/lib -static"

      make install

      [ -f "$out/bin/gcc" ] && [ ! -f "$out/bin/cc" ] && ln -sf gcc "$out/bin/cc"
      [ -f "$out/bin/g++" ] && [ ! -f "$out/bin/c++" ] && ln -sf g++ "$out/bin/c++"

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
        "i686"
        "aarch64"
      ];
    };
    execute = {
      os = "linux";
      cpu = [
        "x86_64"
        "i686"
        "aarch64"
      ];
    };
    target = {
      os = "linux";
      cpu = [
        "x86_64"
        "i686"
        "aarch64"
      ];
    };
  };
}
