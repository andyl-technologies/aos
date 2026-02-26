# stdenv/toolchains/gcc14/gcc.nix — GCC 14.3.0 (RHEL 10, PRODUCTION)
#
# Production GCC built by GCC 11.5.0 from the previous tier. In-tree
# GMP/MPFR/MPC/ISL. Enables PIE and SSP by default (hardening flags).
#
{
  prev,
  buildPlatform,
  hostPlatform,
  targetPlatform,
}:
let
  gcc-src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/gcc/gcc-14.3.0/gcc-14.3.0.tar.xz";
    sha256 = "18slj57b3zizzmc1bn4b6x8rygijfjjmwfzipdvyyzrbspaa5x21";
  };

  gmp-src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/gmp/gmp-6.3.0.tar.xz";
    sha256 = "1kc3dy4jxand0y118yb9715g9xy1fnzqgkwxy02vd57y2fhg2pcw";
  };

  mpfr-src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/mpfr/mpfr-4.2.1.tar.xz";
    sha256 = "1irpgc9aqyhgkwqk7cvib1dgr5v5hf4m0vaaknssyfpkjmab9ydq";
  };

  mpc-src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/mpc/mpc-1.3.1.tar.gz";
    sha256 = "1b6layaybj039fajx8dpy2zvcfy7s02y3y4lficz16vac0fsd0jk";
  };

  isl-src = builtins.fetchTarball {
    url = "https://libisl.sourceforge.io/isl-0.26.tar.xz";
    sha256 = "01krva4ax8zvi365akpzdv8r3a3gdl8sqcdgsg2kxmcy810gay0k";
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
      export PATH="${prev.coreutils}/bin:${prev.gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      cd "$TMPDIR"
      cp -r ${gcc-src} gcc-14.3.0
      cp -r ${gmp-src} gcc-14.3.0/gmp
      cp -r ${mpfr-src} gcc-14.3.0/mpfr
      cp -r ${mpc-src} gcc-14.3.0/mpc
      cp -r ${isl-src} gcc-14.3.0/isl

      SRC="$TMPDIR/gcc-14.3.0"
      cd "$SRC"
      chmod -R u+w .

      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      CC="${prev.gcc}/bin/gcc" CXX="${prev.gcc}/bin/g++" \
      CFLAGS="-O2" CXXFLAGS="-O2" \
      "$SRC/configure" \
        --prefix="$out" \
        --build=${buildPlatform.config} --host=${hostPlatform.config} --target=${targetPlatform.config} \
        --enable-languages=c,c++ \
        --disable-shared --disable-nls --disable-threads \
        --disable-multilib --disable-bootstrap \
        --disable-libsanitizer --disable-libvtv \
        --enable-default-pie --enable-default-ssp \
        --with-native-system-header-dir="${prev.glibc}/include" \
        --program-transform-name=

      make -j"$(nproc)" \
        CFLAGS_FOR_TARGET="-O2 -I${prev.glibc}/include" \
        LDFLAGS_FOR_TARGET="-L${prev.glibc}/lib"

      make install

      [ -f "$out/bin/gcc" ] && [ ! -f "$out/bin/cc" ] && ln -sf gcc "$out/bin/cc"
      [ -f "$out/bin/g++" ] && [ ! -f "$out/bin/c++" ] && ln -sf g++ "$out/bin/c++"

      echo "GCC 14.3.0 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU Compiler Collection 14.3.0 — production compiler with PIE+SSP";
    homepage = "https://gcc.gnu.org/";
    license = "GPL-3.0-or-later";
    build = { os = "linux"; cpu = ["x86_64" "i686" "aarch64"]; };
    execute = { os = "linux"; cpu = ["x86_64" "i686" "aarch64"]; };
    target = { os = "linux"; cpu = ["x86_64" "i686" "aarch64"]; };
  };
}
