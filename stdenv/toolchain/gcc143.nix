# stdenv/toolchain/gcc143.nix — GCC 14.3.0 (production)
#
# Production GCC, compiled by GCC 11.5.0 with modern binutils 2.41 and
# glibc 2.39. This is the final output of the source bootstrap chain.
#
# In-tree GMP/MPFR/MPC/ISL. Enables PIE and SSP by default.
#
{
  gcc115,
  binutils241,
  glibc239,
  busybox136,
  make44,

  system ? "x86_64-linux",
}: let
  fetchSrc = {
    name,
    url,
    hash,
  }:
    builtins.derivation {
      inherit name system;
      builder = "builtin:fetchurl";
      inherit url;
      outputHash = hash;
      outputHashMode = "flat";
      outputHashAlgo = "sha256";
      preferLocalBuild = true;
    };

  gcc-src = fetchSrc {
    name = "gcc-14.3.0.tar.xz";
    url = "https://mirrors.kernel.org/gnu/gcc/gcc-14.3.0/gcc-14.3.0.tar.xz";
    hash = "sha256-4Nx3KXYlYxrI5Q+pL//v6Jmk63AlktpcMu8E4ik6yjo=";
  };

  gmp-src = fetchSrc {
    name = "gmp-6.3.0.tar.xz";
    url = "https://mirrors.kernel.org/gnu/gmp/gmp-6.3.0.tar.xz";
    hash = "sha256-o8K4AgG4nmhhb0rTC8Zq7kknw85Q4zkpyoGdXENTiJg=";
  };

  mpfr-src = fetchSrc {
    name = "mpfr-4.2.1.tar.xz";
    url = "https://mirrors.kernel.org/gnu/mpfr/mpfr-4.2.1.tar.xz";
    hash = "sha256-J3gHNTpnJpeJlpRa8T5Sgp46vXqaW3+yeTiU4Y8fy7I=";
  };

  mpc-src = fetchSrc {
    name = "mpc-1.3.1.tar.gz";
    url = "https://mirrors.kernel.org/gnu/mpc/mpc-1.3.1.tar.gz";
    hash = "sha256-q2QkkvXPiCt0qgy3MM1BCoHtzb7IlRg86TDnBsHHWbg=";
  };

  isl-src = fetchSrc {
    name = "isl-0.26.tar.xz";
    url = "https://libisl.sourceforge.io/isl-0.26.tar.xz";
    hash = "sha256-oLXLBtJPn6nne1X6u+mjyUozYZA0XCVV+ZFbs46XZQQ=";
  };

  target = "i686-linux-gnu";
in
  builtins.derivation {
    name = "gcc-14.3.0";
    inherit system;
    builder = "${busybox136}/bin/sh";
    args = [
      "-c"
      ''
        set -eu
        export PATH="${busybox136}/bin:${gcc115}/bin:${binutils241}/bin:${make44}/bin"

        cd "$TMPDIR"
        tar xJf ${gcc-src}

        tar xJf ${gmp-src}
        mv gmp-6.3.0 gcc-14.3.0/gmp

        tar xJf ${mpfr-src}
        mv mpfr-4.2.1 gcc-14.3.0/mpfr

        tar xzf ${mpc-src}
        mv mpc-1.3.1 gcc-14.3.0/mpc

        tar xJf ${isl-src}
        mv isl-0.26 gcc-14.3.0/isl

        SRC="$TMPDIR/gcc-14.3.0"
        cd "$SRC"
        chmod -R u+w .
        find . -name configure -exec chmod +x {} + 2>/dev/null || true
        find . -name '*.sh' -exec chmod +x {} + 2>/dev/null || true
        chmod +x move-if-change mkinstalldirs install-sh missing depcomp ylwrap 2>/dev/null || true
        find . -type f \( -name '*.c' -o -name '*.h' \) -exec touch {} + 2>/dev/null || true

        mkdir -p "$TMPDIR/build"
        cd "$TMPDIR/build"

        CC="${gcc115}/bin/gcc" CXX="${gcc115}/bin/g++" \
        CFLAGS="-O2" CXXFLAGS="-O2" \
        "$SRC/configure" \
          --prefix="$out" \
          --build=${target} --host=${target} --target=${target} \
          --enable-languages=c,c++ \
          --disable-shared --disable-nls --disable-threads \
          --disable-multilib --disable-bootstrap \
          --disable-libsanitizer --disable-libvtv \
          --enable-default-pie --enable-default-ssp \
          --with-native-system-header-dir="${glibc239}/include" \
          --program-transform-name=

        make -j"$(nproc)" \
          CFLAGS_FOR_TARGET="-O2 -I${glibc239}/include" \
          LDFLAGS_FOR_TARGET="-L${glibc239}/lib"

        make install

        [ -f "$out/bin/gcc" ] && [ ! -f "$out/bin/cc" ] && ln -sf gcc "$out/bin/cc"
        [ -f "$out/bin/g++" ] && [ ! -f "$out/bin/c++" ] && ln -sf g++ "$out/bin/c++"

        echo "GCC 14.3.0 installed to $out"
      ''
    ];
  }
  // {
    meta = {
      description = "GNU Compiler Collection, version 14.3.0";
      homepage = "https://gcc.gnu.org/";
      license = "GPL-3.0-or-later";
      platforms = ["i686-linux" "x86_64-linux" "aarch64-linux"];
    };
  }
