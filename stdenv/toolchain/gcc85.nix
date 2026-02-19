# stdenv/toolchain/gcc85.nix — GCC 8.5.0 (RHEL 8)
#
# Requires C++11 (provided by GCC 4.8.5). In-tree GMP/MPFR/MPC.
#
{
  gcc485, # GCC 4.8.5 from earlier toolchain stage
  binutils220, # Binutils 2.20 from bootstrap exports
  glibc225, # Glibc 2.25 from bootstrap exports
  busybox136, # BusyBox 1.36 from bootstrap exports
  make44, # Make 4.4 from bootstrap exports

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
    name = "gcc-8.5.0.tar.xz";
    url = "https://mirrors.kernel.org/gnu/gcc/gcc-8.5.0/gcc-8.5.0.tar.xz";
    hash = "sha256-0wiEGlEbuDCmEAOXsAQtskzhH2Qtq26m7kSELlMl7VA=";
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

  target = "i686-linux-gnu";
in
  builtins.derivation {
    name = "gcc-8.5.0";
    inherit system;
    builder = "${busybox136}/bin/sh";
    args = [
      "-c"
      ''
        set -eu
        export PATH="${busybox136}/bin:${gcc485}/bin:${binutils220}/bin:${make44}/bin"
        CONFIG_SHELL="${busybox136}/bin/sh"
        export CONFIG_SHELL

        cd "$TMPDIR"
        tar xJf ${gcc-src}

        tar xJf ${gmp-src}
        mv gmp-6.3.0 gcc-8.5.0/gmp

        tar xJf ${mpfr-src}
        mv mpfr-4.2.1 gcc-8.5.0/mpfr

        tar xzf ${mpc-src}
        mv mpc-1.3.1 gcc-8.5.0/mpc

        SRC="$TMPDIR/gcc-8.5.0"
        cd "$SRC"
        chmod -R u+w .
        find . -name configure -exec chmod +x {} + 2>/dev/null || true
        find . -name '*.sh' -exec chmod +x {} + 2>/dev/null || true
        chmod +x move-if-change mkinstalldirs install-sh missing depcomp ylwrap 2>/dev/null || true
        find . -type f \( -name '*.c' -o -name '*.h' \) -exec touch {} + 2>/dev/null || true

        mkdir -p "$TMPDIR/build"
        cd "$TMPDIR/build"

        CC="${gcc485}/bin/gcc" CXX="${gcc485}/bin/g++" \
        CFLAGS="-O2" CXXFLAGS="-O2" \
        "$SRC/configure" \
          --prefix="$out" \
          --build=${target} --host=${target} --target=${target} \
          --enable-languages=c,c++ \
          --disable-shared --disable-nls --disable-threads \
          --disable-multilib --disable-bootstrap \
          --disable-libssp --disable-libgomp --disable-libsanitizer \
          --disable-libmpx --disable-libvtv \
          --with-native-system-header-dir="${glibc225}/include" \
          --program-transform-name=

        make -j"$(nproc)" \
          CFLAGS_FOR_TARGET="-O2 -I${glibc225}/include" \
          LDFLAGS_FOR_TARGET="-L${glibc225}/lib"

        make install

        [ -f "$out/bin/gcc" ] && [ ! -f "$out/bin/cc" ] && ln -sf gcc "$out/bin/cc"
        [ -f "$out/bin/g++" ] && [ ! -f "$out/bin/c++" ] && ln -sf g++ "$out/bin/c++"

        echo "GCC 8.5.0 installed to $out"
      ''
    ];
  }
  // {
    meta = {
      description = "GNU Compiler Collection, version 8.5.0";
      homepage = "https://gcc.gnu.org/";
      license = "GPL-3.0-or-later";
      platforms = ["i686-linux" "x86_64-linux" "aarch64-linux"];
    };
  }
