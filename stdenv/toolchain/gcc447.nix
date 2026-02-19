# stdenv/toolchain/gcc447.nix — GCC 4.4.7 (C+C++, RHEL 6)
#
# Last GCC where the compiler source is pure C. First to produce g++.
# Requires GMP + MPFR (in-tree build).
#
{
  gcc412, # GCC 4.1.2 from earlier toolchain stage
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

  gcc-core-src = fetchSrc {
    name = "gcc-core-4.4.7.tar.bz2";
    url = "https://mirrors.kernel.org/gnu/gcc/gcc-4.4.7/gcc-core-4.4.7.tar.bz2";
    hash = "sha256-xGY7cCOQmkoHXTwrLhf24IKpYlrr/Qzn8deBfkS/VUI=";
  };

  gcc-gxx-src = fetchSrc {
    name = "gcc-g++-4.4.7.tar.bz2";
    url = "https://mirrors.kernel.org/gnu/gcc/gcc-4.4.7/gcc-g++-4.4.7.tar.bz2";
    hash = "sha256-GIL/Kb5R7rP7NJy82p3yAKXDzSDJfdHVkxAeCZizxGk=";
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

  target = "i686-linux-gnu";
in
  builtins.derivation {
    name = "gcc-4.4.7";
    inherit system;
    builder = "${busybox136}/bin/sh";
    args = [
      "-c"
      ''
        set -eu
        export PATH="${busybox136}/bin:${gcc412}/bin:${binutils220}/bin:${make44}/bin"
        CONFIG_SHELL="${busybox136}/bin/sh"
        export CONFIG_SHELL

        cd "$TMPDIR"
        tar xjf ${gcc-core-src}
        tar xjf ${gcc-gxx-src}

        tar xJf ${gmp-src}
        mv gmp-6.3.0 gcc-4.4.7/gmp

        tar xJf ${mpfr-src}
        mv mpfr-4.2.1 gcc-4.4.7/mpfr

        SRC="$TMPDIR/gcc-4.4.7"
        cd "$SRC"
        chmod -R u+w .
        find . -name configure -exec chmod +x {} + 2>/dev/null || true
        find . -name '*.sh' -exec chmod +x {} + 2>/dev/null || true
        chmod +x move-if-change mkinstalldirs install-sh missing depcomp ylwrap 2>/dev/null || true
        find . -type f \( -name '*.c' -o -name '*.h' \) -exec touch {} + 2>/dev/null || true

        mkdir -p "$TMPDIR/build"
        cd "$TMPDIR/build"

        CC="${gcc412}/bin/gcc" CXX=no \
        CFLAGS="-O2 -static" LDFLAGS="-static" \
        "$SRC/configure" \
          --prefix="$out" \
          --build=${target} --host=${target} --target=${target} \
          --enable-languages=c,c++ \
          --disable-shared --disable-nls --disable-threads \
          --disable-multilib --disable-bootstrap \
          --disable-libssp --disable-libgomp --disable-libmudflap \
          --with-native-system-header-dir="${glibc225}/include" \
          --program-transform-name= \
          --with-gmp-include="$SRC/gmp" \
          --with-gmp-lib="$TMPDIR/build/gmp/.libs" \
          --with-mpfr-include="$SRC/mpfr/src" \
          --with-mpfr-lib="$TMPDIR/build/mpfr/src/.libs"

        make -j"$(nproc)" \
          CFLAGS_FOR_TARGET="-O2 -I${glibc225}/include" \
          LDFLAGS_FOR_TARGET="-L${glibc225}/lib -static"

        make install

        [ -f "$out/bin/gcc" ] && [ ! -f "$out/bin/cc" ] && ln -sf gcc "$out/bin/cc"
        [ -f "$out/bin/g++" ] && [ ! -f "$out/bin/c++" ] && ln -sf g++ "$out/bin/c++"

        echo "GCC 4.4.7 installed to $out"
      ''
    ];
  }
  // {
    meta = {
      description = "GNU Compiler Collection, version 4.4.7";
      homepage = "https://gcc.gnu.org/";
      license = "GPL-3.0-or-later";
      platforms = ["i686-linux" "x86_64-linux"];
    };
  }
