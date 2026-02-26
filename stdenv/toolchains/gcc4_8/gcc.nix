# stdenv/toolchains/gcc4_8/gcc.nix — GCC 4.8.5 (C+C++, RHEL 7)
#
# First GCC where the compiler source itself is C++. Requires a C++ compiler
# (g++ from GCC 4.4.7 in prev) to build. Requires GMP + MPFR + MPC (in-tree).
#
{
  prev,
  buildPlatform,
  hostPlatform,
  targetPlatform,
}:
let
  fetchSrc =
    {
      name,
      url,
      hash,
    }:
    builtins.derivation {
      inherit name;
      system = buildPlatform.system;
      builder = "builtin:fetchurl";
      inherit url;
      outputHash = hash;
      outputHashMode = "flat";
      outputHashAlgo = "sha256";
      preferLocalBuild = true;
    };

  gcc-src = fetchSrc {
    name = "gcc-4.8.5.tar.bz2";
    url = "https://mirrors.kernel.org/gnu/gcc/gcc-4.8.5/gcc-4.8.5.tar.bz2";
    hash = "sha256-Ivsefg9opjzuYx2FsgRh0epr2hYvAwljUOOMjUJ+zyM=";
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

in
builtins.derivation {
  name = "gcc-4.8.5";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export PATH="${prev.coreutils}/bin:${prev.gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.bash}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.diffutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.patch}/bin"
      CONFIG_SHELL="${prev.bash}/bin/bash"
      export CONFIG_SHELL

      cd "$TMPDIR"
      tar xjf ${gcc-src}

      tar xJf ${gmp-src}
      mv gmp-6.3.0 gcc-4.8.5/gmp

      tar xJf ${mpfr-src}
      mv mpfr-4.2.1 gcc-4.8.5/mpfr

      tar xzf ${mpc-src}
      mv mpc-1.3.1 gcc-4.8.5/mpc

      SRC="$TMPDIR/gcc-4.8.5"
      cd "$SRC"
      chmod -R u+w .
      find . -name configure -exec chmod +x {} + 2>/dev/null || true
      find . -name '*.sh' -exec chmod +x {} + 2>/dev/null || true
      chmod +x move-if-change mkinstalldirs install-sh missing depcomp ylwrap 2>/dev/null || true
      find . -type f \( -name '*.c' -o -name '*.h' \) -exec touch {} + 2>/dev/null || true

      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      CC="${prev.gcc}/bin/gcc" CXX="${prev.gcc}/bin/g++" \
      CFLAGS="-O2" CXXFLAGS="-O2" \
      "$SRC/configure" \
        --prefix="$out" \
        --build=${hostPlatform.config} --host=${hostPlatform.config} --target=${targetPlatform.config} \
        --enable-languages=c,c++ \
        --disable-shared --disable-nls --disable-threads \
        --disable-multilib --disable-bootstrap \
        --disable-libssp --disable-libgomp --disable-libmudflap \
        --disable-libsanitizer \
        --with-native-system-header-dir="${prev.glibc}/include" \
        --program-transform-name=

      make -j"$(nproc)" \
        CFLAGS_FOR_TARGET="-O2 -I${prev.glibc}/include" \
        LDFLAGS_FOR_TARGET="-L${prev.glibc}/lib"

      make install

      [ -f "$out/bin/gcc" ] && [ ! -f "$out/bin/cc" ] && ln -sf gcc "$out/bin/cc"
      [ -f "$out/bin/g++" ] && [ ! -f "$out/bin/c++" ] && ln -sf g++ "$out/bin/c++"

      echo "GCC 4.8.5 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU Compiler Collection, version 4.8.5";
    homepage = "https://gcc.gnu.org/";
    license = "GPL-3.0-or-later";
    build = { os = "linux"; cpu = ["x86_64" "i686" "aarch64"]; };
    execute = { os = "linux"; cpu = ["x86_64" "i686" "aarch64"]; };
    target = { os = "linux"; cpu = ["x86_64" "i686" "aarch64"]; };
  };
}
