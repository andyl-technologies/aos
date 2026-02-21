# stdenv/toolchains/gcc4_4/gcc.nix — GCC 4.4.7 (C+C++, RHEL 6)
#
# First GCC with C++ support. Last GCC where the compiler source is pure C.
# Requires GMP 4.3.2 + MPFR 2.4.2 built in-tree.
# Built by GCC 4.1.2 from the previous tier.
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
    name = "gmp-4.3.2.tar.bz2";
    url = "https://mirrors.kernel.org/gnu/gmp/gmp-4.3.2.tar.bz2";
    hash = "sha256-k2FiwDEohsIVgQAreZMoKaoEjPr5k3xiZa6qFPHNF3U=";
  };

  mpfr-src = fetchSrc {
    name = "mpfr-2.4.2.tar.bz2";
    url = "https://mirrors.kernel.org/gnu/mpfr/mpfr-2.4.2.tar.bz2";
    hash = "sha256-x+daCKjUnSCC5MruFZGgXRG51WJ1FOZ48C1moSS88ro=";
  };
in
builtins.derivation {
  name = "gcc-4.4.7";
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
      tar xjf ${gcc-core-src}
      tar xjf ${gcc-gxx-src}

      tar xjf ${gmp-src}
      mv gmp-4.3.2 gcc-4.4.7/gmp

      tar xjf ${mpfr-src}
      mv mpfr-2.4.2 gcc-4.4.7/mpfr

      SRC="$TMPDIR/gcc-4.4.7"
      cd "$SRC"
      chmod -R u+w .
      find . -name configure -exec chmod +x {} + 2>/dev/null || true
      find . -name '*.sh' -exec chmod +x {} + 2>/dev/null || true
      chmod +x move-if-change mkinstalldirs install-sh missing depcomp ylwrap 2>/dev/null || true
      find . -type f \( -name '*.c' -o -name '*.h' \) -exec touch {} + 2>/dev/null || true

      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      CC="${prev.gcc}/bin/gcc" CXX=no \
      CFLAGS="-O2 -static" LDFLAGS="-static" \
      "$SRC/configure" \
        --prefix="$out" \
        --build=${hostPlatform.config} --host=${hostPlatform.config} --target=${targetPlatform.config} \
        --enable-languages=c,c++ \
        --disable-shared --disable-nls --disable-threads \
        --disable-multilib --disable-bootstrap \
        --disable-libssp --disable-libgomp --disable-libmudflap \
        --with-native-system-header-dir="${prev.glibc}/include" \
        --program-transform-name= \
        --with-gmp-include="$SRC/gmp" \
        --with-gmp-lib="$TMPDIR/build/gmp/.libs" \
        --with-mpfr-include="$SRC/mpfr/src" \
        --with-mpfr-lib="$TMPDIR/build/mpfr/src/.libs"

      make -j"$(nproc)" \
        CFLAGS_FOR_TARGET="-O2 -I${prev.glibc}/include" \
        LDFLAGS_FOR_TARGET="-L${prev.glibc}/lib -static"

      make install

      [ -f "$out/bin/gcc" ] && [ ! -f "$out/bin/cc" ] && ln -sf gcc "$out/bin/cc"
      [ -f "$out/bin/g++" ] && [ ! -f "$out/bin/c++" ] && ln -sf g++ "$out/bin/c++"

      echo "GCC 4.4.7 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU Compiler Collection, version 4.4.7 (first C++)";
    homepage = "https://gcc.gnu.org/";
    license = "GPL-3.0-or-later";
    platforms = [
      "i686-linux"
      "x86_64-linux"
    ];
  };
}
