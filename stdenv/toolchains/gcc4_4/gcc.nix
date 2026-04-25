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
}: let
  fetchSrc = {
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
        export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
        export PATH="${prev.coreutils}/bin:${prev.gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.bash}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.diffutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.bzip2}/bin:${prev.patch}/bin"
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
        sleep 1
        find . \( -name 'configure' -o -name 'Makefile.in' -o -name 'aclocal.m4' -o -name 'config.h.in' \) -exec touch {} + 2>/dev/null || true

        # Disable fixincludes — it checks for /usr/include which doesn't
        # exist in the Nix sandbox.  Replace fixinc.sh with a no-op and
        # make the directory-existence check tolerate the missing dir.
        ${prev.sed}/bin/sed -i \
          -e 's@\./fixinc\.sh@-c true@' \
          -e 's|then sleep 1; else exit 1; fi;|then sleep 1; else sleep 1; fi;|' \
          gcc/Makefile.in

        # CC wrapper: only passes linker flags when actually linking.
        # Must be in PATH so GCC sub-configures that fall back to bare
        # "gcc" from PATH still go through the wrapper.
        mkdir -p "$TMPDIR/ccwrap"
        cp ${builtins.toFile "cc-wrapper" ''
          #!/bin/sh
          compile=
          for arg; do case "$arg" in -c|-E|-S) compile=1 ;; esac; done
          if [ -z "$compile" ]; then
            exec REAL_GCC -I GLIBC_INCLUDE "$@" -L GLIBC_LIB -Wl,-u,dl_iterate_phdr
          fi
          exec REAL_GCC -I GLIBC_INCLUDE "$@"
        ''} "$TMPDIR/ccwrap/gcc"
        ${prev.sed}/bin/sed -i \
          -e "s|REAL_GCC|${prev.gcc}/bin/gcc|g" \
          -e "s|GLIBC_INCLUDE|${prev.glibc}/include|g" \
          -e "s|GLIBC_LIB|${prev.glibc}/lib|g" \
          "$TMPDIR/ccwrap/gcc"
        chmod +x "$TMPDIR/ccwrap/gcc"
        ln -sf gcc "$TMPDIR/ccwrap/cc"
        export PATH="$TMPDIR/ccwrap:$PATH"

        mkdir -p "$TMPDIR/build"
        cd "$TMPDIR/build"

        CC="$TMPDIR/ccwrap/gcc" CXX=no \
        CC_FOR_BUILD="$TMPDIR/ccwrap/gcc" \
        CPP="$TMPDIR/ccwrap/gcc -E" \
        CPP_FOR_BUILD="$TMPDIR/ccwrap/gcc -E" \
        CFLAGS="-O2 -I${prev.glibc}/include" \
        CFLAGS_FOR_BUILD="-O2 -I${prev.glibc}/include" \
        CPPFLAGS="-I${prev.glibc}/include" \
        CPPFLAGS_FOR_BUILD="-I${prev.glibc}/include" \
        LDFLAGS="-static" \
        LDFLAGS_FOR_BUILD="-static" \
        "$SRC/configure" \
          --prefix="$out" \
          --build=${hostPlatform.config} --host=${hostPlatform.config} --target=${targetPlatform.config} \
          --enable-languages=c,c++ \
          --disable-shared --disable-nls --disable-threads \
          --disable-multilib --disable-bootstrap \
          --disable-libssp --disable-libgomp --disable-libmudflap \
          --with-native-system-header-dir="${prev.glibc}/include" \
          --program-transform-name=

        # Override target-libiberty with no-ops — it fails with "two or more
        # data types" due to xgcc + glibc-2.5 header incompatibility under
        # -pedantic.  target-libiberty is not needed for the toolchain.
        printf '\nall-target-libiberty:\n\t@true\ninstall-target-libiberty:\n\t@true\nconfigure-target-libiberty:\n\t@true\n' >> Makefile

        make -j"$NIX_BUILD_CORES" \
          AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true \
          NATIVE_SYSTEM_HEADER_DIR="${prev.glibc}/include" \
          CFLAGS_FOR_TARGET="-O2 -isystem ${prev.glibc}/include -B${prev.glibc}/lib" \
          CXXFLAGS_FOR_TARGET="-O2 -isystem ${prev.glibc}/include -B${prev.glibc}/lib -D__NO_MATH_INLINES" \
          LDFLAGS_FOR_TARGET="-L${prev.glibc}/lib -B${prev.glibc}/lib -static"

        make install \
          AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true

        [ -f "$out/bin/gcc" ] && [ ! -f "$out/bin/cc" ] && ln -sf gcc "$out/bin/cc"
        [ -f "$out/bin/g++" ] && [ ! -f "$out/bin/c++" ] && ln -sf g++ "$out/bin/c++"

        # Add dl_iterate_phdr stub to libgcc.a — glibc 2.5 static may not
        # provide it, causing undefined reference errors in downstream builds.
        cp ${builtins.toFile "libgcc-extra.c" ''
          /* dl_iterate_phdr stub: no shared objects in static builds */
          int dl_iterate_phdr(int (*callback)(void *, unsigned int, void *),
                              void *data) {
            return 0;
          }
        ''} "$TMPDIR/libgcc_extra.c"
        "$out/bin/gcc" -c -O2 -o "$TMPDIR/libgcc_extra.o" "$TMPDIR/libgcc_extra.c" \
          -isystem ${prev.glibc}/include
        LIBGCC_DIR="$out/lib/gcc/${targetPlatform.config}/4.4.7"
        chmod u+w "$LIBGCC_DIR/libgcc.a"
        ${prev.binutils}/bin/ar r "$LIBGCC_DIR/libgcc.a" "$TMPDIR/libgcc_extra.o"
        ${prev.binutils}/bin/ranlib "$LIBGCC_DIR/libgcc.a"

        # Create empty libgcc_eh.a — glibc expects it but --disable-shared
        # means GCC doesn't build it. An empty archive satisfies the linker.
        "${prev.binutils}/bin/ar" crs "$out/lib/gcc/${targetPlatform.config}/4.4.7/libgcc_eh.a"

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

        echo "GCC 4.4.7 installed to $out"
      ''
    ];
  }
  // {
    meta = {
      description = "GNU Compiler Collection, version 4.4.7 (first C++)";
      homepage = "https://gcc.gnu.org/";
      license = "GPL-3.0-or-later";
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
