# stdenv/toolchains/gcc4_4/gcc.nix - GCC 4.4.7 (C+C++, RHEL 6)
#
# First GCC with C++ support. Last GCC where the compiler source is pure C.
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

  gccCoreSrc = fetchSrc {
    name = "gcc-core-4.4.7.tar.bz2";
    url = "https://mirrors.kernel.org/gnu/gcc/gcc-4.4.7/gcc-core-4.4.7.tar.bz2";
    hash = "sha256-xGY7cCOQmkoHXTwrLhf24IKpYlrr/Qzn8deBfkS/VUI=";
  };

  gccGxxSrc = fetchSrc {
    name = "gcc-g++-4.4.7.tar.bz2";
    url = "https://mirrors.kernel.org/gnu/gcc/gcc-4.4.7/gcc-g++-4.4.7.tar.bz2";
    hash = "sha256-GIL/Kb5R7rP7NJy82p3yAKXDzSDJfdHVkxAeCZizxGk=";
  };

  gmpSrc = fetchSrc {
    name = "gmp-4.3.2.tar.bz2";
    url = "https://mirrors.kernel.org/gnu/gmp/gmp-4.3.2.tar.bz2";
    hash = "sha256-k2FiwDEohsIVgQAreZMoKaoEjPr5k3xiZa6qFPHNF3U=";
  };

  mpfrSrc = fetchSrc {
    name = "mpfr-2.4.2.tar.bz2";
    url = "https://mirrors.kernel.org/gnu/mpfr/mpfr-2.4.2.tar.bz2";
    hash = "sha256-x+daCKjUnSCC5MruFZGgXRG51WJ1FOZ48C1moSS88ro=";
  };

  mkGcc = import ../lib/mk-gcc.nix {
    inherit
      prev
      buildPlatform
      hostPlatform
      targetPlatform
      ;
  };
in
  mkGcc {
    version = "4.4.7";
    unpackCommands = ''
      ${prev.tar}/bin/tar xjf ${gccCoreSrc}
      ${prev.tar}/bin/tar xjf ${gccGxxSrc}
      ${prev.tar}/bin/tar xjf ${gmpSrc}
      mv gmp-4.3.2 gcc-4.4.7/gmp
      ${prev.tar}/bin/tar xjf ${mpfrSrc}
      mv mpfr-2.4.2 gcc-4.4.7/mpfr
    '';
    freezeAutotoolsDirs = [
      "."
      "gmp"
      "mpfr"
    ];
    extraPathDeps = [
      prev.bzip2
    ];
    postUnpack = ''
      find . -name configure -exec chmod +x {} + 2>/dev/null || true
      find . -name '*.sh' -exec chmod +x {} + 2>/dev/null || true
      chmod +x move-if-change mkinstalldirs install-sh missing depcomp ylwrap 2>/dev/null || true

      # Disable fixincludes: it checks for /usr/include, which does not exist
      # in the Nix sandbox.
      ${prev.sed}/bin/sed -i \
        -e 's@\./fixinc\.sh@-c true@' \
        -e 's|then sleep 1; else exit 1; fi;|then sleep 1; else sleep 1; fi;|' \
        gcc/Makefile.in

      # This tier intentionally contains only the core C frontend and the g++
      # component. Enumerate cp directly so configure does not depend on glob
      # state inherited from an early bootstrap shell.
      ${prev.patch}/bin/patch -p1 < ${./patches/gcc-4.4.7-explicit-cxx-frontend.patch}
    '';
    preConfigure = ''
      test -f "$TMPDIR/gcc-4.4.7/gcc/cp/config-lang.in" || {
        echo "GCC 4.4.7 C++ frontend source is missing" >&2
        exit 1
      }

      mkdir -p "$TMPDIR/ccwrap"
      cat > "$TMPDIR/ccwrap/gcc" <<'AOS_GCC_CC'
      #!${prev.bash}/bin/bash
      compile=
      for arg; do case "$arg" in -c|-E|-S) compile=1 ;; esac; done
      if [ -z "$compile" ]; then
        exec ${prev.gcc}/bin/gcc -I ${prev.glibc}/include "$@" -L ${prev.glibc}/lib -Wl,-u,dl_iterate_phdr
      fi
      exec ${prev.gcc}/bin/gcc -I ${prev.glibc}/include "$@"
      AOS_GCC_CC
      chmod +x "$TMPDIR/ccwrap/gcc"
      ln -sf gcc "$TMPDIR/ccwrap/cc"
      export PATH="$TMPDIR/ccwrap:$PATH"
    '';
    configureEnv = [
      ''CC="$TMPDIR/ccwrap/gcc"''
      ''CXX=no''
      ''CC_FOR_BUILD="$TMPDIR/ccwrap/gcc"''
      ''CPP="$TMPDIR/ccwrap/gcc -E"''
      ''CPP_FOR_BUILD="$TMPDIR/ccwrap/gcc -E"''
      ''CFLAGS="-O2 -I${prev.glibc}/include"''
      ''CFLAGS_FOR_BUILD="-O2 -I${prev.glibc}/include"''
      ''CPPFLAGS="-I${prev.glibc}/include"''
      ''CPPFLAGS_FOR_BUILD="-I${prev.glibc}/include"''
      ''LDFLAGS="-static"''
      ''LDFLAGS_FOR_BUILD="-static"''
    ];
    configureBuild = hostPlatform.config;
    configureHost = hostPlatform.config;
    configureFlags = [
      "--enable-languages=c,c++"
      "--disable-shared"
      "--disable-nls"
      "--disable-threads"
      "--disable-multilib"
      "--disable-bootstrap"
      "--disable-libssp"
      "--disable-libgomp"
      "--disable-libmudflap"
      ''--with-native-system-header-dir="${prev.glibc}/include"''
      "--program-transform-name="
    ];
    postConfigure = ''
      printf '\nall-target-libiberty:\n\t@true\ninstall-target-libiberty:\n\t@true\nconfigure-target-libiberty:\n\t@true\n' >> Makefile
    '';
    makeFlags = [
      ''NATIVE_SYSTEM_HEADER_DIR="${prev.glibc}/include"''
      ''CFLAGS_FOR_TARGET="-O2 -isystem ${prev.glibc}/include -B${prev.glibc}/lib"''
      ''CXXFLAGS_FOR_TARGET="-O2 -isystem ${prev.glibc}/include -B${prev.glibc}/lib -D__NO_MATH_INLINES"''
      ''LDFLAGS_FOR_TARGET="-L${prev.glibc}/lib -B${prev.glibc}/lib -static"''
    ];
    postInstall = ''
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

      "${prev.binutils}/bin/ar" crs "$out/lib/gcc/${targetPlatform.config}/4.4.7/libgcc_eh.a"

      for f in "${prev.glibc}/lib/"*.o "${prev.glibc}/lib/"*.a; do
        test -f "$f" && ln -sf "$f" "$out/lib/"
      done

      mkdir -p "$out/${targetPlatform.config}/bin"
      for tool in as ld ar nm ranlib strip objcopy objdump; do
        test -f "${prev.binutils}/bin/$tool" && \
          ln -sf "${prev.binutils}/bin/$tool" "$out/${targetPlatform.config}/bin/$tool"
      done
    '';
    finalMessage = "GCC 4.4.7 installed to $out";
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
