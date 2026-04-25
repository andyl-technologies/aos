# stdenv/toolchains/gcc11/gperf.nix — GNU gperf 3.1 (RHEL 9)
#
# Built with THIS tier's GCC 11.5.0 + binutils 2.35 + glibc 2.34.
# gperf is a C++ program — needs CXX flags.
#
{
  prev,
  gcc,
  binutils,
  glibc,
  texinfo,
  buildPlatform,
  hostPlatform,
}: let
  src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/gperf/gperf-3.1.tar.gz";
    sha256 = "1cdivawkjb635zkq5qd512d533b47w16bg1xm4sybpzcy65xn37k";
  };
in
  builtins.derivation {
    name = "gperf-3.1";
    system = buildPlatform.system;
    builder = "${prev.bash}/bin/bash";
    args = [
      "-c"
      ''
        set -eu
        export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO="${texinfo}/bin/makeinfo"
        export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin"
        export CONFIG_SHELL="${prev.bash}/bin/bash"

        cd "$TMPDIR"
        mkdir gperf-3.1 && (cd ${src} && ${prev.tar}/bin/tar cf - .) | (cd gperf-3.1 && ${prev.tar}/bin/tar xf -)
        cd gperf-3.1
        chmod -R u+w .

        # Touch autotools inputs first, then generated .c/.h, then autotools outputs
        find . -type f \( -name '*.y' -o -name '*.l' -o -name 'Makefile.am' -o -name 'configure.ac' -o -name 'configure.in' -o -name 'acinclude.m4' \) -exec touch {} + 2>/dev/null || true
        sleep 1
        find . -type f \( -name '*.c' -o -name '*.h' -o -name '*.cc' -o -name '*.cpp' \) -exec touch {} + 2>/dev/null || true
        sleep 1
        find . \( -name 'configure' -o -name 'Makefile.in' -o -name 'aclocal.m4' -o -name 'config.h.in' \) -exec touch {} + 2>/dev/null || true
        find . \( -name '*.1' -o -name '*.info' \) -exec touch -t 200001010200.00 {} + 2>/dev/null || true

        mkdir -p "$TMPDIR/build"
        cd "$TMPDIR/build"

        export LIBRARY_PATH="${glibc}/lib"
        GCC_INCDIR="${gcc}/lib/gcc/${hostPlatform.config}/11.5.0/include"

        # Find the C++ include directory
        CXX_INCDIR="$(find ${gcc}/include -maxdepth 1 -name 'c++' -type d 2>/dev/null | head -1)" || true
        CXX_VER_INCDIR=""
        CXX_TARGET_INCDIR=""
        if [ -n "$CXX_INCDIR" ]; then
          CXX_VER_INCDIR="$(find "$CXX_INCDIR" -maxdepth 1 -type d -name '11*' 2>/dev/null | head -1)" || true
          if [ -n "$CXX_VER_INCDIR" ]; then
            CXX_TARGET_INCDIR="$CXX_VER_INCDIR/${hostPlatform.config}"
          fi
        fi

        CXX_INC_FLAGS=""
        if [ -n "$CXX_VER_INCDIR" ]; then
          CXX_INC_FLAGS="-isystem $CXX_VER_INCDIR"
          if [ -d "$CXX_TARGET_INCDIR" ]; then
            CXX_INC_FLAGS="$CXX_INC_FLAGS -isystem $CXX_TARGET_INCDIR"
          fi
        fi

        CC="${gcc}/bin/gcc" \
        CXX="${gcc}/bin/g++" \
        CFLAGS="-O2 -nostdinc -isystem $GCC_INCDIR -isystem $GCC_INCDIR-fixed -isystem ${glibc}/include" \
        CXXFLAGS="-O2 -nostdinc -nostdinc++ $CXX_INC_FLAGS -isystem $GCC_INCDIR -isystem $GCC_INCDIR-fixed -isystem ${glibc}/include" \
        CPPFLAGS="-nostdinc -isystem $GCC_INCDIR -isystem $GCC_INCDIR-fixed -isystem ${glibc}/include" \
        LDFLAGS="-L${glibc}/lib -static" \
        "$TMPDIR/gperf-3.1/configure" \
          --prefix="$out" \
          --build=${hostPlatform.config} --host=${hostPlatform.config} --target=${hostPlatform.config}

        make -j"$NIX_BUILD_CORES" AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true
        make install AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true

        echo "GNU gperf 3.1 installed to $out"
      ''
    ];
  }
  // {
    meta = {
      description = "GNU perfect hash function generator, version 3.1";
      homepage = "https://www.gnu.org/software/gperf/";
      license = "GPL-3.0-or-later";
      build = {
        os = "linux";
      };
      execute = {
        os = "linux";
      };
    };
  }
