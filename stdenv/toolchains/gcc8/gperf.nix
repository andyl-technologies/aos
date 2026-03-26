# stdenv/toolchains/gcc8/gperf.nix — GNU gperf 3.1 (RHEL 8)
#
# Built with THIS tier's GCC 8.5.0 + binutils 2.30 + glibc 2.28.
# gperf is C++, so we use g++.
#
{
  prev,
  gcc,
  binutils,
  glibc,
  buildPlatform,
  hostPlatform,
}:
let
  src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/gperf/gperf-3.1.tar.gz";
    sha256 = "sha256-8wzbi/Hs3+U1qT28ZQI/ZI1Rmgil4YLnL8MsObnasbE=";
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
      export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
      export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      cd "$TMPDIR"
      mkdir gperf-3.1 && (cd ${src} && ${prev.tar}/bin/tar cf - .) | (cd gperf-3.1 && ${prev.tar}/bin/tar xf -)
      cd gperf-3.1
      chmod -R u+w .

      # Touch yacc/lex sources first, then generated .c/.h, then autotools outputs
      find . -type f \( -name '*.y' -o -name '*.l' -o -name 'Makefile.am' -o -name 'configure.ac' -o -name 'configure.in' -o -name 'acinclude.m4' \) -exec touch {} + 2>/dev/null || true
      sleep 1
      find . -type f \( -name '*.c' -o -name '*.h' -o -name '*.cc' -o -name '*.hh' \) -exec touch {} + 2>/dev/null || true
      sleep 1
      find . \( -name 'configure' -o -name 'Makefile.in' -o -name 'aclocal.m4' -o -name 'config.h.in' \) -exec touch {} + 2>/dev/null || true

      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      export LIBRARY_PATH="${glibc}/lib"
      GCC_INCDIR="${gcc}/lib/gcc/${hostPlatform.config}/8.5.0/include"
      CXX_INCDIR="${gcc}/include/c++/8.5.0"
      CC="${gcc}/bin/gcc" \
      CXX="${gcc}/bin/g++" \
      CFLAGS="-O2 -nostdinc -isystem $GCC_INCDIR -isystem $GCC_INCDIR-fixed -isystem ${glibc}/include" \
      CXXFLAGS="-O2 -nostdinc -nostdinc++ -isystem $CXX_INCDIR -isystem $CXX_INCDIR/${hostPlatform.config} -isystem $GCC_INCDIR -isystem $GCC_INCDIR-fixed -isystem ${glibc}/include" \
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
