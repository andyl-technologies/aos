# stdenv/toolchains/gcc14/gperf.nix — GNU gperf 3.1 (RHEL 10)
#
# GNU perfect hash function generator built with THIS tier's GCC 14.3.0 + binutils 2.41 + glibc 2.39.
# Needs C++ (gperf is a C++ program).
#
{
  prev,
  gcc,
  binutils,
  glibc,
  texinfo,
  buildPlatform,
  hostPlatform,
}:
let
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

      # Touch autotools inputs first, then generated .c/.h/.cc/.cpp, then autotools outputs
      find . -type f \( -name '*.y' -o -name '*.l' -o -name 'Makefile.am' -o -name 'configure.ac' -o -name 'configure.in' -o -name 'acinclude.m4' \) -exec touch {} + 2>/dev/null || true
      sleep 1
      find . -type f \( -name '*.c' -o -name '*.h' -o -name '*.cc' -o -name '*.cpp' \) -exec touch {} + 2>/dev/null || true
      sleep 1
      find . \( -name 'configure' -o -name 'Makefile.in' -o -name 'aclocal.m4' -o -name 'config.h.in' \) -exec touch {} + 2>/dev/null || true
      find . -name '*.info' -exec touch -t 200001010200.00 {} + 2>/dev/null || true
      find . -name '*.1' -exec touch {} + 2>/dev/null || true

      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      export LIBRARY_PATH="${glibc}/lib"
      CC="${gcc}/bin/gcc" \
      CXX="${gcc}/bin/g++" \
      CFLAGS="-O2 -isystem ${glibc}/include" \
      CXXFLAGS="-O2 -isystem ${glibc}/include" \
      CPPFLAGS="-isystem ${glibc}/include" \
      LDFLAGS="-L${glibc}/lib -static -no-pie" \
      "$TMPDIR/gperf-3.1/configure" \
        --prefix="$out" \
        --build=${buildPlatform.config} --host=${hostPlatform.config} --target=${hostPlatform.config}

      make -j"$NIX_BUILD_CORES" AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true
      make install AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true

      echo "GNU gperf 3.1 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU perfect hash function generator 3.1";
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
