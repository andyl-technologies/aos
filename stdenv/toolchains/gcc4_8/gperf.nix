# stdenv/toolchains/gcc4_8/gperf.nix — GNU gperf 3.0.4 (RHEL 7)
#
# Built with THIS tier's GCC 4.8.5 + glibc 2.17.
# gperf is a perfect hash function generator used by glibc and other packages.
# Requires C++ (g++).
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
    url = "https://mirrors.kernel.org/gnu/gperf/gperf-3.0.4.tar.gz";
    sha256 = "12pqgvxmyckqv1b5qhi80qmwkvpvr604w7qckbn1dfkykl96rdgb";
  };
in
builtins.derivation {
  name = "gperf-3.0.4";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
      export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.bash}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.diffutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.bzip2}/bin:${prev.patch}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      cd "$TMPDIR"
      mkdir -p gperf-3.0.4 && (cd ${src} && tar cf - .) | (cd gperf-3.0.4 && tar xf -)
      cd gperf-3.0.4
      chmod -R u+w .

      # Touch autotools-generated files to prevent regeneration
      find . -type f -exec touch {} + 2>/dev/null || true

      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      CC="${gcc}/bin/gcc" \
      CXX="${gcc}/bin/g++" \
      CFLAGS="-O2 -isystem ${glibc}/include" \
      CXXFLAGS="-O2 -isystem ${glibc}/include" \
      CPPFLAGS="-isystem ${glibc}/include" \
      LDFLAGS="-L${glibc}/lib -static" \
      "$TMPDIR/gperf-3.0.4/configure" \
        --prefix="$out" \
        --build=${hostPlatform.config} --host=${hostPlatform.config}

      make -j"$NIX_BUILD_CORES" AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true
      make install AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true

      echo "GNU gperf 3.0.4 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU perfect hash function generator, version 3.0.4";
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
