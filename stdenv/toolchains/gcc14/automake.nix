# stdenv/toolchains/gcc14/automake.nix — GNU Automake 1.17 (RHEL 10)
#
# GNU Automake built with THIS tier's tools. Requires autoconf, perl, and m4.
#
{
  prev,
  gcc,
  binutils,
  glibc,
  m4,
  perl,
  autoconf,
  texinfo,
  help2man,
  buildPlatform,
  hostPlatform,
}:
let
  src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/automake/automake-1.17.tar.xz";
    sha256 = "1nwgz937zikw5avzhvvzf57i917pq0q05s73wqr28abwqxa3bll8";
  };
in
builtins.derivation {
  name = "automake-1.17";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO="${texinfo}/bin/makeinfo"
      export PATH="${texinfo}/bin:${help2man}/bin:${autoconf}/bin:${m4}/bin:${perl}/bin:${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      export PERL="${perl}/bin/perl"

      cd "$TMPDIR"
      mkdir automake-1.17 && (cd ${src} && ${prev.tar}/bin/tar cf - .) | (cd automake-1.17 && ${prev.tar}/bin/tar xf -)
      cd automake-1.17
      chmod -R u+w .

      # Break all hardlinks in doc/ (version.texi/stamp-vti, versionmaint.texi/stamp-1, etc.)
      find doc -type f -links +1 -exec sh -c 'cp "$1" "$1.tmp" && mv "$1.tmp" "$1"' _ {} \; 2>/dev/null || true

      # Touch autotools inputs first, then generated .c/.h, then autotools outputs
      find . -type f \( -name '*.y' -o -name '*.l' -o -name 'Makefile.am' -o -name 'configure.ac' -o -name 'configure.in' -o -name 'acinclude.m4' \) -exec touch {} + 2>/dev/null || true
      sleep 1
      find . -type f \( -name '*.c' -o -name '*.h' \) -exec touch {} + 2>/dev/null || true
      sleep 1
      find . \( -name 'configure' -o -name 'Makefile.in' -o -name 'aclocal.m4' -o -name 'config.h.in' \) -exec touch {} + 2>/dev/null || true
      find . -name '*.info' -exec touch -t 200001010200.00 {} + 2>/dev/null || true
      find . -name '*.1' -exec touch {} + 2>/dev/null || true

      # Prevent amhello tarball regeneration (requires working automake, circular dep)
      sleep 1
      touch doc/amhello-1.0.tar.gz 2>/dev/null || true

      export LIBRARY_PATH="${glibc}/lib"
      CC="${gcc}/bin/gcc" \
      CFLAGS="-O2 -isystem ${glibc}/include" \
      CPPFLAGS="-isystem ${glibc}/include" \
      LDFLAGS="-L${glibc}/lib -static -no-pie" \
      PERL="${perl}/bin/perl" \
      ./configure \
        --prefix="$out" \
        --build=${buildPlatform.config} --host=${hostPlatform.config} --target=${hostPlatform.config}

      make -j"$NIX_BUILD_CORES" AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true
      make install AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true

      echo "GNU Automake 1.17 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU Automake 1.17";
    homepage = "https://www.gnu.org/software/automake/";
    license = "GPL-2.0-or-later";
    build = {
      os = "linux";
    };
    execute = {
      os = "linux";
    };
  };
}
