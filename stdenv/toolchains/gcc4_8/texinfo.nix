# stdenv/toolchains/gcc4_8/texinfo.nix — GNU Texinfo 5.1 (RHEL 7)
#
# Built with THIS tier's GCC 4.8.5 + glibc 2.17.
# Texinfo 5.1 is the Perl-based rewrite. Provides `makeinfo`.
#
{
  prev,
  gcc,
  binutils,
  glibc,
  perl,
  help2man,
  buildPlatform,
  hostPlatform,
}:
let
  inherit (import ../../../lib/derivations.nix { system = builtins.currentSystem; }) fetchTarball;

  src = fetchTarball {
    url = "https://mirrors.kernel.org/gnu/texinfo/texinfo-5.1.tar.xz";
    hash = "hash-T1vaT1BMWE9bRkR9rwIbUjuwBpYAnW0Yz+wQWl4HJhU=";
  };
in
builtins.derivation {
  name = "texinfo-5.1";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
      export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.bash}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.diffutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.bzip2}/bin:${prev.patch}/bin:${perl}/bin:${help2man}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      cd "$TMPDIR"
      cp -r ${src} texinfo-5.1
      cd texinfo-5.1
      chmod -R u+w .

      # Use fixed timestamps to prevent regeneration
      find . -type f -exec touch -t 200001010000.00 {} + 2>/dev/null || true
      find . -type f \( -name '*.c' -o -name '*.h' \) -exec touch -t 200001010030.00 {} + 2>/dev/null || true
      find . \( -name 'configure' -o -name 'Makefile.in' -o -name 'aclocal.m4' -o -name 'config.h.in' \) -exec touch -t 200001010100.00 {} + 2>/dev/null || true
      find . \( -name '*.1' -o -name '*.info' \) -exec touch -t 200001010200.00 {} + 2>/dev/null || true

      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      CC="${gcc}/bin/gcc" \
      CFLAGS="-O2 -isystem ${glibc}/include" \
      CPPFLAGS="-isystem ${glibc}/include" \
      LDFLAGS="-L${glibc}/lib -static" \
      PERL="${perl}/bin/perl" \
      "$TMPDIR/texinfo-5.1/configure" \
        --prefix="$out" \
        --build=${hostPlatform.config} --host=${hostPlatform.config} \
        --disable-nls \
        --disable-perl-xs

      make -j"$NIX_BUILD_CORES" AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true
      make install AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true

      echo "GNU Texinfo 5.1 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU documentation system, version 5.1";
    homepage = "https://www.gnu.org/software/texinfo/";
    license = "GPL-3.0-or-later";
    build = {
      os = "linux";
    };
    execute = {
      os = "linux";
    };
  };
}
