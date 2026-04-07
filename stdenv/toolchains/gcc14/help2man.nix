# stdenv/toolchains/gcc14/help2man.nix — GNU help2man 1.49.3 (RHEL 10)
#
# Built from source with THIS tier's GCC 14.3.0 + binutils 2.41 + glibc 2.39.
# help2man is a Perl script that generates man pages from --help output.
#
{
  prev,
  gcc,
  binutils,
  glibc,
  perl,
  buildPlatform,
  hostPlatform,
}:
let
  inherit (import ../../../lib/derivations.nix { system = builtins.currentSystem; }) fetchTarball;

  src = fetchTarball {
    url = "https://mirrors.kernel.org/gnu/help2man/help2man-1.49.3.tar.xz";
    hash = "1hz5jzvgp025wcqlifv23mgb6m8wvk22kgz03g92ha13ympa2i03";
  };
in
builtins.derivation {
  name = "help2man-1.49.3";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
      export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin:${perl}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      cd "$TMPDIR"
      mkdir help2man-1.49.3 && (cd ${src} && ${prev.tar}/bin/tar cf - .) | (cd help2man-1.49.3 && ${prev.tar}/bin/tar xf -)
      cd help2man-1.49.3
      chmod -R u+w .

      # Touch autotools inputs first, then generated .c/.h, then autotools outputs
      find . -type f \( -name '*.y' -o -name '*.l' -o -name 'Makefile.am' -o -name 'configure.ac' -o -name 'configure.in' -o -name 'acinclude.m4' \) -exec touch {} + 2>/dev/null || true
      sleep 1
      find . -type f \( -name '*.c' -o -name '*.h' \) -exec touch {} + 2>/dev/null || true
      sleep 1
      find . \( -name 'configure' -o -name 'Makefile.in' -o -name 'aclocal.m4' -o -name 'config.h.in' \) -exec touch {} + 2>/dev/null || true
      find . -name '*.info' -exec touch -t 200001010200.00 {} + 2>/dev/null || true
      find . -name '*.1' -exec touch {} + 2>/dev/null || true

      export LIBRARY_PATH="${glibc}/lib"
      CC="${gcc}/bin/gcc" \
      CFLAGS="-O2 -isystem ${glibc}/include" \
      CPPFLAGS="-isystem ${glibc}/include" \
      LDFLAGS="-L${glibc}/lib -static -no-pie" \
      PERL="${perl}/bin/perl" \
      ./configure \
        --prefix="$out" \
        --build=${buildPlatform.config} --host=${hostPlatform.config}

      make -j"$NIX_BUILD_CORES" AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true
      make install AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true

      echo "GNU help2man 1.49.3 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU help2man 1.49.3 — generates man pages from --help output";
    homepage = "https://www.gnu.org/software/help2man/";
    license = "GPL-3.0-or-later";
    build = {
      os = "linux";
    };
    execute = {
      os = "linux";
    };
  };
}
