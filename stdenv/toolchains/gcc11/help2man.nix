# stdenv/toolchains/gcc11/help2man.nix — GNU help2man 1.48.5 (RHEL 9)
#
# Built from source with THIS tier's GCC 11.5.0 + binutils 2.35 + glibc 2.34.
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
}: let
  src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/help2man/help2man-1.48.5.tar.xz";
    sha256 = "0d1q54b3pjxss80izg3j7yr76c06fhpx292xaarynx3myiyljwyf";
  };
in
  builtins.derivation {
    name = "help2man-1.48.5";
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
        mkdir help2man-1.48.5 && (cd ${src} && ${prev.tar}/bin/tar cf - .) | (cd help2man-1.48.5 && ${prev.tar}/bin/tar xf -)
        cd help2man-1.48.5
        chmod -R u+w .

        # Touch autotools inputs first, then generated .c/.h, then autotools outputs
        find . -type f \( -name '*.y' -o -name '*.l' -o -name 'Makefile.am' -o -name 'configure.ac' -o -name 'configure.in' -o -name 'acinclude.m4' \) -exec touch {} + 2>/dev/null || true
        sleep 1
        find . -type f \( -name '*.c' -o -name '*.h' \) -exec touch {} + 2>/dev/null || true
        sleep 1
        find . \( -name 'configure' -o -name 'Makefile.in' -o -name 'aclocal.m4' -o -name 'config.h.in' \) -exec touch {} + 2>/dev/null || true
        find . \( -name '*.1' -o -name '*.info' \) -exec touch -t 200001010200.00 {} + 2>/dev/null || true

        export LIBRARY_PATH="${glibc}/lib"
        GCC_INCDIR="${gcc}/lib/gcc/${hostPlatform.config}/11.5.0/include"
        CC="${gcc}/bin/gcc" \
        CFLAGS="-O2 -nostdinc -isystem $GCC_INCDIR -isystem $GCC_INCDIR-fixed -isystem ${glibc}/include" \
        CPPFLAGS="-nostdinc -isystem $GCC_INCDIR -isystem $GCC_INCDIR-fixed -isystem ${glibc}/include" \
        LDFLAGS="-L${glibc}/lib -static" \
        PERL="${perl}/bin/perl" \
        ./configure \
          --prefix="$out" \
          --build=${hostPlatform.config} --host=${hostPlatform.config}

        make -j"$NIX_BUILD_CORES" AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true
        make install AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true

        echo "GNU help2man 1.48.5 installed to $out"
      ''
    ];
  }
  // {
    meta = {
      description = "GNU help2man 1.48.5 — generates man pages from --help output";
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
