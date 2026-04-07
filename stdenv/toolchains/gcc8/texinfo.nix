# stdenv/toolchains/gcc8/texinfo.nix — GNU Texinfo 6.5 (RHEL 8)
#
# Built with THIS tier's GCC 8.5.0 + binutils 2.30 + glibc 2.28.
# Texinfo 6.5 is Perl-based.
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
    url = "https://mirrors.kernel.org/gnu/texinfo/texinfo-6.5.tar.xz";
    hash = "hash-s2LpZW+c3AqrrPmpTIf2lIgEGropkZOTSOOyJxn1jxg=";
  };
in
builtins.derivation {
  name = "texinfo-6.5";
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
      mkdir texinfo-6.5 && (cd ${src} && ${prev.tar}/bin/tar cf - .) | (cd texinfo-6.5 && ${prev.tar}/bin/tar xf -)
      cd texinfo-6.5
      chmod -R u+w .

      # Touch yacc/lex sources first, then generated .c/.h, then autotools outputs
      find . -type f \( -name '*.y' -o -name '*.l' -o -name 'Makefile.am' -o -name 'configure.ac' -o -name 'configure.in' -o -name 'acinclude.m4' \) -exec touch {} + 2>/dev/null || true
      sleep 1
      find . -type f \( -name '*.c' -o -name '*.h' \) -exec touch {} + 2>/dev/null || true
      sleep 1
      find . \( -name 'configure' -o -name 'Makefile.in' -o -name 'aclocal.m4' -o -name 'config.h.in' \) -exec touch {} + 2>/dev/null || true
      find . \( -name '*.1' -o -name '*.info' \) -exec touch -t 200001010200.00 {} + 2>/dev/null || true

      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      export LIBRARY_PATH="${glibc}/lib"
      export PERL="${perl}/bin/perl"
      GCC_INCDIR="${gcc}/lib/gcc/${hostPlatform.config}/8.5.0/include"
      CC="${gcc}/bin/gcc" \
      CFLAGS="-O2 -nostdinc -isystem $GCC_INCDIR -isystem $GCC_INCDIR-fixed -isystem ${glibc}/include" \
      CPPFLAGS="-nostdinc -isystem $GCC_INCDIR -isystem $GCC_INCDIR-fixed -isystem ${glibc}/include" \
      LDFLAGS="-L${glibc}/lib -static" \
      "$TMPDIR/texinfo-6.5/configure" \
        --prefix="$out" \
        --build=${hostPlatform.config} --host=${hostPlatform.config} --target=${hostPlatform.config} \
        --disable-perl-xs \
        --disable-nls

      # Man pages require help2man to run the built binaries, which fails
      # for static binaries. Use -k to continue past man page errors.
      make -k -j"$NIX_BUILD_CORES" AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true || true
      test -f tp/texi2any || { echo "FATAL: texi2any not built"; exit 1; }
      make install -k AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true || true
      test -f "$out/bin/makeinfo" || { echo "FATAL: makeinfo not installed"; exit 1; }

      echo "GNU Texinfo 6.5 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU documentation system, version 6.5";
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
