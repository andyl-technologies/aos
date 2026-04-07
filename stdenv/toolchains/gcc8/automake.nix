# stdenv/toolchains/gcc8/automake.nix — GNU Automake 1.16.1 (RHEL 8)
#
# Built with THIS tier's GCC 8.5.0 + binutils 2.30 + glibc 2.28.
# Needs autoconf + perl + m4.
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
  inherit (import ../../../lib/derivations.nix { system = builtins.currentSystem; }) fetchTarball;

  src = fetchTarball {
    url = "https://mirrors.kernel.org/gnu/automake/automake-1.16.1.tar.xz";
    hash = "hash-/5C0Lb7IwKQDZ3OrwmyjjXqpIxj2M6TokJFwvGuNvLE=";
  };
in
builtins.derivation {
  name = "automake-1.16.1";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
      export PATH="${texinfo}/bin:${help2man}/bin:${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin:${m4}/bin:${perl}/bin:${autoconf}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      cd "$TMPDIR"
      mkdir automake-1.16.1 && (cd ${src} && ${prev.tar}/bin/tar cf - .) | (cd automake-1.16.1 && ${prev.tar}/bin/tar xf -)
      cd automake-1.16.1
      chmod -R u+w .

      # Break all hardlinks in doc/ (version.texi/stamp-vti, versionmaint.texi/stamp-1, etc.)
      find doc -type f -links +1 -exec sh -c 'cp "$1" "$1.tmp" && mv "$1.tmp" "$1"' _ {} \; 2>/dev/null || true

      # Touch yacc/lex sources first, then generated .c/.h, then autotools outputs
      find . -type f \( -name '*.y' -o -name '*.l' -o -name 'Makefile.am' -o -name 'configure.ac' -o -name 'configure.in' -o -name 'acinclude.m4' \) -exec touch {} + 2>/dev/null || true
      sleep 1
      find . -type f \( -name '*.c' -o -name '*.h' \) -exec touch {} + 2>/dev/null || true
      sleep 1
      find . \( -name 'configure' -o -name 'Makefile.in' -o -name 'aclocal.m4' -o -name 'config.h.in' \) -exec touch {} + 2>/dev/null || true
      find . \( -name '*.1' -o -name '*.info' \) -exec touch {} + 2>/dev/null || true

      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      export LIBRARY_PATH="${glibc}/lib"
      export PERL="${perl}/bin/perl"
      GCC_INCDIR="${gcc}/lib/gcc/${hostPlatform.config}/8.5.0/include"
      CC="${gcc}/bin/gcc" \
      CFLAGS="-O2 -nostdinc -isystem $GCC_INCDIR -isystem $GCC_INCDIR-fixed -isystem ${glibc}/include" \
      CPPFLAGS="-nostdinc -isystem $GCC_INCDIR -isystem $GCC_INCDIR-fixed -isystem ${glibc}/include" \
      LDFLAGS="-L${glibc}/lib -static" \
      "$TMPDIR/automake-1.16.1/configure" \
        --prefix="$out" \
        --build=${hostPlatform.config} --host=${hostPlatform.config} --target=${hostPlatform.config}

      # Out-of-tree build needs t/ dir for testsuite-part generation
      mkdir -p t

      # Touch doc artifacts to prevent regeneration (needs autotools + sample project)
      touch "$TMPDIR/automake-1.16.1/doc/amhello-1.0.tar.gz" 2>/dev/null || true
      find "$TMPDIR/automake-1.16.1/doc" -name '*.info' -exec touch {} + 2>/dev/null || true

      make -j"$NIX_BUILD_CORES" AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true
      make install AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true

      echo "GNU Automake 1.16.1 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU Automake, version 1.16.1";
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
