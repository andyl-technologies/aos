# stdenv/toolchains/gcc8/flex.nix — flex 2.6.1 (RHEL 8)
#
# Built with THIS tier's GCC 8.5.0 + binutils 2.30 + glibc 2.28.
#
{
  prev,
  gcc,
  binutils,
  glibc,
  m4,
  texinfo,
  help2man,
  buildPlatform,
  hostPlatform,
}:
let
  src = builtins.fetchTarball {
    url = "https://github.com/westes/flex/releases/download/v2.6.1/flex-2.6.1.tar.xz";
    sha256 = "sha256-Q6xMKCZM24E6qIndXVII38cTQstowhHt+ee/I+K7IfI=";
  };
in
builtins.derivation {
  name = "flex-2.6.1";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
      export PATH="${texinfo}/bin:${help2man}/bin:${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin:${m4}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      cd "$TMPDIR"
      mkdir flex-2.6.1 && (cd ${src} && ${prev.tar}/bin/tar cf - .) | (cd flex-2.6.1 && ${prev.tar}/bin/tar xf -)
      cd flex-2.6.1
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
      GCC_INCDIR="${gcc}/lib/gcc/${hostPlatform.config}/8.5.0/include"
      CC="${gcc}/bin/gcc" \
      CFLAGS="-O2 -nostdinc -isystem $GCC_INCDIR -isystem $GCC_INCDIR-fixed -isystem ${glibc}/include" \
      CPPFLAGS="-nostdinc -isystem $GCC_INCDIR -isystem $GCC_INCDIR-fixed -isystem ${glibc}/include" \
      LDFLAGS="-L${glibc}/lib -static" \
      M4="${m4}/bin/m4" \
      "$TMPDIR/flex-2.6.1/configure" \
        --prefix="$out" \
        --build=${hostPlatform.config} --host=${hostPlatform.config} --target=${hostPlatform.config} \
        --disable-nls

      # Skip tests/ (needs yacc/bison) and doc/ (needs TeX)
      make -j"$NIX_BUILD_CORES" SUBDIRS="lib src" AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true
      make install SUBDIRS="lib src" AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true

      # Create lex symlink
      ln -s flex "$out/bin/lex"

      echo "flex 2.6.1 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "Fast lexical analyser generator, version 2.6.1";
    homepage = "https://github.com/westes/flex";
    license = "BSD-2-Clause";
    build = {
      os = "linux";
    };
    execute = {
      os = "linux";
    };
  };
}
