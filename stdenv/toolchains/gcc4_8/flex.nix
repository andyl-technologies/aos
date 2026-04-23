# stdenv/toolchains/gcc4_8/flex.nix — flex 2.5.37 (RHEL 7)
#
# Built with THIS tier's GCC 4.8.5 + glibc 2.17.
# Self-bootstrapping: ships pre-generated scan.c so no existing flex needed.
# Installs a `lex` symlink for compatibility.
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
}: let
  src = builtins.fetchTarball {
    url = "https://sourceforge.net/projects/flex/files/flex-2.5.37.tar.bz2";
    sha256 = "sha256-yKmh5Z+bOWMv24D7dKJyHHArIlu+fdQ79+c5UvjfqRw=";
  };
in
  builtins.derivation {
    name = "flex-2.5.37";
    system = buildPlatform.system;
    builder = "${prev.bash}/bin/bash";
    args = [
      "-c"
      ''
        set -eu
        export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
        export PATH="${texinfo}/bin:${help2man}/bin:${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.bash}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.diffutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.bzip2}/bin:${prev.patch}/bin:${m4}/bin"
        export CONFIG_SHELL="${prev.bash}/bin/bash"

        cd "$TMPDIR"
        cp -r ${src} flex-2.5.37
        cd flex-2.5.37
        chmod -R u+w .

        # Touch .y/.l sources first, then pre-generated .c/.h, then autotools files
        find . -type f \( -name '*.l' -o -name '*.y' \) -exec touch {} + 2>/dev/null || true
        sleep 1
        find . -type f \( -name '*.c' -o -name '*.h' \) -exec touch {} + 2>/dev/null || true
        sleep 1
        find . \( -name 'configure' -o -name 'Makefile.in' -o -name 'aclocal.m4' -o -name 'config.h.in' \) -exec touch {} + 2>/dev/null || true

        CC="${gcc}/bin/gcc" \
        CFLAGS="-O2 -isystem ${glibc}/include" \
        CPPFLAGS="-isystem ${glibc}/include" \
        LDFLAGS="-L${glibc}/lib -static" \
        ./configure \
          --prefix="$out" \
          --build=${hostPlatform.config} --host=${hostPlatform.config} \
          --disable-nls

        # The Makefile's scan.c rule runs: $(FLEX) -o.c scan.l; sed ... .c > scan.c
        # Without flex, the .c intermediate is never created and sed fails.
        # Provide .c as a copy of the pre-generated scan.c so the rule succeeds.
        cp scan.c .c

        # Skip doc/examples/po — doc tries to build PDFs with TeX
        make -j"$NIX_BUILD_CORES" AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true SUBDIRS="lib ."
        make install AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true SUBDIRS="lib ."

        # Create lex compatibility symlink
        [ ! -f "$out/bin/lex" ] && ln -sf flex "$out/bin/lex"

        echo "flex 2.5.37 installed to $out"
      ''
    ];
  }
  // {
    meta = {
      description = "Fast lexical analyzer generator, version 2.5.37";
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
