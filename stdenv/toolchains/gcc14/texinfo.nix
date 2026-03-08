# stdenv/toolchains/gcc14/texinfo.nix — GNU Texinfo 7.1 (RHEL 10)
#
# GNU Texinfo built with THIS tier's tools. Perl-based; requires perl.
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
  src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/texinfo/texinfo-7.1.tar.xz";
    sha256 = "045aswlbs2n367k1n3xga6gh7bmjq5mkw8yd3zz3w8cxb0zkk16b";
  };
in
builtins.derivation {
  name = "texinfo-7.1";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
      export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin:${perl}/bin:${help2man}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      cd "$TMPDIR"
      mkdir texinfo-7.1 && (cd ${src} && ${prev.tar}/bin/tar cf - .) | (cd texinfo-7.1 && ${prev.tar}/bin/tar xf -)
      cd texinfo-7.1
      chmod -R u+w .

      # Touch yacc/lex sources first, then generated .c/.h, then autotools outputs
      find . -type f \( -name '*.y' -o -name '*.l' -o -name 'Makefile.am' -o -name 'configure.ac' -o -name 'configure.in' -o -name 'acinclude.m4' \) -exec touch {} + 2>/dev/null || true
      sleep 1
      find . -type f \( -name '*.c' -o -name '*.h' \) -exec touch {} + 2>/dev/null || true
      sleep 1
      find . \( -name 'configure' -o -name 'Makefile.in' -o -name 'aclocal.m4' -o -name 'config.h.in' \) -exec touch {} + 2>/dev/null || true
      find . -name '*.info' -exec touch -t 200001010200.00 {} + 2>/dev/null || true
      find . -name '*.1' -exec touch {} + 2>/dev/null || true

      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      export LIBRARY_PATH="${glibc}/lib"
      export PERL="${perl}/bin/perl"
      CC="${gcc}/bin/gcc" \
      CFLAGS="-O2 -isystem ${glibc}/include" \
      CPPFLAGS="-isystem ${glibc}/include" \
      LDFLAGS="-L${glibc}/lib -static -no-pie" \
      PERL="${perl}/bin/perl" \
      "$TMPDIR/texinfo-7.1/configure" \
        --prefix="$out" \
        --build=${buildPlatform.config} --host=${hostPlatform.config} --target=${hostPlatform.config} \
        --disable-nls \
        --disable-perl-xs

      # Generate Commands.pm before make — the build Makefile runs
      # regenerate_commands_perl_info.pl which has #!/usr/bin/env perl shebang
      # that can't work in sandbox. Run it directly via perl.
      mkdir -p "$TMPDIR/build/tp/Texinfo"
      (cd "$TMPDIR/build/tp" && ${perl}/bin/perl \
        "$TMPDIR/texinfo-7.1/tp/maintain/regenerate_commands_perl_info.pl" \
        < "$TMPDIR/texinfo-7.1/tp/Texinfo/command_data.txt")
      touch "$TMPDIR/build/tp/Texinfo/Commands.pm"

      # help2man can't run statically-linked binaries to generate man pages.
      # Use -k to continue past man page errors.
      make -k -j"$NIX_BUILD_CORES" AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true || true
      # Verify critical outputs were built
      test -f tp/texi2any || { echo "FATAL: texi2any not built"; exit 1; }
      make install -k AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true || true

      # make install may skip tp/ if doc/man subdirs fail. Install manually.
      if [ ! -f "$out/bin/texi2any" ]; then
        mkdir -p "$out/bin"
        cp tp/texi2any "$out/bin/texi2any"
        chmod +x "$out/bin/texi2any"
      fi
      [ ! -e "$out/bin/makeinfo" ] && ln -sf texi2any "$out/bin/makeinfo"

      # Install install-info if built
      if [ -f install-info/ginstall-info ] && [ ! -f "$out/bin/install-info" ]; then
        cp install-info/ginstall-info "$out/bin/install-info"
        chmod +x "$out/bin/install-info"
      fi

      # Install Perl modules needed by texi2any
      if [ ! -d "$out/share/texinfo/Texinfo" ]; then
        mkdir -p "$out/share/texinfo"
        cp -r tp/Texinfo "$out/share/texinfo/Texinfo"
      fi

      test -f "$out/bin/makeinfo" || { echo "FATAL: makeinfo not installed"; exit 1; }
      test -f "$out/bin/texi2any" || { echo "FATAL: texi2any not installed"; exit 1; }

      echo "GNU Texinfo 7.1 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU Texinfo documentation system 7.1";
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
