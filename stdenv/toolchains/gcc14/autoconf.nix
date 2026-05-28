# stdenv/toolchains/gcc14/autoconf.nix — GNU Autoconf 2.72 (RHEL 10)
#
# GNU Autoconf built with THIS tier's tools. Requires m4 and perl.
#
{
  prev,
  gcc,
  binutils,
  glibc,
  m4,
  perl,
  texinfo,
  help2man,
  buildPlatform,
  hostPlatform,
}: let
  src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/autoconf/autoconf-2.72.tar.xz";
    sha256 = "1r3922ja9g5ziinpqxgfcc51jhrxvjqnrmc5054jgskylflxc1fp";
  };
in
  builtins.derivation {
    name = "autoconf-2.72";
    system = buildPlatform.system;
    builder = "${prev.bash}/bin/bash";
    args = [
      "-c"
      ''
        set -eu
        export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO="${texinfo}/bin/makeinfo"
        export PATH="${texinfo}/bin:${help2man}/bin:${m4}/bin:${perl}/bin:${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin"
        export CONFIG_SHELL="${prev.bash}/bin/bash"

        export M4="${m4}/bin/m4"
        export PERL="${perl}/bin/perl"

        cd "$TMPDIR"
        mkdir autoconf-2.72 && (cd ${src} && ${prev.tar}/bin/tar cf - .) | (cd autoconf-2.72 && ${prev.tar}/bin/tar xf -)
        cd autoconf-2.72
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

        mkdir -p "$TMPDIR/build"
        cd "$TMPDIR/build"

        export LIBRARY_PATH="${glibc}/lib"
        CC="${gcc}/bin/gcc" \
        CFLAGS="-O2 -isystem ${glibc.dev}/include" \
        CPPFLAGS="-isystem ${glibc.dev}/include" \
        LDFLAGS="-L${glibc.static}/lib -L${glibc}/lib -static -no-pie" \
        M4="${m4}/bin/m4" \
        PERL="${perl}/bin/perl" \
        "$TMPDIR/autoconf-2.72/configure" \
          --prefix="$out" \
          --build=${buildPlatform.config} --host=${hostPlatform.config} --target=${hostPlatform.config}

        make -j"$NIX_BUILD_CORES" AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true
        make install AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true

        echo "GNU Autoconf 2.72 installed to $out"
      ''
    ];
  }
  // {
    meta = {
      description = "GNU Autoconf 2.72";
      homepage = "https://www.gnu.org/software/autoconf/";
      license = "GPL-3.0-or-later";
      build = {
        os = "linux";
      };
      execute = {
        os = "linux";
      };
    };
  }
