# stdenv/toolchains/gcc14/m4.nix — GNU m4 1.4.19 (RHEL 10)
#
# GNU m4 macro processor built with THIS tier's GCC 14.3.0 + binutils 2.41 + glibc 2.39.
#
{
  prev,
  gcc,
  binutils,
  glibc,
  texinfo,
  help2man,
  buildPlatform,
  hostPlatform,
}:
let
  src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/m4/m4-1.4.19.tar.xz";
    sha256 = "02xz8gal0fdc4gzjwyiy1557q31xcpg896yc0y6kd8s5jbynvdmf";
  };
in
builtins.derivation {
  name = "m4-1.4.19";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO="${texinfo}/bin/makeinfo"
      export PATH="${texinfo}/bin:${help2man}/bin:${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      cd "$TMPDIR"
      mkdir m4-1.4.19 && (cd ${src} && ${prev.tar}/bin/tar cf - .) | (cd m4-1.4.19 && ${prev.tar}/bin/tar xf -)
      cd m4-1.4.19
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
      CFLAGS="-O2 -isystem ${glibc}/include" \
      CPPFLAGS="-isystem ${glibc}/include" \
      LDFLAGS="-L${glibc}/lib -static" \
      "$TMPDIR/m4-1.4.19/configure" \
        --prefix="$out" \
        --build=${buildPlatform.config} --host=${hostPlatform.config} --target=${hostPlatform.config} \
        --disable-nls

      make -j"$NIX_BUILD_CORES" AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true
      make install AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true

      echo "GNU m4 1.4.19 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU m4 macro processor 1.4.19";
    homepage = "https://www.gnu.org/software/m4/";
    license = "GPL-3.0-or-later";
    build = {
      os = "linux";
    };
    execute = {
      os = "linux";
    };
  };
}
