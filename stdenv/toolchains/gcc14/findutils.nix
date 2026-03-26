# stdenv/toolchains/gcc14/findutils.nix — GNU findutils 4.10.0 (RHEL 10)
#
# Production GNU findutils built with THIS tier's GCC 14.3.0 + binutils 2.41 + glibc 2.39.
#
{
  prev,
  gcc,
  binutils,
  glibc,
  m4,
  flex,
  bison,
  autoconf,
  automake,
  texinfo,
  help2man,
  buildPlatform,
  hostPlatform,
}:
let
  src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/findutils/findutils-4.10.0.tar.xz";
    sha256 = "17psmb481vpq03lmi8l4r4nm99v4yg3ri5bn4gyy0z1zzi63ywan";
  };
in
builtins.derivation {
  name = "findutils-4.10.0";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO="${texinfo}/bin/makeinfo"
      export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin:${m4}/bin:${flex}/bin:${bison}/bin:${autoconf}/bin:${automake}/bin:${texinfo}/bin:${help2man}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      # CC wrapper: always pass -static (libtool strips -static from LDFLAGS)
      mkdir -p "$TMPDIR/ccwrap"
      printf '#!/bin/sh\nexec ${gcc}/bin/gcc -L${glibc}/lib -static -no-pie "$@"\n' > "$TMPDIR/ccwrap/gcc"
      chmod +x "$TMPDIR/ccwrap/gcc"
      export PATH="$TMPDIR/ccwrap:$PATH"

      cd "$TMPDIR"
      mkdir findutils-4.10.0 && (cd ${src} && ${prev.tar}/bin/tar cf - .) | (cd findutils-4.10.0 && ${prev.tar}/bin/tar xf -)
      cd findutils-4.10.0
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
      CC="$TMPDIR/ccwrap/gcc" \
      CFLAGS="-O2 -isystem ${glibc}/include" \
      CPPFLAGS="-isystem ${glibc}/include" \
      LDFLAGS="-L${glibc}/lib -static -no-pie" \
      "$TMPDIR/findutils-4.10.0/configure" \
        --prefix="$out" \
        --build=${buildPlatform.config} --host=${hostPlatform.config} --target=${hostPlatform.config} \
        --disable-nls

      make -j"$NIX_BUILD_CORES" AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true
      make install AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true

      echo "GNU findutils 4.10.0 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU findutils 4.10.0 (find, xargs, locate)";
    homepage = "https://www.gnu.org/software/findutils/";
    license = "GPL-3.0-or-later";
    build = {
      os = "linux";
    };
    execute = {
      os = "linux";
    };
  };
}
