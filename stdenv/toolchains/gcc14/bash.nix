# stdenv/toolchains/gcc14/bash.nix — Bash 5.2.37 (RHEL 10)
#
# Production Bash built with THIS tier's GCC 14.3.0 + binutils 2.41 + glibc 2.39.
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
  inherit (import ../../../lib/derivations.nix { system = builtins.currentSystem; }) fetchTarball;

  src = fetchTarball {
    url = "https://mirrors.kernel.org/gnu/bash/bash-5.2.37.tar.gz";
    hash = "012fmryg39p4ynmbg3abp6h1mr2ghbvsjfri66gk1ji3ikbcg01c";
  };
in
builtins.derivation {
  name = "bash-5.2.37";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO="${texinfo}/bin/makeinfo"
      export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin:${m4}/bin:${flex}/bin:${bison}/bin:${autoconf}/bin:${automake}/bin:${texinfo}/bin:${help2man}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      cd "$TMPDIR"
      mkdir bash-5.2.37 && (cd ${src} && ${prev.tar}/bin/tar cf - .) | (cd bash-5.2.37 && ${prev.tar}/bin/tar xf -)
      cd bash-5.2.37
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
      CFLAGS="-O2 -isystem ${glibc}/include -Wno-error=implicit-function-declaration" \
      CPPFLAGS="-isystem ${glibc}/include" \
      LDFLAGS="-L${glibc}/lib -static -no-pie" \
      "$TMPDIR/bash-5.2.37/configure" \
        --prefix="$out" \
        --build=${buildPlatform.config} --host=${hostPlatform.config} --target=${hostPlatform.config} \
        --without-bash-malloc \
        --disable-nls

      # Use -j1: bash has parallel build race conditions (builtext.h vs bashline.c)
      make -j1 AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true
      make install AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true

      [ -f "$out/bin/bash" ] && [ ! -f "$out/bin/sh" ] && ln -sf bash "$out/bin/sh"

      echo "Bash 5.2.37 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU Bourne-Again SHell 5.2.37";
    homepage = "https://www.gnu.org/software/bash/";
    license = "GPL-3.0-or-later";
    build = {
      os = "linux";
    };
    execute = {
      os = "linux";
    };
  };
}
