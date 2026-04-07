# stdenv/toolchains/gcc8/findutils.nix — GNU findutils 4.6.0 (RHEL 8)
#
# Built with THIS tier's GCC 8.5.0 + binutils 2.30 + glibc 2.28.
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
    url = "https://mirrors.kernel.org/gnu/findutils/findutils-4.6.0.tar.gz";
    hash = "0aq6sck5sqpbzia1322fk3zyirkwbn909r7mlb6c2yz49m1fcw9d";
  };
in
builtins.derivation {
  name = "findutils-4.6.0";
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
      mkdir findutils-4.6.0 && (cd ${src} && ${prev.tar}/bin/tar cf - .) | (cd findutils-4.6.0 && ${prev.tar}/bin/tar xf -)
      cd findutils-4.6.0
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
      CPPFLAGS="-nostdinc -isystem $GCC_INCDIR -isystem $GCC_INCDIR-fixed -isystem ${glibc}/include -D_IO_ftrylockfile -D_IO_IN_BACKUP=0x100 -include sys/sysmacros.h" \
      LDFLAGS="-L${glibc}/lib -static" \
      "$TMPDIR/findutils-4.6.0/configure" \
        --prefix="$out" \
        --build=${hostPlatform.config} --host=${hostPlatform.config} --target=${hostPlatform.config} \
        --disable-nls

      make -j"$NIX_BUILD_CORES" AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true
      make install AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true

      echo "GNU findutils 4.6.0 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU find, xargs, and locate utilities, version 4.6.0";
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
