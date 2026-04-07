# stdenv/toolchains/gcc11/diffutils.nix — GNU diffutils 3.7 (RHEL 9)
#
# Built with THIS tier's GCC 11.5.0 + binutils 2.35 + glibc 2.34.
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
    url = "https://mirrors.kernel.org/gnu/diffutils/diffutils-3.7.tar.xz";
    hash = "02zg4lj3r8rp13qvvpa28s3ljqlbvvgpnd1mp6q756xs44hckxw1";
  };
in
builtins.derivation {
  name = "diffutils-3.7";
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
      mkdir diffutils-3.7 && (cd ${src} && ${prev.tar}/bin/tar cf - .) | (cd diffutils-3.7 && ${prev.tar}/bin/tar xf -)
      cd diffutils-3.7
      chmod -R u+w .

      # Fix SIGSTKSZ: glibc 2.34+ makes SIGSTKSZ a runtime sysconf() call,
      # breaking #if preprocessor checks in gnulib's c-stack.c
      ${prev.sed}/bin/sed -i 's/SIGSTKSZ < 16384/8192 < 16384/' lib/c-stack.c 2>/dev/null || true

      # Replace source help2man (Perl script with #!/usr/bin/perl) with dummy
      if [ -f man/help2man ]; then
        printf '#!/bin/sh\nexit 0\n' > man/help2man
        chmod +x man/help2man
        find . -name '*.1' -exec touch {} + 2>/dev/null || true
      fi

      # Break all hardlinks in doc/ (version.texi/stamp-vti, versionmaint.texi/stamp-1, etc.)
      find doc -type f -links +1 -exec sh -c 'cp "$1" "$1.tmp" && mv "$1.tmp" "$1"' _ {} \; 2>/dev/null || true

      # Touch autotools inputs first, then generated .c/.h, then autotools outputs
      find . -type f \( -name '*.y' -o -name '*.l' -o -name 'Makefile.am' -o -name 'configure.ac' -o -name 'configure.in' -o -name 'acinclude.m4' \) -exec touch {} + 2>/dev/null || true
      sleep 1
      find . -type f \( -name '*.c' -o -name '*.h' \) -exec touch {} + 2>/dev/null || true
      sleep 1
      find . \( -name 'configure' -o -name 'Makefile.in' -o -name 'aclocal.m4' -o -name 'config.h.in' \) -exec touch {} + 2>/dev/null || true
      find . \( -name '*.1' -o -name '*.info' \) -exec touch -t 200001010200.00 {} + 2>/dev/null || true

      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      export LIBRARY_PATH="${glibc}/lib"
      GCC_INCDIR="${gcc}/lib/gcc/${hostPlatform.config}/11.5.0/include"
      CC="${gcc}/bin/gcc" \
      CFLAGS="-O2 -nostdinc -isystem $GCC_INCDIR -isystem $GCC_INCDIR-fixed -isystem ${glibc}/include" \
      CPPFLAGS="-nostdinc -isystem $GCC_INCDIR -isystem $GCC_INCDIR-fixed -isystem ${glibc}/include" \
      LDFLAGS="-L${glibc}/lib -static" \
      "$TMPDIR/diffutils-3.7/configure" \
        --prefix="$out" \
        --build=${hostPlatform.config} --host=${hostPlatform.config} --target=${hostPlatform.config} \
        --disable-nls

      make -j"$NIX_BUILD_CORES" AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true
      make install AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true

      echo "GNU diffutils 3.7 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU file comparison utilities (diff, cmp, sdiff, diff3), version 3.7";
    homepage = "https://www.gnu.org/software/diffutils/";
    license = "GPL-3.0-or-later";
    build = {
      os = "linux";
    };
    execute = {
      os = "linux";
    };
  };
}
