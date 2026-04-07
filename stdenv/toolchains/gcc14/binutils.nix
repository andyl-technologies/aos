# stdenv/toolchains/gcc14/binutils.nix — binutils 2.41 (RHEL 10)
#
# Modern binutils built with THIS tier's GCC 14.3.0 and the previous
# tier's glibc. Provides the production linker and assembler.
#
{
  prev,
  gcc,
  buildPlatform,
  hostPlatform,
}:
let
  inherit (import ../../../lib/derivations.nix { system = builtins.currentSystem; }) fetchTarball;

  src = fetchTarball {
    url = "https://mirrors.kernel.org/gnu/binutils/binutils-2.41.tar.xz";
    hash = "0shr30dgkifjzlgqgsf0f0nmb8ffbqrkh93w54bnz4sk4v0s7lgi";
  };
in
builtins.derivation {
  name = "binutils-2.41";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
      export PATH="${prev.coreutils}/bin:${gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      cd "$TMPDIR"
      mkdir binutils-2.41 && (cd ${src} && ${prev.tar}/bin/tar cf - .) | (cd binutils-2.41 && ${prev.tar}/bin/tar xf -)
      cd binutils-2.41
      chmod -R u+w .

      # Touch pre-generated flex/bison/yacc files so they appear newer than sources
      find . -type f \( -name '*.l' -o -name '*.y' \) -exec touch {} + 2>/dev/null || true
      sleep 1
      find . -type f \( -name '*.c' -o -name '*.h' \) -exec touch {} + 2>/dev/null || true
      sleep 1
      find . \( -name 'configure' -o -name 'Makefile.in' -o -name 'aclocal.m4' -o -name 'config.h.in' \) -exec touch {} + 2>/dev/null || true
      find . -name '*.info' -exec touch -t 200001010200.00 {} + 2>/dev/null || true
      find . -name '*.1' -exec touch {} + 2>/dev/null || true

      # CC wrapper: always pass -static (libtool strips -static from LDFLAGS)
      mkdir -p "$TMPDIR/ccwrap"
      printf '#!/bin/sh\nexec ${gcc}/bin/gcc -L${prev.glibc}/lib -static -no-pie "$@"\n' > "$TMPDIR/ccwrap/gcc"
      printf '#!/bin/sh\nexec ${gcc}/bin/g++ -L${prev.glibc}/lib -static -no-pie "$@"\n' > "$TMPDIR/ccwrap/g++"
      chmod +x "$TMPDIR/ccwrap/gcc" "$TMPDIR/ccwrap/g++"
      ln -sf gcc "$TMPDIR/ccwrap/cc"
      ln -sf g++ "$TMPDIR/ccwrap/c++"

      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      CC="$TMPDIR/ccwrap/gcc" CXX="$TMPDIR/ccwrap/g++" \
      CFLAGS="-O2" \
      CXXFLAGS="-O2" \
      "$TMPDIR/binutils-2.41/configure" \
        --prefix="$out" \
        --build=${buildPlatform.config} --host=${hostPlatform.config} --target=${hostPlatform.config} \
        --disable-shared --disable-nls \
        --disable-gdb --disable-gdbserver --disable-libdecnumber \
        --disable-readline --disable-sim --disable-gprofng \
        --disable-werror \
        --with-sysroot=/ \
        --program-transform-name=

      make -j"$NIX_BUILD_CORES" AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
      make install AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true

      echo "binutils 2.41 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU binutils 2.41 — linker, assembler, and binary utilities";
    homepage = "https://www.gnu.org/software/binutils/";
    license = "GPL-3.0-or-later";
    build = {
      os = "linux";
    };
    execute = {
      os = "linux";
    };
  };
}
