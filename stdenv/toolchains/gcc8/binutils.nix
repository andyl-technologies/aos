# stdenv/toolchains/gcc8/binutils.nix — binutils 2.30 (RHEL 8)
#
# Built with THIS tier's GCC 8.5.0 and the previous tier's glibc.
#
{
  prev,
  gcc,
  buildPlatform,
  hostPlatform,
}: let
  src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/binutils/binutils-2.30.tar.xz";
    sha256 = "11x6da64y0i165nxhyyb6m89ig5n00hnvj6k6pf8wbz5xicrmiig";
  };

in
  builtins.derivation {
    name = "binutils-2.30";
    system = buildPlatform.system;
    builder = "${prev.bash}/bin/bash";
    args = [
      "-c"
      ''
        set -eu
        export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
        export PATH="${prev.coreutils}/bin:${gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin:${prev.m4}/bin:${prev.flex}/bin:${prev.bison}/bin:${prev.autoconf}/bin:${prev.automake}/bin:${prev.texinfo}/bin:${prev.help2man}/bin"
        export CONFIG_SHELL="${prev.bash}/bin/bash"

        cd "$TMPDIR"
        mkdir binutils-2.30 && (cd ${src} && ${prev.tar}/bin/tar cf - .) | (cd binutils-2.30 && ${prev.tar}/bin/tar xf -)
        cd binutils-2.30
        chmod -R u+w .

        # Touch pre-generated flex/bison/yacc files so they appear newer than sources
        find . -type f \( -name '*.l' -o -name '*.y' \) -exec touch {} + 2>/dev/null || true
        sleep 1
        find . -type f \( -name '*.c' -o -name '*.h' \) -exec touch {} + 2>/dev/null || true
        sleep 1
        find . \( -name 'configure' -o -name 'Makefile.in' -o -name 'aclocal.m4' -o -name 'config.h.in' \) -exec touch {} + 2>/dev/null || true

        # CC wrapper: pass glibc lib path + -static (libtool strips -static from LDFLAGS)
        mkdir -p "$TMPDIR/ccwrap"
        printf '#!/bin/sh\nexec ${gcc}/bin/gcc -L${prev.glibc}/lib -static "$@"\n' > "$TMPDIR/ccwrap/gcc"
        printf '#!/bin/sh\nexec ${gcc}/bin/g++ -L${prev.glibc}/lib -static "$@"\n' > "$TMPDIR/ccwrap/g++"
        chmod +x "$TMPDIR/ccwrap/gcc" "$TMPDIR/ccwrap/g++"
        ln -sf gcc "$TMPDIR/ccwrap/cc"
        ln -sf g++ "$TMPDIR/ccwrap/c++"

        mkdir -p "$TMPDIR/build"
        cd "$TMPDIR/build"

        CC="$TMPDIR/ccwrap/gcc" CXX="$TMPDIR/ccwrap/g++" \
        CFLAGS="-O2" \
        CXXFLAGS="-O2" \
        "$TMPDIR/binutils-2.30/configure" \
          --prefix="$out" \
          --build=${hostPlatform.config} --host=${hostPlatform.config} --target=${hostPlatform.config} \
          --disable-shared --disable-nls \
          --disable-werror \
          --disable-plugins \
          --disable-gdb --disable-gdbserver --disable-libdecnumber \
          --disable-readline --disable-sim \
          --with-sysroot=/ \
          --program-transform-name=

        make -j"$NIX_BUILD_CORES" AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO="${prev.texinfo}/bin/makeinfo"
        make install AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO="${prev.texinfo}/bin/makeinfo"

        echo "binutils 2.30 installed to $out"
      ''
    ];
  }
  // {
    meta = {
      description = "GNU tools for manipulating binaries, version 2.30";
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
