# stdenv/toolchains/gcc4_8/binutils.nix — GNU binutils 2.25 (RHEL 7)
#
# Built with GCC 4.8.5 from this tier.
#
{
  prev,
  gcc,
  buildPlatform,
  hostPlatform,
}: let
  fetchSrc = {
    name,
    url,
    hash,
  }:
    builtins.derivation {
      inherit name;
      system = buildPlatform.system;
      builder = "builtin:fetchurl";
      inherit url;
      outputHash = hash;
      outputHashMode = "flat";
      outputHashAlgo = "sha256";
      preferLocalBuild = true;
    };

  binutils-src = fetchSrc {
    name = "binutils-2.25.tar.bz2";
    url = "https://mirrors.kernel.org/gnu/binutils/binutils-2.25.tar.bz2";
    hash = "sha256-It78Zc+j7yozlfqup11jMcbmLqXfrP7T4uwXsIyIKSM=";
  };
in
  builtins.derivation {
    name = "binutils-2.25";
    system = buildPlatform.system;
    builder = "${prev.bash}/bin/bash";
    args = [
      "-c"
      ''
        set -eu
        export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO="${prev.texinfo}/bin/makeinfo"
        export PATH="${prev.coreutils}/bin:${gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.bash}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.diffutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.bzip2}/bin:${prev.patch}/bin:${prev.m4}/bin:${prev.flex}/bin:${prev.bison}/bin:${prev.autoconf}/bin:${prev.automake}/bin:${prev.texinfo}/bin:${prev.help2man}/bin"

        cd "$TMPDIR"
        tar xjf ${binutils-src}

        SRC="$TMPDIR/binutils-2.25"
        cd "$SRC"
        chmod -R u+w .
        find . -name configure -exec chmod +x {} + 2>/dev/null || true
        find . -name '*.sh' -exec chmod +x {} + 2>/dev/null || true
        chmod +x move-if-change mkinstalldirs install-sh missing depcomp ylwrap 2>/dev/null || true
        # Touch all files first, then touch generated .c/.h files to make them
        # appear newer than their sources (prevents lex/yacc/gperf regeneration)
        find . -type f -exec touch {} + 2>/dev/null || true
        sleep 1
        find . -type f \( -name '*.c' -o -name '*.h' \) -exec touch {} + 2>/dev/null || true
        sleep 1
        find . \( -name 'configure' -o -name 'Makefile.in' -o -name 'aclocal.m4' -o -name 'config.h.in' \) -exec touch {} + 2>/dev/null || true

        # CC/CXX wrappers: at link time, append glibc paths
        mkdir -p "$TMPDIR/ccwrap"
        cp ${builtins.toFile "cc-wrapper" ''
          #!/bin/sh
          compile=
          for arg; do case "$arg" in -c|-E|-S) compile=1 ;; esac; done
          if [ -z "$compile" ]; then
            exec REAL_GCC -isystem GLIBC_INCLUDE "$@" -L GLIBC_LIB -B GLIBC_LIB -static
          fi
          exec REAL_GCC -isystem GLIBC_INCLUDE "$@"
        ''} "$TMPDIR/ccwrap/gcc"
        ${prev.sed}/bin/sed -i \
          -e "s|REAL_GCC|${gcc}/bin/gcc|g" \
          -e "s|GLIBC_INCLUDE|${prev.glibc}/include|g" \
          -e "s|GLIBC_LIB|${prev.glibc}/lib|g" \
          "$TMPDIR/ccwrap/gcc"
        chmod +x "$TMPDIR/ccwrap/gcc"
        cp "$TMPDIR/ccwrap/gcc" "$TMPDIR/ccwrap/g++"
        ${prev.sed}/bin/sed -i "s|${gcc}/bin/gcc|${gcc}/bin/g++|g" "$TMPDIR/ccwrap/g++"
        ln -sf gcc "$TMPDIR/ccwrap/cc"
        ln -sf g++ "$TMPDIR/ccwrap/c++"

        mkdir -p "$TMPDIR/build"
        cd "$TMPDIR/build"

        set +e
        CC="$TMPDIR/ccwrap/gcc" CXX="$TMPDIR/ccwrap/g++" \
        CFLAGS="-O2" \
        CXXFLAGS="-O2" \
        LDFLAGS="-static" \
        "$SRC/configure" \
          --prefix="$out" \
          --build=${hostPlatform.config} --host=${hostPlatform.config} --target=${hostPlatform.config} \
          --disable-shared --disable-nls \
          --disable-gdb --disable-gdbserver --disable-libdecnumber --disable-readline --disable-sim \
          --with-sysroot=/ \
          --program-transform-name=
        configure_status=$?
        set -e
        if [ "$configure_status" -ne 0 ]; then
          echo "binutils 2.25 configure failed; full config.log follows" >&2
          cat config.log >&2
          exit "$configure_status"
        fi

        make -j"$NIX_BUILD_CORES" AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO="${prev.texinfo}/bin/makeinfo"
        make install AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO="${prev.texinfo}/bin/makeinfo"

        echo "binutils 2.25 installed to $out"
      ''
    ];
  }
  // {
    meta = {
      description = "GNU tools for manipulating binaries, version 2.25";
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
