# stdenv/toolchains/gcc14/glibc.nix — glibc 2.39 (RHEL 10)
#
# Modern glibc built with THIS tier's GCC 14.3.0 + binutils 2.41 +
# linux-headers 6.12. Production C library for all downstream packages.
#
# NOTE: We build with shared libraries enabled (default) because glibc 2.34+
# unconditionally includes generated files (libc-modules.h, abi-versions.h,
# first-versions.h, etc.) that are only created during shared builds.
# The --disable-shared path is not viable for modern glibc.
#
{
  prev,
  gcc,
  binutils,
  linuxHeaders,
  buildPlatform,
  hostPlatform,
}: let
  src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/glibc/glibc-2.39.tar.xz";
    sha256 = "0zr0lk75rvkxp0xplfsggaj4fcv1xjpsvg5qrvp6yifim77q2mn0";
  };
in
  builtins.derivation {
    name = "glibc-2.39";
    system = buildPlatform.system;
    builder = "${prev.bash}/bin/bash";
    args = [
      "-c"
      ''
        set -eu
        export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
        export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin:${prev.bison}/bin:${prev.m4}/bin:${prev.python3}/bin"
        export CONFIG_SHELL="${prev.bash}/bin/bash"

        cd "$TMPDIR"
        mkdir glibc-2.39 && (cd ${src} && ${prev.tar}/bin/tar cf - .) | (cd glibc-2.39 && ${prev.tar}/bin/tar xf -)
        cd glibc-2.39
        chmod -R u+w .

        # CC wrapper: supplies the include paths that gccRaw's specs file
        # used to embed (scrubbed to keep gccRaw's $out off the pre-tier
        # chain). Glibc's configure compiles probe programs using stdio.h
        # etc. — needed at build time only; none of this lands in $out.
        mkdir -p "$TMPDIR/ccwrap"
        printf '#!/bin/sh\nexec ${gcc}/bin/gcc -idirafter ${prev.glibc}/include -idirafter ${prev.linuxHeaders} "$@"\n' > "$TMPDIR/ccwrap/gcc"
        printf '#!/bin/sh\nexec ${gcc}/bin/g++ -idirafter ${prev.glibc}/include -idirafter ${prev.linuxHeaders} "$@"\n' > "$TMPDIR/ccwrap/g++"
        chmod +x "$TMPDIR/ccwrap/gcc" "$TMPDIR/ccwrap/g++"

        # Out-of-tree build (required by glibc)
        mkdir -p "$TMPDIR/build"
        cd "$TMPDIR/build"

        CC="$TMPDIR/ccwrap/gcc" CXX="$TMPDIR/ccwrap/g++" \
        AR="${binutils}/bin/ar" \
        RANLIB="${binutils}/bin/ranlib" \
        CFLAGS="-O2" \
        "$TMPDIR/glibc-2.39/configure" \
          --prefix="$out" \
          --build=${buildPlatform.config} \
          --host=${hostPlatform.config} \
          --with-headers="${linuxHeaders}" \
          --disable-profile \
          --disable-nscd \
          --disable-timezone-tools \
          --disable-werror \
          --enable-static-nss \
          --without-gd \
          --without-selinux \
          libc_cv_forced_unwind=yes \
          libc_cv_c_cleanup=yes

        make -j"$NIX_BUILD_CORES" build-programs=no AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
        make install build-programs=no AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true

        # Copy linux headers into glibc output for downstream use
        cp -r "${linuxHeaders}/linux" "$out/include/" 2>/dev/null || true
        cp -r "${linuxHeaders}/asm" "$out/include/" 2>/dev/null || true
        cp -r "${linuxHeaders}/asm-generic" "$out/include/" 2>/dev/null || true

        echo "glibc 2.39 installed to $out"
      ''
    ];
  }
  // {
    meta = {
      description = "GNU C Library 2.39 — production C library";
      homepage = "https://www.gnu.org/software/libc/";
      license = "LGPL-2.1-or-later";
      build = {
        os = "linux";
      };
      execute = {
        os = "linux";
      };
    };
  }
