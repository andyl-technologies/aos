# stdenv/toolchains/gcc3_4_cross/findutils.nix — Phase 7
#
# Native x86_64 GNU findutils 4.1.20, cross-compiled from i686.
#
{
  prev,
  crossGccStage2,
  crossBinutils,
  crossGlibc,
  buildPlatform,
  hostPlatform,
  ...
}: let
  src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/findutils/findutils-4.1.20.tar.gz";
    sha256 = "1msh5bxc96jmry8gn1zm36ic87fjn8r7ffagzaq70vxavr00l5w8";
  };
in
  builtins.derivation {
    name = "findutils-4.1.20";
    system = buildPlatform.system;
    builder = "${prev.bash}/bin/bash";
    args = [
      "-c"
      ''
        set -eu
        export PATH="${prev.coreutils}/bin:${crossGccStage2}/bin:${crossBinutils}/bin:${prev.gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.patch}/bin:${prev.bash}/bin"
        export CONFIG_SHELL="${prev.bash}/bin/bash"

        # Stub autotools — prevents Makefiles from re-running automake/autoconf
        mkdir -p "$TMPDIR/fakebin"
        for tool in autoconf autoheader aclocal automake autoreconf autom4te; do
          printf '#!/bin/sh\nexit 0\n' > "$TMPDIR/fakebin/$tool"
          chmod +x "$TMPDIR/fakebin/$tool"
        done
        export PATH="$TMPDIR/fakebin:$PATH"

        # Copy source to patch gnulib getline conflict with glibc 2.3.4
        cp -r ${src} "$TMPDIR/src"
        chmod -R u+w "$TMPDIR/src"
        # glibc 2.3.4 already provides gnu_getline as inline in bits/stdio.h
        : > "$TMPDIR/src/gnulib/lib/getline.c"
        : > "$TMPDIR/src/gnulib/lib/getline.h"
        # Touch ALL files to prevent autotools regeneration after cp -r
        find "$TMPDIR/src" -type f -exec touch {} + 2>/dev/null || true

        mkdir -p "$TMPDIR/build"
        cd "$TMPDIR/build"

        CC="${crossGccStage2}/bin/${hostPlatform.config}-gcc" \
        AR="${crossBinutils}/bin/${hostPlatform.config}-ar" \
        RANLIB="${crossBinutils}/bin/${hostPlatform.config}-ranlib" \
        CFLAGS="-O2 -isystem ${crossGlibc}/include" \
        LDFLAGS="-L${crossGlibc}/lib -static -Wl,--whole-archive -lnss_files -lnss_dns -lresolv -Wl,--no-whole-archive" \
        "$TMPDIR/src/configure" \
          --prefix="$out" \
          --build=${buildPlatform.config} --host=${hostPlatform.config} \
          --disable-nls

        # Strip autotools regeneration prerequisites from generated Makefiles
        find . -name Makefile | while read f; do
          sed -i 's/^Makefile:.*/Makefile:/; s/^config\.status:.*/config.status:/; s/^configure:.*/configure:/' "$f"
        done

        make -j"$NIX_BUILD_CORES" \
          AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true
        make install \
          AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true

        echo "GNU findutils 4.1.20 (${hostPlatform.config}) installed to $out"
      ''
    ];
  }
