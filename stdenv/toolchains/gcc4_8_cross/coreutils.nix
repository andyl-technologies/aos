# stdenv/toolchains/gcc4_8_cross/coreutils.nix — Phase 7
#
# Native target-arch Coreutils 8.22, cross-compiled from x86_64.
#
{
  prev,
  crossGccStage2,
  crossBinutils,
  crossGlibc,
  buildPlatform,
  hostPlatform,
  ...
}:
let
  src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/coreutils/coreutils-8.22.tar.xz";
    sha256 = "0000000000000000000000000000000000000000000000000000"; # TODO: fix hash
  };
in
builtins.derivation {
  name = "coreutils-8.22";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
      export PATH="${prev.coreutils}/bin:${crossGccStage2}/bin:${crossBinutils}/bin:${prev.gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.bzip2}/bin:${prev.xz}/bin:${prev.diffutils}/bin:${prev.patch}/bin:${prev.bash}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      cp -r ${src} "$TMPDIR/src"
      chmod -R u+w "$TMPDIR/src"
      cd "$TMPDIR/src"
      find . -name configure -exec chmod +x {} + 2>/dev/null || true
      find . -name '*.sh' -exec chmod +x {} + 2>/dev/null || true
      chmod +x install-sh missing mkinstalldirs 2>/dev/null || true
      find . -type f \( -name '*.c' -o -name '*.h' \) -exec touch {} + 2>/dev/null || true
      # Touch generated/autotools files AFTER so they appear newer than their sources
      sleep 1
      find . \( -name 'configure' -o -name 'Makefile.in' -o -name 'aclocal.m4' -o -name 'config.h.in' \) -exec touch {} + 2>/dev/null || true
      touch .version .tarball-version src/fs.h src/version.c src/version.h lib/config.hin man/*.1 2>/dev/null || true

      # Fix gnulib gets() warning — glibc 2.17 removed gets() declaration
      ${prev.sed}/bin/sed -i '/_GL_WARN_ON_USE (gets,/d' lib/stdio.in.h 2>/dev/null || true

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

      # Replace dummy-man with a working stub
      printf '#!/bin/sh\necho ".TH dummy 1"\n' > man/dummy-man 2>/dev/null || true
      chmod +x man/dummy-man 2>/dev/null || true
      touch man/*.1 man/*.x 2>/dev/null || true

      # Man pages need help2man/perl; tolerate their failure
      make -j"$NIX_BUILD_CORES" -k || true
      test -f src/ls || { echo "FATAL: coreutils binaries not built"; exit 1; }
      make install-exec
      test -f "$out/bin/ls" || { echo "FATAL: coreutils not installed"; exit 1; }

      echo "Coreutils 8.22 (${hostPlatform.config}) installed to $out"
    ''
  ];
}
