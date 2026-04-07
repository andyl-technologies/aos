# stdenv/toolchains/gcc8_cross/coreutils.nix — Phase 7
#
# Native target-arch Coreutils 8.30, cross-compiled from x86_64.
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
  inherit (import ../../../lib/derivations.nix { system = builtins.currentSystem; }) fetchTarball;

  src = fetchTarball {
    url = "https://mirrors.kernel.org/gnu/coreutils/coreutils-8.30.tar.xz";
    hash = "0pp6vvpzw0v6s45yq58cszrh514a5v8jq32321apszw7rbffkslb";
  };
in
builtins.derivation {
  name = "coreutils-8.30";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
      export PATH="${prev.coreutils}/bin:${crossGccStage2}/bin:${crossBinutils}/bin:${prev.gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.patch}/bin:${prev.bash}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      cp -r ${src} "$TMPDIR/src"
      chmod -R u+w "$TMPDIR/src"
      cd "$TMPDIR/src"
      find . -name configure -exec chmod +x {} + 2>/dev/null || true
      find . -name '*.sh' -exec chmod +x {} + 2>/dev/null || true
      chmod +x install-sh missing mkinstalldirs build-aux/install-sh 2>/dev/null || true
      find . -type f \( -name '*.y' -o -name '*.l' \) -exec touch {} + 2>/dev/null || true
      sleep 1
      find . -type f \( -name '*.c' -o -name '*.h' \) -exec touch {} + 2>/dev/null || true
      sleep 1
      find . \( -name 'configure' -o -name 'Makefile.in' -o -name 'aclocal.m4' -o -name 'config.h.in' \) -exec touch {} + 2>/dev/null || true
      touch .version .tarball-version man/*.1 2>/dev/null || true

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

      echo "Coreutils 8.30 (${hostPlatform.config}) installed to $out"
    ''
  ];
}
