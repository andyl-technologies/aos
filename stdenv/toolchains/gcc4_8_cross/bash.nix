# stdenv/toolchains/gcc4_8_cross/bash.nix — Phase 7
#
# Native target-arch Bash 4.2, cross-compiled from x86_64.
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
    url = "https://mirrors.kernel.org/gnu/bash/bash-4.2.tar.gz";
    sha256 = "1w96885ks8ya3vxv3cmvhhyp7grhsf5hk0vrw6pz9cn88k18sbcz";
  };
in
builtins.derivation {
  name = "bash-4.2";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
      export PATH="${prev.coreutils}/bin:${crossGccStage2}/bin:${crossBinutils}/bin:${prev.gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.bzip2}/bin:${prev.diffutils}/bin:${prev.patch}/bin:${prev.bash}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      # Dummy size/makeinfo — build-arch `size` can't read target ELF binaries
      mkdir -p "$TMPDIR/fakebin"
      printf '#!/bin/sh\nexit 0\n' > "$TMPDIR/fakebin/size"
      printf '#!/bin/sh\nexit 0\n' > "$TMPDIR/fakebin/makeinfo"
      chmod +x "$TMPDIR/fakebin/size" "$TMPDIR/fakebin/makeinfo"
      export PATH="$TMPDIR/fakebin:$PATH"

      cp -r ${src} "$TMPDIR/src"
      chmod -R u+w "$TMPDIR/src"
      find "$TMPDIR/src" -name configure -exec chmod +x {} + 2>/dev/null || true
      find "$TMPDIR/src" -name '*.sh' -exec chmod +x {} + 2>/dev/null || true
      chmod +x "$TMPDIR/src/support/mkinstalldirs" "$TMPDIR/src/install-sh" "$TMPDIR/src/missing" 2>/dev/null || true
      find "$TMPDIR/src" -type f \( -name '*.c' -o -name '*.h' \) -exec touch {} + 2>/dev/null || true
      sleep 1
      find "$TMPDIR/src" \( -name 'configure' -o -name 'Makefile.in' -o -name 'aclocal.m4' -o -name 'config.h.in' \) -exec touch {} + 2>/dev/null || true

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
        --without-bash-malloc \
        --disable-nls \
        bash_cv_func_sigsetjmp=present

      # -j1: builtext.h generation races with nojobs.c compilation in cross builds
      make -j1
      make install

      test -f "$out/bin/bash" && test ! -f "$out/bin/sh" && ln -sf bash "$out/bin/sh"

      echo "Bash 4.2 (${hostPlatform.config}) installed to $out"
    ''
  ];
}
