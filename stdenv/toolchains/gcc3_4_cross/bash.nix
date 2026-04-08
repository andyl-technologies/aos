# stdenv/toolchains/gcc3_4_cross/bash.nix — Phase 7
#
# Native x86_64 Bash 3.0, cross-compiled from i686.
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
    url = "https://mirrors.kernel.org/gnu/bash/bash-3.0.tar.gz";
    hash = "1i4brapyyivim7mrrrd9iii4a5yilb2wzh9k6zgcwxh0ycpxrbw7";
  };
in
builtins.derivation {
  name = "bash-3.0";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export PATH="${prev.coreutils}/bin:${crossGccStage2}/bin:${crossBinutils}/bin:${prev.gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.patch}/bin:${prev.bash}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      # Dummy size/makeinfo — i686 `size` can't read x86_64 ELF binaries
      mkdir -p "$TMPDIR/fakebin"
      printf '#!${prev.bash}/bin/bash\nexit 0\n' > "$TMPDIR/fakebin/size"
      printf '#!${prev.bash}/bin/bash\nexit 0\n' > "$TMPDIR/fakebin/makeinfo"
      chmod +x "$TMPDIR/fakebin/size" "$TMPDIR/fakebin/makeinfo"
      export PATH="$TMPDIR/fakebin:$PATH"

      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      CC="${crossGccStage2}/bin/${hostPlatform.config}-gcc" \
      AR="${crossBinutils}/bin/${hostPlatform.config}-ar" \
      RANLIB="${crossBinutils}/bin/${hostPlatform.config}-ranlib" \
      CFLAGS="-O2 -isystem ${crossGlibc}/include" \
      LDFLAGS="-L${crossGlibc}/lib -static -Wl,--whole-archive -lnss_files -lnss_dns -lresolv -Wl,--no-whole-archive" \
      ${src}/configure \
        --prefix="$out" \
        --build=${buildPlatform.config} --host=${hostPlatform.config} \
        --without-bash-malloc \
        --disable-nls \
        bash_cv_func_sigsetjmp=present

      # -j1: builtext.h generation races with nojobs.c compilation in cross builds
      make -j1
      make install

      test -f "$out/bin/bash" && test ! -f "$out/bin/sh" && ln -sf bash "$out/bin/sh"

      echo "Bash 3.0 (${hostPlatform.config}) installed to $out"
    ''
  ];
}
