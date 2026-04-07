# stdenv/toolchains/gcc3_4_cross/binutils.nix — Phase 6a
#
# Native x86_64 binutils 2.15, cross-compiled from i686.
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
    url = "https://mirrors.kernel.org/gnu/binutils/binutils-2.15.tar.bz2";
    hash = "1igaw1vps1j0l8zmm4npazjwj287kwxd1rqbbgy39nsrxg9njp5d";
  };
in
builtins.derivation {
  name = "binutils-2.15";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export PATH="${prev.coreutils}/bin:${crossGccStage2}/bin:${crossBinutils}/bin:${prev.gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.patch}/bin:${prev.bash}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      # Dummy lex/flex/makeinfo for configure and install
      mkdir -p "$TMPDIR/fakebin"
      printf '#!/bin/sh\nprintf "int main(){return 0;}\nint yywrap(){return 1;}\n" > lex.yy.c\n' > "$TMPDIR/fakebin/lex"
      printf '#!/bin/sh\nprintf "int main(){return 0;}\nint yywrap(){return 1;}\n" > lex.yy.c\n' > "$TMPDIR/fakebin/flex"
      printf '#!/bin/sh\nexit 0\n' > "$TMPDIR/fakebin/makeinfo"
      chmod +x "$TMPDIR/fakebin/lex" "$TMPDIR/fakebin/flex" "$TMPDIR/fakebin/makeinfo"
      export PATH="$TMPDIR/fakebin:$PATH"

      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      CC="${crossGccStage2}/bin/${hostPlatform.config}-gcc" \
      AR="${crossBinutils}/bin/${hostPlatform.config}-ar" \
      RANLIB="${crossBinutils}/bin/${hostPlatform.config}-ranlib" \
      CFLAGS="-O2 -isystem ${crossGlibc}/include" \
      LDFLAGS="-L${crossGlibc}/lib -static" \
      ${src}/configure \
        --prefix="$out" \
        --build=${buildPlatform.config} \
        --host=${hostPlatform.config} \
        --target=${hostPlatform.config} \
        --disable-shared --disable-nls \
        --disable-gdb --disable-gdbserver --disable-libdecnumber --disable-readline --disable-sim \
        --with-sysroot=/ \
        --program-transform-name=

      make -j"$NIX_BUILD_CORES"
      make install

      echo "Native binutils 2.15 (${hostPlatform.config}) installed to $out"
    ''
  ];
}
