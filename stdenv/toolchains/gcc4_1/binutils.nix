# stdenv/toolchains/gcc4_1/binutils.nix — binutils 2.17 (RHEL 5)
#
# Built with THIS tier's GCC 4.1.2 and the previous tier's glibc.
#
{
  prev,
  gcc,
  buildPlatform,
  hostPlatform,
}:
let
  src = builtins.fetchTarball {
    url = "https://ftp.gnu.org/gnu/binutils/binutils-2.17.tar.bz2";
    sha256 = "054ilydpm1i4clgm2f2ffddwl0047n0cnibyqm60rwa1vizgxw2i";
  };
in
builtins.derivation {
  name = "binutils-2.17";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export PATH="${prev.coreutils}/bin:${gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      cd "$TMPDIR"
      cp -r ${src} binutils-2.17
      cd binutils-2.17
      chmod -R u+w .

      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      CC="${gcc}/bin/gcc" \
      CFLAGS="-O2 -I${prev.glibc}/include" \
      LDFLAGS="-L${prev.glibc}/lib -static" \
      "$TMPDIR/binutils-2.17/configure" \
        --prefix="$out" \
        --build=${hostPlatform.config} --host=${hostPlatform.config} --target=${hostPlatform.config} \
        --disable-shared --disable-nls \
        --disable-werror \
        --with-sysroot=/ \
        --program-transform-name=

      make -j"$(nproc)"
      make install

      echo "binutils 2.17 installed to $out"
    ''
  ];
}
// {
  meta = {
    build = {
      os = "linux";
      cpu = [
        "x86_64"
        "i686"
      ];
    };
    execute = {
      os = "linux";
      cpu = [
        "x86_64"
        "i686"
      ];
    };
  };
}
