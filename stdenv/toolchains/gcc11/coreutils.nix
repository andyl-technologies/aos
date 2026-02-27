# stdenv/toolchains/gcc11/coreutils.nix — GNU Coreutils 8.32 (RHEL 9)
#
# Built with THIS tier's GCC 11.5.0 + binutils 2.35 + glibc 2.34.
#
{
  prev,
  gcc,
  binutils,
  glibc,
  buildPlatform,
  hostPlatform,
}:
let
  src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/coreutils/coreutils-8.32.tar.xz";
    sha256 = "0zds26w4h65w75x3xpdi32hws3vb3idj5n4pm9zrny4mm6pk36jy";
  };
in
builtins.derivation {
  name = "coreutils-8.32";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      cd "$TMPDIR"
      cp -r ${src} coreutils-8.32
      cd coreutils-8.32
      chmod -R u+w .

      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      CC="${gcc}/bin/gcc" \
      CFLAGS="-O2 -I${glibc}/include" \
      LDFLAGS="-L${glibc}/lib -static" \
      "$TMPDIR/coreutils-8.32/configure" \
        --prefix="$out" \
        --build=${buildPlatform.config} --host=${hostPlatform.config} --target=${hostPlatform.config} \
        --disable-nls

      make -j"$(nproc)"
      make install

      echo "Coreutils 8.32 installed to $out"
    ''
  ];
}
// {
  meta = {
    build = {
      os = "linux";
    };
    execute = {
      os = "linux";
    };
  };
}
