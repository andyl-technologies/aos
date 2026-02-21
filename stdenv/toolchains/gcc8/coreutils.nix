# stdenv/toolchains/gcc8/coreutils.nix — GNU Coreutils 8.30 (RHEL 8)
#
# Built with THIS tier's GCC 8.5.0 + binutils 2.30 + glibc 2.28.
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
    url = "https://ftp.gnu.org/gnu/coreutils/coreutils-8.30.tar.xz";
    sha256 = "0pp6vvpzw0v6s45yq58cszrh514a5v8jq32321apszw7rbffkslb";
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
      export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      cd "$TMPDIR"
      cp -r ${src} coreutils-8.30
      cd coreutils-8.30
      chmod -R u+w .

      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      CC="${gcc}/bin/gcc" \
      CFLAGS="-O2 -I${glibc}/include" \
      LDFLAGS="-L${glibc}/lib -static" \
      "$TMPDIR/coreutils-8.30/configure" \
        --prefix="$out" \
        --build=${hostPlatform.config} --host=${hostPlatform.config} --target=${hostPlatform.config} \
        --disable-nls

      make -j"$(nproc)"
      make install

      echo "Coreutils 8.30 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU core utilities (ls, cat, cp, mv, etc.), version 8.30";
    homepage = "https://www.gnu.org/software/coreutils/";
    license = "GPL-3.0-or-later";
    platforms = [
      "i686-linux"
      "x86_64-linux"
      "aarch64-linux"
    ];
  };
}
