# stdenv/toolchains/gcc4_1/linux-headers.nix — Linux 2.6.18 headers (RHEL 5)
#
# Kernel headers installed via headers_install. Required by glibc 2.5.
#
{
  prev,
  gcc,
  binutils,
  buildPlatform,
  hostPlatform,
}:
let
  src = builtins.fetchTarball {
    url = "https://cdn.kernel.org/pub/linux/kernel/v2.6/linux-2.6.18.tar.bz2";
    sha256 = "0sjd9n6jj0x0mbz0y55xxix2kkc0xq0iikjjmhxf709q76x334qn";
  };
in
builtins.derivation {
  name = "linux-headers-2.6.18";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin"

      cd "$TMPDIR"
      cp -r ${src} linux-2.6.18
      cd linux-2.6.18
      chmod -R u+w .

      make ARCH=${hostPlatform.linuxArch} INSTALL_HDR_PATH="$out" headers_install

      echo "Linux 2.6.18 headers installed to $out"
    ''
  ];
}
// {
  meta.platforms = [ "i686-linux" "x86_64-linux" ];
}
