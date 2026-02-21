# stdenv/toolchains/gcc11/linux-headers.nix — Linux 5.14 headers (RHEL 9)
#
# Kernel headers installed via headers_install. Required by glibc 2.34.
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
    url = "https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.14.tar.xz";
    sha256 = "19p30vhxy61qrlq3685f4c6rjgpdnn70xkrjnpdpjvby38m52qsw";
  };
in
builtins.derivation {
  name = "linux-headers-5.14";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin"

      cd "$TMPDIR"
      cp -r ${src} linux-5.14
      cd linux-5.14
      chmod -R u+w .

      make ARCH=${hostPlatform.linuxArch} INSTALL_HDR_PATH="$out" headers_install

      echo "Linux 5.14 headers installed to $out"
    ''
  ];
}
// {
  meta.platforms = [
    "i686-linux"
    "x86_64-linux"
    "aarch64-linux"
  ];
}
