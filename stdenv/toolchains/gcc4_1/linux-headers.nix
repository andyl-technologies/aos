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
    sha256 = "0ad6d97c1z5z79gafbxsd9d9wq4f21hmvp52s91dysqk24fkbdbx";
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
