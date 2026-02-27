# stdenv/toolchains/gcc14/linux-headers.nix — Linux 6.12 headers (RHEL 10)
#
# Kernel headers installed via headers_install. Required by glibc 2.39.
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
    url = "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.12.tar.xz";
    sha256 = "1dnxa60qxkjb8yqadbb1aglj8p57pqkmmg8ikdmlqxlb4vh7vnz3";
  };
in
builtins.derivation {
  name = "linux-headers-6.12";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin"

      cd "$TMPDIR"
      cp -r ${src} linux-6.12
      cd linux-6.12
      chmod -R u+w .

      make ARCH=${hostPlatform.linuxArch} INSTALL_HDR_PATH="$out" headers_install

      echo "Linux 6.12 headers installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "Linux 6.12 kernel headers";
    homepage = "https://www.kernel.org/";
    license = "GPL-2.0-only";
    build = {
      os = "linux";
    };
    execute = {
      os = "linux";
    };
  };
}
