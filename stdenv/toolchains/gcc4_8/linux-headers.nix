# stdenv/toolchains/gcc4_8/linux-headers.nix — Linux kernel headers 3.10 (RHEL 7)
#
# Kernel headers for the RHEL 7 era glibc build.
#
{
  prev,
  gcc,
  buildPlatform,
  hostPlatform,
}:
let
  fetchSrc =
    {
      name,
      url,
      hash,
    }:
    builtins.derivation {
      inherit name;
      system = buildPlatform.system;
      builder = "builtin:fetchurl";
      inherit url;
      outputHash = hash;
      outputHashMode = "flat";
      outputHashAlgo = "sha256";
      preferLocalBuild = true;
    };

  linux-src = fetchSrc {
    name = "linux-3.10.108.tar.xz";
    url = "https://cdn.kernel.org/pub/linux/kernel/v3.x/linux-3.10.108.tar.xz";
    hash = "sha256-OEnqgRlRf2BfnVPFfdbFOa+NWEwvHZAx9PVig680CaU=";
  };

in
builtins.derivation {
  name = "linux-headers-3.10";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export PATH="${prev.coreutils}/bin:${gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.bash}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.diffutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.patch}/bin"

      cd "$TMPDIR"
      tar xJf ${linux-src}
      cd linux-3.10.108
      chmod -R u+w .

      make ARCH=${hostPlatform.linuxArch} INSTALL_HDR_PATH="$out" headers_install

      echo "Linux headers 3.10 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "Linux kernel headers, version 3.10";
    homepage = "https://www.kernel.org/";
    license = "GPL-2.0-only";
    platforms = [
      "i686-linux"
      "x86_64-linux"
      "aarch64-linux"
    ];
  };
}
