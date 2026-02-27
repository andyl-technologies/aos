# stdenv/toolchains/gcc4_4/linux-headers.nix — Linux 2.6.32 headers (RHEL 6)
#
# Kernel headers only — no kernel build. Built with tools from the previous tier.
#
{
  prev,
  buildPlatform,
  hostPlatform,
}: let
  fetchSrc = {
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
    name = "linux-2.6.32.tar.bz2";
    url = "https://cdn.kernel.org/pub/linux/kernel/v2.6/linux-2.6.32.tar.bz2";
    hash = "sha256-UJl4bYC4QH2YphnfACCcI1NRfyLYBP3ZUzs2Kty0UE4=";
  };
in
  builtins.derivation {
    name = "linux-headers-2.6.32";
    system = buildPlatform.system;
    builder = "${prev.bash}/bin/bash";
    args = [
      "-c"
      ''
        set -eu
        export PATH="${prev.coreutils}/bin:${prev.gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.bash}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.diffutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.patch}/bin"

        cd "$TMPDIR"
        tar xjf ${linux-src}
        cd linux-2.6.32
        chmod -R u+w .

        make ARCH=${hostPlatform.linuxArch} INSTALL_HDR_PATH="$out" headers_install

        echo "Linux 2.6.32 headers installed to $out"
      ''
    ];
  }
  // {
    meta = {
      description = "Linux kernel headers, version 2.6.32";
      homepage = "https://www.kernel.org/";
      license = "GPL-2.0-only";
      build = {os = "linux";};
      execute = {os = "linux";};
    };
  }
