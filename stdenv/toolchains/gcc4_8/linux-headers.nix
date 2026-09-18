# stdenv/toolchains/gcc4_8/linux-headers.nix — Linux kernel headers 3.10 (RHEL 7)
#
# Kernel headers for the RHEL 7 era glibc build.
#
{
  prev,
  gcc,
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
    name = "linux-3.10.108.tar.gz";
    url = "https://cdn.kernel.org/pub/linux/kernel/v3.x/linux-3.10.108.tar.gz";
    hash = "sha256-r/k0VLLfM6A5QlPIl3xtNscgWkI69tjU4+HWffyeB/g=";
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
        export PATH="${prev.coreutils}/bin:${gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.bash}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.diffutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.bzip2}/bin:${prev.patch}/bin"

        cd "$TMPDIR"
        tar xzf ${linux-src}
        cd linux-3.10.108
        chmod -R u+w .

        # Pin source helpers that configure or make can execute directly.
        AOS_RUNTIME_SHELL="${prev.bash}/bin/bash" \
          "${prev.bash}/bin/bash" ${../../runtime-scripts.sh} .

        # Build Kbuild helpers against the preceding tier's complete libc.
        make SHELL="${prev.bash}/bin/bash" \
          CONFIG_SHELL="${prev.bash}/bin/bash" \
          HOSTCC="${gcc}/bin/gcc -static" \
          PERL="${prev.perl}/bin/perl" \
          ARCH=${hostPlatform.linuxArch} \
          INSTALL_HDR_PATH="$out" \
          headers_install

        test -s "$out/include/linux/version.h"
        test -s "$out/include/linux/types.h"
        test -s "$out/include/asm/unistd.h"

        echo "Linux headers 3.10 installed to $out"
      ''
    ];
  }
  // {
    meta = {
      description = "Linux kernel headers, version 3.10";
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
