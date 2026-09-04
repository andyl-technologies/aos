##! Linux Headers — Kernel headers for userspace compilation
{
  mkDerivation,
  linuxSource,
  stdenv,
  gnumake,
}: let
  archMap = {
    "x86_64-linux" = {karch = "x86_64";};
    "aarch64-linux" = {karch = "arm64";};
  };
  kernelArch =
    archMap.${stdenv.system}
    or (throw "linux-headers: unsupported system '${stdenv.system}'");
in
  mkDerivation {
    pname = "linux-headers";
    inherit (linuxSource) version src;
    update = linuxSource.updateFor "linux-headers";

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd linux-${linuxSource.version}
        '';
      }
      {
        name = "install";
        script = ''
          # Use 'make headers' to sanitize headers in-tree, then copy manually.
          # This avoids 'make headers_install' which requires rsync, a tool not
          # present in the bootstrap toolchain.
          make headers ARCH=${kernelArch.karch}

          mkdir -p $out/include
          cp -r usr/include/* $out/include/

          # Remove extraneous files left by the kernel build system
          find $out/include -name '*.install.cmd' -delete
          find $out/include -name '..install.cmd' -delete
          find $out/include -name '.install' -delete
        '';
      }
    ];

    meta = {
      description = "Linux kernel headers for userspace compilation";
      homepage = "https://www.kernel.org";
      license = "GPL-2.0-only";
    };
  }
