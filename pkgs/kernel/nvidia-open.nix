##! NVIDIA open GPU kernel modules
{
  mkDerivation,
  fetchurl,
  gnumake,
  bash,
  perl,
  kmod,
  elfutils,
  dwarves,
  linux,
  kernel ? linux,
}: let
  version = "610.43.02";
in
  mkDerivation {
    pname = "nvidia-open-kernel-modules";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/NVIDIA/open-gpu-kernel-modules/archive/refs/tags/${version}.tar.gz"
      ];
      hash = "sha256-Yvu+KVJ+ML4yyzizDfrS6U2xyof3elgJDlY8dmmFfmA=";
    };

    buildDeps = [gnumake bash perl kmod elfutils dwarves];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd open-gpu-kernel-modules-${version}
        '';
      }
      {
        name = "build";
        script = ''
          export LD_LIBRARY_PATH="${elfutils}/lib''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
          make -j"$NIX_BUILD_CORES" modules \
            SYSSRC=${kernel.dev}/lib/modules/${kernel.version}/build \
            SYSOUT=${kernel.dev}/lib/modules/${kernel.version}/build \
            TARGET_ARCH=x86_64 ARCH=x86_64 \
            NV_BUILD_USER=aos NV_BUILD_HOST=aos-builder
        '';
      }
      {
        name = "install";
        script = ''
          export LD_LIBRARY_PATH="${elfutils}/lib''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
          make -j"$NIX_BUILD_CORES" modules_install \
            SYSSRC=${kernel.dev}/lib/modules/${kernel.version}/build \
            SYSOUT=${kernel.dev}/lib/modules/${kernel.version}/build \
            TARGET_ARCH=x86_64 ARCH=x86_64 \
            INSTALL_MOD_PATH="$out" \
            NV_BUILD_USER=aos NV_BUILD_HOST=aos-builder
          find "$out/lib/modules" -type l -delete
        '';
      }
    ];

    meta = {
      description = "Open NVIDIA GPU kernel modules built for the exact AOS kernel";
      homepage = "https://github.com/NVIDIA/open-gpu-kernel-modules";
      license = "MIT OR GPL-2.0-only";
    };

    passthru = {inherit kernel;};
  }
