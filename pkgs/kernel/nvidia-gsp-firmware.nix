##! NVIDIA GSP firmware matched to the open kernel modules
{
  mkDerivation,
  fetchurl,
  bash,
  zstd,
}: let
  version = "610.43.02";
in
  mkDerivation {
    pname = "nvidia-gsp-firmware";
    inherit version;

    src = fetchurl {
      urls = [
        "https://us.download.nvidia.com/XFree86/Linux-x86_64/${version}/NVIDIA-Linux-x86_64-${version}.run"
      ];
      hash = "sha256-MDSgVLtM33dS/43CclZMsQVROAS/9TU4lFkBsWyndGM=";
    };

    buildDeps = [bash zstd];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tail -n +1022 "$src" | zstd -d | tar -x -f - -- \
            firmware/gsp_ga10x.bin \
            firmware/gsp_tu10x.bin
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/lib/firmware/nvidia/${version}"
          cp firmware/gsp_ga10x.bin firmware/gsp_tu10x.bin \
            "$out/lib/firmware/nvidia/${version}/"
        '';
      }
    ];

    meta = {
      description = "NVIDIA GSP firmware matched to open kernel modules ${version}";
      homepage = "https://www.nvidia.com/";
      license = "NVIDIA-Software-License";
    };
  }
