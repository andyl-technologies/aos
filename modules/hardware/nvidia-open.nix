##! modules/hardware/nvidia-open.nix — Open NVIDIA kernel driver support
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.hardware.nvidia.open;
  driver = pkgs.nvidiaOpenForKernel config.system.build.kernel;
in {
  options.aos.hardware.nvidia.open = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Build and load NVIDIA's open kernel modules. A deployment must provide
        matching GSP firmware; compute and graphics APIs also require matching
        separately managed userspace components.
      '';
    };
    gspFirmwarePackage = lib.mkOption {
      type = lib.types.nullOr lib.types.package;
      default = pkgs.nvidia-gsp-firmware;
      description = ''
        Runtime firmware package matching the open kernel-module release.
        The package must expose its files below lib/firmware. It remains out
        of the initrd because GPUs are initialized after switch-root.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = lib.platform.constraints.cpu == "x86_64";
        message = "the packaged NVIDIA open kernel modules currently support x86_64 systems";
      }
      {
        assertion = cfg.gspFirmwarePackage != null;
        message = "NVIDIA open kernel modules require a version-matched GSP firmware package";
      }
    ];
    aos.kernel.modulePackages = [driver];
    aos.kernel.firmwarePackages = [cfg.gspFirmwarePackage];
    aos.kernel.modules = ["nvidia" "nvidia_modeset" "nvidia_uvm" "nvidia_drm"];
    environment.etc."modprobe.d/nvidia-open.conf".text = ''
      blacklist nouveau
      options nvidia_drm modeset=1 fbdev=1
    '';
  };
}
