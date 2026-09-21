##! modules/profiles/bare-metal-zfs.nix — redundant encrypted bare-metal storage
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.profiles.bareMetalZfs;
in {
  options.aos.profiles.bareMetalZfs = {
    enable = lib.mkEnableOption "redundant encrypted ZFS bare-metal boot storage";
    espDevices = lib.mkOption {
      type = lib.types.nonEmptyListOf lib.types.str;
      default = [
        "/dev/disk/by-partlabel/aos-esp-1"
        "/dev/disk/by-partlabel/aos-esp-2"
      ];
      description = "Stable identities for the independently bootable ESP replicas.";
    };
    nvidiaOpen = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Enable NVIDIA open kernel modules and matched runtime GSP firmware.";
    };
    serverManagement = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Enable in-band IPMI and hardware monitoring support.";
    };
  };

  config = lib.mkIf cfg.enable {
    # OpenZFS is a storage stack, not a driver: the module, the userland the
    # mount units and pool services call, and the libraries behind them put the
    # runtime closure around 860 MiB, past the 768 MiB a variant contracts for.
    # That is the cost of choosing this profile, so it carries its own contract
    # rather than every image's budget being loosened to hide it. The priority
    # sits below a variant's plain definition and above mkForce, so a host can
    # still tighten it deliberately.
    aos.image.budgets.maxRuntimeClosureMiB = lib.mkOverride 75 1024;

    aos.boot.storage = {
      backend = "zfs-zvol";
      espDevices = cfg.espDevices;
    };
    aos.security.verity.enable = true;
    aos.hardware.nvidia.open.enable = cfg.nvidiaOpen;
    aos.hardware.serverManagement.enable = cfg.serverManagement;
    aos.monitoring.hardware.enable = cfg.serverManagement;
  };
}
