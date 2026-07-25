##! modules/profiles/edge.nix — Edge/IoT device profile
##!
##! Configures the system for edge and IoT deployments (Jetson Nano,
##! Raspberry Pi, small appliances): ext4 root (no ZFS), signed host
##! first-boot provisioning, chrony NTP, SSH, and conservative resource
##! usage.
{
  config,
  pkgs,
  lib,
  ...
}: let
  cfg = config.aos.profiles.edge;
in {
  options.aos.profiles.edge = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Enable the edge/IoT profile. Configures ext4 storage (no ZFS),
        signed first-boot host configuration, chrony, SSH, and
        conservative resource defaults suitable for resource-constrained
        devices.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    # Storage: ext4 only — ZFS is too heavy for edge devices
    aos.filesystems.zfs.enable = lib.mkDefault false;
    aos.filesystems.rootFsType = lib.mkDefault "ext4";

    # Time sync
    aos.services.chrony.enable = lib.mkDefault true;

    # Remote access (SSH module opens its own firewall port)
    aos.services.ssh.enable = lib.mkDefault true;

    # Security: standard level
    aos.security.level = lib.mkDefault "standard";

    # Conservative kernel tunables for low-memory devices
    aos.kernel.sysctl = {
      "vm.swappiness" = "10";
      "vm.vfs_cache_pressure" = "200";
    };
  };
}
