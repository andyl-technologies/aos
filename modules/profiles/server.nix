##! modules/profiles/server.nix — Server role profile
##!
##! Configures the system for server/cloud deployments: ZFS for persistent
##! storage, cloud-init for boot-time provisioning, NTP via chrony, SSH access,
##! and standard security posture.
{
  config,
  pkgs,
  lib,
  ...
}:
let
  cfg = config.aos.profiles.server;
in
{
  options.aos.profiles.server = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Enable the server profile. Configures ZFS storage, cloud-init
        provisioning, chrony NTP, SSH, and standard security defaults.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    # Storage: ZFS for persistent state
    aos.filesystems.zfs.enable = lib.mkDefault true;
    aos.filesystems.rootFsType = lib.mkDefault "ext4";

    # Provisioning: cloud-init for first-boot configuration
    aos.services.cloudInit.enable = lib.mkDefault true;

    # Time sync
    aos.services.chrony.enable = lib.mkDefault true;

    # Remote access (SSH module opens its own firewall port)
    aos.services.ssh.enable = lib.mkDefault true;

    # Security: standard level (SELinux enforcing, audit, firewall)
    aos.security.level = lib.mkDefault "standard";

    # System packages for server administration
    environment.systemPackages = [
      pkgs.procps-ng
      pkgs.lsof
      pkgs.iproute2
      pkgs.ethtool
      pkgs.curl
      pkgs.jq
    ];
  };
}
