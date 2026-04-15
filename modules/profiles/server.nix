##! modules/profiles/server.nix — Server role profile
##!
##! Configures the system for server/cloud deployments: ignition-based
##! first-boot provisioning in the initrd, encrypted swap, NTP via chrony,
##! SSH access, and standard security posture.
##!
##! ZFS and cloud-init are disabled for this iteration. The tier-ii initrd
##! story moves /var to the ext4 root partition (root is mounted rw) and
##! uses ignition for first-boot configuration. Cloud-init and ZFS will
##! come back in a later iteration.
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
    # Storage: ext4 root partition, /var lives on the root partition
    # for this iteration (ZFS deferred).
    aos.filesystems.zfs.enable = lib.mkDefault false;
    aos.filesystems.rootFsType = lib.mkDefault "ext4";
    # The /etc overlay is mutable, but /var needs to be a writable
    # directory on the root partition — that means mounting root rw.
    # When ZFS lands, /var moves to a ZFS dataset and this flips back.
    aos.filesystems.rootReadOnly = lib.mkDefault false;

    # Provisioning: ignition in the initrd; cloud-init disabled.
    aos.services.cloudInit.enable = lib.mkDefault false;
    aos.services.ignition.enable = lib.mkDefault true;

    # Kernel modules for encrypted swap in stage 2.
    aos.kernel.modules = [ "dm-crypt" "aes" "xts" ];

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
