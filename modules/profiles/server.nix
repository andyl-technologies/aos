##! modules/profiles/server.nix — Server role profile
##!
##! Configures the system for server/cloud deployments: ignition-based
##! first-boot provisioning in the initrd, encrypted swap, NTP via chrony,
##! SSH access, and standard security posture.
##!
##! ZFS is disabled for this iteration. /var lives on its own ext4
##! partition (created by ignition at first boot), so the root filesystem
##! is mounted read-only. ZFS will come back in a later iteration.
{
  config,
  pkgs,
  lib,
  ...
}: let
  cfg = config.aos.profiles.server;
in {
  options.aos.profiles.server = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Enable the server profile. Configures ZFS storage, ignition-based
        first-boot provisioning, chrony NTP, SSH, and standard security
        defaults.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    # Storage: ext4 root (read-only), /var on its own ext4 partition
    # created by ignition at first boot. ZFS deferred.
    aos.filesystems.zfs.enable = lib.mkDefault false;
    aos.filesystems.rootFsType = lib.mkDefault "ext4";
    aos.filesystems.rootReadOnly = lib.mkDefault true;

    # Kernel modules for encrypted swap in stage 2.
    aos.kernel.modules = ["dm-crypt" "aes" "xts"];

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

    aos.roles.aos-registry-server.bundle = true;
    aos.roles.k3s-control-plane.bundle = true;
    aos.roles.k3s-worker.bundle = true;
    aos.roles.k3s-combined.bundle = true;
    aos.roles.test-http-server.bundle = true;
    aos.roles.apm-systemd-client-test.bundle = true;
  };
}
