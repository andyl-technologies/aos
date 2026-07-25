##! modules/profiles/server.nix — host-selectable server runtime role
##!
##! Configures the system for server/cloud deployments: signed host
##! first-boot provisioning in the initrd, encrypted swap, NTP via chrony,
##! SSH access, and standard security posture.
##!
##! ZFS is disabled for this iteration. /var lives on its own ext4
##! partition (created by systemd-repart at first boot), so the root filesystem
##! is mounted read-only. ZFS will come back in a later iteration.
{
  config,
  pkgs,
  lib,
  ...
}: let
  cfg = config.aos.roles.server;
in {
  options.aos.roles.server = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Enable the server runtime role from host.nix. Configures chrony, SSH,
        server identities, package capabilities, and standard security policy.
        Golden-image storage and kernel capabilities are defined by the system
        variant rather than this host-selectable role.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    # Time sync
    aos.services.chrony.enable = lib.mkDefault true;

    # Remote access (SSH module opens its own firewall port)
    aos.services.ssh.enable = lib.mkDefault true;

    aos.users.users.aos-gitd = {
      uid = 800;
      group = "aos-gitd";
      home = "/var/lib/aos-registry-server/registries";
      shell = "/sbin/nologin";
      description = "AOS registry server";
      extraGroups = [];
    };
    aos.users.groups.aos-gitd = {
      gid = 800;
      members = [];
    };

    # Security: standard level (SELinux enforcing, audit, firewall)
    aos.security.level = lib.mkDefault "standard";

    aos.packages.aos-registry-server = {
      package = pkgs.aos-registry-server;
      bundle = lib.mkDefault false;
      preset = false;
    };

    # Test fixtures: not baked into the production image by default. Test
    # systems/fixtures that need them re-enable with `bundle = true`.
    aos.packages.aos-test-agent = {
      package = pkgs.aos-test-agent;
      bundle = lib.mkDefault false;
      preset = false;
    };

    aos.packages.k3s-control-plane = {
      package = lib.mkDefault pkgs.k3s-control-plane;
      bundle = lib.mkDefault false;
      preset = lib.mkDefault false;
    };

    aos.packages.k3s-worker = {
      package = lib.mkDefault pkgs.k3s-worker;
      bundle = lib.mkDefault false;
      preset = lib.mkDefault false;
    };

    aos.packages.k3s-combined = {
      package = lib.mkDefault pkgs.k3s-combined;
      bundle = lib.mkDefault false;
      preset = lib.mkDefault false;
    };

    aos.packages.test-http-server = {
      package = pkgs.test-http-server;
      bundle = lib.mkDefault false;
      preset = false;
    };

    aos.packages.test-static-cache-server = {
      package = pkgs.test-static-cache-server;
      bundle = lib.mkDefault false;
      preset = false;
    };

    aos.packages.apm-systemd-client-test = {
      package = pkgs.apm-systemd-client-test;
      bundle = lib.mkDefault false;
      preset = false;
    };
  };
}
