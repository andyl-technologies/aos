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
  packageModulesAvailable ? false,
  ...
}: let
  cfg = config.aos.roles.server;
in {
  imports =
    if packageModulesAvailable
    then []
    else [../../pkgs/system/_aos-host-policy/role-server.nix];

  config = lib.mkIf cfg.enable {
    aos.packages.aos-registry-server = {
      package = pkgs.aos-registry-server;
      bundle = lib.mkDefault false;
    };

    # Test fixtures: not baked into the production image by default. Test
    # systems/fixtures that need them re-enable with `bundle = true`.
    aos.packages.aos-test-agent = {
      package = pkgs.aos-test-agent;
      bundle = lib.mkDefault false;
    };

    aos.packages.k3s-control-plane = {
      package = lib.mkDefault pkgs.k3s-control-plane;
      bundle = lib.mkDefault false;
    };

    aos.packages.k3s-worker = {
      package = lib.mkDefault pkgs.k3s-worker;
      bundle = lib.mkDefault false;
    };

    aos.packages.k3s-combined = {
      package = lib.mkDefault pkgs.k3s-combined;
      bundle = lib.mkDefault false;
    };

    aos.packages.test-http-server = {
      package = pkgs.test-http-server;
      bundle = lib.mkDefault false;
    };

    aos.packages.test-static-cache-server = {
      package = pkgs.test-static-cache-server;
      bundle = lib.mkDefault false;
    };
  };
}
