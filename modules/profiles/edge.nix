##! modules/profiles/edge.nix — host-selectable edge/IoT runtime role
##!
##! Configures runtime policy for edge and IoT deployments (Jetson Nano,
##! Raspberry Pi, small appliances): chrony NTP, SSH, standard security, and
##! conservative resource usage. Golden-image storage and boot integrity are
##! deliberately owned by systems/edge.nix instead.
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.roles.edge;
in {
  options.aos.roles.edge = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Enable the edge/IoT runtime role from host.nix. Configures chrony,
        SSH, standard security policy, and conservative resource defaults
        suitable for resource-constrained devices. Golden-image storage and
        boot-integrity capabilities are defined by the system variant.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    # Time sync
    aos.services.chrony.enable = lib.mkDefault true;

    # Remote access (SSH module opens its own firewall port)
    aos.services.ssh.enable = lib.mkDefault true;

    # Security: standard level
    aos.security.level = lib.mkDefault "standard";

    # Conservative kernel tunables for low-memory devices
    aos.kernel.sysctl."vm.swappiness" = lib.mkDefault "10";
    aos.kernel.sysctl."vm.vfs_cache_pressure" = lib.mkDefault "200";
  };
}
