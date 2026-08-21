##! modules/hardware/server-management.nix — In-band BMC integration
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.hardware.serverManagement;
in {
  options.aos.hardware.serverManagement.enable = lib.mkOption {
    type = lib.types.bool;
    default = false;
    description = "Enable in-band IPMI access, power control, and watchdog support.";
  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [pkgs.ipmitool];
    aos.kernel.modules = ["ipmi_msghandler" "ipmi_si" "ipmi_devintf" "ipmi_watchdog" "ipmi_poweroff"];
  };
}
