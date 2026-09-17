##! Hardware monitoring feature selection and package-owned abilities.
{
  config,
  pkgs,
  lib,
  ...
}: let
  hardware = config.aos.monitoring.hardware;
in {
  options.aos.monitoring.hardware = {
    enable = lib.mkOption {
      type = lib.abilities.types.boolean;
      default = false;
      description = "Enable hardware health monitoring.";
    };

    watchdog = lib.mkOption {
      type = lib.abilities.types.boolean;
      default = true;
      description = "Enable the selected service manager's hardware watchdog.";
    };

    watchdogTimeout = lib.mkOption {
      type = lib.abilities.types.integer {
        minimum = 1;
        maximum = 86400;
      };
      default = 30;
      description = "Watchdog timeout in seconds before hardware recovery.";
    };
  };

  config.environment.systemPackages = lib.mkIf hardware.enable [pkgs.smartmontools];
}
