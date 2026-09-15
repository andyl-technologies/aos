##! Hardware monitoring feature selection and package-owned abilities.
{
  config,
  pkgs,
  lib,
  ...
}: let
  cfg = config.aos.monitoring.hardware;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  watchdog = serviceManagement.forProducer {
    consumerInstance = "watchdog";
    key = "manager-watchdog";
    interface = {
      alias = "manager-watchdog";
      declaration = config.aos.abilities.interfaces."systemd:systemd-manager-watchdog";
    };
    methods = ["apply" "observe" "remove"];
    parameters = {
      enabled = cfg.watchdog;
      runtime_timeout_millis = cfg.watchdogTimeout * 1000;
      reboot_timeout_millis = cfg.watchdogTimeout * 2000;
      kexec_timeout_millis = cfg.watchdogTimeout * 2000;
    };
  };
  contribution = serviceManagement.splitContribution watchdog;
in {
  options.aos.monitoring.hardware.enable = lib.mkOption {
    type = lib.abilities.types.boolean;
    default = false;
    description = "Enable package-owned hardware health monitoring abilities.";
  };

  config = lib.mkMerge [
    {
      aos.abilities = contribution.declarations;
    }
    (lib.mkIf cfg.enable {
      environment.systemPackages = [pkgs.smartmontools];
      aos.abilities = lib.mkMerge [
        {instances.watchdog = {};}
        contribution.configured
      ];
    })
  ];
}
