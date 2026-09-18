##! Package-owned hardware monitoring policy and manager watchdog request.
{
  config,
  lib,
  ...
}: let
  enabled = lib.attrByPath ["aos" "monitoring" "hardware" "enable"] false config;
  watchdogEnabled = lib.attrByPath ["aos" "monitoring" "hardware" "watchdog"] true config;
  watchdogTimeout = lib.attrByPath ["aos" "monitoring" "hardware" "watchdogTimeout"] 30 config;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  managerWatchdog = lib.abilities.interfaces.managerWatchdog.interface;
  watchdog = serviceManagement.forProducer {
    consumerInstance = "watchdog";
    key = "manager-watchdog";
    interface = managerWatchdog;
    inherit (managerWatchdog) methods;
    parameters = {
      enabled = watchdogEnabled;
      runtime_timeout_millis = watchdogTimeout * 1000;
      reboot_timeout_millis = watchdogTimeout * 2000;
      kexec_timeout_millis = watchdogTimeout * 2000;
    };
  };
  contribution = serviceManagement.splitContribution watchdog;
in {
  config = lib.mkMerge [
    {aos.abilities = contribution.declarations;}
    (lib.mkIf (
        enabled
        && config.aos.abilities.environment
        != null
        && config.aos.abilities.environment.stage == "host"
      ) {
        aos.abilities = lib.mkMerge [
          {instances.watchdog = {};}
          contribution.configured
        ];
      })
  ];
}
