##! Checks independent smartd and manager-watchdog ability activation.
{lib}: let
  evaluate = {
    smartd,
    operatorEnable ? null,
  }:
    lib.evalModules {
      specialArgs = {inherit lib;};
      modules = [
        ../../modules/abilities/default.nix
        {
          options.aos.storage.hardwareMonitoringRecommended = lib.mkOption {
            type = lib.types.bool;
            default = false;
          };
          aos.abilities.environment = {
            authority = "test";
            key = "smartmontools";
            stage = "host";
          };
          aos.monitoring.hardware = {
            enable = true;
            inherit smartd;
          };
        }
      ];
      packageModules = [
        {
          name = "smartmontools";
          module = ../../pkgs/tools/_smartmontools/module.nix;
        }
      ];
      operatorModules = lib.optional (operatorEnable != null) {
        aos.services.smartd.enable = operatorEnable;
      };
    };

  enabled = (evaluate {smartd = true;}).config.aos.abilities;
  watchdogOnly = (evaluate {smartd = false;}).config.aos.abilities;
  operatorEnabled =
    (evaluate {
      smartd = false;
      operatorEnable = true;
    }).config.aos.abilities;
in
  assert enabled.requests ? "smartmontools:smartd-lifecycle";
  assert enabled.requests ? "smartmontools:manager-watchdog";
  assert watchdogOnly.requests ? "smartmontools:manager-watchdog";
  assert !(watchdogOnly.requests ? "smartmontools:smartd-lifecycle");
  assert watchdogOnly.requirementTemplates ? "smartmontools:smartd-service-lifecycle";
  assert operatorEnabled.requests ? "smartmontools:smartd-lifecycle";
  assert operatorEnabled.requests ? "smartmontools:configuration-file"; true
