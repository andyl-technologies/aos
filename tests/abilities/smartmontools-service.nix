##! Checks independent native smartd and manager-watchdog activation.
{
  lib,
  pkgs,
}: let
  evaluate = {
    smartd,
    operatorEnable ? null,
    watchdog ? true,
  }:
    lib.evalPackageModules {
      scope = ["test" "smartmontools"];
      packages = [pkgs.smartmontools];
      operatorModules =
        [
          {
            aos.monitoring.hardware = {
              enable = true;
              inherit smartd watchdog;
            };
          }
        ]
        ++ lib.optional (operatorEnable != null) {aos.services.smartd.enable = operatorEnable;};
    };
  enabled = evaluate {smartd = true;};
  watchdogOnly = evaluate {smartd = false;};
  noWatchdog = evaluate {
    smartd = false;
    watchdog = false;
  };
  operatorEnabled = evaluate {
    smartd = false;
    operatorEnable = true;
  };
  files = result: result.config.aos.abilities.configuration.operations.file.effects;
  watchdog = result: result.config.aos.abilities.managerWatchdog.operations.ensure.effects.smartmontools.input;
in
  assert enabled.config.aos.services.smartd.enable && files enabled ? smartd;
  assert !watchdogOnly.config.aos.services.smartd.enable && files watchdogOnly == {};
  assert (watchdog watchdogOnly).runtime_timeout_millis == 30000;
  assert (watchdog watchdogOnly).reboot_timeout_millis == 60000;
  assert !(watchdog noWatchdog).enabled;
  assert operatorEnabled.config.aos.services.smartd.enable && files operatorEnabled ? smartd; true
