##! Retains ZFS hardware health policy through the selected package module closure.
{
  lib,
  pkgs,
}: let
  packages = [pkgs.aos-zfs-provider pkgs.systemd];
  evaluate = enabled: overrides:
    lib.evalPackageModules {
      inherit packages;
      scope = ["test" "zfs-hardware-monitoring"];
      operatorModules = [
        {
          aos.filesystems.zfs = {
            enable = enabled;
            systemState = false;
            reservedSpace.enable = false;
          };
        }
        overrides
      ];
    };
  defaults = evaluate true {};
  virtualDisks = evaluate true {aos.monitoring.hardware.smartd = false;};
  disabled = evaluate true {aos.monitoring.hardware.enable = false;};
  unused = evaluate false {};
  watchdog = evaluation: evaluation.config.aos.abilities.managerWatchdog.operations.ensure.effects;
  services = evaluation: evaluation.config.aos.abilities.serviceManagement.operations.realize.effects;
  succeeds = value: (builtins.tryEval (builtins.deepSeq value true)).success;
in {
  zfsAdmitsMonitoringContract = builtins.elem pkgs.smartmontools pkgs.aos-zfs-provider.moduleDeps;
  realStorageEnablesMonitoring = defaults.config.aos.storage.hardwareMonitoringRecommended && defaults.config.aos.monitoring.hardware.enable && defaults.config.aos.services.smartd.enable;
  realStorageEnablesWatchdog = (watchdog defaults).smartmontools.input.enabled;
  virtualDisksKeepWatchdog = !virtualDisks.config.aos.services.smartd.enable && !(services virtualDisks ? smartd) && (watchdog virtualDisks).smartmontools.input.enabled;
  explicitMonitoringDisablePreserved = !disabled.config.aos.monitoring.hardware.enable && !(services disabled ? smartd) && !(watchdog disabled ? smartmontools);
  unusedBackendDoesNotEnableMonitoring = !unused.config.aos.storage.hardwareMonitoringRecommended && !unused.config.aos.monitoring.hardware.enable && !(services unused ? smartd) && !(watchdog unused ? smartmontools);
  virtualDiskGraphIsValid = succeeds virtualDisks.deployment.graph;
  realStorageGraphIsValid = succeeds defaults.deployment.graph;
}
