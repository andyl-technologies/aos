# Qualifies boot with the actual manual roles selected, before provisioning.
# Public DATA pins select immutable definitions; no credential bytes, approval,
# original producer entry or initialized TPM floor are supplied by this test.
{
  lib,
  pkgs,
  systems,
  ...
} @ args: let
  # The shared enclosure check observes the manual units before and after the
  # real QEMU/vTPM power cycle, including whether either unit has ever executed.
  baseline = import ./sandbox-funded-startup.nix (args
    // {
      expectedFloorMode = "required-v1";
      expectedUnstartedUnits = [
        "aos-sandbox-controller-floor-initialize.service"
        "aos-sandbox-storage-floor-initialize.service"
      ];
    });
  initialSystem = import ./_sandbox-method46-initial-system.nix {
    inherit lib pkgs systems;
    approvalPublicKeys = {
      controller = lib.genList (_: 11) 32;
      storage = lib.genList (_: 12) 32;
    };
  };
  system = initialSystem.extendModules {
    modules = [{environment.systemPackages = [pkgs.python3];}];
  };
in
  baseline
  // {
    name = "sandbox-method46-initial-startup";
    machines.vm = baseline.machines.vm // {inherit system;};
  }
