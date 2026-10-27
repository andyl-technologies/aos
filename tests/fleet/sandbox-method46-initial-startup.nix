# Qualifies boot with the actual manual roles selected, before provisioning.
# Public DATA pins select immutable definitions; no credential bytes, approval,
# original producer entry or initialized TPM floor are supplied by this test.
{
  lib,
  pkgs,
  systems,
  ...
} @ args: let
  baseline = import ./sandbox-funded-startup.nix (args // {expectedFloorMode = "required-v1";});
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
    testScript =
      baseline.testScript
      + ''
        # The shared enclosure assertions cover enforcing boot and a real
        # QEMU/vTPM power cycle. The selected manual purposes must remain inert
        # afterwards; their definitions supply no automatic initialization.
        initial_units = (
            "aos-sandbox-controller-floor-initialize.service",
            "aos-sandbox-storage-floor-initialize.service",
        )
        with startup_diagnostics(vm, *initial_units):
            for unit in initial_units:
                properties = dict(line.split("=", 1) for line in vm.succeed(
                    f"systemctl show {unit} --property=LoadState,ActiveState,SubState,MainPID,ExecMainPID"
                ).splitlines())
                assert properties == {
                    "LoadState": "loaded",
                    "ActiveState": "inactive",
                    "SubState": "dead",
                    "MainPID": "0",
                    "ExecMainPID": "0",
                }, (unit, properties)
      '';
  }
