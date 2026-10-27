# Exercises the full finite lifecycle enclosure before external provisioning.
# Execution, deletion and recovery reservations grant no operation authority.
{
  lib,
  pkgs,
  systems,
  ...
} @ args: let
  baseline = import ./sandbox-funded-startup.nix args;
  fundedSystem = import ./_sandbox-funded-system.nix {
    inherit lib pkgs systems;
    includeLifecycleReservations = true;
  };
  system = fundedSystem.extendModules {
    # The inherited assertions execute Python inside the image. Keep that
    # dependency when replacing the baseline system with lifecycle funding.
    modules = [{environment.systemPackages = [pkgs.python3];}];
  };
in
  baseline
  // {
    name = "sandbox-lifecycle-funded-startup";
    machines.vm = baseline.machines.vm // {inherit system;};
  }
