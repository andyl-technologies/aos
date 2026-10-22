# Exercises the full finite lifecycle enclosure before external provisioning.
# Execution, deletion and recovery reservations grant no operation authority.
{
  lib,
  pkgs,
  systems,
  ...
} @ args: let
  baseline = import ./sandbox-funded-startup.nix args;
  system = import ./_sandbox-funded-system.nix {
    inherit lib pkgs systems;
    includeLifecycleReservations = true;
  };
in
  baseline
  // {
    name = "sandbox-lifecycle-funded-startup";
    machines.vm = baseline.machines.vm // {inherit system;};
  }
