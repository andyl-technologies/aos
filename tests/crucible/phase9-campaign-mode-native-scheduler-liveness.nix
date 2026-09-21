{
  pkgs,
  lib,
  testing,
  mode,
  system,
}:
import ./phase3-scheduler-liveness.nix {
  inherit pkgs lib testing;
  attrPath = "checks.crucible.phase3.gates.schedulerLiveness";
  campaignComposition = {inherit mode system;};
}
