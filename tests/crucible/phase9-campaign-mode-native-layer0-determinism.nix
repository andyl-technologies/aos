{
  pkgs,
  lib,
  mode,
  system,
  ...
}:
import ./phase1-layer0-determinism.nix {
  inherit pkgs lib;
  attrPath = "checks.crucible.phase1.gates.layer0Determinism";
  campaignComposition = {inherit mode system;};
}
