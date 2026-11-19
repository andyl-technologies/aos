{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.triggerGraphValidator",
  dependencies ? [],
}:
import ./_retained-task-evidence.nix {
  inherit pkgs attrPath dependencies;
  component = "crucible-trigger-graph-validator";
  evidence = "control-flow,condition-validation,node-validation,serialization";
}
