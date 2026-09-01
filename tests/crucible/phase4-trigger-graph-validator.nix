{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.triggerGraphValidator",
  taskIds ? ["T-TRIG-15"],
  dependencies ? [],
}:
import ./_retained-task-evidence.nix {
  inherit pkgs attrPath taskIds dependencies;
  component = "crucible-trigger-graph-validator";
  evidence = "control-flow,condition-validation,node-validation,serialization";
}
