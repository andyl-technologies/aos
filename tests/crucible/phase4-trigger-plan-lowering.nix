{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.triggerPlanLowering",
  dependencies ? [],
}:
import ./_retained-task-evidence.nix {
  inherit pkgs attrPath dependencies;
  component = "crucible-event-graph-plan";
  evidence = "graph-native-plan-serialization";
}
