{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.triggerPlanLowering",
  taskIds ? ["T-TRIG-16"],
  dependencies ? [],
}:
import ./_retained-task-evidence.nix {
  inherit pkgs attrPath taskIds dependencies;
  component = "crucible-event-graph-plan";
  evidence = "graph-native-plan-serialization";
}
