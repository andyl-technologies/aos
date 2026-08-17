{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.triggerActionApplication",
  taskIds ? ["T-TRIG-12"],
  dependencies ? [],
}:
import ./_retained-task-evidence.nix {
  inherit pkgs attrPath taskIds dependencies;
  component = "crucible-trigger-action-application";
  evidence = "control-flow,node-scheduling,verdict,replay";
}
