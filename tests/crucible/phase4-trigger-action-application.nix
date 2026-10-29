{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.triggerActionApplication",
  dependencies ? [],
}:
import ./_retained-task-evidence.nix {
  inherit pkgs attrPath dependencies;
  component = "crucible-trigger-action-application";
  evidence = "control-flow,node-scheduling,verdict,replay";
}
