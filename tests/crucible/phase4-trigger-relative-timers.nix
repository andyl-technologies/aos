{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.triggerRelativeTimers",
  dependencies ? [],
}:
import ./_retained-task-evidence.nix {
  inherit pkgs attrPath dependencies;
  component = "crucible-trigger-relative-timers";
  evidence = "time-condition-leaves,event-graph-replay";
}
