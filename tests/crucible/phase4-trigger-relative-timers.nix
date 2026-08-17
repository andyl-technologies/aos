{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.triggerRelativeTimers",
  taskIds ? ["T-TRIG-14"],
  dependencies ? [],
}:
import ./_retained-task-evidence.nix {
  inherit pkgs attrPath taskIds dependencies;
  component = "crucible-trigger-relative-timers";
  evidence = "time-condition-leaves,event-graph-replay";
}
