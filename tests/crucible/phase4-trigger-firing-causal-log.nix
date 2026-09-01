{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.triggerFiringCausalLog",
  taskIds ? ["T-TRIG-11"],
  dependencies ? [],
}:
import ./_retained-task-evidence.nix {
  inherit pkgs attrPath taskIds dependencies;
  component = "crucible-trigger-causal-log";
  evidence = "event-graph-replay-oracle";
}
