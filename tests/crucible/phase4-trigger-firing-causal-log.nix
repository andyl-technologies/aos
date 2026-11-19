{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.triggerFiringCausalLog",
  dependencies ? [],
}:
import ./_retained-task-evidence.nix {
  inherit pkgs attrPath dependencies;
  component = "crucible-trigger-causal-log";
  evidence = "event-graph-replay-oracle";
}
