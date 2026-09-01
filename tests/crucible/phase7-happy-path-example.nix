{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.happyPathExample",
  taskIds ? ["T-EX-1"],
  dependencies ? [],
}:
import ./_retained-task-evidence.nix {
  inherit pkgs attrPath taskIds dependencies;
  component = "crucible-happy-path-example";
  evidence = "builtin-corpus,graph-serialization,black-box,adversarial-verify";
}
