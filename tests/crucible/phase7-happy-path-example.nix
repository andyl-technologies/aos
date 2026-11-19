{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.happyPathExample",
  dependencies ? [],
}:
import ./_retained-task-evidence.nix {
  inherit pkgs attrPath dependencies;
  component = "crucible-happy-path-example";
  evidence = "builtin-corpus,graph-serialization,black-box,adversarial-verify";
}
