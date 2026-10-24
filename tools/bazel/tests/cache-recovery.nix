##! Standalone entry point for the private cache fault-injection check.
{system ? builtins.currentSystem}:
import ../../../tests/build/_bazel-recovery.nix {
  pkgs = (import ../../.. {inherit system;}).pkgs;
}
