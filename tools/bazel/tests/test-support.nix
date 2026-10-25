##! Executable test-support fixtures; repository audit migration remains separate.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in
  (import ../../../tests/build/_bazel-test-support.nix {inherit pkgs;})
  // {
    conservative = import ../../../tests/build/_bazel-test-support.nix {
      inherit pkgs;
      sourceInventory = null;
    };
  }
