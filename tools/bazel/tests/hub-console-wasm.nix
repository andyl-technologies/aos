##! Browser compilation and configured inventory without claiming browser execution.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in
  (import ../../../tests/build/_bazel-hub-console-wasm.nix {inherit pkgs;})
  // {
    conservative = import ../../../tests/build/_bazel-hub-console-wasm.nix {
      inherit pkgs;
      sourceInventory = null;
    };
  }
