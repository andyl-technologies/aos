##! Portable contract qualification and configured source inventory refresh.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in
  (import ../../../tests/build/_bazel-contracts.nix {inherit pkgs;})
  // {
    conservative = import ../../../tests/build/_bazel-contracts.nix {
      inherit pkgs;
      sourceInventory = null;
    };
  }
