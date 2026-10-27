##! Native integration library execution and configured source inventory.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in
  (import ../../../tests/build/_bazel-native-foundation.nix {inherit pkgs;})
  // {
    conservative = import ../../../tests/build/_bazel-native-foundation.nix {
      inherit pkgs;
      sourceInventory = null;
    };
  }
