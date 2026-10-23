##! Static activation adapter qualification and configured source selection.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in
  (import ../../../tests/build/_bazel-activation-crucible.nix {inherit pkgs;})
  // {
    conservative = import ../../../tests/build/_bazel-activation-crucible.nix {
      inherit pkgs;
      sourceInventory = null;
    };
  }
