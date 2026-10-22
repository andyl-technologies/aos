##! Rebuild conservative source selection when shared-library declarations change.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in {
  conservative = import ../../../tests/build/_bazel-shared.nix {
    inherit pkgs;
    sourceInventory = null;
  };
  precise = import ../../../tests/build/_bazel-shared.nix {inherit pkgs;};
}
