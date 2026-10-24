##! Explicit inventory refresh starts with conservative source selection.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in {
  conservative = import ../../../tests/build/_bazel-device.nix {
    inherit pkgs;
    sourceInventory = null;
  };
  precise = import ../../../tests/build/_bazel-device.nix {inherit pkgs;};
}
