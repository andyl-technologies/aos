##! Control transport qualification and conservative configured metadata refresh.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in
  (import ../../../tests/build/_bazel-control.nix {inherit pkgs;})
  // {
    cross-linux = import ../../../tests/build/_bazel-control-cross.nix {inherit pkgs;};
    conservative = import ../../../tests/build/_bazel-control.nix {
      inherit pkgs;
      sourceInventory = null;
    };
  }
