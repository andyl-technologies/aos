##! Hub service qualification and conservative configured metadata refresh.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in
  (import ../../../tests/build/_bazel-hub-service.nix {inherit pkgs;})
  // {
    conservative = import ../../../tests/build/_bazel-hub-service.nix {
      inherit pkgs;
      sourceInventory = null;
    };
  }
