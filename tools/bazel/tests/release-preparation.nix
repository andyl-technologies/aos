##! Release preparation qualification and conservative configured metadata refresh.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in
  (import ../../../tests/build/_bazel-release-preparation.nix {inherit pkgs;})
  // {
    conservative = import ../../../tests/build/_bazel-release-preparation.nix {
      inherit pkgs;
      sourceInventory = null;
    };
  }
