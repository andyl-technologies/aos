##! Boot preparation qualification and conservative configured inventory refresh.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in
  (import ../../../tests/build/_bazel-boot-preparation.nix {inherit pkgs;})
  // {
    conservative = import ../../../tests/build/_bazel-boot-preparation.nix {
      inherit pkgs;
      sourceInventory = null;
    };
  }
