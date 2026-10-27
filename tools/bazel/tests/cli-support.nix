##! Connected CLI support library qualification and source inventory refresh.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in
  (import ../../../tests/build/_bazel-cli-support.nix {inherit pkgs;})
  // {
    conservative = import ../../../tests/build/_bazel-cli-support.nix {
      inherit pkgs;
      sourceInventory = null;
    };
  }
