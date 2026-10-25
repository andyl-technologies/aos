##! Standalone compiler-cache qualification and conservative source inventory refresh.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in
  (import ../../../tests/build/_bazel-accache.nix {inherit pkgs;})
  // {
    conservative = import ../../../tests/build/_bazel-accache.nix {
      inherit pkgs;
      sourceInventory = null;
    };
  }
