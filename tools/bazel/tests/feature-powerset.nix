##! Explicit native feature-case compilation for the Cargo gate migration.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in
  (import ../../../tests/build/_bazel-feature-powerset.nix {inherit pkgs;})
  // {
    conservative = import ../../../tests/build/_bazel-feature-powerset.nix {
      inherit pkgs;
      sourceInventory = null;
    };
  }
