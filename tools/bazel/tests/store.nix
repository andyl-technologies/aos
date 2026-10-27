##! Rebuild configured store metadata before selecting the precise source graph.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in {
  conservative = import ../../../tests/build/_bazel-store.nix {
    inherit pkgs;
    sourceInventory = null;
  };
  precise = import ../../../tests/build/_bazel-store.nix {inherit pkgs;};
}
