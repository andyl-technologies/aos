##! Qualifies registry browser compilation and package contracts independently.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in
  (import ../../../tests/build/_bazel-registry-web-wasm.nix {inherit pkgs;})
  // {
    conservative = import ../../../tests/build/_bazel-registry-web-wasm.nix {
      inherit pkgs;
      sourceInventory = null;
    };
  }
