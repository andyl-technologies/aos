##! Compiles and inventories the three independently configured controller artifacts.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in
  (pkgs.callPackage ../../../pkgs/tools/crucible/_controller-bazel-build.nix {
    sourceInventories = {
      cli = ../metadata/crucible-controller-cli-inventory.json;
      debugger = ../metadata/crucible-controller-debugger-inventory.json;
      scenario = ../metadata/crucible-controller-scenario-inventory.json;
    };
  })
  // {
    conservative = pkgs.callPackage ../../../pkgs/tools/crucible/_controller-bazel-build.nix {};
    artifact-parity = import ../../../tests/build/_bazel-crucible-controller-artifacts.nix {inherit pkgs;};
    test-cargo = import ../../../tests/build/_bazel-crucible-controller-test-cargo.nix {inherit pkgs;};
  }
