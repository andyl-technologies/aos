##! Qualifies independent controller artifacts and the combined release-test graph.
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
  // rec {
    conservative = pkgs.callPackage ../../../pkgs/tools/crucible/_controller-bazel-build.nix {};
    artifact-parity = import ../../../tests/build/_bazel-crucible-controller-artifacts.nix {inherit pkgs;};
    test-cargo = import ../../../tests/build/_bazel-crucible-controller-test-cargo.nix {inherit pkgs;};
    test-graph = import ../../../tests/build/_bazel-crucible-controller-tests.nix {inherit pkgs;};
    test-graph-conservative = import ../../../tests/build/_bazel-crucible-controller-tests.nix {
      inherit pkgs;
      sourceInventory = null;
    };
    test-features = pkgs.runCommand "aos-bazel-crucible-controller-test-features" {buildDeps = [pkgs.python3];} ''
      mkdir -p "$out"
      cp ${./verify_protocol.py} verify_protocol.py
      cp ${./verify_pilot.py} verify_pilot.py
      ${pkgs.python3}/bin/python3 verify_protocol.py --features-only \
        --inventory ${test-graph.compilation}/inventory.json \
        --messages ${test-cargo}/cargo-messages.jsonl \
        ${pkgs.lib.escapeShellArgs (pkgs.lib.concatMap (name: ["--package-path" "${name}=${test-graph.packages.${name}}"])
          (builtins.attrNames test-graph.packages))} \
        --output "$out/features.json"
    '';
    test-cases = pkgs.runCommand "aos-bazel-crucible-controller-test-cases" {buildDeps = [pkgs.python3];} ''
      mkdir -p "$out"
      ${pkgs.python3}/bin/python3 ${./verify_controller_cases.py} \
        --inventory ${test-graph.compilation}/inventory.json \
        --discovery ${test-graph.compilation}/test-cases.json \
        --messages ${test-cargo}/cargo-messages.jsonl \
        --nextest ${test-cargo}/nextest-list.json \
        --output "$out/cases.json"
    '';
  }
