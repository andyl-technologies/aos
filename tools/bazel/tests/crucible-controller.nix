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
    test-feature-policy = test-graph.feature-policy;
    test-architecture = test-graph.architecture;
    test-architecture-cargo = import ../../../tests/build/_bazel-cargo-oracle.nix {
      inherit pkgs;
      pname = "aos-bazel-crucible-controller-architecture-cargo-oracle";
      packages = ["crucible-test-support"];
      cargoFlags = ["--test" "control_plane_boundary" "--test" "crate_layer_graph" "--test" "crate_artifact_types"];
      captureCompilerArguments = true;
    };
    test-architecture-parity = let
      helpers = builtins.path {
        path = ./.;
        name = "aos-controller-architecture-qualification-tools";
        filter = path: type:
          type
          == "regular"
          && builtins.elem (baseNameOf path) [
            "verify_controller_architecture.py"
            "verify_cache.py"
            "verify_compiler_sources.py"
            "verify_pilot.py"
            "verify_source_audits.py"
          ];
      };
    in
      pkgs.runCommand "aos-bazel-crucible-controller-architecture-parity" {
        buildDeps = [pkgs.python3];
        sharedBuildCache = false;
      } ''
        PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 ${helpers}/verify_controller_architecture.py \
          --strict ${test-graph.architecture} --strict-root ${test-graph.workspace.source} \
          --conservative ${test-graph-conservative.architecture} --conservative-root ${test-graph-conservative.workspace.source} \
          --oracle ${test-architecture-cargo} --cargo-root ${test-architecture-cargo.src} \
          --graph ${pkgs.aosBazelArchitecture}/architecture.json --output "$out"
      '';
    test-sources = pkgs.runCommand "aos-bazel-crucible-controller-test-sources" {buildDeps = [pkgs.python3];} ''
      mkdir -p "$out"
      ${pkgs.python3}/bin/python3 ${./verify_compiler_sources.py} \
        --inventory ${test-graph.compilation}/inventory.json \
        --bazel-root ${test-graph.workspace.source} --cargo-root ${test-cargo.src} \
        --output "$out/sources.json"
    '';
    test-features = pkgs.runCommand "aos-bazel-crucible-controller-test-features" {buildDeps = [pkgs.python3];} ''
      mkdir -p "$out"
      cp ${test-sources}/sources.json "$out/sources.json"
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
      cp ${test-sources}/sources.json "$out/sources.json"
      ${pkgs.python3}/bin/python3 ${./verify_controller_cases.py} \
        --inventory ${test-graph.compilation}/inventory.json \
        --discovery ${test-graph.compilation}/test-cases.json \
        --messages ${test-cargo}/cargo-messages.jsonl \
        --nextest ${test-cargo}/nextest-list.json \
        --output "$out/cases.json"
    '';
  }
