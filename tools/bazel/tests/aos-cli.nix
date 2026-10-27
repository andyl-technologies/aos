##! CLI conversion checkpoints; runtime qualification is kept explicit.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
  architectureOracleSource = import ../../../pkgs/tools/aos/_workspace-source.nix {inherit (pkgs) lib;};
  verifier = builtins.path {
    path = ./.;
    name = "aos-cli-parity-tools";
    filter = path: type:
      type == "regular" && builtins.elem (baseNameOf path) ["verify_cli.py" "verify_protocol.py" "verify_pilot.py"];
  };
  regenerationDefault = import ../../../tests/build/_bazel-aos-cli.nix {
    inherit pkgs;
    sourceInventory = null;
  };
  regenerationFleet = import ../../../tests/build/_bazel-aos-cli.nix {
    inherit pkgs;
    fleet = true;
    sourceInventory = null;
  };
  regenerationProduction = import ../../../tests/build/_bazel-aos-cli-production.nix {
    inherit pkgs;
    sourceInventory = null;
  };

  testConfiguration = fleet: let
    candidate = import ../../../tests/build/_bazel-aos-cli.nix {inherit pkgs fleet;};
    cargo = import ../../../tests/build/_bazel-aos-cli-cargo.nix {inherit pkgs fleet;};
    cargo-execution-inspection = import ../../../tests/build/_bazel-compiler-execution.nix {
      inherit pkgs cargo;
      compilerArguments = "${cargo}/compiler-compile-arguments.jsonl";
      # Some traced tasks disappear before strace can decode their syscall.
      # Retain them without treating requested-command coverage as a complete trace.
      retainUnresolvedTasks = true;
      pname = "aos-bazel-aos-cli-${profile}-compiler-execution-inspection";
    };
    editor = import ../../../tests/build/_bazel-aos-cli-editor.nix {inherit pkgs fleet;};
    profile =
      if fleet
      then "fleet"
      else "default";
    parity = pkgs.runCommand "aos-bazel-aos-cli-${profile}-cargo-parity" {buildDeps = [pkgs.python3];} ''
      mkdir -p "$out"
      ${pkgs.python3}/bin/python3 ${verifier}/verify_cli.py \
        --tests ${candidate.tests}/evidence/tests \
        --inventory ${candidate.tests}/inventory.json \
        --cargo ${cargo} --output "$out/parity.json"
    '';
    execution-profiles = import ../qualification/rust-profiles.nix {
      inherit pkgs cargo parity;
      compareStrip = true;
      compareNativeDefaults = true;
      nativeExecution = cargo-execution-inspection;
      externalRepositoryPrefix = "@@+aos_tools_repository+aos_aos_cli_";
      pname = "aos-bazel-aos-cli-${profile}-test-profiles";
      build = candidate.tests;
    };
  in
    candidate
    // editor
    // {
      inherit cargo cargo-execution-inspection execution-profiles;
      cargo-complete-execution = pkgs.runCommand "aos-bazel-aos-cli-${profile}-complete-native-execution" {buildDeps = [pkgs.python3];} ''
        mkdir -p "$out"
        ${pkgs.python3}/bin/python3 - ${cargo-execution-inspection}/execution.json <<'PY'
        import json
        from pathlib import Path
        import sys

        capture = json.loads(Path(sys.argv[1]).read_text())["execution_capture"]
        if not capture["complete"] or capture["unresolved_task_records"]:
            raise ValueError("complete native execution capture remains unqualified: " + str(capture))
        PY
        cp ${cargo-execution-inspection}/execution.json "$out/execution.json"
      '';
      test-parity = parity;
      oracle = pkgs.runCommand "aos-bazel-aos-cli-${profile}-qualified-test-profiles" {buildDeps = [parity execution-profiles];} ''
        mkdir -p "$out"
        cp ${parity}/parity.json "$out/parity.json"
        cp ${execution-profiles}/evidence.json "$out/execution-profiles.json"
        cp ${execution-profiles}/strip-semantics.json "$out/strip-semantics.json"
        cp ${execution-profiles}/profile-semantics.json "$out/profile-semantics.json"
        cp ${cargo-execution-inspection}/execution.json "$out/native-compiler-execution.json"
        cp ${cargo-execution-inspection}/toolchain-closure.json "$out/native-toolchain-closure.json"
      '';
    };
in {
  compiler-trace-conformance = import ../qualification/compiler-trace.nix {inherit pkgs;};
  architecture = pkgs.runCommand "aos-bazel-architecture-cargo-parity" {buildDeps = [pkgs.python3];} ''
    mkdir -p "$out"
    ${pkgs.python3}/bin/python3 ${./verify_architecture.py} \
      --architecture ${pkgs.aosBazelArchitecture}/architecture.json \
      --workspace-directory ${architectureOracleSource}/crates \
      --additional-workspace-directory ${architectureOracleSource}/crates/accache \
      --output "$out/parity.json"
  '';
  # Regeneration must remain available when declarations make the checked-in
  # inventory stale. The merge reads only the declared conservative source tree.
  inventories = {
    default = regenerationDefault.inventory;
    fleet = regenerationFleet.inventory;
    production = regenerationProduction.inventory;
    merged = let
      merger = builtins.path {
        path = ../metadata;
        name = "aos-cli-inventory-merger";
        filter = path: type:
          type == "regular" && builtins.elem (baseNameOf path) ["merge_inventory.py" "export_inventory.py"];
      };
    in
      pkgs.runCommand "aos-bazel-aos-cli-source-inventory" {buildDeps = [pkgs.python3];} ''
        mkdir -p "$out"
        export PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=${merger}
        ${pkgs.python3}/bin/python3 ${merger}/merge_inventory.py \
          --root ${regenerationFleet.workspace.source} \
          --inputs ${regenerationProduction.inventory}/inventory.json \
            ${regenerationDefault.inventory}/inventory.json \
            ${regenerationFleet.inventory}/inventory.json \
          --output "$out/inventory.json"
      '';
  };
  default = testConfiguration false;
  fleet = testConfiguration true;
  production = import ../../../tests/build/_bazel-aos-cli-production.nix {inherit pkgs;};
  production-precise = import ../../../tests/build/_bazel-aos-cli-production.nix {
    inherit pkgs;
    sourceInventory = ../../../tools/bazel/metadata/aos-cli-inventory.json;
  };
  execution-profiles = import ../../../tests/build/_bazel-aos-cli-execution-profiles.nix {inherit pkgs;};
}
