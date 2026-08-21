{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.workloadSeed",
  taskIds ? ["T-WL-3"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = import ../../pkgs/tools/crucible/_cargo-deps-hash.nix;
  };

  workloadDoc = builtins.readFile ../../docs/rfcs/0010-crucible/33-examples-and-workloads.md;
  engineModel = import ./_crucible-model-source.nix {inherit lib;};
  engineLib = builtins.readFile ../../crates/crucible/src/lib.rs;
  workloadTest = builtins.readFile ../../crates/crucible/tests/workload_model.rs;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/33-examples-and-workloads.md" workloadDoc [
      {
        label = "T-WL-3 completion note";
        needle = "Completed by `checks.crucible.phase4.workloadSeed`";
      }
      {
        label = "black-box workload seed note";
        needle = "GuestWorkloadSeed";
      }
      {
        label = "plain cmdline workload seed";
        needle = "`wseed=0x...`";
      }
      {
        label = "white-box not required";
        needle = "white-box path is never required";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" engineModel [
      {
        label = "workload seed scenario parameter";
        needle = "pub const WORKLOAD_SEED_SCENARIO_PARAMETER: &str = \"wseed\";";
      }
      {
        label = "black-box suffices invariant";
        needle = "pub const WORKLOAD_SEED_BLACK_BOX_CONFIG_SUFFICES: bool = true;";
      }
      {
        label = "white-box not required invariant";
        needle = "pub const WORKLOAD_SEED_REQUIRES_WHITE_BOX: bool = false;";
      }
      {
        label = "workload seed type";
        needle = "pub struct GuestWorkloadSeed";
      }
      {
        label = "workload seed cmdline helper";
        needle = "pub fn guest_workload_seed(mut self, seed: GuestWorkloadSeed) -> Self";
      }
      {
        label = "world node workload seed parser";
        needle = "pub fn guest_workload_seed(&self) -> Option<GuestWorkloadSeed>";
      }
      {
        label = "workload seed parser";
        needle = "fn parse_guest_workload_seed_parameter";
      }
      {
        label = "workload seed command-line rendering";
        needle = "fn cmdline_with_guest_workload_seed";
      }
      {
        label = "invalid workload seed error";
        needle = "WorldNodeInvalidWorkloadSeed";
      }
      {
        label = "duplicate workload seed error";
        needle = "WorldNodeDuplicateWorkloadSeed";
      }
      {
        label = "workload seed validator";
        needle = "fn validate_world_node_workload_seed";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" engineLib [
      {
        label = "workload seed type re-export";
        needle = "GuestWorkloadSeed";
      }
      {
        label = "workload seed parameter re-export";
        needle = "WORKLOAD_SEED_SCENARIO_PARAMETER";
      }
      {
        label = "black-box suffices re-export";
        needle = "WORKLOAD_SEED_BLACK_BOX_CONFIG_SUFFICES";
      }
      {
        label = "white-box not-required re-export";
        needle = "WORKLOAD_SEED_REQUIRES_WHITE_BOX";
      }
    ]
    ++ failuresFor "crates/crucible/tests/workload_model.rs" workloadTest [
      {
        label = "plain cmdline seed test";
        needle = "workload_seed_is_plain_content_addressed_cmdline_config";
      }
      {
        label = "scenario identity seed test";
        needle = "workload_seed_changes_scenario_identity_without_changing_global_seed";
      }
      {
        label = "black-box suffices test";
        needle = "workload_seed_black_box_config_path_suffices_without_white_box";
      }
      {
        label = "malformed duplicate seed test";
        needle = "workload_seed_rejects_malformed_and_duplicate_values";
      }
      {
        label = "serialized seed validation test";
        needle = "workload_seed_rejects_malformed_toml_and_binary_forms";
      }
      {
        label = "white-box disabled assertion";
        needle = "WhiteBoxPolicy::Disabled";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 workload seed import";
        needle = "workloadSeed = import ./phase4-workload-seed.nix";
      }
      {
        label = "phase4 workload seed attr path";
        needle = "checks.crucible.phase4.workloadSeed";
      }
      {
        label = "phase4 workload seed task id";
        needle = "taskIds = [\"T-WL-3\"]";
      }
    ];
in
  if failures != []
  then
    throw ''
      crucible phase4 workload seed check failed:
      ${builtins.concatStringsSep "\n" failures}
    ''
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-workload-seed";
      version = "0";
      src = crucibleSrc;
      buildDeps = [pkgs.coreutils pkgs.rust pkgs.sed];
      phases = [
        {
          name = "unpack";
          script = ''
            cp -R "$src" source
            chmod -R u+w source
            cd source
          '';
        }
        {
          name = "configure";
          script = ''
            set -eu
            export CARGO_HOME="$TMPDIR/cargo-home"
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            mkdir -p "$CARGO_HOME" .cargo
            if [ -f "${cargoDeps}/.cargo/config.toml" ]; then
              sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
                > .cargo/config.toml
            else
              printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "${cargoDeps}"\n\n' \
                > .cargo/config.toml
            fi
          '';
        }
        {
          name = "run-workload-seed";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            require_listed() {
              listed="$1"
              test_name="$2"
              if [ -z "$(sed -n "/$test_name/p" "$listed")" ]; then
                printf 'missing expected test: %s\n' "$test_name" >&2
                exit 1
              fi
            }
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-workload-seed-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test workload_model \
              -- --list > "$TMPDIR/workload-seed-tests"
            require_listed \
              "$TMPDIR/workload-seed-tests" \
              "workload_seed_is_plain_content_addressed_cmdline_config"
            require_listed \
              "$TMPDIR/workload-seed-tests" \
              "workload_seed_changes_scenario_identity_without_changing_global_seed"
            require_listed \
              "$TMPDIR/workload-seed-tests" \
              "workload_seed_black_box_config_path_suffices_without_white_box"
            require_listed \
              "$TMPDIR/workload-seed-tests" \
              "workload_seed_rejects_malformed_and_duplicate_values"
            require_listed \
              "$TMPDIR/workload-seed-tests" \
              "workload_seed_rejects_malformed_toml_and_binary_forms"
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-workload-seed-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test workload_model \
              workload_seed_is_plain_content_addressed_cmdline_config \
              -- --exact --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-workload-seed-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test workload_model \
              workload_seed_changes_scenario_identity_without_changing_global_seed \
              -- --exact --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-workload-seed-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test workload_model \
              workload_seed_black_box_config_path_suffices_without_white_box \
              -- --exact --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-workload-seed-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test workload_model \
              workload_seed_rejects_malformed_and_duplicate_values \
              -- --exact --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-workload-seed-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test workload_model \
              workload_seed_rejects_malformed_toml_and_binary_forms \
              -- --exact --test-threads=1
          '';
        }
        {
          name = "write-result";
          script = ''
            set -eu
            mkdir -p "$out"
            cat > "$out/result" <<'RESULT'
            PASS
            check=${attrPath}
            tasks=${taskList}
            workload_seed_parameter=wseed
            workload_seed_delivery=black-box-cmdline
            workload_seed_content_addressed=true
            workload_seed_white_box_required=false
            workload_seed_validation=malformed-and-duplicate-rejected
            RESULT
          '';
        }
      ];
    }
