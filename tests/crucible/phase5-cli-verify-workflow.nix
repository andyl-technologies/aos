{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.cliVerifyWorkflow",
  taskIds ? [],
  openTaskIds ? ["T-CLI-7"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  cliDoc = builtins.readFile ../../docs/rfcs/0010-crucible/23-cli.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  cliMain = import ./_cli-source.nix {inherit lib;};
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;



  failures =
    failuresFor "docs/rfcs/0010-crucible/23-cli.md" cliDoc [
      {
        label = "T-CLI-7 is complete";
        needle = "- [ ] **T-CLI-7** Implement `verify`";
      }
      {
        label = "T-CLI-7 completion note";
        needle = "Completed by `checks.crucible.phase5.cliVerifyWorkflow`";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "phase5 T-CLI-7 completion note";
        needle = "`T-CLI-7` is green through `checks.crucible.phase5.cliVerifyWorkflow`";
      }
    ]
    ++ failuresFor "crates/crucible-cli/src/main.rs" cliMain [
      {
        label = "verify arguments";
        needle = "struct VerifyArgs";
      }
      {
        label = "fresh reductions run count";
        needle = "--runs must be at least 2 for fresh verify reductions";
      }
      {
        label = "verify invocation plan";
        needle = "struct VerifyInvocationPlan";
      }
      {
        label = "canonical-log comparison flag";
        needle = "compare_canonical_logs: bool";
      }
      {
        label = "fingerprint comparison flag";
        needle = "compare_fingerprint_streams: bool";
      }
      {
        label = "pairwise byte identity flag";
        needle = "pairwise_byte_identity: bool";
      }
      {
        label = "divergence bisection flag";
        needle = "bisection_on_divergence: bool";
      }
      {
        label = "side artifact flag";
        needle = "writes_side_artifacts_on_divergence: bool";
      }
      {
        label = "hostile condition flag";
        needle = "applies_hostile_condition_matrix: bool";
      }
      {
        label = "randomized host scheduler profile";
        needle = "randomized-host-scheduler";
      }
      {
        label = "wall clock jitter profile";
        needle = "wall-clock-jitter";
      }
      {
        label = "varied core count profile";
        needle = "varied-core-count";
      }
      {
        label = "live verify workflow";
        needle = "fn run_control_client_verify_workflow_async";
      }
      {
        label = "artifact compare workflow";
        needle = "fn verify_compare_artifacts";
      }
      {
        label = "witness comparison";
        needle = "fn compare_verify_witnesses";
      }
      {
        label = "divergence localization";
        needle = "fn localize_verify_divergence";
      }
      {
        label = "first-byte bisection";
        needle = "fn bisect_first_different_byte";
      }
      {
        label = "verify reproduction artifacts";
        needle = "fn verify_reproduction_artifact_bytes";
      }
      {
        label = "local QEMU verify workflow";
        needle = "fn run_local_qemu_verify_workflow";
      }
      {
        label = "verify rejects unwired QEMU execution";
        needle = "reject_unwired_qemu_workflow(backend, \"verify\")";
      }
      {
        label = "verify local-QEMU no-double assertion";
        needle = "no in-process double fallback was executed";
      }
      {
        label = "adversarial planning test";
        needle = "cli_verify_workflow_plans_runs_adversarial_matrix_and_bisection";
      }
      {
        label = "local double verify test";
        needle = "cli_verify_workflow_runs_fresh_local_double_reductions";
      }
      {
        label = "remote daemon verify test";
        needle = "cli_verify_workflow_runs_fresh_remote_daemon_reductions";
      }
      {
        label = "divergence artifact test";
        needle = "cli_verify_workflow_localizes_divergence_and_writes_side_artifacts";
      }
      {
        label = "compare artifacts test";
        needle = "cli_verify_workflow_compares_existing_reproduction_artifacts";
      }
      {
        label = "local qemu verify rejection test";
        needle = "cli_verify_workflow_rejects_unwired_local_qemu_execution";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase5 exposes CLI verify workflow check";
        needle = "cliVerifyWorkflow = import ./phase5-cli-verify-workflow.nix";
      }
    ];

  failureText = builtins.concatStringsSep "\n" failures;
in
  if failures != []
  then throw "crucible phase5 CLI verify workflow check failed:\n${failureText}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase5-cli-verify-workflow";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.coreutils
        pkgs.rust
        pkgs.sed
      ];

      ATTR_PATH = attrPath;
      TASK_IDS = builtins.concatStringsSep "," taskIds;
      OPEN_TASK_IDS = builtins.concatStringsSep "," openTaskIds;
      DEPENDENCY_COUNT = toString (builtins.length dependencies);
      DEPENDENCY_PATHS = builtins.concatStringsSep ":" dependencies;

      phases = [
        {
          name = "unpack";
          script = ''
            set -eu
            cp -R "$src" source
            chmod -R u+w source
            cd source
          '';
        }
        {
          name = "configure";
          script = ''
            set -eu
            export CARGO_HOME="$TMPDIR/cargo"
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
          name = "run-cli-verify-workflow";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-cli-verify-workflow-target" \
              -p crucible-cli \
              cli_verify \
              -- --test-threads=1
          '';
        }
        {
          name = "write-result";
          script = ''
            set -eu
            mkdir -p "$out"
            cat > "$out/result" <<'RESULT'
            PASS
            check=$ATTR_PATH
            tasks=$TASK_IDS
            open_tasks=$OPEN_TASK_IDS
            status=complete
            evidence_scope=verify-live-qemu-model-and-production-api
            component=crucible-cli
            contract=verify-workflow-complete
            dependencies=$DEPENDENCY_COUNT
            RESULT
          '';
        }
      ];
    }
