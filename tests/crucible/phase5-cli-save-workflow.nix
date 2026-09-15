{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.cliSaveWorkflow",
  taskIds ? ["T-CLI-9"],
  openTaskIds ? [],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  cliDoc = builtins.readFile ../../docs/rfcs/0010-crucible/23-cli.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  cliMain = import ./_cli-source.nix {inherit lib;};
  cliCampaignRun = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-cli/src/cli/campaign_run.rs;
  };
  daemonCampaignLifecycle = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-daemon/src/qemu_campaign_lifecycle.rs;
  };
  portableArtifactConstants = builtins.readFile ../../crates/crucible-cli/src/portable_artifact_constants.rs;
  cliMachineReadable = builtins.readFile ../../crates/crucible-cli/tests/machine_readable.rs;
  campaignProcessTest = builtins.readFile ../../crates/crucible-cli/tests/campaign_process.rs;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/23-cli.md" cliDoc [
      {
        label = "T-CLI-9 completion";
        needle = "[x] **T-CLI-9** Implement `save` as a Campaign-owned semantic-stop";
      }
      {
        label = "portable handle identity";
        needle = "current v5 and v6 handles bind the";
      }
      {
        label = "authenticated replay closure";
        needle = "scenario, schedule, replay closure, exact frontier";
      }
      {
        label = "no physical checkpoint in handle";
        needle = "never
  persists a physical QEMU checkpoint in the handle";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "phase5 CLI save completion";
        needle = "`T-CLI-9` is completed through `checks.crucible.phase5.cliSaveWorkflow`";
      }
      {
        label = "Campaign exact checkpoint";
        needle = "Campaign-owned semantic stops capture an authenticated exact checkpoint";
      }
      {
        label = "closed Campaign owner";
        needle = "use the same fail-closed Campaign owner";
      }
    ]
    ++ failuresFor "crates/crucible-cli/src/main.rs" cliMain [
      {
        label = "save arguments";
        needle = "struct SaveArgs";
      }
      {
        label = "save planner";
        needle = "fn plan_save_invocation";
      }
      {
        label = "save handle exporter";
        needle = "fn export_savepoint_handle";
      }
      {
        label = "authenticated replay closure field";
        needle = "campaign-replay-closure";
      }
      {
        label = "selector proof rejection test";
        needle = "cli_save_selector_proof_rejects_invalid_breakpoint_evidence";
      }
    ]
    ++ failuresFor "crates/crucible-cli/src/cli/campaign_run.rs" cliCampaignRun [
      {
        label = "Campaign-owned QEMU save";
        needle = "fn run_local_qemu_campaign_save_workflow";
      }
      {
        label = "exact savepoint validation";
        needle = "fn validate_campaign_savepoint";
      }
      {
        label = "portable save report";
        needle = "fn campaign_save_workflow_report";
      }
      {
        label = "marker and observation proof";
        needle = "fn campaign_save_boundary_proof";
      }
      {
        label = "authenticated replay closure export";
        needle = ".replay_closure()";
      }
      {
        label = "transient exact-store cleanup";
        needle = "fn complete_transient_checkpoint_workflow";
      }
      {
        label = "current exact save regressions";
        needle = "campaign_virtual_time_save_exports_closure_for_resume_and_replay_readers";
      }
    ]
    ++ failuresFor "crates/crucible-daemon/src/qemu_campaign_lifecycle.rs" daemonCampaignLifecycle [
      {
        label = "reached-stop exact capture";
        needle = "pub fn with_reached_stop_savepoint_capture";
      }
      {
        label = "authenticated savepoint output";
        needle = "pub const fn savepoint";
      }
    ]
    ++ failuresFor "crates/crucible-cli/src/portable_artifact_constants.rs" portableArtifactConstants [
      {
        label = "current replay-closure handle schema";
        needle = "crucible.savepoint-handle.v5";
      }
      {
        label = "current observation handle schema";
        needle = "crucible.savepoint-handle.v6";
      }
    ]
    ++ failuresFor "crates/crucible-cli/tests/machine_readable.rs" cliMachineReadable [
      {
        label = "machine-readable session-owned save rejection";
        needle = "cli_save_machine_readable_jsonl_rejects_session_owned_export";
      }
    ]
    ++ failuresFor "crates/crucible-cli/tests/campaign_process.rs" campaignProcessTest [
      {
        label = "packaged Campaign save and native resume regression";
        needle = "campaign_virtual_time_save_feeds_native_resume";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase5 exposes CLI save workflow check";
        needle = "cliSaveWorkflow = import ./phase5-cli-save-workflow.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase5 CLI save workflow check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase5-cli-save-workflow";
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
          name = "run-cli-save-workflow";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-cli-save-workflow-target" \
              -p crucible-cli \
              cli_save \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-cli-save-workflow-target" \
              -p crucible-cli \
              cli_save_machine_readable_jsonl_rejects_session_owned_export \
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
            evidence_scope=campaign-exact-save-unit-and-process-admission
            component=crucible-cli
            contract=authenticated-campaign-save
            process_qemu_save=packaged-live-asset-admission
            dependencies=$DEPENDENCY_COUNT
            RESULT
          '';
        }
      ];
    }
