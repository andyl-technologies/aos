{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.cliReplayCheck",
  taskIds ? ["T-CLI-12"],
  openTaskIds ? [],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
  networkInitramfs = import ./phase2-qemu-live-network-io-guest.nix {inherit pkgs;};

  cliDoc = builtins.readFile ../../docs/rfcs/0010-crucible/23-cli.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  cliMain = import ./_cli-source.nix {inherit lib;};
  liveReplayContract =
    builtins.readFile ../../crates/crucible-cli/src/cli/artifact/live_qemu.rs
    + builtins.readFile ../../crates/crucible-cli/src/cli/artifact/live_qemu/tests.rs;
  artifactCapture = builtins.concatStringsSep "\n" (map builtins.readFile [
    ../../crates/crucible-cli/src/cli/artifact_capture.rs
    ../../crates/crucible-cli/src/cli/artifact_capture_test.rs
  ]);
  cliMachineReadable = builtins.readFile ../../crates/crucible-cli/tests/machine_readable.rs;
  cliE2e = builtins.readFile ../../crates/crucible-cli/tests/gate_e2e_determinism.rs;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/23-cli.md" cliDoc [
      {
        label = "T-CLI-12 replay check partial-evidence note";
        needle = "Completed under `checks.crucible.phase5.cliReplayCheck`";
      }
      {
        label = "replay bisect progress";
        needle = "artifact-to-artifact `--bisect <other-artifact>`";
      }
      {
        label = "content-addressed replay component resolution progress";
        needle = "resolves missing content-addressed component payloads";
      }
      {
        label = "process replay check progress";
        needle = "process-tests real-binary\n  `replay --check` success/mismatch and `replay --to <SAVEPOINT>`";
      }
      {
        label = "process replay to progress";
        needle = "target-validation JSONL output with replay records plus `final_outcome`";
      }
      {
        label = "replay identity before store progress";
        needle = "pinned identity path before store access";
      }
      {
        label = "replay inline store validation progress";
        needle = "validates declared DAG-store references against inline payloads";
      }
      {
        label = "replay to synopsis";
        needle = "--to <savepoint>        Validate a target savepoint handle or checkpoint hash.";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "phase5 CLI replay check completion note";
        needle = "`T-CLI-12` is completed through `checks.crucible.phase5.cliReplayCheck`";
      }
      {
        label = "phase5 process replay check progress";
        needle = "process-level\n  `replay --check` success/mismatch and `replay --to <SAVEPOINT>`";
      }
      {
        label = "phase5 process replay to progress";
        needle = "target-validation JSONL coverage with replay records plus `final_outcome`";
      }
    ]
    ++ failuresFor "crates/crucible-cli/src/main.rs" cliMain [
      {
        label = "replay check flag";
        needle = "check: Option<PathBuf>";
      }
      {
        label = "replay bisect flag";
        needle = "bisect: Option<PathBuf>";
      }
      {
        label = "replay canonical log reconstruction";
        needle = "let canonical_log_bytes = canonical_log_entry_bytes(&canonical_log);";
      }
      {
        label = "ordinary replay pure reduction execution";
        needle = "fn replay_embedded_model_artifact";
      }
      {
        label = "ordinary replay invokes the model reproduction oracle";
        needle = "let replay = model.replay()";
      }
      {
        label = "ordinary replay reduction test";
        needle = "cli_replay_reexecutes_embedded_model_reproduction";
      }
      {
        label = "failed-run artifact reduction test";
        needle = "a failed-run artifact must reexecute its embedded model reproduction";
      }
      {
        label = "replay component hydration";
        needle = "fn hydrate_replay_artifact_components";
      }
      {
        label = "replay component store URI resolution";
        needle = "parse_blake3_content_hash(\"component store URI\"";
      }
      {
        label = "replay bisect implementation";
        needle = "fn replay_bisect_artifacts";
      }
      {
        label = "replay bisect divergence error";
        needle = "replay --bisect divergence";
      }
      {
        label = "dedicated replay check error";
        needle = "CliError::ReplayCheck";
      }
      {
        label = "byte mismatch diagnostic";
        needle = "replay --check mismatch";
      }
      {
        label = "byte mismatch first difference";
        needle = "first_diff_byte=";
      }
      {
        label = "byte mismatch length diagnostics";
        needle = "original_len=";
      }
      {
        label = "byte mismatch replayed length diagnostics";
        needle = "replayed_len=";
      }
      {
        label = "byte-identical replay check test";
        needle = "cli_replay_check_accepts_byte_identical_canonical_log";
      }
      {
        label = "content-addressed component replay test";
        needle = "cli_replay_resolves_content_addressed_component_payloads";
      }
      {
        label = "externalized identity priority test";
        needle = "cli_replay_externalized_identity_mismatch_keeps_identity_exit";
      }
      {
        label = "inline payload store URI mismatch test";
        needle = "cli_replay_rejects_inline_component_store_uri_mismatch";
      }
      {
        label = "replay check uses public JSONL trace bytes";
        needle = "emit_canonical_trace(OutputFormat::Jsonl";
      }
      {
        label = "replay check reconstructs decision payload summaries";
        needle = "fn decision_payload_summary";
      }
      {
        label = "mismatched replay check test";
        needle = "cli_replay_check_rejects_mismatch_with_failure_exit";
      }
      {
        label = "replay help advertises check";
        needle = "--check <original-log>";
      }
      {
        label = "replay help advertises bisect";
        needle = "--bisect <other-artifact>";
      }
      {
        label = "replay to savepoint flag";
        needle = "to: Option<String>";
      }
      {
        label = "replay to savepoint implementation";
        needle = "fn replay_to_savepoint";
      }
      {
        label = "replay to savepoint evidence validation";
        needle = "savepoint_evidence(\"replay --to\"";
      }
      {
        label = "replay to savepoint oracle validation";
        needle = "let oracle = validate_checkpoint_with_replay_oracle";
      }
      {
        label = "replay to savepoint prefix check";
        needle = "savepoint frontier has {target_decisions} decisions";
      }
      {
        label = "typed replay to schedule-prefix proof schema";
        needle = "crucible.replay.schedule-prefix-proof.v1";
      }
      {
        label = "typed replay to schedule-prefix proof implementation";
        needle = "fn prove_replay_schedule_prefix";
      }
      {
        label = "typed replay to schedule-prefix output";
        needle = "schedule_prefix=typed";
      }
      {
        label = "typed replay to schedule-prefix digest";
        needle = "typed_prefix_digest";
      }
      {
        label = "typed replay to resolved payload binding";
        needle = "let actual_payload_summary = decision_payload_summary(artifact, actual)?;";
      }
      {
        label = "typed replay to status line helper";
        needle = "fn replay_to_savepoint_status_line";
      }
      {
        label = "replay human output writer";
        needle = "fn write_replay_report_human";
      }
      {
        label = "replay dispatch emits replay report output";
        needle = "emit_replay_report_output(cli, &report)?;";
      }
      {
        label = "replay machine-readable output helper";
        needle = "fn emit_replay_report_output";
      }
      {
        label = "replay machine-readable trace entries";
        needle = "fn replay_machine_readable_trace_entries";
      }
      {
        label = "typed replay to non-prefix diagnostic";
        needle = "schedule-prefix mismatch at decision";
      }
      {
        label = "typed replay to non-prefix rejection test";
        needle = "cli_replay_to_savepoint_rejects_non_matching_schedule_prefix";
      }
      {
        label = "typed replay to missing payload rejection test";
        needle = "cli_replay_to_savepoint_rejects_missing_prefix_decision_payload";
      }
      {
        label = "replay to materialized temporal graph implementation";
        needle = "fn materialize_replay_to_savepoint";
      }
      {
        label = "replay to unified replay operation";
        needle = "UnifiedGraphOperationEvidence::Replay";
      }
      {
        label = "replay to unified operation validation";
        needle = "validate_unified_operation";
      }
      {
        label = "replay to materialized temporal graph output";
        needle = "materialization=model-temporal-graph";
      }
      {
        label = "replay to single VM fingerprint output";
        needle = "single_vm_fingerprint";
      }
      {
        label = "replay to materialized checkpoint output";
        needle = "materialized_checkpoint";
      }
      {
        label = "replay to savepoint target validation output";
        needle = "status=target-validated";
      }
      {
        label = "replay help advertises to";
        needle = "--to <savepoint>";
      }
      {
        label = "replay to savepoint positive test";
        needle = "cli_replay_to_savepoint_validates_artifact_prefix_and_oracle";
      }
      {
        label = "replay to checkpoint hash test";
        needle = "write_checkpoint_closure_fixture(&store_root";
      }
      {
        label = "replay to savepoint scenario mismatch test";
        needle = "cli_replay_to_savepoint_rejects_scenario_mismatch";
      }
      {
        label = "replay to savepoint prefix overrun test";
        needle = "cli_replay_to_savepoint_rejects_target_beyond_artifact_prefix";
      }
      {
        label = "replay bisect divergence test";
        needle = "cli_replay_bisects_artifact_divergence";
      }
      {
        label = "replay bisect identical test";
        needle = "cli_replay_bisect_accepts_identical_artifacts";
      }
    ]
    ++ failuresFor "crates/crucible-cli/src/cli/artifact/live_qemu.rs" liveReplayContract [
      {
        label = "closed live replay producer matrix";
        needle = "live_qemu_replay_contract_accepts_every_closed_producer";
      }
      {
        label = "unchanged fork resume recipe regression";
        needle = "live_qemu_replay_contract_round_trips_unmodified_fork_resume";
      }
      {
        label = "pre-branch choice rejection regression";
        needle = "live_qemu_replay_contract_rejects_pre_branch_choices";
      }
      {
        label = "fingerprint scope compatibility regression";
        needle = "live_qemu_replay_contract_rejects_incompatible_fingerprint_scope";
      }
      {
        label = "unknown control command regression";
        needle = "live_qemu_replay_contract_rejects_unknown_control_commands";
      }
      {
        label = "unsupported startup control regression";
        needle = "live_qemu_replay_contract_rejects_unsupported_startup_controls";
      }
      {
        label = "initial control ordering regression";
        needle = "live_qemu_replay_contract_rejects_noncontiguous_initial_controls";
      }
    ]
    ++ failuresFor "crates/crucible-cli/src/cli/artifact_capture.rs" artifactCapture [
      {
        label = "terminal all-node capture selection regression";
        needle = "terminal_fingerprint_capture_selects_one_reindexed_sample_per_node";
      }
      {
        label = "terminal duplicate-node capture rejection regression";
        needle = "terminal_fingerprint_capture_rejects_duplicate_node_suffix";
      }
    ]
    ++ failuresFor "crates/crucible-cli/tests/machine_readable.rs" cliMachineReadable [
      {
        label = "process replay check JSONL regression";
        needle = "cli_exit_machine_readable_replay_check_jsonl_reports_final_outcome";
      }
      {
        label = "process replay artifact record assertion";
        needle = "\"replay_artifact\"";
      }
      {
        label = "process replay check record assertion";
        needle = "\"replay_check\"";
      }
      {
        label = "process replay check mismatch exit assertion";
        needle = "replay --check mismatch --format jsonl should exit 1";
      }
      {
        label = "process replay check mismatch status assertion";
        needle = "status=mismatch";
      }
      {
        label = "process replay to JSONL regression";
        needle = "cli_exit_machine_readable_replay_to_savepoint_jsonl_reports_final_outcome";
      }
      {
        label = "process replay to record assertion";
        needle = "\"replay_to_savepoint\"";
      }
      {
        label = "process replay to target validation assertion";
        needle = "status=target-validated";
      }
      {
        label = "process replay to materialization assertion";
        needle = "materialization=model-temporal-graph";
      }
      {
        label = "process replay to unified operation assertion";
        needle = "unified_operation=replay";
      }
      {
        label = "process replay to human text forbidden assertion";
        needle = "assert!(!stdout.contains(\"crucible: replay --to\"));";
      }
    ]
    ++ failuresFor "crates/crucible-cli/tests/gate_e2e_determinism.rs" cliE2e [
      {
        label = "machine-independent replay profile test";
        needle = "gate_e2e_determinism_cli_target_replays_from_artifact_on_different_machine_profile";
      }
      {
        label = "machine-independent quiet profile";
        needle = "HostAdversaryProfile::quiet_single_core()";
      }
      {
        label = "machine-independent loaded profile";
        needle = "HostAdversaryProfile::loaded_many_core()";
      }
      {
        label = "machine-independent profile distinction";
        needle = "assert_ne!(reproduced.profile, baseline.profile);";
      }
      {
        label = "machine-independent canonical-log identity";
        needle = "assert_eq!(reproduced.canonical_log, baseline.canonical_log);";
      }
      {
        label = "machine-independent fingerprint identity";
        needle = "assert_eq!(reproduced.final_fingerprint, baseline.final_fingerprint);";
      }
      {
        label = "machine-independent artifact identity";
        needle = "assert_eq!(reproduced.artifact_digest, baseline.artifact_digest);";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase5 exposes CLI replay check";
        needle = "cliReplayCheck = import ./phase5-cli-replay-check.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase5 CLI replay check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase5-cli-replay-check";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.coreutils
        pkgs.crucible
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
            cp -R "$src" source
            chmod -R u+w source
            cd source
          '';
        }
        {
          name = "configure";
          script = ''
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
          name = "run-cli-replay-check";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-cli-replay-check-target" \
              -p crucible-cli \
              cli_replay \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-cli-replay-check-target" \
              -p crucible-cli \
              live_qemu_replay_contract \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-cli-replay-check-target" \
              -p crucible-cli \
              terminal_fingerprint_capture \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-cli-replay-check-target" \
              -p crucible-cli \
              --test gate_e2e_determinism \
              gate_e2e_determinism_cli_target_replays_from_artifact_on_different_machine_profile \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-cli-replay-check-target" \
              -p crucible-cli \
              cli_help_surface_rejects_unimplemented_future_flags \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-cli-replay-check-target" \
              -p crucible-cli \
              cli_exit_machine_readable_replay_check_jsonl_reports_final_outcome \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-cli-replay-check-target" \
              -p crucible-cli \
              cli_exit_machine_readable_replay_to_savepoint_jsonl_reports_final_outcome \
              -- --test-threads=1

            artifact_dir="$TMPDIR/crucible-live-replay-artifacts"
            store_dir="$TMPDIR/crucible-live-replay-store"
            producer_log="$TMPDIR/crucible-live-replay-producer.jsonl"
            mkdir -p "$artifact_dir" "$store_dir"
            set +e
            CRUCIBLE_INITRD="${networkInitramfs}/initrd.img" \
              "${pkgs.crucible}/bin/crucible" \
              --backend qemu \
              --seed 42 \
              --format jsonl \
              --trace "$producer_log" \
              --artifact-dir "$artifact_dir" \
              --store "$store_dir" \
              run \
              ../tests/crucible/fixtures/happy-path.scenario.toml \
              --max-quanta 1 \
              --save-on fail \
              > "$TMPDIR/crucible-live-replay-producer.out"
            producer_status=$?
            set -e
            test "$producer_status" -eq 2
            artifact=$(find "$artifact_dir" -type f -name 'repro-timeout-*.crucible' -print -quit)
            test -n "$artifact"
            checkpoint=$(
              sed -n \
                's/.*checkpoint=\(blake3:[0-9a-f]*\).*/\1/p' \
                "$TMPDIR/crucible-live-replay-producer.out"
            )
            test -n "$checkpoint"
            # The artifact-owned canonical log ends before the CLI's
            # self-referential final-outcome line, which names the completed
            # artifact digest.
            sed '$d' "$producer_log" > "$TMPDIR/crucible-live-replay-check.jsonl"

            CRUCIBLE_INITRD="${networkInitramfs}/initrd.img" \
              "${pkgs.crucible}/bin/crucible" \
              --backend qemu \
              --format jsonl \
              --store "$store_dir" \
              replay "$artifact" \
              > "$TMPDIR/crucible-live-replay.out"
            CRUCIBLE_INITRD="${networkInitramfs}/initrd.img" \
              "${pkgs.crucible}/bin/crucible" \
              --backend qemu \
              --format jsonl \
              --store "$store_dir" \
              replay "$artifact" \
              --check "$TMPDIR/crucible-live-replay-check.jsonl" \
              > "$TMPDIR/crucible-live-replay-check.out"
            CRUCIBLE_INITRD="${networkInitramfs}/initrd.img" \
              "${pkgs.crucible}/bin/crucible" \
              --backend qemu \
              --format jsonl \
              --store "$store_dir" \
              replay "$artifact" \
              --bisect "$artifact" \
              > "$TMPDIR/crucible-live-replay-bisect.out"
            CRUCIBLE_INITRD="${networkInitramfs}/initrd.img" \
              "${pkgs.crucible}/bin/crucible" \
              --backend qemu \
              --format jsonl \
              --store "$store_dir" \
              replay "$artifact" \
              --to "$checkpoint" \
              > "$TMPDIR/crucible-live-replay-to.out"

            grep -q '"kind":"replay_reduction".*status=reexecuted' \
              "$TMPDIR/crucible-live-replay.out"
            grep -q '"kind":"replay_live_qemu".*status=validated.*producer=run' \
              "$TMPDIR/crucible-live-replay.out"
            grep -q '"kind":"replay_check".*status=byte-identical' \
              "$TMPDIR/crucible-live-replay-check.out"
            grep -q '"kind":"replay_bisect".*status=byte-identical' \
              "$TMPDIR/crucible-live-replay-bisect.out"
            grep -q '"kind":"replay_to_savepoint".*status=target-validated' \
              "$TMPDIR/crucible-live-replay-to.out"
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
            evidence_scope=replay-model-and-live-qemu-process-validation
            component=crucible-cli
            replay_check=byte-identical-canonical-log
            replay_to_schedule_prefix=typed-payload-backed
            replay_to_materialization=model-temporal-graph
            replay_machine_independent=mock-host-profile
            replay_process=live-qemu-ordinary,check,both-bisect-sides,to-savepoint-target-validation
            producer_contract_matrix=run,verify,search,fuzz,fork
            dependencies=$DEPENDENCY_COUNT
            RESULT
          '';
        }
      ];
    }
