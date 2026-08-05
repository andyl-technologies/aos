{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.cliExitMachineReadable",
  taskIds ? ["T-CLI-15"],
  openTaskIds ? [],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoVendor {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-fWBTuyTXJ+/0BiVbB5WAtCqVwufg04NH4BJdocT+moU=";
  };

  cliDoc = builtins.readFile ../../docs/rfcs/0010-crucible/23-cli.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  cliMain = import ./_cli-source.nix {inherit lib;};
  cliProcessTest = builtins.readFile ../../crates/crucible-cli/tests/machine_readable.rs;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/23-cli.md" cliDoc [
      {
        label = "T-CLI-15 machine-readable completion note";
        needle = "Completed by\n  `checks.crucible.phase5.cliExitMachineReadable`";
      }
      {
        label = "T-CLI-15 replay process coverage note";
        needle = "`fuzz`, marker-resolved QEMU `save`, `resume`, and `fork`, `replay --check`";
      }
      {
        label = "T-CLI-15 replay-to process coverage note";
        needle = "and `replay --to <SAVEPOINT>` JSONL output with parsed";
      }
      {
        label = "T-CLI-15 live-QEMU route coverage";
        needle = "including the live-QEMU run/save/resume/fork/search/";
      }
    ]
    ++ forbiddenFor "docs/rfcs/0010-crucible/23-cli.md" cliDoc [
      {
        label = "stale T-CLI-15 remaining gate range";
        needle = "remaining run-capable command-behavior gates (`T-CLI-7 … T-CLI-13`)";
      }
      {
        label = "stale T-CLI-15 open blocker range";
        needle = "remaining run-capable command-behavior gates (`T-CLI-10 … T-CLI-13`)";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "phase5 T-CLI-15 partial note";
        needle = "`T-CLI-15` is completed through `checks.crucible.phase5.cliExitMachineReadable`";
      }
      {
        label = "phase5 T-CLI-15 live-QEMU route coverage";
        needle = "regression-testing the RFC §15 exit-code classes, including the live-QEMU";
      }
      {
        label = "phase5 T-CLI-15 qemu process coverage note";
        needle = "marker-resolved QEMU `save`, `resume`, and\n  `fork`, `replay --check`";
      }
      {
        label = "phase5 T-CLI-15 replay-to process coverage note";
        needle = "and `replay --to <SAVEPOINT>`\n  JSONL output";
      }
    ]
    ++ forbiddenFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "stale phase5 T-CLI-15 remaining gate range";
        needle = "command-behavior gates `T-CLI-7 … T-CLI-13` so the same contract can be";
      }
    ]
    ++ failuresFor "crates/crucible-cli/src/main.rs" cliMain [
      {
        label = "machine-readable format classifier";
        needle = "fn is_machine_readable";
      }
      {
        label = "human output suppression predicate";
        needle = "fn should_emit_human_backend_output";
      }
      {
        label = "dispatch human output suppression predicate";
        needle = "fn should_emit_human_dispatch_output";
      }
      {
        label = "seed announcement uses machine-readable suppression";
        needle = "if emit_human";
      }
      {
        label = "machine-readable trace entries";
        needle = "fn backend_machine_readable_trace_entries";
      }
      {
        label = "final outcome entry kind";
        needle = "kind: String::from(\"final_outcome\")";
      }
      {
        label = "final outcome summary";
        needle = "fn final_outcome_summary";
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
        label = "replay final outcome summary";
        needle = "fn replay_final_outcome_summary";
      }
      {
        label = "final outcome exit code field";
        needle = "exit_code={} canonical_log={}";
      }
      {
        label = "trace output uses final outcome entries";
        needle = "let trace_entries = backend_machine_readable_trace_entries(outcome);";
      }
      {
        label = "json/jsonl suppress human stdout";
        needle = "!format.is_machine_readable()";
      }
      {
        label = "success exit mapping";
        needle = "Self::Outcome(BackendCommandStatus::Passed) => 0";
      }
      {
        label = "failure exit mapping";
        needle = "Self::Outcome(BackendCommandStatus::Failed) => 1";
      }
      {
        label = "timeout exit mapping";
        needle = "Self::Outcome(BackendCommandStatus::Timeout) => 2";
      }
      {
        label = "crash exit mapping";
        needle = "Self::Outcome(BackendCommandStatus::Crashed) => 3";
      }
      {
        label = "identity mismatch exit mapping";
        needle = "Self::Identity(_) => 3";
      }
      {
        label = "discovery/config exit mapping";
        needle = "Self::Backend(_) => 4";
      }
      {
        label = "invalid scenario exit mapping";
        needle = "Self::InvalidScenario(_) => 5";
      }
      {
        label = "usage exit mapping";
        needle = "Self::Usage(_) => 64";
      }
      {
        label = "exit code mapping regression";
        needle = "cli_exit_machine_readable_mapping_matches_rfc_15";
      }
      {
        label = "final outcome output regression";
        needle = "cli_exit_machine_readable_output_records_final_outcome";
      }
    ]
    ++ failuresFor "crates/crucible-cli/tests/machine_readable.rs" cliProcessTest [
      {
        label = "process stdout regression";
        needle = "cli_exit_machine_readable_process_stdout_is_pure_json";
      }
      {
        label = "qemu save process rejection regression";
        needle = "cli_save_qemu_process_requires_packaged_live_guest_assets";
      }
      {
        label = "qemu resume process rejection regression";
        needle = "cli_resume_qemu_process_requires_packaged_live_guest_assets";
      }
      {
        label = "qemu fork process rejection regression";
        needle = "cli_fork_qemu_process_requires_packaged_live_guest_assets";
      }
      {
        label = "search fuzz process stdout regression";
        needle = "cli_exit_machine_readable_search_fuzz_jsonl_reports_final_outcome";
      }
      {
        label = "retained evidence failure process stdout regression";
        needle = "cli_exit_machine_readable_search_retained_evidence_failure_jsonl_reports_final_outcome";
      }
      {
        label = "replay check process stdout regression";
        needle = "cli_exit_machine_readable_replay_check_jsonl_reports_final_outcome";
      }
      {
        label = "replay-to process stdout regression";
        needle = "cli_exit_machine_readable_replay_to_savepoint_jsonl_reports_final_outcome";
      }
      {
        label = "real crucible binary execution";
        needle = "CARGO_BIN_EXE_crucible";
      }
      {
        label = "jsonl parser assertion";
        needle = "serde_json::from_str::<Value>(line)";
      }
      {
        label = "run canonical jsonl assertion";
        needle = "\"run_scenario\"";
      }
      {
        label = "save canonical jsonl assertion";
        needle = "\"save_export\"";
      }
      {
        label = "qemu save live-asset admission assertion";
        needle = "assert!(stderr.contains(\"requires the AOS kernel\"))";
      }
      {
        label = "qemu resume and fork no-unwired assertion";
        needle = "!stderr.contains(\"execution is unavailable\")";
      }
      {
        label = "qemu live route no-double assertion";
        needle = "!stderr.contains(\"double fallback\")";
      }
      {
        label = "search canonical jsonl assertion";
        needle = "\"search_strategy_run\"";
      }
      {
        label = "failure final outcome assertion";
        needle = "exit_code={expected_exit_code}";
      }
      {
        label = "replay artifact canonical jsonl assertion";
        needle = "\"replay_artifact\"";
      }
      {
        label = "replay check canonical jsonl assertion";
        needle = "\"replay_check\"";
      }
      {
        label = "replay-to canonical jsonl assertion";
        needle = "\"replay_to_savepoint\"";
      }
      {
        label = "replay check mismatch jsonl assertion";
        needle = "status=mismatch";
      }
      {
        label = "replay check mismatch exit assertion";
        needle = "replay --check mismatch --format jsonl should exit 1";
      }
      {
        label = "replay human text forbidden in process stdout";
        needle = "crucible: replay artifact";
      }
      {
        label = "retained evidence failure exit assertion";
        needle = "retained-evidence search --format jsonl should exit 1";
      }
      {
        label = "fuzz canonical jsonl assertion";
        needle = "\"coverage_guided_fuzz_run\"";
      }
      {
        label = "final outcome last record assertion";
        needle = "final_outcome should be the last machine-readable record";
      }
      {
        label = "jsonl process assertion";
        needle = "jsonl stdout must contain only JSON object lines";
      }
      {
        label = "json process assertion";
        needle = "json stdout must start with a JSON array";
      }
      {
        label = "human text forbidden in process stdout";
        needle = "stdout must not contain human text";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase5 exposes CLI exit machine-readable check";
        needle = "cliExitMachineReadable = import ./phase5-cli-exit-machine-readable.nix";
      }
    ];

  failureText = builtins.concatStringsSep "\n" failures;
in
  if failures != []
  then throw "crucible phase5 CLI exit machine-readable check failed:\n${failureText}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase5-cli-exit-machine-readable";
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
            sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
                > .cargo/config.toml
          '';
        }
        {
          name = "run-cli-exit-machine-readable";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-cli-exit-machine-readable-target" \
              -p crucible-cli \
              cli_exit_machine_readable \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-cli-exit-machine-readable-target" \
              --features test-double \
              -p crucible-cli \
              --test machine_readable \
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
            evidence_scope=process-format-and-exit-code-model-routes
            component=crucible-cli
            contract=exit-codes-and-machine-readable-final-outcome
            process_matrix=local-double-qemu-replay-jsonl
            dependencies=$DEPENDENCY_COUNT
            RESULT
          '';
        }
      ];
    }
