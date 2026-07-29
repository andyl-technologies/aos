{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.eventLogDeterminism",
  taskIds ? ["T-OBS-6"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  model = import ./_crucible-model-source.nix {inherit lib;};
  trigger = import ./_crucible-trigger-source.nix {inherit lib;};
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  determinismTest = builtins.readFile ../../crates/crucible/tests/event_log_determinism.rs;
  replayOracleTest = builtins.readFile ../../crates/crucible/tests/gate_replay_oracle.rs;
  e2eDeterminismTest = builtins.readFile ../../crates/crucible/tests/gate_e2e_determinism_concurrency.rs;
  observabilityDoc = builtins.readFile ../../docs/rfcs/0010-crucible/19-observability-event-log.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;


  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/19-observability-event-log.md" observabilityDoc [
      {
        label = "T-OBS-6 checked off";
        needle = "- [x] **T-OBS-6**";
      }
      {
        label = "T-OBS-6 completion note";
        needle = "Completed by `checks.crucible.phase4.eventLogDeterminism`";
      }
      {
        label = "causal subsequence completion note";
        needle = "renumbered causal subsequence";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "causal projection entry type";
        needle = "pub struct EventLogCausalProjectionEntry";
      }
      {
        label = "causal projection type";
        needle = "pub struct EventLogCausalProjection";
      }
      {
        label = "determinism comparison result";
        needle = "pub struct EventLogDeterminismComparison";
      }
      {
        label = "determinism mismatch detail";
        needle = "pub struct EventLogDeterminismMismatch";
      }
      {
        label = "causal projection builder";
        needle = "pub fn event_log_causal_projection";
      }
      {
        label = "determinism comparison API";
        needle = "pub fn compare_event_log_determinism";
      }
      {
        label = "observational entries stripped";
        needle = "entry.class == SchedulerEventLogClass::Causal";
      }
      {
        label = "renumbered material helper";
        needle = "scheduler_event_log_entry_with_material";
      }
      {
        label = "canonical bytes use segment encoder";
        needle = "scheduler_event_log_segment_bytes(scheduler_event_log_empty_prefix(), &canonical_entries)";
      }
      {
        label = "byte-identical pass condition";
        needle = "expected.canonical_bytes == reproduced.canonical_bytes";
      }
      {
        label = "raw index mismatch localization";
        needle = "expected_raw_index";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "causal projection export";
        needle = "EventLogCausalProjection";
      }
      {
        label = "determinism comparison export";
        needle = "EventLogDeterminismComparison";
      }
      {
        label = "comparison API export";
        needle = "compare_event_log_determinism";
      }
      {
        label = "projection API export";
        needle = "event_log_causal_projection";
      }
    ]
    ++ failuresFor "crates/crucible/src/trigger.rs" trigger [
      {
        label = "trigger replay uses canonical comparison";
        needle = "compare_event_log_determinism(expected, reproduced).passes()";
      }
      {
        label = "trigger prefix comparison uses canonical comparison";
        needle = "compare_event_log_determinism(&expected_entries, &reproduced_entries).passes()";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "replay oracle compares event-log offsets";
        needle = "fat_state.event_log != thin_state.event_log";
      }
    ]
    ++ failuresFor "crates/crucible/tests/event_log_determinism.rs" determinismTest [
      {
        label = "renumbering test";
        needle = "causal_projection_renumbers_past_observational_interleaving";
      }
      {
        label = "causal mismatch test";
        needle = "causal_projection_bytes_differ_on_first_causal_payload_change";
      }
      {
        label = "observational verbosity test";
        needle = "observational_verbosity_changes_do_not_change_causal_projection";
      }
      {
        label = "replay oracle offset test";
        needle = "replay_oracle_rejects_fat_checkpoint_with_inconsistent_event_log_offset";
      }
      {
        label = "canonical bytes asserted";
        needle = "canonical_bytes()";
      }
      {
        label = "mismatch raw index asserted";
        needle = "expected_raw_index";
      }
    ]
    ++ failuresFor "crates/crucible/tests/gate_replay_oracle.rs" replayOracleTest [
      {
        label = "replay-oracle imports comparison";
        needle = "compare_event_log_determinism";
      }
      {
        label = "replay-oracle compares causal log";
        needle = "let comparison = compare_event_log_determinism(&expected_log, &reproduced_log);";
      }
      {
        label = "replay-oracle checks byte equality";
        needle = "comparison.expected().canonical_bytes()";
      }
    ]
    ++ failuresFor "crates/crucible/tests/gate_e2e_determinism_concurrency.rs" e2eDeterminismTest [
      {
        label = "e2e imports comparison";
        needle = "compare_event_log_determinism";
      }
      {
        label = "e2e projection gate test";
        needle = "gate_e2e_determinism_uses_causal_event_log_projection";
      }
      {
        label = "e2e actual workload projection test";
        needle = "gate_e2e_determinism_compares_actual_causal_event_log_projection";
      }
      {
        label = "e2e actual concurrent workload projection test";
        needle = "gate_e2e_determinism_compares_actual_concurrent_causal_event_log_projection";
      }
      {
        label = "e2e compares causal log";
        needle = "let comparison = compare_event_log_determinism(&expected_log, &reproduced_log);";
      }
      {
        label = "e2e compares actual workload log";
        needle = "let comparison = compare_event_log_determinism(&first_log, &second_log);";
      }
      {
        label = "e2e checks byte equality";
        needle = "comparison.expected().canonical_bytes()";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 event log determinism import";
        needle = "eventLogDeterminism = import ./phase4-event-log-determinism.nix";
      }
      {
        label = "phase4 event log determinism attr path";
        needle = "checks.crucible.phase4.eventLogDeterminism";
      }
      {
        label = "phase4 event log determinism task id";
        needle = "taskIds = [\"T-OBS-6\"]";
      }
    ];
in
  if failures != []
  then throw "crucible phase4 event-log determinism check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-event-log-determinism";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.coreutils
        pkgs.rust
        pkgs.sed
      ];

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
          name = "run-event-log-determinism";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-event-log-determinism-target" \
              -p crucible \
              --test event_log_determinism \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-event-log-determinism-target" \
              -p crucible \
              --features test-double \
              --test gate_replay_oracle \
              gate_replay_oracle_fixed_checkpoint_corpus_matches_thin_reduction \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
          --target-dir "$TMPDIR/crucible-event-log-determinism-target" \
          -p crucible \
          --features test-double \
          --test gate_e2e_determinism_concurrency \
          gate_e2e_determinism_compares_actual \
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
            check=${attrPath}
            tasks=${taskList}
            component=crucible-event-log
            causal_subsequence_projection=true
            observational_entries_excluded=true
            replay_oracle_event_log_offset=true
            RESULT
          '';
        }
      ];
    }
