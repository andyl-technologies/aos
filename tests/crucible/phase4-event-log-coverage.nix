{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.eventLogCoverage",
  taskIds ? ["T-OBS-9"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = import ../../pkgs/tools/crucible/_cargo-deps-hash.nix;
  };

  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  model = import ./_crucible-model-source.nix {inherit lib;};
  trigger = import ./_crucible-trigger-source.nix {inherit lib;};
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  coverageTest = builtins.readFile ../../crates/crucible/tests/event_log_coverage.rs;
  determinismTest = builtins.readFile ../../crates/crucible/tests/event_log_determinism.rs;
  replayOracleTest = builtins.readFile ../../crates/crucible/tests/event_graph_replay_oracle.rs;
  observabilityDoc = builtins.readFile ../../docs/rfcs/0010-crucible/19-observability-event-log.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/19-observability-event-log.md" observabilityDoc [
      {
        label = "T-OBS-9 completion note";
        needle = "Completed by `checks.crucible.phase4.eventLogCoverage`";
      }
      {
        label = "coverage fingerprint from projection note";
        needle = "checkpoint coverage fingerprints are derived from that coverage projection";
      }
    ]
    ++ failuresFor "crates/crucible/src/trigger.rs" trigger [
      {
        label = "named coverage marker constructor";
        needle = "pub fn coverage_marker(retired_icount: Icount, node: NodeId, marker: MarkerId) -> Self";
      }
      {
        label = "named coverage payload";
        needle = "CoverageMarker {";
      }
      {
        label = "coverage marker formal material";
        needle = "observable=coverage-marker";
      }
      {
        label = "coverage marker not guest-marker predicate";
        needle = "ObservableEventPayload::CoverageMarker { .. }";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "coverage observation enum";
        needle = "pub enum EventLogCoverageObservation";
      }
      {
        label = "coverage projection type";
        needle = "pub struct EventLogCoverageProjection";
      }
      {
        label = "coverage projection entry";
        needle = "pub struct EventLogCoverageProjectionEntry";
      }
      {
        label = "coverage projection API";
        needle = "pub fn event_log_coverage_projection";
      }
      {
        label = "coverage fingerprint API";
        needle = "pub fn coverage_fingerprint_from_event_log";
      }
      {
        label = "empty projection has absent fingerprint";
        needle = "ContentHash::default()";
      }
      {
        label = "coverage fingerprint is unique observation set";
        needle = ".collect::<BTreeSet<_>>()";
      }
      {
        label = "basic-block coverage attribute";
        needle = "String::from(\"basic_block\")";
      }
      {
        label = "named coverage attribute";
        needle = "String::from(\"named\")";
      }
      {
        label = "named coverage projects as coverage";
        needle = "EventPayload::new(\"coverage\", attributes)";
      }
      {
        label = "basic-block coverage source is engine";
        needle = "ObservableEventPayload::CoverageBlock { .. }";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "checkpoint derives coverage from event log";
        needle = "pub fn with_coverage_from_event_log";
      }
      {
        label = "checkpoint uses coverage projection API";
        needle = "crate::scheduler::coverage_fingerprint_from_event_log(entries)";
      }
      {
        label = "graph cache coverage entry point";
        needle = "pub fn cache_snapshot_with_event_log_coverage";
      }
      {
        label = "graph cache stamps coverage before insert";
        needle = "checkpoint.with_coverage_fingerprint(fingerprint)";
      }
      {
        label = "graph cache stamps checkpoint node";
        needle = "checkpoint.coverage_fingerprint = fingerprint";
      }
      {
        label = "recorded thin node inherits cached coverage";
        needle = "checkpoint.coverage_fingerprint = snapshot.coverage_fingerprint";
      }
      {
        label = "search consumes checkpoint coverage fingerprint";
        needle = "checkpoint.coverage_fingerprint";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "coverage observation export";
        needle = "EventLogCoverageObservation";
      }
      {
        label = "coverage projection export";
        needle = "EventLogCoverageProjection";
      }
      {
        label = "coverage fingerprint export";
        needle = "coverage_fingerprint_from_event_log";
      }
      {
        label = "coverage projection API export";
        needle = "event_log_coverage_projection";
      }
    ]
    ++ failuresFor "crates/crucible/tests/event_log_coverage.rs" coverageTest [
      {
        label = "basic and named coverage projection test";
        needle = "coverage_projection_reads_basic_blocks_and_named_markers_from_one_log";
      }
      {
        label = "coverage payload class test";
        needle = "coverage_entries_project_as_observational_coverage_payloads";
      }
      {
        label = "checkpoint fingerprint test";
        needle = "coverage_fingerprint_is_checkpoint_feedback_from_log_projection";
      }
      {
        label = "graph cache production path test";
        needle = "graph_cache_snapshot_stamps_checkpoint_coverage_from_event_log_projection";
      }
      {
        label = "delayed closure coverage test";
        needle = "delayed_checkpoint_closure_preserves_cached_coverage_fingerprint";
      }
      {
        label = "delayed closure records via persistence";
        needle = "persist_checkpoint_closure";
      }
      {
        label = "graph cache test checks checkpoint node";
        needle = "checkpoint_node(child.id())";
      }
      {
        label = "graph cache test checks thin eviction preserves fingerprint";
        needle = "evict_fat_checkpoint_to_thin";
      }
      {
        label = "causal exclusion test";
        needle = "coverage_projection_is_excluded_from_causal_determinism_comparison";
      }
      {
        label = "named marker constructor used";
        needle = "ObservableEvent::coverage_marker";
      }
      {
        label = "graph cache uses coverage projection";
        needle = "cache_snapshot_with_event_log_coverage";
      }
      {
        label = "search materialization returns stamped checkpoint";
        needle = "materialize_hot_checkpoint";
      }
      {
        label = "causal comparison remains passing";
        needle = "assert!(comparison.passes())";
      }
    ]
    ++ failuresFor "crates/crucible/tests/event_log_determinism.rs" determinismTest [
      {
        label = "determinism comparison still exists";
        needle = "compare_event_log_determinism";
      }
      {
        label = "observational verbosity excluded";
        needle = "observational_verbosity_changes_do_not_change_causal_projection";
      }
    ]
    ++ failuresFor "crates/crucible/tests/event_graph_replay_oracle.rs" replayOracleTest [
      {
        label = "coverage marker replay material";
        needle = "observable:coverage-marker";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 event log coverage import";
        needle = "eventLogCoverage = import ./phase4-event-log-coverage.nix";
      }
      {
        label = "phase4 event log coverage attr path";
        needle = "checks.crucible.phase4.eventLogCoverage";
      }
      {
        label = "phase4 event log coverage task id";
        needle = "taskIds = [\"T-OBS-9\"]";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/event_log_coverage.rs" coverageTest [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "unfinished todo";
        needle = "todo!";
      }
      {
        label = "unfinished unimplemented";
        needle = "unimplemented!";
      }
    ];
in
  if failures != []
  then throw "crucible phase4 event-log coverage check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-event-log-coverage";
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
          name = "run-event-log-coverage";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-event-log-coverage-target" \
              -p crucible \
              --test event_log_coverage \
              --test event_log_determinism \
              --test event_graph_replay_oracle \
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
            event_log_coverage_projection=true
            checkpoint_coverage_fingerprint=projection-digest
            coverage_determinism_class=observational
            RESULT
          '';
        }
      ];
    }
