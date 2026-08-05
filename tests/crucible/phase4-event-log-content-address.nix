{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.eventLogContentAddress",
  taskIds ? ["T-OBS-5"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoVendor {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-fWBTuyTXJ+/0BiVbB5WAtCqVwufg04NH4BJdocT+moU=";
  };

  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  model = import ./_crucible-model-source.nix {inherit lib;};
  trigger = import ./_crucible-trigger-source.nix {inherit lib;};
  contentAddressTest = builtins.readFile ../../crates/crucible/tests/event_log_content_address.rs;
  gateContentAddressTest = builtins.readFile ../../crates/crucible/tests/gate_content_address.rs;
  schemaTest = builtins.readFile ../../crates/crucible/tests/event_log_schema.rs;
  payloadTest = builtins.readFile ../../crates/crucible/tests/event_log_payload.rs;
  observabilityDoc = builtins.readFile ../../docs/rfcs/0010-crucible/19-observability-event-log.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/19-observability-event-log.md" observabilityDoc [
      {
        label = "T-OBS-5 completion note";
        needle = "Completed by `checks.crucible.phase4.eventLogContentAddress`";
      }
      {
        label = "content-addressed binary completion note";
        needle = "versioned binary event-log segments";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "binary segment magic";
        needle = "EVENT_LOG_SEGMENT_BINARY_MAGIC";
      }
      {
        label = "binary segment version";
        needle = "EVENT_LOG_SEGMENT_BINARY_VERSION";
      }
      {
        label = "little-endian scalar encoding";
        needle = "to_le_bytes()";
      }
      {
        label = "binary segment decoder";
        needle = "fn decode_scheduler_event_log_segment";
      }
      {
        label = "decode encode identity check";
        needle = "decoded.encode() == bytes";
      }
      {
        label = "shared event-log segment store";
        needle = "struct EventLogSegmentStore";
      }
      {
        label = "store-backed constructor";
        needle = "pub fn with_segment_store(store: Arc<dyn DagStore>)";
      }
      {
        label = "offset resume constructor";
        needle = "pub fn from_offset_with_segment_store(";
      }
      {
        label = "scheduler shared-store constructor";
        needle = "pub fn new_with_event_log_segment_store";
      }
      {
        label = "scheduler offset resume constructor";
        needle = "pub fn new_with_event_log_offset_and_segment_store";
      }
      {
        label = "append stores canonical segment bytes";
        needle = "self.segment_store.put_segment(&segment_bytes)?";
      }
      {
        label = "text view decoded from canonical bytes";
        needle = "decode_scheduler_event_log_segment(&segment_bytes)";
      }
      {
        label = "current offset retains appended segment";
        needle = "offset: current_offset";
      }
      {
        label = "resumed condition prefix base";
        needle = "condition_base_events";
      }
      {
        label = "derived text projection field";
        needle = "pub segment_text: String";
      }
      {
        label = "quantum text projection field";
        needle = "pub event_log_segment_text: String";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "runtime carries event-log offset";
        needle = "pub event_log: EventLogOffset";
      }
      {
        label = "runtime preserves checkpoint event-log offset";
        needle = ".map(|state| state.event_log)";
      }
      {
        label = "materialized checkpoint uses runtime event-log offset";
        needle = "runtime.event_log";
      }
      {
        label = "pure replay stale event-log guard";
        needle = "EventLogReplayUnsupported";
      }
      {
        label = "pure replay refuses nonzero retained event log";
        needle = "runtime.event_log.events != 0";
      }
      {
        label = "event-log segments require stored bytes";
        needle = "CowDeltaKind::EventLogSegment =>";
      }
      {
        label = "event-log segment lookup in graph store";
        needle = "lookup-event-log-segment";
      }
      {
        label = "event-log store key is raw segment key";
        needle = "keys.insert(cow_ref.content)";
      }
    ]
    ++ failuresFor "crates/crucible/src/trigger.rs" trigger [
      {
        label = "condition prefix supports resumed base sequence";
        needle = "from_scheduler_event_log_entries_with_base";
      }
      {
        label = "condition prefix stores base sequence";
        needle = "base_sequence";
      }
      {
        label = "resumed facts-through-point unit test";
        needle = "facts_through_point_preserves_resumed_event_log_base_sequence";
      }
      {
        label = "offline offsets retain appended segment";
        needle = "EventLogOffset::with_appended_segment";
      }
    ]
    ++ failuresFor "crates/crucible/tests/event_log_content_address.rs" contentAddressTest [
      {
        label = "binary canonical segment test";
        needle = "event_log_segments_are_binary_canonical_with_derived_text_view";
      }
      {
        label = "segment magic asserted";
        needle = "b\"CRUCIBLE-ELOGSEG\"";
      }
      {
        label = "little-endian version asserted";
        needle = "1_u32.to_le_bytes()";
      }
      {
        label = "shared store dedup test";
        needle = "shared_segment_store_deduplicates_identical_segments";
      }
      {
        label = "shared MemoryDagStore constructor";
        needle = "EventLog::with_segment_store";
      }
      {
        label = "scheduler shared-store integration test";
        needle = "scheduler_writes_event_log_segments_to_shared_store";
      }
      {
        label = "scheduler shared-store constructor exercised";
        needle = "SingleScheduler::new_with_event_log_segment_store";
      }
      {
        label = "dedup object count assertion";
        needle = "object_count()";
      }
      {
        label = "fork prefix sharing test";
        needle = "cloned_event_logs_share_prefixes_and_segment_store_on_fork";
      }
      {
        label = "resume offset test";
        needle = "resumed_event_log_continues_appending_after_stored_offset";
      }
      {
        label = "resume constructor exercised";
        needle = "EventLog::from_offset_with_segment_store";
      }
      {
        label = "temporal graph segment closure test";
        needle = "temporal_graph_closure_references_stored_event_log_segment_bytes";
      }
      {
        label = "stale offset replay rejection test";
        needle = "thin_replay_rejects_stale_nonzero_event_log_offset";
      }
      {
        label = "stale offset error asserted";
        needle = "EngineError::EventLogReplayUnsupported";
      }
      {
        label = "graph closure uses shared store";
        needle = "persist_checkpoint_closure(shared.as_ref(), &child)";
      }
      {
        label = "stored raw segment bytes asserted";
        needle = ".get(&segment_hash)";
      }
      {
        label = "graph cow delta value is raw segment key";
        needle = "keys.cow_deltas.get(&cow_ref), Some(&segment_hash)";
      }
      {
        label = "event-log cow delta asserted";
        needle = "CowDeltaKind::EventLogSegment";
      }
    ]
    ++ failuresFor "crates/crucible/tests/gate_content_address.rs" gateContentAddressTest [
      {
        label = "graph store test stores event-log bytes";
        needle = "event-log segment bytes should store";
      }
      {
        label = "gc test stores left event-log bytes";
        needle = "left event-log segment bytes should store";
      }
      {
        label = "gc test stores right event-log bytes";
        needle = "right event-log segment bytes should store";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 exposes event-log content-address check";
        needle = "eventLogContentAddress = import ./phase4-event-log-content-address.nix";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/event_log_schema.rs" schemaTest [
      {
        label = "schema test decodes canonical segment as UTF-8";
        needle = "String::from_utf8(append.segment_bytes)";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/event_log_payload.rs" payloadTest [
      {
        label = "payload test decodes canonical segment as UTF-8";
        needle = "String::from_utf8(append.segment_bytes)";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/event_log_content_address.rs" contentAddressTest [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "pending placeholder";
        needle = "todo!";
      }
    ];
in
  if failures != []
  then throw "crucible phase4 event-log content-address check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-event-log-content-address";
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
            sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
                > .cargo/config.toml
          '';
        }
        {
          name = "run-event-log-content-address";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-event-log-content-address-target" \
              -p crucible \
              --test event_log_content_address \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-event-log-content-address-target" \
              -p crucible \
              --lib event_log_segment_binary_round_trips_to_same_bytes \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-event-log-content-address-target" \
              -p crucible \
              --lib facts_through_point_preserves_resumed_event_log_base_sequence \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-event-log-content-address-target" \
              -p crucible \
              --features test-double \
              --test gate_content_address \
              gate_content_address_temporal_graph_persists_checkpoint_closure_in_dag_store \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-event-log-content-address-target" \
              -p crucible \
              --features test-double \
              --test gate_content_address \
              gate_content_address_gc_refcounts_abandoned_branch_unique_objects \
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
            content_addressed_segments=true
            binary_canonical_serialization=true
            prefix_sharing=true
            checkpoint_event_log_offset=true
            RESULT
          '';
        }
      ];
    }
