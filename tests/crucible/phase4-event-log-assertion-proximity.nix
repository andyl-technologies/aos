{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.eventLogAssertionProximity",
  taskIds ? ["T-OBS-14"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoVendor {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-fWBTuyTXJ+/0BiVbB5WAtCqVwufg04NH4BJdocT+moU=";
  };

  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  trigger = import ./_crucible-trigger-source.nix {inherit lib;};
  model = import ./_crucible-model-source.nix {inherit lib;};
  catalog = builtins.readFile ../../crates/crucible/src/event_catalog.rs;
  catalogTest = builtins.readFile ../../crates/crucible/tests/event_kind_catalog.rs;
  proximityTest = builtins.readFile ../../crates/crucible/tests/event_log_assertion_proximity.rs;
  observabilityDoc = builtins.readFile ../../docs/rfcs/0010-crucible/19-observability-event-log.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/19-observability-event-log.md" observabilityDoc [
      {
        label = "T-OBS-14 completion note";
        needle = "Completed by `checks.crucible.phase4.eventLogAssertionProximity`";
      }
      {
        label = "minimum projection note";
        needle = "minimum-distance";
      }
    ]
    ++ failuresFor "crates/crucible/src/trigger.rs" trigger [
      {
        label = "assertion proximity constructor";
        needle = "pub fn assertion_proximity(";
      }
      {
        label = "assertion proximity payload";
        needle = "AssertionProximity {";
      }
      {
        label = "assertion proximity external material";
        needle = "observable=assertion-proximity";
      }
      {
        label = "assertion proximity does not satisfy guest marker predicate";
        needle = "ObservableEventPayload::AssertionProximity { .. } => false";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "assertion proximity projection entry";
        needle = "pub struct EventLogAssertionProximityProjectionEntry";
      }
      {
        label = "assertion proximity projection type";
        needle = "pub struct EventLogAssertionProximityProjection";
      }
      {
        label = "assertion proximity projection API";
        needle = "pub fn event_log_assertion_proximity_projection";
      }
      {
        label = "assertion proximity fingerprint API";
        needle = "pub fn assertion_proximity_fingerprint_from_event_log";
      }
      {
        label = "empty projection has absent fingerprint";
        needle = "ContentHash::default()";
      }
      {
        label = "minimum projection domain";
        needle = "crucible.scheduler.event-log.assertion-proximity-projection.v1";
      }
      {
        label = "projection minimum key includes quantifier";
        needle = "entry.quantifier,";
      }
      {
        label = "assertion proximity event kind";
        needle = "EventPayload::new(\"assertion_proximity\", attributes)";
      }
      {
        label = "assertion proximity distance attribute";
        needle = "EventAttributeValue::U128(*distance)";
      }
      {
        label = "assertion proximity quantifier attribute";
        needle = "String::from(\"quantifier\")";
      }
      {
        label = "assertion proximity report append API";
        needle = "pub fn append_assertion_proximity_events";
      }
      {
        label = "report append reads report proximities";
        needle = "report.proximities().iter()";
      }
      {
        label = "assertion proximity is observational";
        needle = "ObservableEventPayload::AssertionProximity { .. } => EventLevel::Debug";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "checkpoint proximity fingerprint";
        needle = "pub assertion_proximity_fingerprint: ContentHash";
      }
      {
        label = "checkpoint derives proximity from event log";
        needle = "pub fn with_assertion_proximity_from_event_log";
      }
      {
        label = "graph cache stamps proximity from event log";
        needle = "pub fn cache_snapshot_with_event_log_assertion_proximity";
      }
      {
        label = "graph cache uses proximity projection API";
        needle = "crate::scheduler::assertion_proximity_fingerprint_from_event_log(entries)";
      }
      {
        label = "thin checkpoint inherits cached proximity";
        needle = "checkpoint.assertion_proximity_fingerprint =";
      }
      {
        label = "checkpoint store material includes proximity";
        needle = "assertion_proximity_fingerprint={}";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "assertion proximity projection export";
        needle = "EventLogAssertionProximityProjection";
      }
      {
        label = "assertion proximity projection entry export";
        needle = "EventLogAssertionProximityProjectionEntry";
      }
      {
        label = "assertion proximity fingerprint export";
        needle = "assertion_proximity_fingerprint_from_event_log";
      }
      {
        label = "assertion proximity projection API export";
        needle = "event_log_assertion_proximity_projection";
      }
    ]
    ++ failuresFor "crates/crucible/src/event_catalog.rs" catalog [
      {
        label = "assertion proximity catalog kind";
        needle = "kind: \"assertion_proximity\"";
      }
      {
        label = "assertion proximity catalog attributes";
        needle = "attributes: &[\"distance\", \"id\", \"node\", \"quantifier\"]";
      }
    ]
    ++ failuresFor "crates/crucible/tests/event_kind_catalog.rs" catalogTest [
      {
        label = "assertion proximity catalog golden vector";
        needle = "entry kind=assertion_proximity class=observational sources=engine attributes=distance,id,node,quantifier";
      }
      {
        label = "assertion proximity catalog class test";
        needle = "(\"assertion_proximity\", EventClass::Observational)";
      }
    ]
    ++ failuresFor "crates/crucible/tests/event_log_assertion_proximity.rs" proximityTest [
      {
        label = "observational projection test";
        needle = "assertion_proximity_entries_are_observational_and_projected";
      }
      {
        label = "determinism exclusion test";
        needle = "assertion_proximity_is_excluded_from_causal_determinism";
      }
      {
        label = "minimum distance fingerprint test";
        needle = "assertion_proximity_fingerprint_uses_minimum_distance_per_assertion";
      }
      {
        label = "minimum fingerprint ignores timing";
        needle = "same_minimum_later";
      }
      {
        label = "minimum buckets include quantifier and node";
        needle = "assertion_proximity_minimums_are_bucketed_by_quantifier_and_node";
      }
      {
        label = "production scheduler append test";
        needle = "scheduler_appends_report_proximities_to_unified_event_log";
      }
      {
        label = "lossless distance serialization assertion";
        needle = "event_payload.attribute.distance.value.type=u128";
      }
      {
        label = "wide distance serialization test";
        needle = "assertion_proximity_distance_serializes_losslessly_above_u64_max";
      }
      {
        label = "checkpoint feedback test";
        needle = "assertion_proximity_fingerprint_is_checkpoint_feedback_from_log_projection";
      }
      {
        label = "graph cache feedback test";
        needle = "graph_cache_snapshot_stamps_checkpoint_assertion_proximity_from_event_log_projection";
      }
      {
        label = "causal projection assertion";
        needle = "event_log_causal_projection";
      }
      {
        label = "determinism comparison assertion";
        needle = "compare_event_log_determinism";
      }
      {
        label = "observational class assertion";
        needle = "EventClass::Observational";
      }
      {
        label = "event-log-only graph cache API";
        needle = "cache_snapshot_with_event_log_assertion_proximity";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 assertion proximity import";
        needle = "eventLogAssertionProximity = import ./phase4-event-log-assertion-proximity.nix";
      }
      {
        label = "phase4 assertion proximity attr path";
        needle = "checks.crucible.phase4.eventLogAssertionProximity";
      }
      {
        label = "phase4 assertion proximity task id";
        needle = "taskIds = [\"T-OBS-14\"]";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/event_log_assertion_proximity.rs" proximityTest [
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
    ]
    ++ forbiddenFor "crates/crucible/src/model.rs" model [
      {
        label = "parallel proximity fingerprint setter";
        needle = "with_assertion_proximity_fingerprint";
      }
    ];
in
  if failures != []
  then throw "crucible phase4 event-log assertion proximity check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-event-log-assertion-proximity";
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
            sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
                > .cargo/config.toml
          '';
        }
        {
          name = "run-event-log-assertion-proximity";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-event-log-assertion-proximity-target" \
              -p crucible \
              --test event_log_assertion_proximity \
              --test event_kind_catalog \
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
            event_kind=assertion_proximity
            projection=minimum-distance
            determinism_class=observational
            checkpoint_feedback=true
            graph_cache_feedback=true
            RESULT
          '';
        }
      ];
    }
