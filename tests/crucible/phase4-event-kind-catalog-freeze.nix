{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.eventKindCatalogFreeze",
  taskIds ? ["T-OBS-13"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-ULD9g6d87886b8O6/sGCMktquGwaUAyf+DLHUrFzod0=";
  };

  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  catalog = builtins.readFile ../../crates/crucible/src/event_catalog.rs;
  catalogTest = builtins.readFile ../../crates/crucible/tests/event_kind_catalog.rs;
  triggerTest = builtins.readFile ../../crates/crucible/tests/trigger_firing_causal_log.rs;
  observabilityDoc = builtins.readFile ../../docs/rfcs/0010-crucible/19-observability-event-log.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  requiredKinds = [
    "state_transition"
    "event_activated"
    "trigger_fired"
    "signal_transition"
    "signal_sample"
    "signal_state_transition"
    "binding_activation"
    "binding_deactivation"
    "fault_opportunity"
    "effect_choice"
    "effect_combined"
    "effect_applied"
    "effect_rejected"
    "network_profile"
    "association_transition"
    "trace_alignment"
    "node_started"
    "node_crashed"
    "node_completed"
    "timer_armed"
    "timer_fired"
    "timer_cancelled"
    "message_delivered"
    "message_dropped"
    "assertion_evaluated"
    "assertion_state_changed"
    "savepoint"
    "fork"
    "tick"
    "diagnostic"
    "coverage"
    "assertion_proximity"
    "guest_marker"
  ];
  requiredKindFailures =
    lib.concatMap (
      kind:
        lib.optionals (!(hasInfix "kind: \"${kind}\"" catalog)) [
          "crates/crucible/src/event_catalog.rs: missing required RFC kind `${kind}`"
        ]
    )
    requiredKinds;

  failures =
    failuresFor "docs/rfcs/0010-crucible/19-observability-event-log.md" observabilityDoc [
      {
        label = "T-OBS-13 completion note";
        needle = "Completed by `checks.crucible.phase4.eventKindCatalogFreeze`";
      }
      {
        label = "catalog golden-vector completion note";
        needle = "golden-vector";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "event catalog module";
        needle = "pub mod event_catalog;";
      }
      {
        label = "event catalog version export";
        needle = "EVENT_KIND_CATALOG_VERSION";
      }
      {
        label = "event catalog entry export";
        needle = "EventKindCatalogEntry";
      }
      {
        label = "event catalog dependency export";
        needle = "EventKindCatalogDependency";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "scheduler class lookup reads catalog";
        needle = "crate::event_catalog::event_kind_catalog_class(payload.kind())";
      }
      {
        label = "trigger firing payload";
        needle = "SchedulerEventLogPayload::TriggerFired";
      }
      {
        label = "trigger fired event kind";
        needle = "EventPayload::new(\"trigger_fired\", attributes)";
      }
      {
        label = "trigger fired condition summary attribute";
        needle = "String::from(\"condition\")";
      }
    ]
    ++ failuresFor "crates/crucible/src/event_catalog.rs" catalog [
      {
        label = "catalog version";
        needle = "pub const EVENT_KIND_CATALOG_VERSION: u32 = 4;";
      }
      {
        label = "catalog entry type";
        needle = "pub struct EventKindCatalogEntry";
      }
      {
        label = "catalog dependency type";
        needle = "pub struct EventKindCatalogDependency";
      }
      {
        label = "catalog lookup";
        needle = "pub fn event_kind_catalog_entry";
      }
      {
        label = "catalog class lookup";
        needle = "pub fn event_kind_catalog_class";
      }
      {
        label = "canonical material";
        needle = "pub fn event_kind_catalog_canonical_material";
      }
      {
        label = "canonical bytes";
        needle = "pub fn event_kind_catalog_canonical_bytes";
      }
      {
        label = "dependency map";
        needle = "pub fn event_kind_catalog_dependency_map";
      }
      {
        label = "trigger fired condition catalog attribute";
        needle = "attributes: &[\"action\", \"at\", \"condition\", \"event\"]";
      }
      {
        label = "causal class fixed in catalog";
        needle = "class: SchedulerEventLogClass::Causal";
      }
      {
        label = "observational class fixed in catalog";
        needle = "class: SchedulerEventLogClass::Observational";
      }
      {
        label = "assertions dependency";
        needle = "18-assertions-properties";
      }
      {
        label = "control-plane dependency";
        needle = "20-session-control-plane";
      }
      {
        label = "api dependency";
        needle = "21-api";
      }
      {
        label = "advanced-features dependency";
        needle = "22-advanced-features";
      }
      {
        label = "determinism harness dependency";
        needle = "24-determinism-harness-testing";
      }
    ]
    ++ requiredKindFailures
    ++ failuresFor "crates/crucible/tests/event_kind_catalog.rs" catalogTest [
      {
        label = "version/single-source test";
        needle = "event_kind_catalog_is_versioned_sorted_and_single_source_for_classes";
      }
      {
        label = "rfc required kinds test";
        needle = "event_kind_catalog_contains_rfc_19_7_required_kinds";
      }
      {
        label = "dependency map test";
        needle = "event_kind_catalog_records_structural_dependency_map";
      }
      {
        label = "dependency resolution test";
        needle = "event_kind_catalog_dependencies_resolve_to_catalog_entries";
      }
      {
        label = "golden vector test";
        needle = "event_kind_catalog_canonical_serialization_matches_golden_vector";
      }
      {
        label = "golden serialization literal";
        needle = "EXPECTED_CATALOG_SERIALIZATION";
      }
    ]
    ++ failuresFor "crates/crucible/tests/trigger_firing_causal_log.rs" triggerTest [
      {
        label = "trigger firing causal test";
        needle = "trigger_firing_is_causal_event_log_entry_not_schedule_decision";
      }
      {
        label = "trigger firing not decision assertion";
        needle = "trigger firing must not be recorded as a Decision";
      }
      {
        label = "condition truth not logged regression";
        needle = "condition_evaluated";
      }
      {
        label = "trigger firing condition summary assertion";
        needle = "event_payload().string(\"condition\")";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 event-kind catalog freeze import";
        needle = "eventKindCatalogFreeze = import ./phase4-event-kind-catalog-freeze.nix";
      }
      {
        label = "phase4 event-kind catalog freeze attr path";
        needle = "checks.crucible.phase4.eventKindCatalogFreeze";
      }
      {
        label = "phase4 event-kind catalog freeze task id";
        needle = "taskIds = [\"T-OBS-13\"]";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/event_kind_catalog.rs" catalogTest [
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
  then throw "crucible phase4 event-kind catalog freeze check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-event-kind-catalog-freeze";
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
          name = "run-event-kind-catalog-freeze";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-event-kind-catalog-freeze-target" \
              -p crucible \
              --test event_kind_catalog \
              --test trigger_firing_causal_log \
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
            catalog_version=1
            catalog_golden_vector=true
            structural_dependency_map=true
            trigger_fired=causal
            trigger_firing_schedule_decision=false
            RESULT
          '';
        }
      ];
    }
