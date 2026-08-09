{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.eventLogPayload",
  taskIds ? ["T-OBS-3"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  eventCatalog = builtins.readFile ../../crates/crucible/src/event_catalog.rs;
  trigger = import ./_crucible-trigger-source.nix {inherit lib;};
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  payloadTest = builtins.readFile ../../crates/crucible/tests/event_log_payload.rs;
  formalTraceTest = builtins.readFile ../../crates/crucible/tests/formal_trace_export.rs;
  reproductionTest = builtins.readFile ../../crates/crucible/tests/assertion_violation_reproduction.rs;
  observabilityDoc = builtins.readFile ../../docs/rfcs/0010-crucible/19-observability-event-log.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/19-observability-event-log.md" observabilityDoc [
      {
        label = "T-OBS-3 completion note";
        needle = "Completed by `checks.crucible.phase4.eventLogPayload`";
      }
      {
        label = "diagnostic escape hatch requirement";
        needle = "`diagnostic` escape hatch";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "open payload struct";
        needle = "pub struct EventPayload";
      }
      {
        label = "typed attribute enum";
        needle = "pub enum EventAttributeValue";
      }
      {
        label = "diagnostic payload type";
        needle = "pub struct EventDiagnosticPayload";
      }
      {
        label = "entry stores open payload";
        needle = "event_payload: EventPayload";
      }
      {
        label = "open payload accessor";
        needle = "pub fn event_payload(&self) -> &EventPayload";
      }
      {
        label = "kind accessor";
        needle = "pub fn kind(&self) -> &str";
      }
      {
        label = "typed attribute accessor";
        needle = "pub fn attribute(&self, name: &str) -> Option<&EventAttributeValue>";
      }
      {
        label = "typed string accessor";
        needle = "pub fn string(&self, name: &str) -> Option<&str>";
      }
      {
        label = "typed u64 accessor";
        needle = "pub fn u64(&self, name: &str) -> Option<u64>";
      }
      {
        label = "typed level accessor";
        needle = "pub fn level(&self, name: &str) -> Option<EventLevel>";
      }
      {
        label = "diagnostic constructor";
        needle = "pub fn diagnostic(";
      }
      {
        label = "diagnostic scheduler payload";
        needle = "Diagnostic(EventDiagnosticPayload)";
      }
      {
        label = "payload view included in entry hash";
        needle = "&self.event_payload,";
      }
      {
        label = "payload material included in canonical material";
        needle = "event_payload_material(\"event_payload\", event_payload)";
      }
      {
        label = "segment material carries payload kind";
        needle = "entry.payload.kind";
      }
      {
        label = "diagnostic observational class value";
        needle = "SchedulerEventLogClass::Observational";
      }
      {
        label = "level derived independently";
        needle = "SchedulerEventLogPayload::Diagnostic(diagnostic) => diagnostic.level";
      }
    ]
    ++ failuresFor "crates/crucible/src/event_catalog.rs" eventCatalog [
      {
        label = "diagnostic observational catalog class";
        needle = "kind: \"diagnostic\",\n        class: SchedulerEventLogClass::Observational,";
      }
    ]
    ++ failuresFor "crates/crucible/src/trigger.rs" trigger [
      {
        label = "replay compares causal projection";
        needle = "fn event_log_causal_projections_match";
      }
      {
        label = "public replay path computes projection divergence";
        needle = "let event_logs_differ =\n        !event_log_causal_projections_match(recorded_log.entries(), reproduced_log.entries())";
      }
      {
        label = "causal projection raw index";
        needle = "struct ProjectedCausalEventLogEntry";
      }
      {
        label = "causal prefix raw mapping";
        needle = "fn event_log_raw_prefix_for_causal_prefix";
      }
      {
        label = "causal projection entry comparator";
        needle = "fn event_log_causal_projection_prefixes_match";
      }
      {
        label = "replay divergence uses projection";
        needle = "!event_log_causal_projections_match";
      }
      {
        label = "formal trace typed diagnostic attributes";
        needle = "fn external_event_attribute_value_material";
      }
      {
        label = "formal trace event level labels";
        needle = "fn external_event_level_label";
      }
      {
        label = "diagnostic details emitted";
        needle = "diagnostic.details";
      }
      {
        label = "causal projection unit test";
        needle = "causal_projection_comparison_ignores_observational_entries";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "EventPayload export";
        needle = "EventPayload";
      }
      {
        label = "EventAttributeValue export";
        needle = "EventAttributeValue";
      }
      {
        label = "EventDiagnosticPayload export";
        needle = "EventDiagnosticPayload";
      }
    ]
    ++ failuresFor "crates/crucible/tests/event_log_payload.rs" payloadTest [
      {
        label = "payload attribute test";
        needle = "payload_attributes_are_read_by_name_and_type";
      }
      {
        label = "diagnostic escape test";
        needle = "diagnostic_payload_is_typed_observational_escape_hatch";
      }
      {
        label = "level class orthogonality test";
        needle = "level_is_orthogonal_to_event_class";
      }
      {
        label = "name/type string read";
        needle = "payload.string(\"marker\")";
      }
      {
        label = "wrong type rejected";
        needle = "payload.u64(\"retired_icount\"), None";
      }
      {
        label = "fault typed accessor tested";
        needle = "fault_payload.fault(\"fault\")";
      }
      {
        label = "level typed accessor tested";
        needle = "payload.level(\"severity\")";
      }
      {
        label = "diagnostic kind assertion";
        needle = "payload.kind(), \"diagnostic\"";
      }
      {
        label = "observational error-level diagnostic";
        needle = "diagnostic_error.class(), EventClass::Observational";
      }
    ]
    ++ failuresFor "crates/crucible/tests/formal_trace_export.rs" formalTraceTest [
      {
        label = "typed diagnostic formal trace test";
        needle = "formal_trace_export_includes_typed_diagnostic_details";
      }
      {
        label = "diagnostic typed details asserted";
        needle = "diagnostic.details=10";
      }
      {
        label = "diagnostic strings hex encoded";
        needle = "diagnostic.name.bytes=646961670a6e616d65";
      }
    ]
    ++ failuresFor "crates/crucible/tests/assertion_violation_reproduction.rs" reproductionTest [
      {
        label = "diagnostic replay nonperturbation regression";
        needle = "violation_reproduction_ignores_observational_diagnostic_replay_entries";
      }
      {
        label = "diagnostic replay uses artifact replay check";
        needle = "diagnostic-only replay log difference should reproduce the violation";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 exposes event-log payload check";
        needle = "eventLogPayload = import ./phase4-event-log-payload.nix";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/event_log_payload.rs" payloadTest [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "pending placeholder";
        needle = "todo!";
      }
    ]
    ++ forbiddenFor "crates/crucible/src/trigger.rs" trigger [
      {
        label = "raw diagnostic name export";
        needle = "diagnostic.name={}";
      }
      {
        label = "full replay event-log equality";
        needle = "recorded_log.entries() != reproduced_log.entries()";
      }
    ];
in
  if failures != []
  then throw "crucible phase4 event-log payload check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-event-log-payload";
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
          name = "run-event-log-payload";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-event-log-payload-target" \
              -p crucible \
              --test event_log_payload \
              --test assertion_violation_reproduction \
              --test formal_trace_export \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-event-log-payload-target" \
              -p crucible \
              --lib causal_projection_comparison_ignores_observational_entries \
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
            open_payload_kind=true
            typed_named_attributes=true
            diagnostic_escape_hatch=true
            level_class_orthogonal=true
            RESULT
          '';
        }
      ];
    }
