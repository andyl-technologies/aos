{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.eventLogUnified",
  taskIds ? ["T-OBS-1"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  eventLogTest = builtins.readFile ../../crates/crucible/tests/event_log_unified.rs;
  emitStepTest = builtins.readFile ../../crates/crucible/tests/scheduler_emit_step.rs;
  triggerFiringTest = builtins.readFile ../../crates/crucible/tests/trigger_firing_causal_log.rs;
  observabilityDoc = builtins.readFile ../../docs/rfcs/0010-crucible/19-observability-event-log.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/19-observability-event-log.md" observabilityDoc [
      {
        label = "T-OBS-1 completion note";
        needle = "Completed by `checks.crucible.phase4.eventLogUnified`";
      }
      {
        label = "one log requirement";
        needle = "exactly **one** event log per run";
      }
      {
        label = "single append path requirement";
        needle = "single append path";
      }
      {
        label = "projection requirement";
        needle = "every consumer reads a projection";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "unified log entry name";
        needle = "pub type LogEntry = SchedulerEventLogEntry";
      }
      {
        label = "unified event log owner";
        needle = "pub struct EventLog";
      }
      {
        label = "event log append path";
        needle = "pub fn append_entries";
      }
      {
        label = "event log sequence allocator";
        needle = "pub fn next_sequence";
      }
      {
        label = "event log offset projection";
        needle = "pub fn offset(&self) -> EventLogOffset";
      }
      {
        label = "condition projection";
        needle = "pub fn condition_prefix(&self) -> &ConditionEventLogPrefix";
      }
      {
        label = "single scheduler event-log owner";
        needle = "event_log: EventLog";
      }
      {
        label = "observable append uses unified path";
        needle = "self.event_log.append_entries(entries)";
      }
      {
        label = "scheduler EMIT uses unified sequence owner";
        needle = "self.event_log.next_sequence(entries.len())";
      }
      {
        label = "condition prefix derives from same retained entries";
        needle = "ConditionEventLogPrefix::from_scheduler_event_log_entries_with_base";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "EventLog export";
        needle = "EventLog,";
      }
      {
        label = "EventLogCausalProjection export";
        needle = "EventLogCausalProjection,";
      }
      {
        label = "IoCompletion export";
        needle = "IoCompletion,";
      }
      {
        label = "LogEntry export";
        needle = "LogEntry,";
      }
      {
        label = "NetworkLookahead export";
        needle = "NetworkLookahead,";
      }
    ]
    ++ failuresFor "crates/crucible/tests/event_log_unified.rs" eventLogTest [
      {
        label = "unified append test";
        needle = "event_log_append_path_feeds_offsets_and_condition_projection";
      }
      {
        label = "non-dense sequence rejection test";
        needle = "event_log_rejects_non_dense_append_sequence";
      }
      {
        label = "EventLog test owner";
        needle = "EventLog::new";
      }
      {
        label = "condition projection assertion";
        needle = "log.condition_prefix().point().kind()";
      }
    ]
    ++ failuresFor "crates/crucible/tests/scheduler_emit_step.rs" emitStepTest [
      {
        label = "scheduler EMIT still appends through log";
        needle = "emit_appends_resolved_happenings_before_decisions_with_dense_content_hashes";
      }
      {
        label = "scheduler offset advances across quanta";
        needle = "step_advances_schedule_and_event_log_prefix_across_quanta";
      }
    ]
    ++ failuresFor "crates/crucible/tests/trigger_firing_causal_log.rs" triggerFiringTest [
      {
        label = "trigger consumers use event-log prefix";
        needle = "trigger_firing_is_causal_event_log_entry_not_schedule_decision";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 exposes event-log unified check";
        needle = "eventLogUnified = import ./phase4-event-log-unified.nix";
      }
    ]
    ++ forbiddenFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "old scheduler event-log prefix field";
        needle = "event_log_prefix: ContentHash";
      }
      {
        label = "old scheduler event-log byte field";
        needle = "event_log_bytes: u64";
      }
      {
        label = "old scheduler event-log event field";
        needle = "event_log_events: u64";
      }
      {
        label = "old scheduler condition-log storage";
        needle = "condition_event_log_entries: Vec<SchedulerEventLogEntry>";
      }
      {
        label = "old scheduler append helper";
        needle = "fn append_event_log_entries";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/event_log_unified.rs" eventLogTest [
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
  then throw "crucible phase4 event-log unified check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-event-log-unified";
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
          name = "run-event-log-unified";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-event-log-unified-target" \
              -p crucible \
              --test event_log_unified \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-event-log-unified-target" \
              -p crucible \
              --test scheduler_emit_step \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-event-log-unified-target" \
              -p crucible \
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
            component=crucible-event-log
            one_log_per_run=true
            single_append_path=EventLog::append_entries
            projections=condition-prefix,event-log-offset
            RESULT
          '';
        }
      ];
    }
