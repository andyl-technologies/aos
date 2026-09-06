{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.eventLogSchema",
  taskIds ? ["T-OBS-2"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  libSource = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible/src/lib.rs;
  };
  schemaTest = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible/tests/event_log_schema.rs;
  };
  observabilityDoc = builtins.readFile ../../docs/rfcs/0010-crucible/19-observability-event-log.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/19-observability-event-log.md" observabilityDoc [
      {
        label = "T-OBS-2 completion note";
        needle = "Completed by `checks.crucible.phase4.eventLogSchema`";
      }
      {
        label = "mandatory icount completion note";
        needle = "`VirtualTime` plus an `Icount` stamp";
      }
      {
        label = "entry schema task text";
        needle = "closed `EventSource` set incl.";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "event-log time schema";
        needle = "pub struct EventLogTime";
      }
      {
        label = "event-log icount stamp";
        needle = "pub struct EventLogIcountStamp";
      }
      {
        label = "closed event-source enum";
        needle = "pub enum EventSource";
      }
      {
        label = "command correlation source";
        needle = "Command {";
      }
      {
        label = "display level enum";
        needle = "pub enum EventLevel";
      }
      {
        label = "event class compatibility alias";
        needle = "pub type EventClass = SchedulerEventLogClass";
      }
      {
        label = "entry stores full time";
        needle = "at: EventLogTime";
      }
      {
        label = "event-log time has mandatory icount";
        needle = "pub icount: EventLogIcountStamp";
      }
      {
        label = "boundary icount fallback";
        needle = "retired: virtual_time.ticks";
      }
      {
        label = "entry stores closed source";
        needle = "source: EventSource";
      }
      {
        label = "entry stores display level";
        needle = "level: EventLevel";
      }
      {
        label = "full time accessor";
        needle = "pub fn time(&self) -> &EventLogTime";
      }
      {
        label = "source accessor";
        needle = "pub fn source(&self) -> &EventSource";
      }
      {
        label = "level accessor";
        needle = "pub fn level(&self) -> EventLevel";
      }
      {
        label = "command source derivation";
        needle = "EventSource::Command";
      }
      {
        label = "control decision command id";
        needle = "command_id: control.sequence";
      }
      {
        label = "entry hash material includes source level class";
        needle = "scheduler_event_log_entry_material(\n            sequence,\n            &time,\n            &source,\n            level,\n            class,";
      }
      {
        label = "valid-hash material includes stored schema fields";
        needle = "&self.source,\n                    self.level,\n                    self.class,";
      }
      {
        label = "segment material carries virtual time";
        needle = "entry.at_virtual_time_ticks";
      }
      {
        label = "segment material carries icount";
        needle = "entry.at_icount_retired";
      }
      {
        label = "segment material carries source";
        needle = "entry.source";
      }
      {
        label = "segment material carries level";
        needle = "entry.level";
      }
      {
        label = "segment material carries class";
        needle = "entry.class";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "EventSource export";
        needle = "EventSource";
      }
      {
        label = "EventLevel export";
        needle = "EventLevel";
      }
      {
        label = "EventLogTime export";
        needle = "EventLogTime";
      }
    ]
    ++ failuresFor "crates/crucible/tests/event_log_schema.rs" schemaTest [
      {
        label = "schema field test";
        needle = "event_log_entries_carry_source_level_class_and_icount_stamp";
      }
      {
        label = "command correlation test";
        needle = "command_caused_entries_preserve_command_correlation_source";
      }
      {
        label = "guest source assertion";
        needle = "EventSource::Guest";
      }
      {
        label = "command source assertion";
        needle = "EventSource::Command";
      }
      {
        label = "icount assertion";
        needle = "Icount { retired: 99 }";
      }
      {
        label = "command boundary icount assertion";
        needle = "Icount { retired: 12 }";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 exposes event-log schema check";
        needle = "eventLogSchema = import ./phase4-event-log-schema.nix";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/event_log_schema.rs" schemaTest [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "pending placeholder";
        needle = "todo!";
      }
      {
        label = "optional icount stamp";
        needle = "Option<EventLogIcountStamp>";
      }
    ];
in
  if failures != []
  then throw "crucible phase4 event-log schema check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-event-log-schema";
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
          name = "run-event-log-schema";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-event-log-schema-target" \
              -p crucible \
              --test event_log_schema \
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
            schema_fields=seq,at,source,payload,level,class
            event_source_closed_set=true
            command_correlation_source=true
            icount_stamp_field=true
            RESULT
          '';
        }
      ];
    }
