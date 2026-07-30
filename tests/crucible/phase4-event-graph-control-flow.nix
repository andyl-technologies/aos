{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.eventGraphControlFlow",
  taskIds ? ["T-TRIG-1"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  trigger = import ./_crucible-trigger-source.nix {inherit lib;};
  model = import ./_crucible-model-source.nix {inherit lib;};
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  eventGraphTest = builtins.readFile ../../crates/crucible/tests/event_graph_control_flow.rs;
  triggerDoc = builtins.readFile ../../docs/rfcs/0010-crucible/17a-conditions-and-triggers.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  engineFacingSources = builtins.concatStringsSep "\n" [
    trigger
    libSource
    (import ./_crucible-scheduler-source.nix {inherit lib;})
    (builtins.readFile ../../crates/crucible-api/src/lib.rs)
    (import ./_cli-source.nix {inherit lib;})
    (builtins.readFile ../../crates/crucible-daemon/src/lib.rs)
    (import ./_crucible-session-source.nix {inherit lib;})
  ];
  failures =
    failuresFor "docs/rfcs/0010-crucible/17a-conditions-and-triggers.md" triggerDoc [
      {
        label = "T-TRIG-1 completion note";
        needle = "Completed by `checks.crucible.phase4.eventGraphControlFlow`";
      }
      {
        label = "event graph replay gate complete";
        needle = "Completed by `checks.crucible.phase4.gates.replayOracle`";
      }
      {
        label = "event graph serialization task text";
        needle = "serializable content-addressed form";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "event id";
        needle = "pub struct EventId";
      }
    ]
    ++ failuresFor "crates/crucible/src/trigger.rs" trigger [
      {
        label = "shared condition alias";
        needle = "pub type Condition = Predicate";
      }
      {
        label = "trigger re-exports event id";
        needle = "pub use crate::model::EventId";
      }
      {
        label = "event shape";
        needle = "pub struct Event";
      }
      {
        label = "optional trigger field";
        needle = "trigger: Option<Condition>";
      }
      {
        label = "fire policy";
        needle = "pub enum FirePolicy";
      }
      {
        label = "closed action set";
        needle = "pub enum Action";
      }
      {
        label = "log level shape";
        needle = "pub enum LogLevel";
      }
      {
        label = "event graph";
        needle = "pub struct EventGraph";
      }
      {
        label = "event graph state";
        needle = "pub struct EventGraphState";
      }
      {
        label = "opaque evaluation point";
        needle = "pub struct EventEvaluationPoint {\n    at: VirtualTime,\n    kind: EventEvaluationKind,";
      }
      {
        label = "event firing";
        needle = "pub struct EventFiring";
      }
      {
        label = "opaque event firing fields";
        needle = "pub struct EventFiring {\n    event: EventId,\n    at: VirtualTime,\n    condition_summary: String,\n    action: Action,";
      }
      {
        label = "evaluation point time accessor";
        needle = "pub fn at(self) -> VirtualTime";
      }
      {
        label = "evaluation point kind accessor";
        needle = "pub fn kind(self) -> EventEvaluationKind";
      }
      {
        label = "opaque event firing event accessor";
        needle = "pub fn event(&self) -> &EventId";
      }
      {
        label = "opaque event firing action accessor";
        needle = "pub fn action(&self) -> &Action";
      }
      {
        label = "pass-driven local firing producer";
        needle = "pub fn evaluate_event_graph";
      }
      {
        label = "genesis entrypoint";
        needle = "pub const fn genesis()";
      }
      {
        label = "deterministic scheduler entry boundary";
        needle = "pub fn event_log_entry(entry: &SchedulerEventLogEntry) -> Self";
      }
      {
        label = "duplicate-id rejection";
        needle = "DuplicateEventId";
      }
      {
        label = "repeatable entrypoint rejection";
        needle = "RepeatableEntrypoint";
      }
      {
        label = "declared event order";
        needle = "for event in graph.events()";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "trigger module export";
        needle = "pub mod trigger;";
      }
      {
        label = "event graph re-export";
        needle = "EventGraph";
      }
      {
        label = "event state re-export";
        needle = "EventGraphState";
      }
      {
        label = "action re-export";
        needle = "Action";
      }
      {
        label = "log level re-export";
        needle = "LogLevel";
      }
    ]
    ++ failuresFor "crates/crucible/tests/event_graph_control_flow.rs" eventGraphTest [
      {
        label = "entrypoint and trigger policy test";
        needle = "event_graph_evaluates_entrypoints_named_triggers_and_fire_policies";
      }
      {
        label = "duplicate id test";
        needle = "event_graph_rejects_duplicate_event_ids";
      }
      {
        label = "repeatable entrypoint test";
        needle = "event_graph_rejects_repeatable_entrypoints";
      }
      {
        label = "declared order test";
        needle = "event_graph_preserves_declared_order_for_simultaneous_triggers";
      }
      {
        label = "action spine test";
        needle = "event_graph_action_spine_names_specified_control_actions";
      }
      {
        label = "condition handles";
        needle = "Condition::named";
      }
      {
        label = "once events";
        needle = "Event::once";
      }
      {
        label = "repeatable events";
        needle = "Event::repeatable";
      }
      {
        label = "pass helper evaluation";
        needle = "support::evaluate_graph";
      }
      {
        label = "evaluation point accessors";
        needle = "boundary.kind()";
      }
      {
        label = "all action variants";
        needle = "Action::Group";
      }
      {
        label = "log level shape";
        needle = "level: LogLevel";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 exposes event graph control-flow check";
        needle = "eventGraphControlFlow = import ./phase4-event-graph-control-flow.nix";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/event_graph_control_flow.rs" eventGraphTest [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "pending implementation panic";
        needle = "implementation is pending";
      }
      {
        label = "unfinished todo";
        needle = "todo!";
      }
    ]
    ++ forbiddenFor "engine-facing control-flow surfaces" engineFacingSources [
      {
        label = "direct scenario fault injection API";
        needle = "fn inject_fault(&mut";
      }
      {
        label = "direct scenario fault healing API";
        needle = "fn heal_fault(&mut";
      }
      {
        label = "direct scenario poke API";
        needle = "fn poke";
      }
      {
        label = "public event-firing event field";
        needle = "pub struct EventFiring {\n    pub";
      }
      {
        label = "public evaluation point field";
        needle = "pub struct EventEvaluationPoint {\n    pub";
      }
      {
        label = "public event-firing action field";
        needle = "pub struct EventFiring {\n    pub event: EventId,\n    pub at: VirtualTime,\n    pub action: Action";
      }
    ];
in
  if failures != []
  then throw "crucible phase4 event-graph control-flow check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-event-graph-control-flow";
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
          name = "run-event-graph-control-flow";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-event-graph-control-flow-target" \
              -p crucible \
              --test event_graph_control_flow \
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
            component=crucible-trigger
            gates=gate:layer1-injection,gate:e2e-determinism
            model=event-graph-control-flow-spine
            condition_semantics=implemented-T-TRIG-2-through-T-TRIG-11
            plan_lowering=implemented-T-TRIG-16
            verdicts=implemented-T-TRIG-17
            event_graph_serialization=implemented-T-TRIG-18
            black_box_guarantee=implemented-T-TRIG-19
            replay_oracle=implemented-T-TRIG-20
            RESULT
          '';
        }
      ];
    }
