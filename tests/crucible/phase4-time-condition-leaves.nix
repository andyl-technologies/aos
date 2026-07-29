{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.timeConditionLeaves",
  taskIds ? ["T-TRIG-3"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  model = import ./_crucible-model-source.nix {inherit lib;};
  trigger = import ./_crucible-trigger-source.nix {inherit lib;};
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  timeTest = builtins.readFile ../../crates/crucible/tests/condition_time_leaves.rs;
  triggerDoc = builtins.readFile ../../docs/rfcs/0010-crucible/17a-conditions-and-triggers.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;



  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/17a-conditions-and-triggers.md" triggerDoc [
      {
        label = "T-TRIG-3 checked off";
        needle = "- [x] **T-TRIG-3**";
      }
      {
        label = "T-TRIG-3 completion note";
        needle = "Completed by `checks.crucible.phase4.timeConditionLeaves`";
      }
      {
        label = "event graph replay gate complete";
        needle = "Completed by `checks.crucible.phase4.gates.replayOracle`";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "event id moved into shared model";
        needle = "pub struct EventId";
      }
      {
        label = "At predicate leaf";
        needle = "At {\n        /// Virtual time where the predicate becomes true.";
      }
      {
        label = "After predicate leaf";
        needle = "After {\n        /// Virtual duration after the referenced event fires.";
      }
      {
        label = "Timer predicate leaf";
        needle = "Timer {\n        /// Timer identity armed by an event action.";
      }
      {
        label = "At constructor";
        needle = "pub fn at(at: VirtualTime) -> Self";
      }
      {
        label = "After constructor";
        needle = "pub fn after(duration: SimDuration, of: EventId) -> Self";
      }
      {
        label = "Timer constructor";
        needle = "pub fn timer(name: TimerId) -> Self";
      }
      {
        label = "At TOML form";
        needle = "PredicateTomlKind::At";
      }
      {
        label = "After TOML form";
        needle = "PredicateTomlKind::After";
      }
      {
        label = "Timer TOML form";
        needle = "PredicateTomlKind::Timer";
      }
      {
        label = "At binary tag";
        needle = "Predicate::At { at } => {\n            writer.write_u8(6);";
      }
      {
        label = "After binary tag";
        needle = "Predicate::After { duration, of } => {\n            writer.write_u8(7);";
      }
      {
        label = "Timer binary tag";
        needle = "Predicate::Timer { name } => {\n            writer.write_u8(8);";
      }
      {
        label = "After canonical material uses event id";
        needle = "event_id_material(of)";
      }
      {
        label = "Timer canonical material uses timer id";
        needle = "timer_id_material(name)";
      }
      {
        label = "trigger-only property validation error";
        needle = "PropertyPredicateTriggerOnly";
      }
      {
        label = "After rejected from properties";
        needle = "Predicate::After { .. } => Err(EngineError::PropertyPredicateTriggerOnly";
      }
      {
        label = "Timer rejected from properties";
        needle = "Predicate::Timer { .. } => Err(EngineError::PropertyPredicateTriggerOnly";
      }
    ]
    ++ failuresFor "crates/crucible/src/trigger.rs" trigger [
      {
        label = "EventId compatibility re-export";
        needle = "pub use crate::model::EventId";
      }
      {
        label = "At evaluated from virtual time";
        needle = "Condition::At { at } => evaluator.evaluation_point().at() == *at";
      }
      {
        label = "After evaluated from firing history";
        needle = "Condition::After { duration, of } => evaluator";
      }
      {
        label = "After leaf uses last event firing";
        needle = ".last_event_firing(of)";
      }
      {
        label = "After leaf uses checked addition";
        needle = "fired_at.ticks.checked_add(duration.nanos)";
      }
      {
        label = "Timer evaluated from timer fire time";
        needle = "Condition::Timer { name } => evaluator";
      }
      {
        label = "timer fire lookup hook";
        needle = "fn timer_fire_time(&self, timer: &TimerId) -> Option<VirtualTime>";
      }
      {
        label = "event firing lookup hook";
        needle = "fn last_event_firing(&self, event: &EventId) -> Option<VirtualTime>";
      }
      {
        label = "condition evaluator event firing injection";
        needle = "pub fn with_event_firings";
      }
      {
        label = "condition evaluator timer fire injection";
        needle = "pub fn with_timer_fires";
      }
      {
        label = "event graph firing history";
        needle = "last_firing: BTreeMap<EventId, VirtualTime>";
      }
      {
        label = "event graph updates firing history";
        needle = "self.last_firing.insert(event.id.clone(), point.at())";
      }
      {
        label = "graph evaluator wraps firing history";
        needle = "struct EventGraphConditionEvaluator";
      }
      {
        label = "unknown event reference error";
        needle = "UnknownEventReference";
      }
      {
        label = "unknown timer reference error";
        needle = "UnknownTimerReference";
      }
      {
        label = "armable timer collection";
        needle = "fn armed_timer_names(events: &[Event]) -> BTreeSet<TimerId>";
      }
      {
        label = "grouped action timer collection";
        needle = "collect_timer_names(action, timers);";
      }
      {
        label = "condition reference validator";
        needle = "fn validate_condition_references";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "EventId re-export";
        needle = "EventId";
      }
      {
        label = "ConditionEvaluation re-export";
        needle = "ConditionEvaluation";
      }
      {
        label = "ConditionEvaluator re-export";
        needle = "ConditionEvaluator";
      }
      {
        label = "EventGraphError re-export";
        needle = "EventGraphError";
      }
    ]
    ++ failuresFor "crates/crucible/tests/condition_time_leaves.rs" timeTest [
      {
        label = "At exact-time test";
        needle = "at_leaf_is_true_only_at_the_exact_virtual_time";
      }
      {
        label = "After relative firing history test";
        needle = "after_leaf_is_relative_to_known_event_firing_history";
      }
      {
        label = "Timer fire-time test";
        needle = "timer_leaf_is_true_at_evaluator_supplied_timer_fire_time";
      }
      {
        label = "EventGraph firing history test";
        needle = "event_graph_supplies_last_firing_history_to_after_leaves";
      }
      {
        label = "After reference validation test";
        needle = "event_graph_validates_after_references_declared_events";
      }
      {
        label = "Timer reference validation test";
        needle = "event_graph_validates_timer_references_armable_timers";
      }
      {
        label = "Grouped ArmTimer validation test";
        needle = "event_graph_accepts_timer_reference_to_grouped_arm_timer_action";
      }
      {
        label = "ConditionEvaluation event firing hook used";
        needle = ".with_event_firings(";
      }
      {
        label = "ConditionEvaluation timer hook used";
        needle = ".with_timer_fires(";
      }
      {
        label = "Unknown event error asserted";
        needle = "EventGraphError::UnknownEventReference";
      }
      {
        label = "Unknown timer error asserted";
        needle = "EventGraphError::UnknownTimerReference";
      }
      {
        label = "At property serialization roundtrip";
        needle = "at_leaf_round_trips_through_properties_serialization";
      }
      {
        label = "edge-shaped properties rejected";
        needle = "properties_reject_edge_shaped_after_and_timer_leaves";
      }
      {
        label = "At TOML assertion";
        needle = "toml.contains(\"kind = \\\"at\\\"\")";
      }
      {
        label = "compact binary roundtrip";
        needle = "Properties::from_compact_binary_for_world";
      }
      {
        label = "trigger-only property error asserted";
        needle = "EngineError::PropertyPredicateTriggerOnly";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 exposes time condition leaves check";
        needle = "timeConditionLeaves = import ./phase4-time-condition-leaves.nix";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/condition_time_leaves.rs" timeTest [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "unfinished todo";
        needle = "todo!";
      }
      {
        label = "pending implementation panic";
        needle = "implementation is pending";
      }
    ];
in
  if failures != []
  then throw "crucible phase4 time-condition-leaves check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-time-condition-leaves";
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
          name = "run-time-condition-leaves";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-time-condition-leaves-target" \
              -p crucible \
              --test condition_time_leaves \
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
            time_leaves=at,after,timer
            reference_validation=after-events,timer-armers
            RESULT
          '';
        }
      ];
    }
