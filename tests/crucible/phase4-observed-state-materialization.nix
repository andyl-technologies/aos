{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.observedStateMaterialization",
  taskIds ? ["T-ASRT-4"],
}: let
  inherit (import ./_test-gate.nix {inherit pkgs lib;}) mkCrucibleTestGate;

  trigger = import ./_crucible-trigger-source.nix {inherit lib;};
  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  crateRoot = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible/src/lib.rs;
  };
  observedStateTest = builtins.readFile ../../crates/crucible/tests/observed_state_materialization.rs;
  deterministicConditionTest = builtins.readFile ../../crates/crucible/tests/deterministic_condition_evaluation.rs;
  assertionDoc = builtins.readFile ../../docs/rfcs/0010-crucible/18-assertions-properties.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  # Character-exact scrub of Rust comments and string literals. The fold is
  # chunked per source line (each chunk keeps its trailing newline, and the
  # parser state — mode/depth/skip — threads across chunks) with the output
  # string forced after every chunk. A whole-file per-character fold builds a
  # haystack-deep chain of unforced `+` thunks and overflows the evaluator
  # stack on large sources.
  scrubCommentsAndStrings = import ./_rust-scrub.nix {inherit lib;};

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/18-assertions-properties.md" assertionDoc [
      {
        label = "T-ASRT-4 completion note";
        needle = "Completed by `checks.crucible.phase4.observedStateMaterialization`";
      }
    ]
    ++ failuresFor "crates/crucible/src/trigger.rs" trigger [
      {
        label = "observed state view";
        needle = "pub struct ObservedState<'log>";
      }
      {
        label = "observed state from checked prefix";
        needle = "pub fn observed_state(&self) -> ObservedState<'_>";
      }
      {
        label = "observable events view";
        needle = "pub fn observable_events(self) -> &'log [ObservableEvent]";
      }
      {
        label = "ordering facts view";
        needle = "pub fn ordering_facts(self) -> &'log [ObservedOrderingFact]";
      }
      {
        label = "typed fault evidence folded separately";
        needle = "SchedulerEventLogPayload::FaultObservation(_)";
      }
      {
        label = "ordering fact enum";
        needle = "pub enum ObservedOrderingFact";
      }
      {
        label = "private observed-state storage";
        needle = "pub(super) observable_events:";
      }
      {
        label = "checked prefix constructor";
        needle = "fn from_scheduler_event_log_entries";
      }
      {
        label = "dense prefix validation";
        needle = "ConditionEvaluationError::NonPrefixEventLogSequence";
      }
      {
        label = "entry hash validation";
        needle = "ConditionEvaluationError::InvalidEventLogEntryHash";
      }
      {
        label = "future entry rejection";
        needle = "ConditionEvaluationError::FutureEventLogEntry";
      }
      {
        label = "observed-state fold helper";
        needle = "fn push_observed_state_facts";
      }
      {
        label = "black-box observable payload fold";
        needle = "SchedulerEventLogPayload::Observable(payload)";
      }
      {
        label = "resolved ordering fold";
        needle = "SchedulerEventLogPayload::ResolvedHappening(event)";
      }
      {
        label = "delivery-order fold";
        needle = "Decision::DeliveryOrder(order)";
      }
      {
        label = "trigger fault fold";
        needle = "SchedulerEventLogPayload::TriggerActionApplied(application)";
      }
      {
        label = "ignored nondeterministic decisions";
        needle = "Decision::RngDraw(_)";
      }
      {
        label = "ignored host/preemption decision";
        needle = "Decision::Preemption(_)";
      }
      {
        label = "evaluation pass exposes observed state";
        needle = "pub fn observed_state(&self) -> ObservedState<'_>";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "test-only typed event-log constructor";
        needle = "pub(crate) fn with_payload_for_test";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" crateRoot [
      {
        label = "observed state export";
        needle = "ObservedState";
      }
      {
        label = "observed ordering fact export";
        needle = "ObservedOrderingFact";
      }
      {
        label = "checked prefix export";
        needle = "ConditionEventLogPrefix";
      }
      {
        label = "test typed payload constructor";
        needle = "condition_payload_entry_for_test";
      }
    ]
    ++ failuresFor "crates/crucible/tests/observed_state_materialization.rs" observedStateTest [
      {
        label = "internal fault evidence does not enter assertion state";
        needle = "fault_evidence_does_not_expose_internal_state_to_assertion_predicates";
      }
      {
        label = "checked prefix materialization test";
        needle = "observed_state_materializes_only_checked_event_log_prefix";
      }
      {
        label = "invalid prefix rejection test";
        needle = "observed_state_rejects_future_invalid_or_non_dense_prefixes";
      }
      {
        label = "host time unordered map static test";
        needle = "observed_state_implementation_avoids_host_time_and_unordered_maps";
      }
      {
        label = "raw RNG draw ignored by observed state";
        needle = "Decision::RngDraw";
      }
      {
        label = "raw override ignored by observed state";
        needle = "Decision::Override";
      }
      {
        label = "preemption ignored by observed state";
        needle = "Decision::Preemption";
      }
      {
        label = "checked future rejection";
        needle = "ConditionEvaluationError::FutureEventLogEntry";
      }
    ]
    ++ failuresFor "crates/crucible/tests/deterministic_condition_evaluation.rs" deterministicConditionTest [
      {
        label = "existing prefix-event-only regression";
        needle = "condition_evaluation_uses_checked_prefix_events_only";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 observed state check import";
        needle = "observedStateMaterialization = import ./phase4-observed-state-materialization.nix";
      }
      {
        label = "phase4 observed state attr path";
        needle = "attrPath = \"checks.crucible.phase4.observedStateMaterialization\"";
      }
    ]
    ++ forbiddenFor "crates/crucible/src/trigger.rs" (scrubCommentsAndStrings trigger) [
      {
        label = "host wall-clock dependency";
        needle = "SystemTime";
      }
      {
        label = "host instant dependency";
        needle = "time::Instant";
      }
      {
        label = "std time dependency";
        needle = "std::time";
      }
      {
        label = "unordered hash map";
        needle = "HashMap";
      }
      {
        label = "unordered hash set";
        needle = "HashSet";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/observed_state_materialization.rs" observedStateTest [
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
  then throw "crucible phase4 observed-state-materialization check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    mkCrucibleTestGate {
      pname = "crucible-phase4-observed-state-materialization";

      buildDeps = [
        pkgs.coreutils
        pkgs.sed
      ];

      phases = [
        {
          name = "run-observed-state-materialization";
          script = ''
            set -eu
            cd crates
            crucible-cargo test \
              -p crucible \
              --test observed_state_materialization \
              --test deterministic_condition_evaluation \
              --test observable_condition_leaves \
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
            observed_state_materialized_from_prefix=true
            RESULT
          '';
        }
      ];
    }
