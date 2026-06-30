{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.observedStateMaterialization",
  taskIds ? ["T-ASRT-4"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  trigger = builtins.readFile ../../crates/crucible/src/trigger.rs;
  scheduler = builtins.readFile ../../crates/crucible/src/scheduler.rs;
  crateRoot = builtins.readFile ../../crates/crucible/src/lib.rs;
  observedStateTest = builtins.readFile ../../crates/crucible/tests/observed_state_materialization.rs;
  deterministicConditionTest = builtins.readFile ../../crates/crucible/tests/deterministic_condition_evaluation.rs;
  assertionDoc = builtins.readFile ../../docs/rfcs/0010-crucible/18-assertions-properties.md;
  defaultChecks = builtins.readFile ./default.nix;

  hasInfix = needle: haystack: let
    needleLen = builtins.stringLength needle;
    haystackLen = builtins.stringLength haystack;
    maxStart = haystackLen - needleLen;
    indexes =
      if needleLen == 0
      then [0]
      else if maxStart < 0
      then []
      else builtins.genList (index: index) (maxStart + 1);
  in
    builtins.any (index:
      builtins.substring index needleLen haystack == needle)
    indexes;

  failuresFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (!(hasInfix requirement.needle content)) [
          "${fileLabel}: missing ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  forbiddenFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (hasInfix requirement.needle content) [
          "${fileLabel}: forbidden ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/18-assertions-properties.md" assertionDoc [
      {
        label = "T-ASRT-4 checked off";
        needle = "- [x] **T-ASRT-4**";
      }
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
        label = "fault facts view";
        needle = "pub fn fault_facts(self) -> &'log [ObservedFaultFact]";
      }
      {
        label = "ordering fact enum";
        needle = "pub enum ObservedOrderingFact";
      }
      {
        label = "fault fact enum";
        needle = "pub enum ObservedFaultFact";
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
        label = "probabilistic fault outcome fold";
        needle = "Decision::FaultFires(fault)";
      }
      {
        label = "control fault fold";
        needle = "Decision::ControlFault(control)";
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
        label = "ignored app-random decision";
        needle = "Decision::AppRandom(_)";
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
        label = "observed fault fact export";
        needle = "ObservedFaultFact";
      }
      {
        label = "test typed payload constructor";
        needle = "condition_payload_entry_for_test";
      }
    ]
    ++ failuresFor "crates/crucible/tests/observed_state_materialization.rs" observedStateTest [
      {
        label = "checked prefix materialization test";
        needle = "observed_state_materializes_only_checked_event_log_prefix";
      }
      {
        label = "fault fact materialization test";
        needle = "observed_state_materializes_fault_activation_and_heal_facts";
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
        label = "app random ignored by observed state";
        needle = "Decision::AppRandom";
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
    ++ forbiddenFor "crates/crucible/src/trigger.rs" trigger [
      {
        label = "host wall-clock dependency";
        needle = "SystemTime";
      }
      {
        label = "host instant dependency";
        needle = "Instant";
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
    pkgs.mkDerivation {
      pname = "crucible-phase4-observed-state-materialization";
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
          name = "run-observed-state-materialization";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-observed-state-materialization-target" \
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
