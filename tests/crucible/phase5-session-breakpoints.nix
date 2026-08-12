{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.sessionBreakpoints",
  taskIds ? ["T-SESS-7"],
  openTaskIds ? [],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  sessionLib = import ./_crucible-session-source.nix {inherit lib;};
  schedulerLib = import ./_crucible-scheduler-source.nix {inherit lib;};
  triggerLib = import ./_crucible-trigger-source.nix {inherit lib;};
  sessionDoc = builtins.readFile ../../docs/rfcs/0010-crucible/20-session-control-plane.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;
  openTaskList = builtins.concatStringsSep "," openTaskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/20-session-control-plane.md" sessionDoc [
      {
        label = "T-SESS-7 completion note";
        needle = "Completed by `checks.crucible.phase5.sessionBreakpoints`";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "phase5 breakpoint completion note";
        needle = "`T-SESS-7` is completed by `checks.crucible.phase5.sessionBreakpoints`";
      }
    ]
    ++ failuresFor "crates/crucible-session/src/lib.rs" sessionLib [
      {
        label = "breakpoint firing record";
        needle = "pub struct BreakpointFiring";
      }
      {
        label = "breakpoint firing storage";
        needle = "breakpoint_firings: Vec<BreakpointFiring>";
      }
      {
        label = "breakpoint firing accessor";
        needle = "pub fn breakpoint_firings(&self) -> &[BreakpointFiring]";
      }
      {
        label = "shared condition prefix";
        needle = "ConditionEventLogPrefix::from_scheduler_event_log_entries";
      }
      {
        label = "shared condition evaluator";
        needle = "ConditionEvaluationPass::from_log_prefix";
      }
      {
        label = "scheduler quiescence evidence";
        needle = "pass.with_scheduler_quiescence(quiescence)";
      }
      {
        label = "no-entry breakpoint prefix";
        needle = "fn breakpoint_condition_prefix";
      }
      {
        label = "synthetic evaluation boundary";
        needle = "ConditionEventLogPrefix::from_evaluation_boundary";
      }
      {
        label = "full-prefix synthetic boundary";
        needle = "from_scheduler_event_log_entries_with_evaluation_boundary";
      }
      {
        label = "breakpoint transition evaluation";
        needle = "fn evaluate_breakpoints";
      }
      {
        label = "current quantum entry count";
        needle = "emitted_event_log_entries";
      }
      {
        label = "repeatable last truth tracking";
        needle = "last_truth";
      }
      {
        label = "once latch tracking";
        needle = "once_latches";
      }
      {
        label = "shared evaluator once latch seeding";
        needle = ".with_once_latches(self.breakpoints.once_latches(id))";
      }
      {
        label = "breakpoint firing dispatcher";
        needle = "fn fire_breakpoint";
      }
      {
        label = "action breakpoint scheduler control";
        needle = "fn apply_breakpoint_action";
      }
      {
        label = "action breakpoint prevalidation";
        needle = "fn plan_breakpoint_action";
      }
      {
        label = "action controls applied at boundary";
        needle = "apply_control_operations_at_boundary(planned_controls.clone())";
      }
      {
        label = "action control logged";
        needle = "record_boundary_control_kind";
      }
      {
        label = "unsupported action error";
        needle = "UnsupportedBreakpointAction";
      }
      {
        label = "unsupported fault error";
        needle = "UnsupportedBreakpointFault";
      }
      {
        label = "step one-shot primitive";
        needle = "BreakpointSpec::suspend_once(Self::stop_condition";
      }
      {
        label = "step shared evaluator oracle";
        needle = "struct StepConditionLeaves";
      }
      {
        label = "step predicate evaluated through condition pass";
        needle = "evaluate_assertion_condition(&self.breakpoint.predicate)";
      }
      {
        label = "suspend nonperturbation test";
        needle = "breakpoint_suspend_uses_shared_condition_and_preserves_canonical_log";
      }
      {
        label = "repeatable trace transition test";
        needle = "repeatable_trace_breakpoint_fires_on_false_to_true_transitions";
      }
      {
        label = "once combinator latch test";
        needle = "breakpoint_once_combinator_latches_across_boundaries";
      }
      {
        label = "action breakpoint control test";
        needle = "breakpoint_action_applies_scheduler_control_at_boundary";
      }
      {
        label = "unsupported action test";
        needle = "unsupported_breakpoint_action_fails_loudly";
      }
      {
        label = "unsupported fault test";
        needle = "unsupported_breakpoint_fault_fails_loudly";
      }
      {
        label = "action group prevalidation test";
        needle = "breakpoint_action_group_is_prevalidated_before_control_application";
      }
      {
        label = "node and assertion leaf test";
        needle = "breakpoint_conditions_cover_node_and_assertion_state_leaves";
      }
      {
        label = "after and timer leaf test";
        needle = "breakpoint_conditions_cover_after_and_timer_runtime_facts";
      }
      {
        label = "quiescent leaf test";
        needle = "quiescent_breakpoint_uses_scheduler_quiescence_evidence";
      }
      {
        label = "no-entry quiescent test";
        needle = "quiescent_breakpoint_fires_without_emitted_entries";
      }
      {
        label = "post-event no-entry boundary test";
        needle = "no_entry_breakpoint_after_prior_event_uses_current_boundary";
      }
      {
        label = "step one-shot test";
        needle = "step_modes_are_expressible_as_one_shot_breakpoints";
      }
      {
        label = "deterministic breakpoint host metadata";
        needle = "pub struct BreakpointHostMetadata";
      }
      {
        label = "named host predicate no-entry boundary test";
        needle = "breakpoint_named_host_predicate_fires_at_no_entry_quantum_boundary";
      }
      {
        label = "symbol metadata breakpoint test";
        needle = "breakpoint_symbol_metadata_resolves_coverage_and_memory_leaves";
      }
    ]
    ++ failuresFor "crates/crucible/src/trigger.rs" triggerLib [
      {
        label = "public condition prefix builder";
        needle = "pub fn from_scheduler_event_log_entries";
      }
      {
        label = "condition pass once latch seed";
        needle = "pub fn with_once_latches";
      }
      {
        label = "condition pass once latch accessor";
        needle = "pub fn once_latches(&self) -> &[Condition]";
      }
      {
        label = "public segment prefix builder";
        needle = "pub fn from_scheduler_event_log_entries_with_base_sequence";
      }
      {
        label = "public boundary prefix builder";
        needle = "pub fn from_evaluation_boundary";
      }
      {
        label = "public full-prefix boundary builder";
        needle = "pub fn from_scheduler_event_log_entries_with_evaluation_boundary";
      }
      {
        label = "condition prefix event firing facts";
        needle = "event_firings: BTreeMap<EventId, VirtualTime>";
      }
      {
        label = "condition prefix timer facts";
        needle = "timer_fires: BTreeMap<TimerId, VirtualTime>";
      }
      {
        label = "condition runtime fact extraction";
        needle = "fn push_condition_runtime_facts";
      }
      {
        label = "runtime facts enter condition pass";
        needle = "event_firings: prefix.event_firings";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" schedulerLib [
      {
        label = "quantum outcome quiescence field";
        needle = "pub scheduler_quiescence: Option<SchedulerQuiescence>";
      }
      {
        label = "single scheduler quiescence outcome";
        needle = "scheduler_quiescence: Some(self.quiescence()?)";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase5 exposes session breakpoint check";
        needle = "sessionBreakpoints = import ./phase5-session-breakpoints.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase5 session-breakpoints check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase5-session-breakpoints";
      version = "0";
      src = crucibleSrc;

      buildDeps =
        [
          pkgs.coreutils
          pkgs.rust
          pkgs.sed
        ]
        ++ dependencies;

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
          name = "run-session-breakpoints";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-session-breakpoints-target" \
              -p crucible-session \
              --lib \
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
            open_tasks=${openTaskList}
            status=partial
            component=crucible-session
            breakpoints=shared-condition-vocabulary
            dispositions=suspend-trace-action
            policies=one-shot-repeatable
            quiescence=scheduler-evidence
            RESULT
          '';
        }
      ];
    }
