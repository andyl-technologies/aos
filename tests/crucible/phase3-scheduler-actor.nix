{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase3.schedulerActor",
  taskIds ? ["T-SCHED-1"],
}: let
  inherit (import ./_test-gate.nix {inherit pkgs lib;}) mkCrucibleTestGate;

  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  libSource = builtins.readFile ../../crates/crucible/crucible-engine/src/lib.rs;
  schedulerActorTest = builtins.readFile ../../crates/crucible/crucible-engine/tests/scheduler_actor.rs;
  schedulingDoc = builtins.readFile ../../docs/rfcs/0010-crucible/08-scheduling.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/08-scheduling.md" schedulingDoc [
      {
        label = "T-SCHED-1 completion note";
        needle = "Completed by `checks.crucible.phase3.schedulerActor`";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-engine/src/scheduler.rs" scheduler [
      {
        label = "scheduler actor";
        needle = "pub struct SchedulerActor";
      }
      {
        label = "scheduler actor handle";
        needle = "pub struct SchedulerActorHandle";
      }
      {
        label = "scheduler actor message";
        needle = "enum SchedulerActorMessage";
      }
      {
        label = "single scheduler core";
        needle = "pub struct SingleScheduler";
      }
      {
        label = "control inbox";
        needle = "control_inbox: Vec<ControlOperation>";
      }
      {
        label = "decision RNG cursor";
        needle = "decision_rng_cursor: DecisionRngState";
      }
      {
        label = "boundary yield counter";
        needle = "boundary_yields: u64";
      }
      {
        label = "actor run loop";
        needle = "pub fn run_once";
      }
      {
        label = "handle queue control API";
        needle = "pub fn queue_control(&self, operation: ControlOperation)";
      }
      {
        label = "handle drive quantum API";
        needle = "pub fn drive_quantum";
      }
      {
        label = "handle snapshot API";
        needle = "pub fn snapshot";
      }
      {
        label = "control inbox drain";
        needle = "fn drain_control_events";
      }
      {
        label = "control inbox yield";
        needle = "fn yield_to_control_inbox";
      }
      {
        label = "actor state snapshot";
        needle = "pub struct SchedulerActorStateSnapshot";
      }
      {
        label = "decision RNG cursor advance";
        needle = "fn advance_decision_rng_cursor";
      }
      {
        label = "lock-free run proof";
        needle = "scheduler lock spans node advance";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-engine/src/lib.rs" libSource [
      {
        label = "scheduler actor export";
        needle = "SchedulerActor";
      }
      {
        label = "actor snapshot export";
        needle = "SchedulerActorStateSnapshot";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-engine/tests/scheduler_actor.rs" schedulerActorTest [
      {
        label = "control inbox boundary test";
        needle = "scheduler_actor_drains_message_control_inbox_at_quantum_boundary";
      }
      {
        label = "nonrandom progress preserves decision RNG cursor";
        needle = "scheduler_actor_nonrandom_progress_does_not_advance_rng_cursor";
      }
      {
        label = "read-only state snapshot test";
        needle = "scheduler_actor_state_snapshot_is_read_only";
      }
      {
        label = "non-frontier rejection test";
        needle = "scheduler_actor_rejects_non_frontier_message";
      }
      {
        label = "message handle use";
        needle = "SchedulerActorHandle";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase3 exposes scheduler actor check";
        needle = "schedulerActor = import ./phase3-scheduler-actor.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase3 scheduler actor check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    mkCrucibleTestGate {
      pname = "crucible-phase3-scheduler-actor";

      runtimeDeps = [pkgs.sqlite];

      buildDeps = [
        pkgs.sqlite
        pkgs.coreutils
        pkgs.sed
      ];

      phases = [
        {
          name = "run-scheduler-actor";
          script = ''
            set -eu
            cd crates
            crucible-cargo test \
              -p crucible-engine \
              --test scheduler_actor \
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
            component=crucible-scheduler
            actor=single-owner
            control_inbox=boundary-drained
            decision_rng_cursor=scheduler-owned
            RESULT
          '';
        }
      ];
    }
