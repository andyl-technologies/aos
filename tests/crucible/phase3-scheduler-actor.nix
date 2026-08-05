{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase3.schedulerActor",
  taskIds ? ["T-SCHED-1"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoVendor {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-fWBTuyTXJ+/0BiVbB5WAtCqVwufg04NH4BJdocT+moU=";
  };

  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  schedulerActorTest = builtins.readFile ../../crates/crucible/tests/scheduler_actor.rs;
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
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
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
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "scheduler actor export";
        needle = "SchedulerActor";
      }
      {
        label = "actor snapshot export";
        needle = "SchedulerActorStateSnapshot";
      }
    ]
    ++ failuresFor "crates/crucible/tests/scheduler_actor.rs" schedulerActorTest [
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
    pkgs.mkDerivation {
      pname = "crucible-phase3-scheduler-actor";
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
            sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
                > .cargo/config.toml
          '';
        }
        {
          name = "run-scheduler-actor";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-actor-target" \
              -p crucible \
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
