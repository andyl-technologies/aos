{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase3.schedulerQuiescence",
  taskIds ? ["T-SCHED-11"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = import ../../pkgs/tools/crucible/_cargo-deps-hash.nix;
  };

  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  schedulingDoc = builtins.readFile ../../docs/rfcs/0010-crucible/08-scheduling.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/08-scheduling.md" schedulingDoc [
      {
        label = "T-SCHED-11 completion note";
        needle = "Completed by `checks.crucible.phase3.schedulerQuiescence`";
      }
      {
        label = "quiescence requirement";
        needle = "Quiescence MUST be computed from authoritative scheduler state";
      }
      {
        label = "no host timeout requirement";
        needle = "MUST NOT depend on a host timeout";
      }
      {
        label = "idle nodes do not constrain peers";
        needle = "idle nodes do not constrain peers";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "quiescence evidence type";
        needle = "pub struct SchedulerQuiescence";
      }
      {
        label = "quiescence blocker type";
        needle = "pub enum SchedulerQuiescenceBlocker";
      }
      {
        label = "public quiescence predicate";
        needle = "pub fn quiescence(&self) -> Result<SchedulerQuiescence, SchedulerError>";
      }
      {
        label = "pending control blocker";
        needle = "SchedulerQuiescenceBlocker::PendingControl";
      }
      {
        label = "pending scheduler event blocker";
        needle = "SchedulerQuiescenceBlocker::PendingEvent";
      }
      {
        label = "pending exact local event blocker";
        needle = "SchedulerQuiescenceBlocker::PendingExactLocalEvent";
      }
      {
        label = "runnable node blocker";
        needle = "SchedulerQuiescenceBlocker::RunnableNode";
      }
      {
        label = "canonical event queue inspection";
        needle = "ordered_scheduled_events(&self.pending_events)";
      }
      {
        label = "exact local wakeup inspection";
        needle = "next_exact_local_event(\n            &node.id,";
      }
      {
        label = "idle wake candidate";
        needle = "fn idle_advance_candidate";
      }
      {
        label = "idle wake time from pending state";
        needle = "fn idle_wake_time";
      }
      {
        label = "liveness loop uses quiescence predicate";
        needle = "scheduler.quiescence()?.is_quiescent()";
      }
      {
        label = "all-idle quiescence test";
        needle = "scheduler_quiescence_detects_all_idle_authoritative_state";
      }
      {
        label = "runnable pending event control test";
        needle = "scheduler_quiescence_blocks_on_runnable_node_pending_event_and_control";
      }
      {
        label = "idle exact wakeup test";
        needle = "scheduler_quiescence_blocks_idle_nodes_with_exact_local_wakeups";
      }
      {
        label = "idle exact wakeup liveness test";
        needle = "scheduler_quiescence_fast_forwards_idle_exact_wakeup_without_deadlock";
      }
      {
        label = "idle exact wakeup time-limit test";
        needle = "scheduler_quiescence_idle_exact_wakeup_after_time_limit_stops_at_limit";
      }
      {
        label = "idle pending delivery liveness test";
        needle = "scheduler_quiescence_fast_forwards_idle_pending_delivery_without_deadlock";
      }
      {
        label = "I/O and fault blocker test";
        needle = "scheduler_quiescence_blocks_future_io_and_fault_events";
      }
      {
        label = "idle peer non-constraint test";
        needle = "scheduler_quiescence_ignores_idle_nodes_when_peer_can_advance";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "quiescence evidence exported";
        needle = "SchedulerQuiescence";
      }
      {
        label = "quiescence blockers exported";
        needle = "SchedulerQuiescenceBlocker";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase3 exposes scheduler quiescence check";
        needle = "schedulerQuiescence = import ./phase3-scheduler-quiescence.nix";
      }
    ]
    ++ forbiddenFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "host time API";
        needle = "std::time";
      }
      {
        label = "instant now API";
        needle = "Instant::now";
      }
      {
        label = "system time API";
        needle = "SystemTime";
      }
      {
        label = "sleep API";
        needle = "thread::sleep";
      }
      {
        label = "park timeout API";
        needle = "park_timeout";
      }
    ];
in
  if failures != []
  then throw "crucible phase3 scheduler quiescence check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase3-scheduler-quiescence";
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
          name = "run-scheduler-quiescence";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-quiescence-target" \
              -p crucible \
              --lib \
              scheduler_quiescence \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-quiescence-target" \
              -p crucible \
              --features test-double \
              --test gate_scheduler_liveness \
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
            quiescence=authoritative-scheduler-state
            host_timeout=false
            blockers=runnable,pending-event,pending-control,exact-local-event
            idle_nodes_constrain_peers=false
            RESULT
          '';
        }
      ];
    }
