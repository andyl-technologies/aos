{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase3.schedulerIdleFastForward",
  taskIds ? ["T-SCHED-15"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-ULD9g6d87886b8O6/sGCMktquGwaUAyf+DLHUrFzod0=";
  };

  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  idleTest = builtins.readFile ../../crates/crucible/tests/scheduler_idle_fast_forward.rs;
  schedulingDoc = builtins.readFile ../../docs/rfcs/0010-crucible/08-scheduling.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/08-scheduling.md" schedulingDoc [
      {
        label = "T-SCHED-15 completion note";
        needle = "Completed by `checks.crucible.phase3.schedulerIdleFastForward`";
      }
      {
        label = "idle fast-forward requirement";
        needle = "idle fast-forward";
      }
      {
        label = "effective clock requirement";
        needle = "effective clock";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "effective clock type";
        needle = "pub struct SchedulerEffectiveClock";
      }
      {
        label = "effective clock source";
        needle = "pub enum SchedulerEffectiveClockSource";
      }
      {
        label = "public effective clocks accessor";
        needle = "pub fn effective_clocks";
      }
      {
        label = "private effective clock projection";
        needle = "fn effective_clock_for_node";
      }
      {
        label = "idle wake source";
        needle = "SchedulerEffectiveClockSource::IdleWake";
      }
      {
        label = "idle candidate uses effective clock";
        needle = "let projection = self.effective_clock_for_node(node)?";
      }
      {
        label = "idle wake time reducer";
        needle = "fn idle_wake_time";
      }
      {
        label = "time-limit clamp";
        needle = "wake_time = min_instant(wake_time, self.time_limit)";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "effective clock export";
        needle = "SchedulerEffectiveClock";
      }
      {
        label = "effective clock source export";
        needle = "SchedulerEffectiveClockSource";
      }
    ]
    ++ failuresFor "crates/crucible/tests/scheduler_idle_fast_forward.rs" idleTest [
      {
        label = "timer fast-forward test";
        needle = "idle_fast_forward_jumps_to_exact_timer_wake_without_schedule_decision";
      }
      {
        label = "peer effective-clock test";
        needle = "idle_effective_clock_uses_wake_time_and_does_not_constrain_peer_behind_it";
      }
      {
        label = "pending-delivery wake test";
        needle = "idle_fast_forward_uses_earliest_pending_delivery_as_wake";
      }
      {
        label = "time-limit clamp test";
        needle = "idle_fast_forward_clamps_exact_wake_to_time_limit";
      }
      {
        label = "no-wake current clock test";
        needle = "idle_without_wake_keeps_current_effective_clock_and_produces_no_advance";
      }
      {
        label = "idle wake source assertion";
        needle = "SchedulerEffectiveClockSource::IdleWake";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase3 exposes scheduler idle-fast-forward check";
        needle = "schedulerIdleFastForward = import ./phase3-scheduler-idle-fast-forward.nix";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/scheduler_idle_fast_forward.rs" idleTest [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "pending placeholder";
        needle = "todo!";
      }
      {
        label = "wall-clock dependency";
        needle = "std::time";
      }
      {
        label = "sleep dependency";
        needle = "sleep(";
      }
    ];
in
  if failures != []
  then throw "crucible phase3 scheduler idle-fast-forward check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase3-scheduler-idle-fast-forward";
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
          name = "run-scheduler-idle-fast-forward";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-idle-fast-forward-target" \
              -p crucible \
              --test scheduler_idle_fast_forward \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-idle-fast-forward-target" \
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
            idle_fast_forward=exact-wake-zero-wall-clock-time
            effective_clock=idle-wake-projection
            peer_constraint=idle-wake-does-not-hold-back-peer
            wall_clock_dependency=false
            RESULT
          '';
        }
      ];
    }
