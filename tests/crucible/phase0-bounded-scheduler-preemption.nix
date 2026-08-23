{
  pkgs,
  lib,
}: let
  harnessSource = builtins.readFile ./_bounded-scheduler-preemption.sh;
  targetWrapperSource = builtins.readFile ./_bounded-scheduler-preemption-target.sh;
  rustSchedulerSource = builtins.readFile ../../crates/crucible-qemu/src/bounded_scheduler_preemption.rs;
  consumerSources = [
    {
      label = "tests/crucible/phase0-s1.nix";
      source = builtins.readFile ./phase0-s1.nix;
      evidence = "host_adversary=\"$HOST_ADVERSARY\"";
      cleanup = "bounded_preemption_cleanup; exit 143";
    }
    {
      label = "tests/crucible/phase0-s6.nix";
      source = builtins.readFile ./phase0-s6.nix;
      evidence = "host_adversary=bounded-scheduler-preemption";
      cleanup = "bounded_preemption_cleanup; exit 143";
    }
    {
      label = "tests/crucible/phase0-s11.nix";
      source = builtins.readFile ./phase0-s11.nix;
      evidence = "host_adversary=bounded-scheduler-preemption";
      cleanup = "cleanup_active_qemu; exit 143";
    }
    {
      label = "tests/crucible/phase0-aarch64-s1-s6.nix";
      source = builtins.readFile ./phase0-aarch64-s1-s6.nix;
      evidence = "host_adversary=bounded-scheduler-preemption";
      cleanup = "bounded_preemption_cleanup; exit 143";
    }
    {
      label = "tests/crucible/phase1-guest-entropy-launch.nix";
      source = builtins.readFile ./phase1-guest-entropy-launch.nix;
      evidence = "host_adversary=bounded-scheduler-preemption-second-run";
      cleanup = "bounded_preemption_cleanup; exit 143";
    }
    {
      label = "tests/crucible/phase2-qemu-nvcpu-fingerprint.nix";
      source = builtins.readFile ./phase2-qemu-nvcpu-fingerprint.nix;
      evidence = "real_qemu_adversary=second-run-bounded-scheduler-preemption";
      cleanup = "cleanup_qemu; exit 143";
    }
  ];
  rustSchedulerConsumers = [
    {
      label = "crates/crucible-qemu/src/live_plugin_quantum_gate";
      source =
        builtins.readFile ../../crates/crucible-qemu/src/live_plugin_quantum_gate.rs
        + builtins.readFile ../../crates/crucible-qemu/src/live_plugin_quantum_gate/preemption_gate.rs
        + builtins.readFile ../../crates/crucible-qemu/src/live_plugin_quantum_gate/scheduler.rs;
    }
    {
      label = "crates/crucible-qemu/src/single_vm_fingerprint/plugin_live_runner.rs";
      source = builtins.readFile ../../crates/crucible-qemu/src/single_vm_fingerprint/plugin_live_runner.rs;
    }
    {
      label = "crates/crucible-qemu/src/supervision/block_io_gate";
      source =
        builtins.readFile ../../crates/crucible-qemu/src/supervision/block_io_gate.rs
        + builtins.readFile ../../crates/crucible-qemu/src/supervision/block_io_gate/support.rs;
    }
    {
      label = "crates/crucible-qemu/src/supervision/ninep_io_gate";
      source =
        builtins.readFile ../../crates/crucible-qemu/src/supervision/ninep_io_gate.rs
        + builtins.readFile ../../crates/crucible-qemu/src/supervision/ninep_io_gate/support.rs;
    }
    {
      label = "crates/crucible-qemu/src/supervision/node_step_gate";
      source =
        builtins.readFile ../../crates/crucible-qemu/src/supervision/node_step_gate.rs
        + builtins.readFile ../../crates/crucible-qemu/src/supervision/node_step_gate/support.rs;
    }
    {
      label = "crates/crucible-qemu/src/supervision/network_io_gate";
      source = builtins.readFile ../../crates/crucible-qemu/src/supervision/network_io_gate/drive.rs;
    }
  ];
  removedAdversarySources = [
    {
      label = "crates/crucible-qemu/examples/crucible-qemu-live-terminal-horizon.rs";
      source = builtins.readFile ../../crates/crucible-qemu/examples/crucible-qemu-live-terminal-horizon.rs;
      repeatEvidence = ''println!("second_run_repeat=active")'';
    }
    {
      label = "crates/crucible-qemu/examples/crucible-qemu-live-terminal-targets.rs";
      source = builtins.readFile ../../crates/crucible-qemu/examples/crucible-qemu-live-terminal-targets.rs;
      repeatEvidence = ''println!("second_ordinal_repeat=true")'';
    }
  ];
  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  sourceRequirements = [
    {
      label = "finite perturbation count";
      needle = "BOUNDED_PREEMPTION_COUNT=6";
    }
    {
      label = "short bounded pause";
      needle = "BOUNDED_PREEMPTION_PAUSE_SECONDS=0.015";
    }
    {
      label = "sleep between perturbations";
      needle = "BOUNDED_PREEMPTION_INTERVAL_SECONDS=0.001";
    }
    {
      label = "independent wall timeout";
      needle = "BOUNDED_PREEMPTION_WALL_TIMEOUT_SECONDS=2";
    }
    {
      label = "guest progress admission";
      needle = "bounded_preemption_wait_for_guest_progress";
    }
    {
      label = "actual target stop";
      needle = "kill -STOP \"$bsp_worker_target\"";
    }
    {
      label = "observed stopped process state";
      needle = "state=stopped";
    }
    {
      label = "unconditional target resume";
      needle = "kill -CONT \"$bsp_worker_target\"";
    }
    {
      label = "independent watchdog resume";
      needle = "if kill -CONT \"$bsp_watchdog_target\"";
    }
    {
      label = "worker exit cleanup";
      needle = "trap 'bsp_worker_cleanup' EXIT";
    }
    {
      label = "worker interruption cleanup";
      needle = "trap 'exit 143' TERM";
    }
    {
      label = "verified QEMU executable";
      needle = ''readlink -f "/proc/$BOUNDED_QEMU_PID/exe"'';
    }
  ];
  sourceFailures = failuresFor "tests/crucible/_bounded-scheduler-preemption.sh" harnessSource sourceRequirements;
  forbiddenFailures =
    lib.optional (hasInfix "yes >" harnessSource || hasInfix "yes >/" harnessSource)
    "bounded scheduler preemption harness contains an unbounded yes worker";
  targetWrapperFailures = failuresFor "tests/crucible/_bounded-scheduler-preemption-target.sh" targetWrapperSource [
    {
      label = "PID recorded before exec";
      needle = ''printf '%s\n' "$$" > "$pid_file_tmp"'';
    }
    {
      label = "stable target process identity";
      needle = ''exec "$@"'';
    }
  ];
  rustSchedulerFailures =
    failuresFor "crates/crucible-qemu/src/bounded_scheduler_preemption.rs" rustSchedulerSource [
      {
        label = "single finite preemption controller";
        needle = ''name(String::from("crucible-qemu-scheduler-preemption"))'';
      }
      {
        label = "finite perturbation count";
        needle = "BOUNDED_PREEMPTION_COUNT: u32 = 6";
      }
      {
        label = "short bounded pause";
        needle = "BOUNDED_PREEMPTION_PAUSE_MILLISECONDS: u64 = 15";
      }
      {
        label = "stable authenticated QEMU handle";
        needle = "pidfd_open(raw_pid";
      }
      {
        label = "pid-reuse-safe signaling";
        needle = "pidfd_send_signal(pidfd";
      }
      {
        label = "kernel-observed QEMU stop";
        needle = "| WaitIdOptions::NOWAIT\n                | WaitIdOptions::NOHANG,";
      }
      {
        label = "unconditional QEMU resume";
        needle = "Signal::CONT";
      }
      {
        label = "independent resume watchdog";
        needle = "BOUNDED_PREEMPTION_WALL_TIMEOUT";
      }
      {
        label = "pending-work start barrier";
        needle = "start_rx.recv()";
      }
      {
        label = "unreleased controller fails closed";
        needle = "BoundedSchedulerPreemptionError::NotStarted";
      }
      {
        label = "first stop rejects completed work";
        needle = "observation.confirm_pending(pending_at_stop)";
      }
      {
        label = "synchronous controller cleanup";
        needle = "controller.join()";
      }
    ]
    ++ lib.optionals (
      hasInfix "black_box" rustSchedulerSource
      || hasInfix "while !stop.load" rustSchedulerSource
      || hasInfix "HOST_LOAD_WORKERS" rustSchedulerSource
    ) ["bounded Rust scheduler harness retains a CPU burner or unbounded worker shape"];
  rustConsumerFailures =
    lib.concatMap (
      consumer:
        failuresFor consumer.label consumer.source [
          {
            label = "shared bounded scheduler harness";
            needle = "BoundedSchedulerPreemption as HostAdversary";
          }
          {
            label = "fallible preemption startup";
            needle = "HostAdversary::start_if";
          }
          {
            label = "first stop synchronizes with pending quantum";
            needle = "HostAdversary::certify_";
          }
          {
            label = "verified preemption completion";
            needle = "HostAdversary::finish_if_present";
          }
        ]
        ++ lib.optionals (
          hasInfix "HOST_LOAD_WORKERS" consumer.source
          || hasInfix "HostLoad" consumer.source
          || hasInfix "black_box(accumulator)" consumer.source
        ) ["${consumer.label}: retains a duplicated or multi-worker CPU burner"]
    )
    rustSchedulerConsumers;
  removedAdversaryFailures =
    lib.concatMap (
      consumer:
        failuresFor consumer.label consumer.source [
          {
            label = "accurate unperturbed-repeat evidence";
            needle = consumer.repeatEvidence;
          }
        ]
        ++ lib.optionals (
          hasInfix "HostLoad" consumer.source
          || hasInfix "spin_loop" consumer.source
          || hasInfix "while !stop.load" consumer.source
        ) ["${consumer.label}: retains a CPU adversary unrelated to its terminal-target invariant"]
    )
    removedAdversarySources;
  consumerFailures =
    lib.concatMap (
      consumer:
        failuresFor consumer.label consumer.source [
          {
            label = "shared actual-QEMU launcher";
            needle = "bounded_preemption_launch_qemu";
          }
          {
            label = "bounded scheduler perturbation";
            needle = "bounded_preemption_start";
          }
          {
            label = "guest execution progress anchor";
            needle = "bounded_preemption_wait_for_guest_progress";
          }
          {
            label = "cancellation cleanup";
            needle = consumer.cleanup;
          }
          {
            label = "accurate adversary evidence";
            needle = consumer.evidence;
          }
        ]
        ++ lib.optionals (
          hasInfix "yes >" consumer.source
          || hasInfix "yes >/" consumer.source
          || hasInfix ("start_" + "jitter") consumer.source
          || hasInfix ("host_adversary=" + "jitter-load") consumer.source
        ) ["${consumer.label}: retains an unbounded or stale jitter fixture"]
    )
    consumerSources;
  sourceCheck =
    if sourceFailures ++ forbiddenFailures ++ targetWrapperFailures ++ consumerFailures ++ rustSchedulerFailures ++ rustConsumerFailures ++ removedAdversaryFailures == []
    then true
    else
      throw (lib.concatStringsSep "\n"
        (sourceFailures ++ forbiddenFailures ++ targetWrapperFailures ++ consumerFailures ++ rustSchedulerFailures ++ rustConsumerFailures ++ removedAdversaryFailures));
in
  assert sourceCheck;
    pkgs.mkDerivation {
      pname = "crucible-phase0-bounded-scheduler-preemption";
      version = "0";
      src = null;

      HARNESS = ./_bounded-scheduler-preemption.sh;
      TARGET_WRAPPER = ./_bounded-scheduler-preemption-target.sh;

      phases = [
        {
          name = "run-bounded-scheduler-preemption-tests";
          script = ''
            set -eu

            fail() {
              echo "FAIL: $*" >&2
              exit 1
            }

            cat > "$TMPDIR/qemu-system-preemption-fixture.c" <<'FIXTURE_C'
            #define _POSIX_C_SOURCE 200809L
            #include <signal.h>
            #include <stdio.h>
            #include <stdlib.h>
            #include <time.h>
            #include <unistd.h>

            static volatile sig_atomic_t continued;

            static void on_continue(int signal_number) {
              (void)signal_number;
              continued++;
            }

            int main(int argc, char **argv) {
              struct sigaction action = {0};
              struct timespec delay = {.tv_sec = 0, .tv_nsec = 10000000};
              FILE *events;

              if (argc != 2) {
                return 2;
              }
              events = fopen(argv[1], "w");
              if (events == NULL) {
                return 2;
              }
              setvbuf(events, NULL, _IONBF, 0);
              action.sa_handler = on_continue;
              if (sigemptyset(&action.sa_mask) != 0
                  || sigaction(SIGCONT, &action, NULL) != 0) {
                return 2;
              }
              fprintf(events, "ready pid=%ld\n", (long)getpid());
              for (unsigned iteration = 0; iteration < 3000; iteration++) {
                fprintf(events, "heartbeat=%u continued=%d\n", iteration, continued);
                nanosleep(&delay, NULL);
              }
              return 0;
            }
            FIXTURE_C
            cc -std=c11 -O2 -Wall -Wextra -Werror \
              "$TMPDIR/qemu-system-preemption-fixture.c" \
              -o "$TMPDIR/qemu-system-preemption-fixture"

            BOUNDED_PREEMPTION_TARGET_WRAPPER="$TARGET_WRAPPER"
            . "$HARNESS"

            wait_for_pattern() {
              bsp_pattern="$1"
              bsp_path="$2"
              bsp_attempt=0
              while [ "$bsp_attempt" -lt 500 ]; do
                if grep -q "$bsp_pattern" "$bsp_path" 2>/dev/null; then
                  return 0
                fi
                sleep 0.01
                bsp_attempt=$((bsp_attempt + 1))
              done
              return 1
            }

            # Startup proves that the PID selected for perturbation belongs to
            # the exec'd target, not to the timeout process.
            bounded_preemption_launch_qemu \
              10 "$TMPDIR/startup.pid" - "$TMPDIR/qemu-system-preemption-fixture" \
              "$TMPDIR/qemu-system-preemption-fixture" "$TMPDIR/startup.events"
            startup_pid="$BOUNDED_QEMU_PID"
            [ "$startup_pid" != "$BOUNDED_QEMU_WAIT_PID" ] \
              || fail "target PID aliases timeout PID"
            wait_for_pattern '^ready pid=' "$TMPDIR/startup.events" \
              || fail "target did not start"
            bounded_preemption_cleanup
            ! kill -0 "$startup_pid" 2>/dev/null \
              || fail "normal cleanup left target alive"

            # Perturbation proves all finite STOP/CONT pairs execute and the
            # target observes continued execution afterward.
            bounded_preemption_launch_qemu \
              10 "$TMPDIR/perturb.pid" - "$TMPDIR/qemu-system-preemption-fixture" \
              "$TMPDIR/qemu-system-preemption-fixture" "$TMPDIR/perturb.events"
            wait_for_pattern '^ready pid=' "$TMPDIR/perturb.events" \
              || fail "perturbation target did not report progress"
            bounded_preemption_start \
              "$TMPDIR/perturbation.log" "$TMPDIR/perturb.events" "ready pid="
            bounded_preemption_finish "$TMPDIR/perturbation.log"
            wait_for_pattern 'continued=6' "$TMPDIR/perturb.events" \
              || fail "target did not observe every continuation"
            bounded_preemption_cleanup

            # Let the independent watchdog expire while the target is stopped.
            # It must issue SIGCONT itself before terminating the worker.
            BOUNDED_PREEMPTION_PAUSE_SECONDS=5
            BOUNDED_PREEMPTION_WALL_TIMEOUT_SECONDS=0.10
            bounded_preemption_launch_qemu \
              10 "$TMPDIR/watchdog.pid" - "$TMPDIR/qemu-system-preemption-fixture" \
              "$TMPDIR/qemu-system-preemption-fixture" "$TMPDIR/watchdog.events"
            wait_for_pattern '^ready pid=' "$TMPDIR/watchdog.events" \
              || fail "watchdog target did not report progress"
            bounded_preemption_start \
              "$TMPDIR/watchdog.log" "$TMPDIR/watchdog.events" "ready pid="
            wait_for_pattern '^stop iteration=1 ' "$TMPDIR/watchdog.log" \
              || fail "watchdog fixture never stopped target"
            if bounded_preemption_finish "$TMPDIR/watchdog.log"; then
              fail "watchdog-expired adversary unexpectedly completed"
            fi
            grep -q '^watchdog-resume target=.* status=success$' "$TMPDIR/watchdog.log" \
              || fail "watchdog did not independently resume target"
            wait_for_pattern 'continued=[1-9]' "$TMPDIR/watchdog.events" \
              || fail "target did not execute after watchdog resume"
            bounded_preemption_cleanup
            BOUNDED_PREEMPTION_PAUSE_SECONDS=0.015
            BOUNDED_PREEMPTION_WALL_TIMEOUT_SECONDS=2

            # An ordinary failing test body must run its EXIT cleanup and reap
            # both the target and finite adversary.
            failure_pid_file="$TMPDIR/failure-target.pid"
            (
              trap 'bounded_preemption_cleanup' EXIT TERM INT
              bounded_preemption_launch_qemu \
                10 "$TMPDIR/failure-launch.pid" - "$TMPDIR/qemu-system-preemption-fixture" \
                "$TMPDIR/qemu-system-preemption-fixture" "$TMPDIR/failure.events"
              printf '%s\n' "$BOUNDED_QEMU_PID" > "$failure_pid_file"
              wait_for_pattern '^ready pid=' "$TMPDIR/failure.events"
              bounded_preemption_start \
                "$TMPDIR/failure-preemption.log" "$TMPDIR/failure.events" "ready pid="
              false
            ) && fail "failure-cleanup fixture unexpectedly succeeded"
            failure_pid=$(cat "$failure_pid_file")
            ! kill -0 "$failure_pid" 2>/dev/null \
              || fail "failure cleanup left target alive"

            # Cancellation is exercised while QEMU is known to be stopped.
            # TERM must resume it before the enclosing cleanup terminates it.
            interruption_pid_file="$TMPDIR/interruption-target.pid"
            interruption_worker_file="$TMPDIR/interruption-worker.pid"
            (
              trap 'bounded_preemption_cleanup; exit 143' TERM
              trap 'bounded_preemption_cleanup' EXIT INT
              BOUNDED_PREEMPTION_PAUSE_SECONDS=2
              BOUNDED_PREEMPTION_WALL_TIMEOUT_SECONDS=5
              bounded_preemption_launch_qemu \
                10 "$TMPDIR/interruption-launch.pid" - "$TMPDIR/qemu-system-preemption-fixture" \
                "$TMPDIR/qemu-system-preemption-fixture" "$TMPDIR/interruption.events"
              printf '%s\n' "$BOUNDED_QEMU_PID" > "$interruption_pid_file"
              wait_for_pattern '^ready pid=' "$TMPDIR/interruption.events"
              bounded_preemption_start \
                "$TMPDIR/interruption-preemption.log" \
                "$TMPDIR/interruption.events" "ready pid="
              printf '%s\n' "$BOUNDED_PREEMPTION_PID" > "$interruption_worker_file"
              while [ ! -f "$TMPDIR/release-interruption" ]; do
                sleep 0.01
              done
            ) &
            interruption_controller_pid="$!"
            wait_for_pattern '^stop iteration=1 ' "$TMPDIR/interruption-preemption.log" \
              || fail "interruption fixture never stopped target"
            kill -TERM "$interruption_controller_pid"
            wait "$interruption_controller_pid" 2>/dev/null || true
            interruption_pid=$(cat "$interruption_pid_file")
            interruption_worker_pid=$(cat "$interruption_worker_file")
            ! kill -0 "$interruption_pid" 2>/dev/null \
              || fail "interruption cleanup left target alive"
            ! kill -0 "$interruption_worker_pid" 2>/dev/null \
              || fail "interruption cleanup left adversary alive"
            grep -q '^cleanup target=' "$TMPDIR/interruption-preemption.log" \
              || fail "interruption cleanup did not resume the stopped target"

            mkdir -p "$out"
            cp "$TMPDIR/perturbation.log" "$out/perturbation.log"
            cp "$TMPDIR/interruption-preemption.log" "$out/interruption.log"
            {
              echo PASS
              echo startup=actual-exec-pid
              echo perturbations=6
              echo normal_cleanup=complete
              echo failure_cleanup=complete
              echo interruption_cleanup=resumed-and-reaped
              echo watchdog_expiry_cleanup=independent-resume-and-reap
              echo requested_stopped_milliseconds=90
              echo nominal_worker_wall_milliseconds=95
              echo worker_wall_timeout_seconds=2
              echo synthetic_busy_workers=0
            } > "$out/result"
          '';
        }
      ];

      meta.description = "Bounded QEMU scheduler-preemption adversary tests";
    }
