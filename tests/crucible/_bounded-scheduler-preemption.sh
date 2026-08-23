# Reusable host-scheduling adversary for deterministic QEMU gates.
#
# The old fixture ran three `yes` processes for the whole guest execution,
# consuming three host cores per derivation.  This fixture instead interrupts
# QEMU itself six times. The first stop follows the guest-progress marker
# immediately; later stops are separated by 1 ms sleeps. Each configured stop
# is 15 ms: 90 ms of requested stopped time and about 95 ms nominal worker
# lifetime. A separate sleeping watchdog terminates the worker and
# resumes QEMU after two seconds. No helper generates synthetic CPU load, and
# existing outer `timeout` processes bound each QEMU run's wall-clock duration.

BOUNDED_PREEMPTION_COUNT=6
BOUNDED_PREEMPTION_PAUSE_SECONDS=0.015
BOUNDED_PREEMPTION_INTERVAL_SECONDS=0.001
BOUNDED_PREEMPTION_WALL_TIMEOUT_SECONDS=2
BOUNDED_PREEMPTION_PID=""
BOUNDED_PREEMPTION_WATCHDOG_PID=""
BOUNDED_PREEMPTION_TARGET_PID=""
BOUNDED_QEMU_PID=""
BOUNDED_QEMU_WAIT_PID=""

bounded_preemption_wait_for_guest_progress() {
  bsp_progress_path="$1"
  bsp_progress_needle="$2"
  bsp_progress_attempts="$3"
  bsp_progress_delay="$4"
  bsp_progress_attempt=0

  while [ "$bsp_progress_attempt" -lt "$bsp_progress_attempts" ]; do
    if grep -Fq "$bsp_progress_needle" "$bsp_progress_path" 2>/dev/null; then
      return 0
    fi
    if [ -z "$BOUNDED_QEMU_PID" ] || ! kill -0 "$BOUNDED_QEMU_PID" 2>/dev/null; then
      echo "bounded scheduler preemption: QEMU exited before guest progress" >&2
      return 1
    fi
    sleep "$bsp_progress_delay"
    bsp_progress_attempt=$((bsp_progress_attempt + 1))
  done

  echo "bounded scheduler preemption: guest progress marker did not appear" >&2
  return 1
}

bounded_preemption_launch_qemu() {
  bsp_timeout_seconds="$1"
  bsp_pid_file="$2"
  bsp_working_directory="$3"
  bsp_expected_qemu="$4"
  shift 4

  if [ -n "$BOUNDED_QEMU_WAIT_PID" ] || [ -n "$BOUNDED_QEMU_PID" ]; then
    echo "bounded scheduler preemption: QEMU is already active" >&2
    return 1
  fi
  if [ ! -x "$CONFIG_SHELL" ] || [ ! -f "$BOUNDED_PREEMPTION_TARGET_WRAPPER" ]; then
    echo "bounded scheduler preemption: hermetic target wrapper is unavailable" >&2
    return 1
  fi

  rm -f "$bsp_pid_file"
  timeout "$bsp_timeout_seconds" \
    "$CONFIG_SHELL" "$BOUNDED_PREEMPTION_TARGET_WRAPPER" \
    "$bsp_pid_file" "$bsp_working_directory" "$@" &
  BOUNDED_QEMU_WAIT_PID="$!"

  bsp_expected_qemu=$(readlink -f "$bsp_expected_qemu")
  bsp_attempt=0
  while [ "$bsp_attempt" -lt 500 ]; do
    if [ -s "$bsp_pid_file" ]; then
      BOUNDED_QEMU_PID=$(sed -n '1p' "$bsp_pid_file")
      case "$BOUNDED_QEMU_PID" in
        '' | *[!0-9]*)
          echo "bounded scheduler preemption: invalid target PID" >&2
          bounded_preemption_cleanup
          return 1
          ;;
      esac

      bsp_actual_qemu=$(readlink -f "/proc/$BOUNDED_QEMU_PID/exe" 2>/dev/null || true)
      if [ "$bsp_actual_qemu" = "$bsp_expected_qemu" ]; then
        return 0
      fi
    fi

    if ! kill -0 "$BOUNDED_QEMU_WAIT_PID" 2>/dev/null; then
      echo "bounded scheduler preemption: QEMU exited before PID verification" >&2
      bounded_preemption_cleanup
      return 1
    fi
    sleep 0.01
    bsp_attempt=$((bsp_attempt + 1))
  done

  echo "bounded scheduler preemption: actual QEMU PID was not verified" >&2
  bounded_preemption_cleanup
  return 1
}

bounded_preemption_start() {
  bsp_event_log="$1"
  bsp_progress_path="$2"
  bsp_progress_needle="$3"
  if [ -z "$BOUNDED_QEMU_PID" ] || ! kill -0 "$BOUNDED_QEMU_PID" 2>/dev/null; then
    echo "bounded scheduler preemption: QEMU is not running" >&2
    return 1
  fi
  if [ -n "$BOUNDED_PREEMPTION_PID" ]; then
    echo "bounded scheduler preemption: adversary is already active" >&2
    return 1
  fi
  if ! grep -Fq "$bsp_progress_needle" "$bsp_progress_path" 2>/dev/null; then
    echo "bounded scheduler preemption: guest progress was not established" >&2
    return 1
  fi

  : > "$bsp_event_log"
  printf 'guest-progress-before source=%s needle=%s\n' \
    "$bsp_progress_path" "$bsp_progress_needle" >> "$bsp_event_log"
  BOUNDED_PREEMPTION_TARGET_PID="$BOUNDED_QEMU_PID"
  (
    bsp_worker_target="$BOUNDED_PREEMPTION_TARGET_PID"
    bsp_worker_iteration=0
    bsp_worker_cleanup() {
      # SIGCONT is unconditional so interruption during a stopped interval can
      # never strand the QEMU process in TASK_STOPPED.
      kill -CONT "$bsp_worker_target" 2>/dev/null || true
      printf 'cleanup target=%s\n' "$bsp_worker_target" >> "$bsp_event_log"
    }
    trap 'bsp_worker_cleanup' EXIT
    trap 'exit 143' TERM
    trap 'exit 130' INT

    while [ "$bsp_worker_iteration" -lt "$BOUNDED_PREEMPTION_COUNT" ]; do
      if [ "$bsp_worker_iteration" -ne 0 ]; then
        sleep "$BOUNDED_PREEMPTION_INTERVAL_SECONDS"
      fi
      kill -STOP "$bsp_worker_target" 2>/dev/null || exit 70
      bsp_stop_attempt=0
      while ! grep -q '^State:.*[Tt]' "/proc/$bsp_worker_target/status" 2>/dev/null; do
        if ! kill -0 "$bsp_worker_target" 2>/dev/null; then
          exit 72
        fi
        if [ "$bsp_stop_attempt" -ge 100 ]; then
          exit 73
        fi
        sleep 0.001
        bsp_stop_attempt=$((bsp_stop_attempt + 1))
      done
      bsp_worker_iteration=$((bsp_worker_iteration + 1))
      printf 'stop iteration=%s target=%s state=stopped\n' \
        "$bsp_worker_iteration" "$bsp_worker_target" >> "$bsp_event_log"
      sleep "$BOUNDED_PREEMPTION_PAUSE_SECONDS"
      kill -CONT "$bsp_worker_target" 2>/dev/null || exit 71
      printf 'continue iteration=%s target=%s\n' \
        "$bsp_worker_iteration" "$bsp_worker_target" >> "$bsp_event_log"
    done
    printf 'complete perturbations=%s\n' \
      "$BOUNDED_PREEMPTION_COUNT" >> "$bsp_event_log"
  ) &
  BOUNDED_PREEMPTION_PID="$!"
  (
    bsp_watchdog_target="$BOUNDED_PREEMPTION_TARGET_PID"
    bsp_watchdog_worker="$BOUNDED_PREEMPTION_PID"
    sleep "$BOUNDED_PREEMPTION_WALL_TIMEOUT_SECONDS"
    if kill -0 "$bsp_watchdog_worker" 2>/dev/null; then
      printf 'wall-timeout seconds=%s\n' \
        "$BOUNDED_PREEMPTION_WALL_TIMEOUT_SECONDS" >> "$bsp_event_log"
      # Resume independently before asking the worker to exit. This remains
      # effective even if the worker is delayed or its EXIT trap regresses.
      if kill -CONT "$bsp_watchdog_target" 2>/dev/null; then
        printf 'watchdog-resume target=%s status=success\n' \
          "$bsp_watchdog_target" >> "$bsp_event_log"
      else
        printf 'watchdog-resume target=%s status=failed\n' \
          "$bsp_watchdog_target" >> "$bsp_event_log"
      fi
      kill -TERM "$bsp_watchdog_worker" 2>/dev/null || true
    fi
  ) &
  BOUNDED_PREEMPTION_WATCHDOG_PID="$!"
}

bounded_preemption_finish() {
  bsp_event_log="$1"
  if [ -z "$BOUNDED_PREEMPTION_PID" ]; then
    echo "bounded scheduler preemption: adversary was not started" >&2
    return 1
  fi

  bsp_worker_status=0
  wait "$BOUNDED_PREEMPTION_PID" || bsp_worker_status="$?"
  BOUNDED_PREEMPTION_PID=""
  if [ -n "$BOUNDED_PREEMPTION_WATCHDOG_PID" ]; then
    kill -TERM "$BOUNDED_PREEMPTION_WATCHDOG_PID" 2>/dev/null || true
    wait "$BOUNDED_PREEMPTION_WATCHDOG_PID" 2>/dev/null || true
    BOUNDED_PREEMPTION_WATCHDOG_PID=""
  fi
  BOUNDED_PREEMPTION_TARGET_PID=""
  if [ "$bsp_worker_status" -ne 0 ]; then
    echo "bounded scheduler preemption: adversary failed with status $bsp_worker_status" >&2
    return 1
  fi

  bsp_stop_count=$(grep -c '^stop iteration=' "$bsp_event_log" || true)
  bsp_continue_count=$(grep -c '^continue iteration=' "$bsp_event_log" || true)
  if [ "$bsp_stop_count" -ne "$BOUNDED_PREEMPTION_COUNT" ] \
    || [ "$bsp_continue_count" -ne "$BOUNDED_PREEMPTION_COUNT" ] \
    || ! grep -q "^complete perturbations=$BOUNDED_PREEMPTION_COUNT$" "$bsp_event_log"; then
    echo "bounded scheduler preemption: incomplete perturbation evidence" >&2
    return 1
  fi
}

bounded_preemption_stop() {
  if [ -n "$BOUNDED_PREEMPTION_PID" ]; then
    kill -TERM "$BOUNDED_PREEMPTION_PID" 2>/dev/null || true
    wait "$BOUNDED_PREEMPTION_PID" 2>/dev/null || true
    BOUNDED_PREEMPTION_PID=""
  fi
  if [ -n "$BOUNDED_PREEMPTION_WATCHDOG_PID" ]; then
    kill -TERM "$BOUNDED_PREEMPTION_WATCHDOG_PID" 2>/dev/null || true
    wait "$BOUNDED_PREEMPTION_WATCHDOG_PID" 2>/dev/null || true
    BOUNDED_PREEMPTION_WATCHDOG_PID=""
  fi
  if [ -n "$BOUNDED_PREEMPTION_TARGET_PID" ]; then
    kill -CONT "$BOUNDED_PREEMPTION_TARGET_PID" 2>/dev/null || true
    BOUNDED_PREEMPTION_TARGET_PID=""
  fi
}

bounded_preemption_wait_qemu() {
  if [ -z "$BOUNDED_QEMU_WAIT_PID" ]; then
    echo "bounded scheduler preemption: no QEMU process is active" >&2
    return 1
  fi

  bsp_wait_status=0
  wait "$BOUNDED_QEMU_WAIT_PID" || bsp_wait_status="$?"
  BOUNDED_QEMU_WAIT_PID=""
  BOUNDED_QEMU_PID=""
  return "$bsp_wait_status"
}

bounded_preemption_cleanup() {
  bounded_preemption_stop

  if [ -n "$BOUNDED_QEMU_PID" ]; then
    kill -CONT "$BOUNDED_QEMU_PID" 2>/dev/null || true
    kill -TERM "$BOUNDED_QEMU_PID" 2>/dev/null || true
  fi
  if [ -n "$BOUNDED_QEMU_WAIT_PID" ]; then
    kill -TERM "$BOUNDED_QEMU_WAIT_PID" 2>/dev/null || true
    wait "$BOUNDED_QEMU_WAIT_PID" 2>/dev/null || true
  fi
  BOUNDED_QEMU_PID=""
  BOUNDED_QEMU_WAIT_PID=""
}
