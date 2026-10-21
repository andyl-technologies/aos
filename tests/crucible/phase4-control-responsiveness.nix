{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.gates.controlResponsiveness",
  taskIds ? ["T-CAM-4.5" "T-CAM-4.6" "T-CAM-4.9" "T-CAM-8.1" "T-CAM-8.2"],
  dependencies ? [],
}: let
  inherit (import ./_test-gate.nix {inherit pkgs lib;}) mkCrucibleTestGate;
in
  mkCrucibleTestGate {
    pname = "crucible-phase4-control-responsiveness";

    buildDeps =
      [
        pkgs.coreutils
        pkgs.grep
        pkgs.sed
      ]
      ++ dependencies;
    ATTR_PATH = attrPath;
    TASK_IDS = builtins.concatStringsSep "," taskIds;
    DEPENDENCY_COUNT = toString (builtins.length dependencies);

    phases = [
      {
        name = "run-control-responsiveness";
        script = ''
          set -eu

          exact_test="executor_pool::tests::campaign_controls_remain_responsive_while_every_executor_slot_is_busy"
          if list_output=$(crucible-cargo test \
            -p crucible-daemon --lib "$exact_test" -- --exact --list 2>&1); then
            :
          else
            cargo_status=$?
            printf '%s\n' "$list_output" >&2
            exit "$cargo_status"
          fi
          exact_count=$(printf '%s\n' "$list_output" | grep -Fxc "$exact_test: test" || true)
          if [ "$exact_count" -ne 1 ]; then
            printf '%s\n' "$list_output" >&2
            echo "expected exactly one test named $exact_test, found $exact_count" >&2
            exit 1
          fi

          if test_output=$(crucible-cargo test \
            -p crucible-daemon --lib "$exact_test" -- \
            --exact --test-threads=1 2>&1); then
            :
          else
            cargo_status=$?
            printf '%s\n' "$test_output" >&2
            exit "$cargo_status"
          fi
          printf '%s\n' "$test_output"
          if ! printf '%s\n' "$test_output" \
            | grep -F "test result: ok. 1 passed;" >/dev/null; then
            echo "exact test $exact_test did not report one passed test" >&2
            exit 1
          fi
        '';
      }
      {
        name = "write-result";
        script = ''
          mkdir -p "$out"
          {
            printf 'PASS\n'
            printf 'gate=gate:control-responsiveness\n'
            printf 'attr_path=%s\n' "$ATTR_PATH"
            printf 'task_ids=%s\n' "$TASK_IDS"
            printf 'dependency_count=%s\n' "$DEPENDENCY_COUNT"
            printf 'tier=model\n'
            printf 'controls=campaign-pause,campaign-status,campaign-pin,executor-shutdown\n'
            printf 'saturation=fixed-workers-busy-with-accepted-queue\n'
            printf 'control_latency_bound_ms=250\n'
            printf 'shutdown=sticky-cancel-drain-join\n'
            printf 'cancellation=all-executing-signaled,queued-drained-without-execution,admission-closed\n'
            printf 'reservation_release=after-physical-worker-exit-acknowledgement\n'
            printf 'open_scope=\n'
          } > "$out/result"
        '';
      }
    ];
  }
