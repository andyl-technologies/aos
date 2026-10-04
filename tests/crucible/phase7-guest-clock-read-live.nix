# Qualifies fresh clock returns; it does not close absolute Linux clock scale.
{
  pkgs,
  testing,
  clockReadFlightCommand,
  rootfsDeps,
  attemptHostSetupScript,
}:
# The zero-offset TSC proof is source-bound to the audited reset, SVM and
# VMState writers. A native selection change requires re-auditing this profile.
assert (import ../../pkgs/emulation/qemu-patches/_atomic-patch.nix).commit
== "39a0e603dd25905ada9f87276485375f9836b70c";
  testing.mkVMTest {
    name = "crucible-fresh-guest-clock-read-equivalence";
    memory = 8192;
    timeout = 1200;
    rootfsDeps =
      rootfsDeps
      ++ [
        pkgs.python3
        "${./phase7-time-ownership-receipts.py}"
        "${./phase7-guest-clock-read-receipts.py}"
        "${../../crates/crucible-qemu/src/launch.rs}"
      ];
    testScript = ''
      set -eu
      ${attemptHostSetupScript}
      export CRUCIBLE_TIME_OWNERSHIP_WITNESS=1
      export CRUCIBLE_GUEST_CLOCK_READ_FLIGHT=1
      result=/tmp/guest-clock-read-result
      capture=/tmp/guest-clock-read-native-receipts
      evidence=/tmp/guest-clock-read-evidence.json

      report_failure() {
        original_status=$1
        original_stage=$2
        echo "guest-clock-read failure stage=$original_stage status=$original_status" || true
        ${pkgs.coreutils}/bin/tail -c 16384 "$result" || true
        ${pkgs.coreutils}/bin/tail -c 65536 "$capture" || true
        ${pkgs.coreutils}/bin/head -c 65536 "$evidence" || true
        exit "$original_status"
      }

      if ${clockReadFlightCommand} "$evidence" > "$result" 2> "$capture"; then
        :
      else
        report_failure "$?" producer
      fi
      for item in PASS diagnostic_mode=guest-clock-read-equivalence \
        actual_guest_clock_returns_restart_identical=true \
        tsc_original_read_brackets_valid=true idle_hold_clock_unchanged=true \
        authorized_exact_timer_wake_raw_unchanged=true \
        absolute_linux_clock_calibration_qualified=false \
        fork_child_clock_ownership_qualified=false; do
        if ${pkgs.grep}/bin/grep -Fxq "$item" "$result"; then
          :
        else
          report_failure "$?" result
        fi
      done
      if ${pkgs.python3}/bin/python3 ${./phase7-guest-clock-read-receipts.py} \
        "$evidence" "$capture" ${./phase7-time-ownership-receipts.py} \
        ${../../crates/crucible-qemu/src/launch.rs}; then
        :
      else
        report_failure "$?" original-evidence
      fi
      cat "$result"
    '';
  }
