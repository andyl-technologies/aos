{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.gates.campaignReplay.rawGate",
  taskIds ? ["T-CAM-3.5" "T-CAM-4.7" "T-CAM-4.10" "T-CAM-8.4"],
  dependencies ? [],
}: let
  inherit (import ./_test-gate.nix {inherit pkgs lib;}) mkCrucibleTestGate;
in
  mkCrucibleTestGate {
    pname = "crucible-phase4-campaign-replay";

    buildDeps = [pkgs.coreutils] ++ dependencies;

    phases = [
      {
        name = "run-campaign-replay";
        script = ''
          set -eu

          # One exact invocation per test executable. Each required test
          # must be listed once, report its own `ok` line, and count toward
          # the executable's exact pass total.
          run_gate_tests() {
            gate_package=$1
            gate_binary=$2
            shift 2
            gate_log="$TMPDIR/campaign-replay-$gate_package-$gate_binary.log"

            CRUCIBLE_EXACT_TESTS_LOG="$gate_log" crucible-exact-tests \
              -p "$gate_package" --test "$gate_binary" -- --test-threads=1 "$@"
            for gate_test in "$@"; do
              if ! grep -Fqx "test $gate_test ... ok" "$gate_log"; then
                printf 'required test did not report success: %s\n' "$gate_test" >&2
                exit 1
              fi
            done
          }

          run_gate_tests \
            crucible-campaign \
            gate_campaign_replay \
            strict_campaign_planner_reproduces_every_accepted_step
          run_gate_tests \
            crucible \
            gate_campaign_replay \
            offline_rich_finding_replays_without_campaign_store
          run_gate_tests \
            crucible \
            gate_minimization \
            automatic_minimization_selects_and_authenticates_the_latest_interesting_window \
            automatic_minimization_uses_the_bounded_terminal_suffix_without_a_campaign_branch

          mkdir -p "$out"
          cat > "$out/result" <<RESULT
          PASS
          check=${attrPath}
          tasks=${builtins.concatStringsSep "," taskIds}
          gate=gate:campaign-replay
          scope=portable-model,strict,production-qemu,native
          tier=automated
          selectors=strict_campaign_planner_reproduces_every_accepted_step,offline_rich_finding_replays_without_campaign_store,automatic_minimization_selects_and_authenticates_the_latest_interesting_window,automatic_minimization_uses_the_bounded_terminal_suffix_without_a_campaign_branch,campaign_run_production_qemu_exact_checkpoint_then_replay_matches,interactive_session_captures_and_replays_exact_live_artifact
          evidence=campaign_production_qemu_exact_checkpoint_replay=true,interactive_packaged_capture_replay=true
          RESULT
        '';
      }
    ];
  }
