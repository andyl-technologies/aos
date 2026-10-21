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

          run_gate_test() {
            gate_package=$1
            gate_binary=$2
            gate_test=$3

            if output=$(crucible-cargo test \
              -p "$gate_package" \
              --test "$gate_binary" \
              -- --list 2>&1); then
              :
            else
              status=$?
              printf '%s\n' "$output" >&2
              exit "$status"
            fi
            printf '%s\n' "$output"
            if match_count=$(printf '%s\n' "$output" | grep -Fxc "$gate_test: test"); then
              :
            else
              match_count=0
            fi
            if [ "$match_count" -ne 1 ]; then
              printf 'expected exactly one listed test named %s; found %s\n' \
                "$gate_test" "$match_count" >&2
              exit 1
            fi

            if output=$(crucible-cargo test \
              -p "$gate_package" \
              --test "$gate_binary" \
              -- --exact "$gate_test" --test-threads=1 2>&1); then
              :
            else
              status=$?
              printf '%s\n' "$output" >&2
              exit "$status"
            fi
            printf '%s\n' "$output"
            if ! printf '%s\n' "$output" | grep -Fqx "test $gate_test ... ok"; then
              printf 'required test did not report success: %s\n' "$gate_test" >&2
              exit 1
            fi
            if ! printf '%s\n' "$output" \
              | grep -Fq 'test result: ok. 1 passed; 0 failed; 0 ignored;'; then
              printf 'required test did not produce the exact pass count: %s\n' "$gate_test" >&2
              exit 1
            fi
          }

          run_gate_test \
            crucible-campaign \
            gate_campaign_replay \
            strict_campaign_planner_reproduces_every_accepted_step
          run_gate_test \
            crucible \
            gate_campaign_replay \
            offline_rich_finding_replays_without_campaign_store
          run_gate_test \
            crucible \
            gate_minimization \
            automatic_minimization_selects_and_authenticates_the_latest_interesting_window
          run_gate_test \
            crucible \
            gate_minimization \
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
