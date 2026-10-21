{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.gates.campaignColdContinuity",
  taskIds ? ["T-CAM-1.3" "T-CAM-1.4" "T-CAM-1.5" "T-CAM-5.8" "T-CAM-5.9"],
  dependencies ? [],
}: let
  inherit (import ./_test-gate.nix {inherit pkgs lib;}) mkCrucibleTestGate;
in
  mkCrucibleTestGate {
    pname = "crucible-phase5-campaign-cold-continuity";

    buildDeps =
      [
        pkgs.coreutils
        pkgs.grep
        pkgs.sed
      ]
      ++ dependencies;

    phases = [
      {
        name = "run-campaign-cold-continuity";
        script = ''
          set -eu

          gate_test=campaign_cold_continuity_survives_pause_restart_archive_restore_and_resume
          helper_test=continuity_process_helper
          listing=$(crucible-cargo test \
            -p crucible-campaign \
            --test gate_campaign_cold_continuity \
            -- --list)
          printf '%s\n' "$listing" | grep -Fqx "$gate_test: test"
          printf '%s\n' "$listing" | grep -Fqx "$helper_test: test"

          gate_output=$(crucible-cargo test \
            -p crucible-campaign \
            --test gate_campaign_cold_continuity \
            "$gate_test" \
            -- --exact --test-threads=1 2>&1)
          printf '%s\n' "$gate_output"
          printf '%s\n' "$gate_output" \
            | grep -F "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out"

          run_exact_lib_test() {
            test_name=$1
            test_listing=$(crucible-cargo test \
              -p crucible-campaign \
              --lib "$test_name" \
              -- --list)
            printf '%s\n' "$test_listing" | grep -Fqx "$test_name: test"
            crucible-cargo test \
              -p crucible-campaign \
              --lib "$test_name" \
              -- --exact --test-threads=1
          }

          for regression in \
            repository::tests::discovery::initial_discovery_pause_retains_the_unspent_grant \
            repository::tests::execution::driver::claimable_attempt_pages_are_bounded_snapshot_bound_and_restart_rebuildable \
            repository::tests::transfer::every_archive_policy_preserves_its_partition_and_head_eligibility \
            repository::tests::transfer::archive_with_undeclared_snapshot_children_fails_closed \
            repository::tests::validation::command_replay_precedes_stale_check_and_preserves_response \
            repository::tests::validation::pin_command_projects_retention_and_replays_exactly_after_later_mutation
          do
            run_exact_lib_test "$regression"
          done

          mkdir -p "$out"
          cat > "$out/result" <<RESULT
          PASS
          check=${attrPath}
          tasks=${builtins.concatStringsSep "," taskIds}
          gate=gate:campaign-cold-continuity
          tier=model
          separate_os_processes=true
          pause_restart_restore_resume=true
          same_snapshot_source_destination=true
          public_graph_frontier_queries=true
          retained_observation_finding_corpus=true
          exact_pin_materialization_selected=true
          exact_checkpoint_closure_authenticated=true
          claimable_unpublished_attempts=1
          resume_accounting_once=true
          RESULT
        '';
      }
    ];
  }
