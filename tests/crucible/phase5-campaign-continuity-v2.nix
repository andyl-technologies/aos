{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.gates.campaignContinuityV2",
  taskIds ? ["T-CAM-1.3" "T-CAM-1.4" "T-CAM-1.5" "T-CAM-5.8" "T-CAM-5.9"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
in
  pkgs.mkDerivation {
    pname = "crucible-phase5-campaign-continuity-v2";
    version = "0";
    src = crucibleSrc;

    buildDeps =
      [
        pkgs.coreutils
        pkgs.grep
        pkgs.rust
        pkgs.sed
      ]
      ++ dependencies;

    phases = [
      {
        name = "unpack";
        script = ''
          set -eu
          cp -R "$src" source
          chmod -R u+w source
          cd source
        '';
      }
      {
        name = "configure";
        script = ''
          set -eu
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
        name = "run-campaign-continuity-v2";
        script = ''
          set -eu
          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi

          target="$TMPDIR/crucible-campaign-continuity-v2-target"
          gate_test=campaign_continuity_v2_survives_pause_restart_archive_restore_and_resume
          helper_test=continuity_process_helper
          listing=$(cargo test \
            --frozen \
            --offline \
            --target-dir "$target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-campaign \
            --test gate_campaign_continuity_v2 \
            -- --list)
          printf '%s\n' "$listing" | grep -Fqx "$gate_test: test"
          printf '%s\n' "$listing" | grep -Fqx "$helper_test: test"

          gate_output=$(cargo test \
            --frozen \
            --offline \
            --target-dir "$target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-campaign \
            --test gate_campaign_continuity_v2 \
            "$gate_test" \
            -- --exact --test-threads=1 2>&1)
          printf '%s\n' "$gate_output"
          printf '%s\n' "$gate_output" \
            | grep -F "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out"

          run_exact_lib_test() {
            test_name=$1
            test_listing=$(cargo test \
              --frozen \
              --offline \
              --target-dir "$target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-campaign \
              --lib "$test_name" \
              -- --list)
            printf '%s\n' "$test_listing" | grep -Fqx "$test_name: test"
            cargo test \
              --frozen \
              --offline \
              --target-dir "$target" \
              --manifest-path crates/Cargo.toml \
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
          gate=gate:campaign-continuity-v2
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
