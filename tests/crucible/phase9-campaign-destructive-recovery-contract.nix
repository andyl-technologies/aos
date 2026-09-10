{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase9.gates.campaignDestructiveRecoveryContract",
  taskIds ? ["T-CAM-0.5" "T-CAM-4.8" "T-CAM-5.8" "T-CAM-6.9" "T-CAM-7.7" "T-CAM-9.7"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
in
  pkgs.mkDerivation {
    pname = "crucible-phase9-campaign-destructive-recovery-contract";
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
          sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
            > .cargo/config.toml
        '';
      }
      {
        name = "validate-contract-and-prerequisites";
        script = ''
          set -eu
          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi

          target="$TMPDIR/campaign-destructive-recovery-target"
          cargo test \
            --frozen \
            --offline \
            --target-dir "$target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-harness \
            --test campaign_destructive_recovery_contract \
            -- --test-threads=1

          run_exact_lib_test() {
            package=$1
            name=$2
            if listing=$(cargo test \
              --frozen \
              --offline \
              --target-dir "$target" \
              --manifest-path crates/Cargo.toml \
              -p "$package" \
              --lib "$name" \
              -- --exact --list 2>&1)
            then
              :
            else
              status=$?
              printf '%s\n' "$listing"
              return "$status"
            fi
            count=$(printf '%s\n' "$listing" | grep -Fxc "$name: test" || true)
            test "$count" -eq 1

            if output=$(cargo test \
              --frozen \
              --offline \
              --target-dir "$target" \
              --manifest-path crates/Cargo.toml \
              -p "$package" \
              --lib "$name" \
              -- --exact --test-threads=1 2>&1)
            then
              :
            else
              status=$?
              printf '%s\n' "$output"
              return "$status"
            fi
            printf '%s\n' "$output"
            printf '%s\n' "$output" | grep -Fq 'test result: ok. 1 passed;'
          }

          run_exact_feature_lib_test() {
            package=$1
            feature=$2
            name=$3
            if listing=$(cargo test \
              --frozen \
              --offline \
              --target-dir "$target" \
              --manifest-path crates/Cargo.toml \
              -p "$package" \
              --features "$feature" \
              --lib "$name" \
              -- --exact --list 2>&1)
            then
              :
            else
              status=$?
              printf '%s\n' "$listing"
              return "$status"
            fi
            count=$(printf '%s\n' "$listing" | grep -Fxc "$name: test" || true)
            test "$count" -eq 1

            if output=$(cargo test \
              --frozen \
              --offline \
              --target-dir "$target" \
              --manifest-path crates/Cargo.toml \
              -p "$package" \
              --features "$feature" \
              --lib "$name" \
              -- --exact --test-threads=1 2>&1)
            then
              :
            else
              status=$?
              printf '%s\n' "$output"
              return "$status"
            fi
            printf '%s\n' "$output"
            printf '%s\n' "$output" | grep -Fq 'test result: ok. 1 passed;'
          }

          run_exact_feature_lib_test \
            crucible-campaign \
            destructive-recovery-faults \
            repository::tests::execution::driver::coordinator_fault_before_observation_commit_recovers_exactly_once

          run_exact_feature_lib_test \
            crucible-campaign \
            destructive-recovery-faults \
            repository::tests::destructive_recovery::daemon_fault_during_snapshot_publication_recovers_complete_ref

          run_exact_feature_lib_test \
            crucible-daemon \
            destructive-recovery-faults \
            exact_checkpoint_store::tests::exact_capture_enospc_restart_retries_root_last_publication

          run_exact_feature_lib_test \
            crucible-cas \
            destructive-recovery-faults \
            content_store::s3::tests::multipart_remove_leaf_aborts_before_completion_and_retries

          run_exact_feature_lib_test \
            crucible-cas \
            destructive-recovery-faults \
            content_store::s3::tests::credential_expiry_preserves_identity_and_authenticated_retry

          run_exact_feature_lib_test \
            crucible-cas \
            destructive-recovery-faults \
            content_store::tests::corrupt_tier_copy_fails_closed_then_repairs_from_authenticated_lower_tier

          run_exact_feature_lib_test \
            crucible-cas \
            destructive-recovery-faults \
            content_store::tests::pack_index_interruption_recovers_old_generation_and_retries

          run_exact_feature_lib_test \
            crucible-daemon \
            destructive-recovery-faults \
            qemu_hot_fork_world_factory::tests::world_fork_one_vm_failure_quarantines_partial_world

          for cas_test in \
            content_store::tests::changing_and_failing_sources_leave_no_published_object_or_staging_file \
            content_store::s3::tests::interrupted_upload_aborts_and_failed_abort_is_explicit \
            content_store::s3::tests::credential_expiry_and_configuration_bounds_fail_closed \
            content_store::tests::read_through_cache_failure_does_not_hide_authenticated_source_bytes \
            content_store::tests::compressed_directory_rejects_oversized_sources_and_corrupt_physical_records \
            content_store::tests::packed_initialization_waits_for_in_flight_staging \
            content_store::tests::packed_backend_restarts_repackages_and_keeps_old_reader_inodes_valid \
            content_store::tests::packed_backend_rejects_corruption_and_cleans_unindexed_complete_packs
          do
            run_exact_lib_test crucible-cas "$cas_test"
          done

          for daemon_test in \
            executor_worker::tests::operational_worker_failure_requeues_without_growing_the_bounded_queue \
            assignment_ledger::tests::memory_ledger_matches_conditional_publish_contract \
            executor_supervisor::tests::restart_recovers_publishing_without_losing_the_expected_observation \
            executor_supervisor::tests::durable_restart_replaces_stale_running_and_preserves_completion \
            durable_managed_hot_checkpoint_pool::tests::restart_reconstructs_all_records_as_cold_without_claiming_live_sources \
            executor_supervisor::tests::paused_execution_resumes_from_the_exact_root_and_survives_restart \
            exact_checkpoint_store::tests::cancellation_after_preparation_stops_before_the_first_publication_write \
            qemu_hot_fork_world_resource::tests::partial_world_ambiguous_failure_quarantines_the_aggregate \
            qemu_hot_fork_world_factory::tests::target_world_resource_preflight_rejects_before_source_checkout_or_guard_installation \
            hot_checkpoint_manager::tests::pressure_demotes_the_coldest_exact_coordinate_deterministically \
            qemu_resource_guard::tests::cancellation_that_wins_before_begin_signals_and_rolls_back \
            qemu_resource_guard::tests::failed_reap_quarantines_process_and_filesystem_authority_once
          do
            run_exact_lib_test crucible-daemon "$daemon_test"
          done

          mkdir -p "$out"
          cat > "$out/result" <<RESULT
          CONTRACT_VALIDATED
          check=${attrPath}
          tasks=${builtins.concatStringsSep "," taskIds}
          gate=gate:campaign-destructive-recovery
          injection_classes=14
          prerequisite_tests=28
          operator_commands=contract-validated
          fault_build_hooks=coordinator-before-observation-commit,daemon-during-snapshot-publication,exact-capture-enospc,multipart-remove-leaf,store-credential-expiry,corrupt-tier-copy,pack-index-interruption,world-fork-one-vm-failure-implemented;remaining-required
          manual_evidence=required
          acceptance=not-evaluated
          RESULT
        '';
      }
    ];
  }
