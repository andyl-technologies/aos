{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.gates.campaignStoreComposition",
  taskIds ? ["T-CAM-5.5" "T-CAM-5.6" "T-CAM-5.7"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
in
  pkgs.mkDerivation {
    pname = "crucible-phase5-campaign-store-composition";
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
        name = "run-campaign-store-composition";
        script = ''
          set -eu
          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi

          target="$TMPDIR/crucible-campaign-store-composition-target"
          component_test=same_campaign_survives_direct_rpc_and_independent_component_restarts
          component_listing=$(cargo test \
            --frozen \
            --offline \
            --target-dir "$target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-daemon \
            --test gate_campaign_component_contract \
            "$component_test" \
            -- --list)
          printf '%s\n' "$component_listing" | grep -Fqx "$component_test: test"
          cargo test \
            --frozen \
            --offline \
            --target-dir "$target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-cas \
            --test gate_campaign_store_composition \
            -- --test-threads=1
          cargo test \
            --frozen \
            --offline \
            --target-dir "$target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-cli \
            --features test-double \
            --test gate_campaign_store_composition \
            -- --test-threads=1
          cargo test \
            --frozen \
            --offline \
            --target-dir "$target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-daemon \
            --test gate_campaign_component_contract \
            "$component_test" \
            -- --exact --test-threads=1

          run_exact_lib_test() {
            package=$1
            test_name=$2
            listing=$(cargo test \
              --frozen \
              --offline \
              --target-dir "$target" \
              --manifest-path crates/Cargo.toml \
              -p "$package" \
              --lib "$test_name" \
              -- --list)
            printf '%s\n' "$listing" | grep -Fqx "$test_name: test"
            cargo test \
              --frozen \
              --offline \
              --target-dir "$target" \
              --manifest-path crates/Cargo.toml \
              -p "$package" \
              --lib "$test_name" \
              -- --exact --test-threads=1
          }

          # Cover the admitted specialized layers through their real graph
          # implementations; each exact name is first required to list once.
          for cas_test in \
            content_store::tests::profile_and_namespace_boundaries_compose_at_the_graph_root \
            content_store::tests::compressed_directory_is_a_bounded_versioned_graph_leaf \
            content_store::tests::encrypted_directory_graph_identity_excludes_secret_key_material \
            content_store::tests::compressed_encrypted_directory_is_a_versioned_graph_leaf \
            content_store::tests::logical_and_physical_quotas_compose_without_an_admin_bypass \
            content_store::tests::durable_write_back_survives_restart_and_exposes_exact_retention_roots \
            content_store::tests::write_back_journal_recovers_torn_tail_and_rejects_corruption \
            content_store::tests::packed_store_graph_is_admitted_and_requires_an_isolated_persistent_root \
            content_store::s3::tests::graph_binds_exact_endpoint_capability_and_canonical_configuration
          do
            run_exact_lib_test crucible-cas "$cas_test"
          done

          # Exercise the daemon owner's restart, interrupted journal, quota,
          # cache, write-back-root, packed, and S3 global-GC paths.
          for daemon_test in \
            campaign_gc::tests::policy_aware_gc_evicts_a_wrapped_read_through_cache_with_a_required_copy \
            campaign_gc::tests::write_back_journal_roots_are_planned_and_revalidated_before_gc_deletion \
            campaign_gc::tests::interrupted_apply_retains_journal_and_requires_a_fresh_plan \
            campaign_gc::tests::directory_plan_journal_and_apply_survive_full_backend_restart \
            campaign_gc::tests::compressed_graph_admin_drives_plaintext_accounted_gc_across_restart \
            campaign_gc::tests::encrypted_graph_admin_drives_plaintext_accounted_gc_across_restart \
            campaign_gc::tests::compressed_encrypted_graph_admin_drives_plaintext_accounted_gc_across_restart \
            campaign_gc::tests::logical_quota_graph_gc_reclaims_admission_capacity_across_restart \
            campaign_gc::tests::packed_graph_admin_drives_restart_safe_logical_gc_without_deleting_live_pack_bytes \
            campaign_gc::tests::s3::s3_graph_admin_drives_global_gc_across_restart
          do
            run_exact_lib_test crucible-daemon "$daemon_test"
          done

          # Preserve the full component-contract negative surface with exact
          # planner, restart, stale-epoch, and cancellation/completion cases.
          for daemon_contract_test in \
            executor_supervisor::tests::completion_and_cancellation_races_are_idempotent \
            executor_supervisor::tests::durable_restart_replaces_stale_running_and_preserves_completion \
            campaign_attachment::tests::attached_frontier_planner_rejects_a_later_explorer_change_before_invocation \
            planner_loopback::tests::direct_and_loopback_planner_components_are_identical \
            planner_loopback::tests::planner_loopback_rejects_partial_frames_with_a_finite_deadline \
            planner_process::tests::process_frame_rejects_reserved_version_and_size_drift \
            planner_process::pipes::tests::unread_request_pipe_obeys_the_exchange_deadline \
            planner_process::pipes::tests::inherited_output_pipe_does_not_outlive_deadline_or_block_next_evaluation
          do
            run_exact_lib_test crucible-daemon "$daemon_contract_test"
          done

          # Planner identity, aggregate bounds, deterministic replay, and raw
          # vectors remain explicit rather than inferred from process flight.
          for campaign_contract_test in \
            planner_service::tests::planner_request_is_strict_bounded_and_has_a_golden_vector \
            planner_service::tests::raw_planner_request_and_response_vectors_decode_and_validate_without_construction \
            planner_service::tests::planning_bundle_stops_retaining_at_the_aggregate_byte_bound \
            planner_service::tests::checked_direct_planner_rejects_cross_request_replay \
            planner_service::tests::planner_response_digest_binds_same_invocation_bundle_bytes \
            repository::tests::coordination::planning::planner_driver_rejects_invalid_static_configuration_without_repository_writes \
            repository::tests::coordination::planning::planner_no_work_is_owned_replayable_and_state_continuous \
            campaign_service::tests::campaign_status_messages_are_snapshot_bound_and_have_raw_vectors \
            tests::scenario_default_records_have_frozen_versioned_vectors
          do
            run_exact_lib_test crucible-campaign "$campaign_contract_test"
          done

          mkdir -p "$out"
          cat > "$out/result" <<RESULT
          PASS
          check=${attrPath}
          tasks=${builtins.concatStringsSep "," taskIds}
          gate=gate:campaign-store-composition
          allowed_transparent_layer_orders=6
          routes=true
          tiers=true
          write_through=true
          write_back=true
          public_store_owner=true
          same_campaign_direct_and_split_process=true
          independent_coordinator_executor_restart=true
          accepted_cancellation_completion_race=true
          stale_assignment_rejection=true
          planner_negative_results=oversized,incompatible,stalled,nondeterministic
          planner_raw_golden_vectors=true
          semantic_observation_publication=true
          branch_edge_credit_exactly_once=true
          global_gc=true
          interrupted_gc_journal=true
          packed_restart_and_repack=true
          specialized_layers=compressed,encrypted,compressed-encrypted,logical-quota,physical-quota,namespaced,profile-validated,s3
          RESULT
        '';
      }
    ];
  }
