{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.gates.signalFaultSystem",
  taskIds ? [],
  liveNetwork,
  liveBlock,
  liveNineP,
  liveNodeLifecycle,
  liveFaultHardware,
  sharedCause,
  patchMicrotests,
  checkpointMaterialization,
  replayOracle,
  stateSpaceSearch,
  cliSearchFuzz,
  e2eDeterminism,
  campaignContinuity,
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
  qemuSeries = import ../../pkgs/emulation/qemu-patches/_series.nix;
  requiredQemuTaskIds = map (patch: "T-QEMU-${builtins.substring 0 4 patch.file}") (
    builtins.filter
    (patch: !(builtins.lessThan (builtins.substring 0 4 patch.file) "0047"))
    qemuSeries.patches
  );
  taskList = builtins.concatStringsSep "," taskIds;
  requiredQemuTaskList = builtins.concatStringsSep "," requiredQemuTaskIds;
in
  pkgs.mkDerivation {
    pname = "crucible-phase7-signal-fault-system";
    version = "0";
    src = crucibleSrc;

    buildDeps =
      [
        pkgs.coreutils
        pkgs.grep
        pkgs.rust
        pkgs.sed
        liveNetwork
        liveBlock
        liveNineP
        liveNodeLifecycle
        liveFaultHardware
        sharedCause
        patchMicrotests
        checkpointMaterialization
        replayOracle
        stateSpaceSearch
        cliSearchFuzz
        e2eDeterminism
        campaignContinuity
      ]
      ++ dependencies;

    phases = [
      {
        name = "unpack";
        script = ''
          cp -R "$src" source
          chmod -R u+w source
          cd source
        '';
      }
      {
        name = "configure";
        script = ''
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
        name = "run-closed-system-tests";
        script = ''
          set -eu
          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi

          target="$TMPDIR/signal-fault-system-target"
          crucible_lib_tests="$TMPDIR/crucible-lib-tests"
          cargo test \
            --frozen \
            --offline \
            --target-dir "$target" \
            --manifest-path crates/Cargo.toml \
            -p crucible \
            --lib \
            -- --list > "$crucible_lib_tests"
          qemu_lib_tests="$TMPDIR/crucible-qemu-lib-tests"
          cargo test \
            --frozen \
            --offline \
            --target-dir "$target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-qemu \
            --lib \
            -- --list > "$qemu_lib_tests"
          shmem_lib_tests="$TMPDIR/crucible-shmem-lib-tests"
          cargo test \
            --frozen \
            --offline \
            --target-dir "$target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-shmem \
            --lib \
            -- --list > "$shmem_lib_tests"
          plugin_lib_tests="$TMPDIR/crucible-qemu-plugin-lib-tests"
          cargo test \
            --frozen \
            --offline \
            --target-dir "$target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-qemu-plugin \
            --lib \
            -- --list > "$plugin_lib_tests"
          api_lib_tests="$TMPDIR/crucible-api-lib-tests"
          cargo test \
            --frozen \
            --offline \
            --target-dir "$target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-api \
            --lib \
            -- --list > "$api_lib_tests"
          device_lib_tests="$TMPDIR/crucible-device-lib-tests"
          cargo test \
            --frozen \
            --offline \
            --target-dir "$target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-device \
            --lib \
            -- --list > "$device_lib_tests"

          run_exact_crucible_test() {
            test_name="$1"
            grep -Fqx "$test_name: test" "$crucible_lib_tests"
            cargo test \
              --frozen \
              --offline \
              --target-dir "$target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --lib "$test_name" \
              -- --exact --include-ignored --test-threads=1
          }

          run_exact_qemu_test() {
            test_name="$1"
            grep -Fqx "$test_name: test" "$qemu_lib_tests"
            cargo test \
              --frozen \
              --offline \
              --target-dir "$target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu \
              --lib "$test_name" \
              -- --exact --include-ignored --test-threads=1
          }

          run_exact_shmem_test() {
            test_name="$1"
            grep -Fqx "$test_name: test" "$shmem_lib_tests"
            cargo test \
              --frozen \
              --offline \
              --target-dir "$target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-shmem \
              --lib "$test_name" \
              -- --exact --include-ignored --test-threads=1
          }

          run_exact_api_test() {
            test_name="$1"
            grep -Fqx "$test_name: test" "$api_lib_tests"
            cargo test \
              --frozen \
              --offline \
              --target-dir "$target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-api \
              --lib "$test_name" \
              -- --exact --include-ignored --test-threads=1
          }

          run_exact_device_test() {
            test_name="$1"
            grep -Fqx "$test_name: test" "$device_lib_tests"
            cargo test \
              --frozen \
              --offline \
              --target-dir "$target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-device \
              --lib "$test_name" \
              -- --exact --include-ignored --test-threads=1
          }

          run_exact_plugin_test() {
            test_name="$1"
            grep -Fqx "$test_name: test" "$plugin_lib_tests"
            cargo test \
              --frozen \
              --offline \
              --target-dir "$target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              --lib "$test_name" \
              -- --exact --include-ignored --test-threads=1
          }

          taxonomy_tests="$TMPDIR/rfc0014-taxonomy-ledger-tests"
          cargo test \
            --frozen \
            --offline \
            --target-dir "$target" \
            --manifest-path crates/Cargo.toml \
            -p crucible \
            --test rfc0014_taxonomy_ledger \
            -- --list > "$taxonomy_tests"
          taxonomy_match_test=rfc0014_taxonomy_ledger_matches_every_executable_row
          taxonomy_negative_test=rfc0014_taxonomy_ledger_parser_rejects_hostile_row_mutations
          grep -Fqx "$taxonomy_match_test: test" "$taxonomy_tests"
          grep -Fqx "$taxonomy_negative_test: test" "$taxonomy_tests"
          export CRUCIBLE_RFC0014_TAXONOMY_LEDGER_OUTPUT="$TMPDIR/rfc0014-taxonomy-ledger.tsv"
          cargo test \
            --frozen \
            --offline \
            --target-dir "$target" \
            --manifest-path crates/Cargo.toml \
            -p crucible \
            --test rfc0014_taxonomy_ledger \
            "$taxonomy_match_test" \
            -- --exact --include-ignored --test-threads=1
          unset CRUCIBLE_RFC0014_TAXONOMY_LEDGER_OUTPUT
          cargo test \
            --frozen \
            --offline \
            --target-dir "$target" \
            --manifest-path crates/Cargo.toml \
            -p crucible \
            --test rfc0014_taxonomy_ledger \
            "$taxonomy_negative_test" \
            -- --exact --include-ignored --test-threads=1
          test "$(wc -l < "$TMPDIR/rfc0014-taxonomy-ledger.tsv")" -eq 226
          test "$(grep -c '^4\.2-wired[[:space:]]' "$TMPDIR/rfc0014-taxonomy-ledger.tsv")" -eq 76
          test "$(grep -c '^4\.3-radio[[:space:]]' "$TMPDIR/rfc0014-taxonomy-ledger.tsv")" -eq 52
          test "$(grep -c '^4\.4-satellite[[:space:]]' "$TMPDIR/rfc0014-taxonomy-ledger.tsv")" -eq 20
          test "$(grep -c '^4\.5-node[[:space:]]' "$TMPDIR/rfc0014-taxonomy-ledger.tsv")" -eq 41
          test "$(grep -c '^4\.6-storage[[:space:]]' "$TMPDIR/rfc0014-taxonomy-ledger.tsv")" -eq 37

          for test_target in \
            gate_signal_fault_system \
            fault_reference \
            formal_trace_export \
            fault_observation_log \
            signal_fault_wakeup
          do
            cargo test \
              --frozen \
              --offline \
              --target-dir "$target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test "$test_target" \
              -- --test-threads=1
          done

          printf '%s\n' '${taskList}' \
            | tr ',' '\n' \
            | sed '/^$/d' \
            | sort -u \
            > "$TMPDIR/declared-signal-fault-tasks"
          if grep -Eq '^- \[ \] \*\*T-[A-Z0-9-]+\*\*' \
            docs/rfcs/0014-signal-driven-fault-model/07-implementation-plan.md
          then
            echo 'FAIL: RFC-0014 retains an open executable task' >&2
            exit 1
          fi
          grep -E '^- \[x\] \*\*T-[A-Z0-9-]+\*\*' \
            docs/rfcs/0014-signal-driven-fault-model/07-implementation-plan.md \
            | sed -E 's/^- \[x\] \*\*([^*]+)\*\*.*/\1/' \
            | sort -u \
            > "$TMPDIR/rfc-signal-fault-tasks"
          if ! cmp -s \
            "$TMPDIR/rfc-signal-fault-tasks" \
            "$TMPDIR/declared-signal-fault-tasks"
          then
            echo 'FAIL: final gate task metadata differs from RFC-0014' >&2
            echo 'RFC tasks absent from the gate:' >&2
            comm -23 \
              "$TMPDIR/rfc-signal-fault-tasks" \
              "$TMPDIR/declared-signal-fault-tasks" >&2
            echo 'gate tasks absent from the RFC:' >&2
            comm -13 \
              "$TMPDIR/rfc-signal-fault-tasks" \
              "$TMPDIR/declared-signal-fault-tasks" >&2
            exit 1
          fi

          printf '%s\n' '${requiredQemuTaskList}' \
            | tr ',' '\n' \
            | sed '/^$/d' \
            | sort -u \
            > "$TMPDIR/carried-qemu-patch-tasks"
          grep -E '^T-QEMU-[0-9]{4}$' \
            "$TMPDIR/declared-signal-fault-tasks" \
            > "$TMPDIR/declared-qemu-patch-tasks"
          if ! cmp -s \
            "$TMPDIR/carried-qemu-patch-tasks" \
            "$TMPDIR/declared-qemu-patch-tasks"
          then
            echo 'FAIL: final gate QEMU tasks differ from the carried patch series' >&2
            exit 1
          fi

          cargo test \
            --frozen \
            --offline \
            --target-dir "$target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-qemu \
            --test production_fault_checkpoint \
            -- --test-threads=1

          run_exact_crucible_test \
            scheduler::tests::signal_fault_frontier_preserves_parent_time_and_typed_candidates
          run_exact_crucible_test \
            scheduler::tests::production_backend::lifecycle_activity_requirement_rejects_release_before_scheduler_publication
          run_exact_crucible_test \
            model::fault_signal::plan::tests::resource_admission::world_resource_admission_applies_authored_static_topology_limits
          run_exact_crucible_test \
            model::fault_signal::binding_runtime::tests::refined_coordinate::locked_replay_retains_and_enforces_a_backend_refined_coordinate
          run_exact_crucible_test \
            model::fault_signal::runtime::tests::resolved_effect_trace_rejects_unversioned_and_future_envelopes
          run_exact_crucible_test \
            model::fault_signal::runtime::tests::resolved_effect_trace_preflights_authored_collection_counts
          run_exact_crucible_test \
            model::fault_signal::execution_runtime::replay_tests::resolved_effect_trace_public_decode_round_trips_nonempty_and_applies_authored_limits
          run_exact_crucible_test \
            model::fault_signal::execution_runtime::capacity_preflight::tests::borrowed_capacity_wire_matches_a_real_host_record_candidate
          run_exact_crucible_test \
            model::fault_signal::fallible_decode::tests::nested_sequence_allocation_uses_the_authored_fat_checkpoint_coordinate
          run_exact_crucible_test \
            model::fault_signal::execution_runtime::replay_tests::fault_runtime_checkpoint_preflights_authored_record_count_before_decode
          run_exact_crucible_test \
            model::fault_signal::binding_runtime::tests::rollback::malformed_adapter_success_rolls_back_the_entire_boundary
          run_exact_crucible_test \
            model::fault_signal::binding_runtime::tests::rollback::commit_reported_rollback_ambiguity_is_terminal_even_with_valid_rejection_evidence
          run_exact_crucible_test \
            model::fault_signal::tests::allocation_free_vector_element_type_preserves_the_boxed_wire_shape
          run_exact_qemu_test \
            fault_action_sink::tests::staged_qemu_results_and_evidence_use_reserved_storage
          run_exact_qemu_test \
            fault_action_sink::tests::typed_prepare_reserves_only_the_exact_evidence_capacity
          run_exact_qemu_test \
            fault_action_sink::tests::dynamic_prepare_limit_preserves_authored_coordinates
          run_exact_qemu_test \
            supervision::host_io_runtime::tests::preparation_result_is_admitted_before_exact_storage_allocation
          run_exact_qemu_test \
            supervision::host_io_runtime::tests::fault_result_publication_waits_for_the_full_control_pump
          run_exact_qemu_test \
            node::tests::fault_command::invalid_fault_event_sequence_is_terminal_across_retries
          run_exact_qemu_test \
            node::tests::exact_lifecycle::exact_snapshot_rejects_staged_fault_event_ownership
          run_exact_qemu_test \
            node::tests::exact_lifecycle::permanent_failure_retires_and_removes_the_authoritative_generation
          run_exact_qemu_test \
            node::tests::exact_lifecycle::restored_replacement_requires_explicit_release_after_install
          run_exact_qemu_test \
            node::tests::shutdown_and_preemption::process_identity_components_reuse_preowned_executable_storage
          run_exact_qemu_test \
            node::error::tests::resource_limit_coordinates_survive_node_and_scheduler_conversion
          run_exact_qemu_test \
            node::tests::fault_event_budget::node_set_arms_one_node_from_one_aggregate_fault_event_budget
          run_exact_qemu_test \
            node::tests::fault_event_budget::selected_node_step_rearms_the_retained_aggregate_fault_event_budget
          run_exact_qemu_test \
            node::tests::fault_event_budget::fault_event_limit_rejects_before_consuming_staged_ownership
          run_exact_qemu_test \
            node::tests::fault_event_budget::fault_event_payload_limit_rejects_before_copying_or_consuming_ownership
          run_exact_qemu_test \
            node::tests::fault_event_budget::fault_event_inline_payload_limit_rejects_before_copying_or_consuming_ownership
          run_exact_qemu_test \
            mapped_quantum::fault_event_tests::mapped_preview_preserves_exact_production_resource_coordinates
          run_exact_qemu_test \
            mapped_quantum::fault_event_tests::mapped_inline_preview_preserves_exact_production_resource_coordinates
          run_exact_qemu_test \
            node::tests::fault_event_budget::fingerprint_nodes_spend_one_sequential_fault_event_budget
          run_exact_qemu_test \
            node::tests::fault_event_budget::production_restore_requires_clean_fault_event_ownership
          run_exact_qemu_test \
            node::tests::fault_event_budget::production_restore_rejects_fault_event_published_by_fingerprint
          run_exact_qemu_test \
            production_fault_runtime::runtime_tests::recovery_tests::live_host_fault_event_drain_reaches_production_authentication
          run_exact_qemu_test \
            production_fault_runtime::runtime_tests::external_event_reservation_is_charged_before_boundary_apply
          run_exact_qemu_test \
            production_fault_runtime::lifecycle_tests::boot_ready_exhaustion_preserves_requested_intent_and_effective_terminal_decision
          run_exact_qemu_test \
            production_fault_runtime::lifecycle_tests::lifecycle_intent_preview_enforces_the_authored_pending_mutation_limit
          run_exact_qemu_test \
            production_fault_runtime::lifecycle_tests::outer_poison_latch_rejects_an_inert_plan_after_ambiguous_visibility
          run_exact_shmem_test \
            fault_event::tests::event_snapshot_authenticates_without_consuming_transport_ownership
          run_exact_shmem_test \
            fault_event::tests::event_snapshot_rejects_payload_bytes_without_consuming_transport_ownership
          run_exact_shmem_test \
            fault_event::tests::event_snapshot_rejects_inline_payload_before_copying_or_consuming
          run_exact_api_test \
            vm_lifecycle::runtime::tests::durable_run_state::durable_run_state_rejects_an_unowned_journal_process_identity
          run_exact_api_test \
            vm_lifecycle::runtime::tests::durable_run_state::durable_run_state_rejects_an_arbitrary_current_with_an_owned_replacement
          run_exact_api_test \
            vm_lifecycle::runtime::tests::durable_run_state::durable_run_state_accepts_a_prepared_replacement_at_the_exact_node_limit
          run_exact_api_test \
            vm_lifecycle::runtime::tests::durable_run_state::durable_run_state_rejects_prepared_ownership_in_intent_or_committed_phase
          run_exact_api_test \
            vm_lifecycle::runtime::tests::durable_run_state::durable_run_state_accepts_both_quarantined_manifest_commit_windows
          run_exact_api_test \
            vm_lifecycle::runtime::tests::durable_run_state::durable_run_state_rejects_split_file_intermediate_ownership
          run_exact_api_test \
            vm_lifecycle::runtime::tests::durable_run_state::durable_run_state_rejects_impossible_permanent_failure_ownership
          run_exact_api_test \
            vm_lifecycle::runtime::tests::durable_run_state::durable_run_state_accepts_boot_successor_reservation_before_authentication
          run_exact_api_test \
            vm_lifecycle::runtime::tests::durable_run_state::durable_run_state_rejects_boot_with_terminal_exit_ownership
          run_exact_api_test \
            vm_lifecycle::runtime::tests::durable_run_state::durable_run_state_rejects_saturated_terminal_successor_generation
          run_exact_api_test \
            vm_lifecycle::quantum_loop::lifecycle::staging::tests::terminal_precommit_reserves_effective_successor_generation
          run_exact_api_test \
            vm_lifecycle::quantum_loop::lifecycle::publication::tests::restored_generation_release_is_causally_gated_by_scheduler_publication
          run_exact_api_test \
            vm_lifecycle::quantum_loop::lifecycle::restart_ownership::tests::terminal_generation_selection_moves_preowned_storage
          run_exact_api_test \
            vm_lifecycle::quantum_loop::lifecycle::restart_ownership::tests::terminal_successor_launch_owns_exact_app_random_continuation
          run_exact_api_test \
            vm_lifecycle::quantum_loop::checkpoint_capture::tests::preparation_is_all_or_nothing_before_live_capture
          run_exact_api_test \
            vm_lifecycle::quantum_loop::checkpoint_capture::tests::cleanup_attempts_every_capture_in_reverse_order
          run_exact_api_test \
            vm_lifecycle::quantum_loop::checkpoint_capture::tests::publication_registry_retains_only_durable_or_indeterminate_owners
          run_exact_api_test \
            vm_lifecycle::quantum_loop::checkpoint_capture::tests::production_transaction_deletes_before_publication_and_retains_failed_cleanup
          run_exact_api_test \
            vm_lifecycle::checkpoint_store::publication::tests::publication_commit_tail_distinguishes_rollback_from_durability_uncertainty
          run_exact_api_test \
            vm_lifecycle::checkpoint_store::publication::tests::production_publication_rename_is_visible_only_when_admitted
          run_exact_api_test \
            vm_lifecycle::checkpoint_store::publication::tests::published_checkpoint_count_ignores_transaction_staging_directories
          run_exact_api_test \
            vm_lifecycle::checkpoint_store::publication::tests::new_checkpoint_count_is_admitted_before_publication_with_exact_coordinates
          run_exact_api_test \
            vm_lifecycle::checkpoint_store::read_budget::tests::checkpoint_read_budget_rejects_manifest_before_file_allocation
          run_exact_api_test \
            vm_lifecycle::checkpoint_store::read_budget::tests::checkpoint_read_allocation_failure_keeps_pre_reservation_coordinates
          run_exact_api_test \
            vm_lifecycle::checkpoint_store::recovery::tests::production_checkpoint_load_rejects_manifest_bytes_before_decode
          run_exact_api_test \
            vm_lifecycle::checkpoint_store::decode::tests::production_manifest_decode_rejects_hostile_target_length_before_elements
          run_exact_api_test \
            vm_lifecycle::checkpoint_store::decode::tests::nested_string_is_admitted_before_owned_copy_with_exact_coordinates
          run_exact_api_test \
            vm_lifecycle::checkpoint_store::decode::tests::string_larger_than_default_cbor_scratch_round_trips_canonically
          run_exact_api_test \
            vm_lifecycle::checkpoint_store::decision_wire::tests::fallible_decision_wire_preserves_canonical_bytes_and_nested_text
          grep -Fq 'node: decode::FallibleString' \
            crates/crucible-api/src/vm_lifecycle/checkpoint_store.rs
          grep -Fq 'node_generations: Vec<(decode::FallibleString, u64)>' \
            crates/crucible-api/src/vm_lifecycle/checkpoint_store.rs
          grep -Fq 'node_times: Vec<(decode::FallibleString, u64)>' \
            crates/crucible-api/src/vm_lifecycle/checkpoint_store.rs
          grep -Fq 'decisions: Vec<decision_wire::DecisionWire>' \
            crates/crucible-api/src/vm_lifecycle/checkpoint_store.rs
          grep -Fq 'decode_cbor_with_limits(payload, limits, "malformed closure manifest")' \
            crates/crucible-api/src/vm_lifecycle/checkpoint_store/decode.rs
          grep -Fq 'decode::decode_cbor_with_limits(bytes, limits, "decode exact lifecycle continuation")' \
            crates/crucible-api/src/vm_lifecycle/checkpoint_store.rs
          run_exact_api_test \
            vm_lifecycle::checkpoint_recovery::tests::fresh_process_removes_only_abandoned_checkpoint_staging
          run_exact_api_test \
            vm_lifecycle::storage_faults::tests::ambiguous_shared_ninep_commit_poisons_runtime_before_return
          run_exact_api_test \
            vm_lifecycle::storage_faults::tests::storage_resource_limits_preserve_exact_coordinates_through_scheduler
          run_exact_device_test \
            block::fault::tests::resource_usage::pending_operation_usage_tracks_count_and_largest_request_extent
          run_exact_device_test \
            block::fault::tests::resource_usage::media_rule_usage_tracks_existing_and_prospective_intervals
          run_exact_device_test \
            ninep::fault_policy_tests::fault_resource_usage_tracks_sessions_fids_and_object_versions
          test "$(grep -Fc 'let prepared_targets = prepare_exact_checkpoint_targets(' \
            crates/crucible-api/src/vm_lifecycle/quantum_loop.rs)" -eq 1
          checkpoint_prepare_line="$(grep -Fn \
            'let prepared_targets = prepare_exact_checkpoint_targets(' \
            crates/crucible-api/src/vm_lifecycle/quantum_loop.rs | cut -d: -f1)"
          checkpoint_capture_line="$(grep -Fn \
            'for prepared in prepared_targets {' \
            crates/crucible-api/src/vm_lifecycle/quantum_loop.rs | cut -d: -f1)"
          test "$checkpoint_prepare_line" -lt "$checkpoint_capture_line"
          test "$(grep -Fc 'checkpoint_capture::resolve_exact_checkpoint_capture(' \
            crates/crucible-api/src/vm_lifecycle/quantum_loop.rs)" -eq 1
          test "$(grep -Fc '    fn prepare_terminal_replacements(' \
            crates/crucible-api/src/vm_lifecycle/quantum_loop.rs)" -eq 1
          test "$(grep -Fc '    fn abort_staged_terminal_replacements(' \
            crates/crucible-api/src/vm_lifecycle/quantum_loop.rs)" -eq 1
          sed -n \
            '/fn prepare_terminal_replacements(/,/fn abort_staged_terminal_replacements(/p' \
            crates/crucible-api/src/vm_lifecycle/quantum_loop.rs \
            > "$TMPDIR/post-apply-terminal-restart"
          test -s "$TMPDIR/post-apply-terminal-restart"
          grep -Fq 'fn prepare_terminal_replacements(' \
            "$TMPDIR/post-apply-terminal-restart"
          grep -Fq 'fn abort_staged_terminal_replacements(' \
            "$TMPDIR/post-apply-terminal-restart"
          if grep -E \
            'private_backend_gdbstub_path|qemu_unix_gdbstub_endpoint|try_lifecycle_crash_detector|Production(Block|Ninep)FaultCoordinator::new|launch_configs' \
            "$TMPDIR/post-apply-terminal-restart"
          then
            echo 'FAIL: deterministic terminal restart ownership is constructed after APPLY' >&2
            exit 1
          fi
          grep -Fq 'prepare_terminal_lifecycle_ownership(' \
            crates/crucible-api/src/vm_lifecycle/quantum_loop/lifecycle.rs
          grep -Fq 'ProductionBlockFaultCoordinator::new(' \
            crates/crucible-api/src/vm_lifecycle/quantum_loop/lifecycle/restart_ownership.rs
          grep -Fq 'ProductionNinepFaultCoordinator::new(' \
            crates/crucible-api/src/vm_lifecycle/quantum_loop/lifecycle/restart_ownership.rs
          run_exact_api_test \
            vm_lifecycle::runtime::tests::durable_run_state::durable_run_state_rejects_unpublishable_replacement_transitions
          run_exact_api_test \
            vm_lifecycle::runtime::tests::durable_run_state::durable_run_state_rejects_unjournaled_staged_process_owner
          run_exact_api_test \
            vm_lifecycle::runtime::tests::durable_run_state::durable_run_state_rejects_unrelated_quarantined_postcommit_owner
          run_exact_api_test \
            vm_lifecycle::runtime::tests::durable_run_state::resource_limits::durable_run_state_rejects_old_outer_version_before_owned_decode
          run_exact_api_test \
            vm_lifecycle::runtime::tests::durable_run_state::resource_limits::durable_run_state_rejects_impossible_completed_exit_history
          run_exact_api_test \
            vm_lifecycle::runtime::tests::durable_run_state::resource_limits::durable_run_state_writer_preserves_resource_limit_coordinates
          run_exact_api_test \
            vm_lifecycle::runtime::tests::durable_run_state::resource_limits::durable_run_state_rejects_oversized_json_before_decode
          run_exact_api_test \
            vm_lifecycle::runtime::tests::durable_run_state::resource_limits::durable_run_state_persists_one_aggregate_envelope
          run_exact_api_test \
            vm_lifecycle::runtime::tests::durable_run_state::resource_limits::durable_run_state_preflights_aggregate_bytes_before_owned_decode
          run_exact_api_test \
            vm_lifecycle::runtime::tests::durable_run_state::resource_limits::durable_run_state_preflights_process_count_before_owned_map_decode
          run_exact_api_test \
            server::resource_limit::tests::rpc_resource_limit_response_preserves_exact_coordinates
          run_exact_api_test \
            client::resource_limit::tests::rpc_resource_limit_decodes_to_typed_lifecycle_error
          run_exact_api_test \
            vm_lifecycle::process_owners::decode_budget::tests::lifecycle_record_allocation_reports_previously_owned_record_usage
          run_exact_api_test \
            vm_lifecycle::quantum_loop::lifecycle::persistence::recovery::error::tests::decode_allocation_error_adds_the_complete_runtime_base
          run_exact_api_test \
            vm_lifecycle::runtime::tests::durable_run_state::resource_limits::durable_run_state_owned_decode_is_canonical_and_escape_free
          run_exact_api_test \
            vm_lifecycle::runtime::tests::durable_run_state_recovers_an_unfinished_run_before_reuse
          run_exact_api_test \
            vm_lifecycle::runtime::tests::durable_run_state_rejects_empty_active_transaction_phases
          run_exact_api_test \
            vm_lifecycle::quantum_loop::lifecycle::process_ownership::tests::terminal_process_ownership_binds_service_state_to_exact_transition
          run_exact_api_test \
            vm_lifecycle::quantum_loop::lifecycle::persistence::tests::fixed_journal_writer_uses_only_reserved_storage
          run_exact_api_test \
            vm_lifecycle::quantum_loop::lifecycle::persistence::tests::fixed_journal_writer_rejects_growth_without_mutation
          run_exact_api_test \
            vm_lifecycle::quantum_loop::lifecycle::persistence::tests::lifecycle_encoding_reserve_uses_the_measured_total_capacity
          run_exact_qemu_test \
            production_fault_runtime::checkpoint_codec::preflight::tests::preflight_applies_event_records_as_one_aggregate_ceiling
          run_exact_qemu_test \
            production_fault_runtime::runtime_tests::recovery_tests::qemu_event_staging_uses_remaining_aggregate_ledger_capacity
          run_exact_qemu_test \
            production_fault_runtime::evaluation::publication::tests::production_evaluation_publication_is_owned_before_commit
          run_exact_qemu_test \
            production_fault_runtime::lifecycle_tests::ownership::lifecycle_work_transfer_preserves_buffers_and_holds_barrier_until_release_completion
          run_exact_qemu_test \
            production_fault_runtime::lifecycle_tests::ownership::lifecycle_owners_are_bound_to_the_creating_runtime_instance
          run_exact_qemu_test \
            production_fault_runtime::lifecycle_tests::lifecycle_intent_preview_is_action_exact_and_ignores_active_hang_rules
          run_exact_plugin_test \
            fault_command::tests::bridge_translates_capabilities_and_local_rejections_at_logical_time
          run_exact_plugin_test \
            runtime::live_callbacks::tests::fault_event_control::control_boundary_retries_occurrence_event_after_host_drain_before_ack
          run_exact_plugin_test \
            runtime::live_callbacks::tests::logical_restore::post_vmstate_pause_reconstructs_idle_jump_offset_before_acknowledging
          run_exact_plugin_test \
            runtime::live_whitebox::app_random::tests::logical_restore_discards_priming_draws_exactly_once
          run_exact_plugin_test \
            args::tests::plugin_args_require_and_validate_authored_storage_history_limits
          run_exact_plugin_test \
            block_io::tests::resource_limits::completed_history_refuses_epochs_and_gaps_at_exact_authored_coordinates
          run_exact_plugin_test \
            block_io::tests::resource_limits::transport_restore_admits_history_counts_before_owned_decode
          run_exact_qemu_test \
            launch::plugin_config::tests::authored_storage_history_limits_are_explicit_and_fail_closed
          run_exact_qemu_test \
            supervision::node_step_gate::support::tests::authored_storage_history_limits_reach_the_plugin_launch_boundary
          grep -Fq \
            '.with_fault_resource_limits(source.plan().fault_signals().resource_limits())' \
            crates/crucible-api/src/vm_lifecycle.rs
          grep -Fq 'args.storage_history_limits(),' \
            crates/crucible-qemu-plugin/src/runtime/live_callbacks.rs
          grep -Fq 'attach_devices_with_history_limits(' \
            crates/crucible-qemu-plugin/src/runtime.rs
          grep -Fq 'from_directed_rings_with_history_limits(' \
            crates/crucible-qemu-plugin/src/runtime/live_callbacks/devices/attachment.rs
          run_exact_qemu_test \
            fault_action_sink::node_payload::tests::memory_bit_flip_rejects_authored_length_before_expanding_mask
          run_exact_qemu_test \
            production_fault_runtime::lifecycle_tests::qemu_action_ledger_retains_impulses_and_removed_rules_for_events
          run_exact_api_test \
            vm_lifecycle::network_faults::route::tests::resource_limits::pending_network_output_admission_uses_frame_and_pending_limits
          run_exact_api_test \
            vm_lifecycle::network_faults::route::tests::resource_limits::queue_admission_uses_aggregate_frame_and_byte_limits
          run_exact_api_test \
            vm_lifecycle::network_faults::route::tests::resource_limits::shared_medium_and_custody_admission_share_the_authored_queue_budget
          run_exact_api_test \
            vm_lifecycle::network_faults::route::tests::resource_limits::contact_and_restore_admission_use_authored_aggregate_coordinates
          run_exact_qemu_test \
            node::tests::fault_command::fault_command_applies_at_exact_current_boundary_without_guest_progress
          run_exact_shmem_test \
            fault_command::tests::result_transport_reuses_preallocated_payload_storage_without_consuming_on_short_buffer

          network_effect_rows="$TMPDIR/causal-network-production-effect-rows"
          : > "$network_effect_rows"
          export CRUCIBLE_NETWORK_PRODUCTION_EFFECT_ROWS="$network_effect_rows"
          cargo test \
            --frozen \
            --offline \
            --target-dir "$target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-api \
            --lib vm_lifecycle::network_faults \
            -- --test-threads=1
          unset CRUCIBLE_NETWORK_PRODUCTION_EFFECT_ROWS
          sort -o "$network_effect_rows" "$network_effect_rows"
          test "$(wc -l < "$network_effect_rows")" -eq 31
          cut -d= -f2- "$network_effect_rows" | cut -d'|' -f1 \
            | sort > "$TMPDIR/causal-network-effect-kinds"
          printf '%s\n' \
            network.access_delay \
            network.association \
            network.availability \
            network.burst_error_state \
            network.connection_state \
            network.contact \
            network.control_plane_service \
            network.control_result_transform \
            network.custody_queue \
            network.detected_frame_error \
            network.duplicate \
            network.firewall_disposition \
            network.flap \
            network.forwarder_lifecycle \
            network.forwarding_mutation \
            network.frame_loss \
            network.jitter \
            network.mtu \
            network.negotiated_mode \
            network.pause_backpressure \
            network.payload_transform \
            network.profile_delta \
            network.propagation_delay \
            network.queue_policy \
            network.recipient_subset \
            network.reorder \
            network.rf_channel \
            network.route_transition \
            network.service_curve \
            network.shared_medium \
            network.token_bucket \
            | sort > "$TMPDIR/expected-causal-network-effect-kinds"
          cmp "$TMPDIR/expected-causal-network-effect-kinds" \
            "$TMPDIR/causal-network-effect-kinds"

          storage_effect_rows="$TMPDIR/causal-storage-production-effect-rows"
          : > "$storage_effect_rows"
          export CRUCIBLE_STORAGE_PRODUCTION_EFFECT_ROWS="$storage_effect_rows"
          cargo test \
            --frozen \
            --offline \
            --target-dir "$target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-api \
            --lib vm_lifecycle::storage_faults \
            -- --test-threads=1
          cargo test \
            --frozen \
            --offline \
            --target-dir "$target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-qemu \
            --lib production_fault_runtime \
            -- --test-threads=1
          cargo test \
            --frozen \
            --offline \
            --target-dir "$target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-qemu \
            --lib checkpoint::bounded_cbor::tests \
            -- --test-threads=1
          cargo test \
            --frozen \
            --offline \
            --target-dir "$target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-qemu \
            --lib node_set_sequence_restore_rejects_late_invalid_node_without_partial_mutation \
            -- --test-threads=1
          cargo test \
            --frozen \
            --offline \
            --target-dir "$target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-qemu \
            --lib fault_action_sink \
            -- --test-threads=1
          cargo test \
            --frozen \
            --offline \
            --target-dir "$target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-qemu \
            --lib storage_fault_resolver \
            -- --test-threads=1
          unset CRUCIBLE_STORAGE_PRODUCTION_EFFECT_ROWS
          sort -o "$storage_effect_rows" "$storage_effect_rows"
          test "$(wc -l < "$storage_effect_rows")" -eq 20
          cut -d= -f2- "$storage_effect_rows" | cut -d'|' -f1 \
            | sort > "$TMPDIR/causal-storage-effect-kinds"
          printf '%s\n' \
            ninep.result \
            ninep.visibility \
            storage.array_state \
            storage.availability \
            storage.completion_reorder \
            storage.controller_lifecycle \
            storage.duplicate_completion \
            storage.flash_state \
            storage.flush_disposition \
            storage.latency \
            storage.media_range \
            storage.operation_failure \
            storage.persistence_order \
            storage.read_transform \
            storage.reported_capacity \
            storage.service \
            storage.stall_timeout \
            storage.volatile_cache \
            storage.volatile_cache_loss \
            storage.write_disposition \
            | sort > "$TMPDIR/expected-causal-storage-effect-kinds"
          cmp "$TMPDIR/expected-causal-storage-effect-kinds" \
            "$TMPDIR/causal-storage-effect-kinds"

          production_matrix="$TMPDIR/production-effect-matrix"
          export CRUCIBLE_PRODUCTION_EFFECT_MATRIX_OUTPUT="$production_matrix"
          cargo test \
            --frozen \
            --offline \
            --target-dir "$target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-api \
            --test production_effect_matrix \
            -- --test-threads=1
          unset CRUCIBLE_PRODUCTION_EFFECT_MATRIX_OUTPUT
          test -s "$production_matrix"
          test "$(wc -l < "$production_matrix")" = \
            "$(cut -d '|' -f 1 "$production_matrix" | sort -u | wc -l)"
          test "$(grep -c '|network|' "$production_matrix")" -gt 0
          test "$(grep -c '|storage|' "$production_matrix")" -gt 0
          test "$(grep -c '|node|' "$production_matrix")" -gt 0
          if grep '|network|' "$production_matrix" \
            | grep -Fv '|gate:live-network-io|'
          then
            echo 'FAIL: a network effect lacks the live network gate' >&2
            exit 1
          fi
          if grep '|storage|' "$production_matrix" \
            | grep -Ev '\|gate:live-(block|9p)-io\|'
          then
            echo 'FAIL: a storage effect lacks a live storage gate' >&2
            exit 1
          fi
          if grep '|node|' "$production_matrix" \
            | grep -Ev '\|gate:(live-node-lifecycle-fault|live-node-lifecycle-matrix|live-fault-hardware|patch-microtests)\|'
          then
            echo 'FAIL: a node effect lacks a live QEMU conformance gate' >&2
            exit 1
          fi

          # These names belonged to the replaced execution hierarchy. Keep the
          # check source-only so prose migration guidance does not trip it.
          if grep -R -n -E \
            '\b(Fault[P]lanEntry|FiniteFault|PermanentFault)\b|pub (enum|struct) Fault[[:space:]]*\{' \
            crates/crucible/src crates/crucible-api/src crates/crucible-qemu/src
          then
            echo 'FAIL: retired fault execution API is present' >&2
            exit 1
          fi
          if grep -R -n -E 'inject_[f]ault|heal_[f]ault|Inject[F]ault|Heal[F]ault|FaultPlan|PermanentAt|crucible\.scenario-family\.v1' \
            docs/rfcs/0010-crucible docs/users/crucible \
            | grep -v 'there is no `Inject[F]ault`, `Heal[F]ault`, `FaultSpec`' \
            | grep -v 'checks.crucible.phase4.faultPlan'
          then
            echo 'FAIL: retired normative fault or scenario-family vocabulary is present' >&2
            exit 1
          fi
          mkdir -p "$TMPDIR/unfinished-guard/nested"
          printf '%s\n' 'unimplemented!()' > "$TMPDIR/unfinished-guard/nested/probe.rs"
          if ! grep -R -q -E 'todo!\(|unimplemented!\(' "$TMPDIR/unfinished-guard"
          then
            echo 'FAIL: unfinished-code guard does not recurse into nested modules' >&2
            exit 1
          fi

          if grep -R -n -E 'todo!\(|unimplemented!\(' \
            crates/crucible/src/model/fault_signal \
            crates/crucible-api/src/vm_lifecycle/network_faults \
            crates/crucible-api/src/vm_lifecycle/storage_faults \
            crates/crucible-device/src/block/fault \
            crates/crucible-device/src/netlink \
            crates/crucible-device/src/ninep/fault \
            crates/crucible-qemu/src/fault_action_sink \
            crates/crucible-qemu/src/node_set \
            crates/crucible-qemu/src/production_fault_runtime.rs \
            crates/crucible-qemu/src/production_fault_runtime \
            crates/crucible-qemu/src/supervision/host_io_runtime \
            crates/crucible-qemu-plugin/src/fault_command \
            crates/crucible-qemu-plugin/src/runtime/live_callbacks
          then
            echo 'FAIL: unfinished production fault implementation is present' >&2
            exit 1
          fi
        '';
      }
      {
        name = "validate-production-evidence";
        script = ''
          set -eu

          network_result=${liveNetwork}/result
          network_world_result=${liveNetwork}/live-world-network.result
          grep -Fxq PASS "$network_result"
          grep -Fxq 'gate=gate:live-network-io' "$network_result"
          grep -Fxq 'network_backend=hostless-qemu-hubport' "$network_result"
          grep -Fxq 'deterministic_under_scheduler_preemption=true' "$network_result"
          grep -Fxq 'host_adversary=bounded-scheduler-preemption' "$network_result"
          grep -Fxq PASS "$network_world_result"
          grep -Fxq 'backend=production-qemu-lifecycle' "$network_world_result"
          grep -Fxq 'search_branch=loss-fire' "$network_world_result"
          grep -Fxq 'branch_decisions_match=true' "$network_world_result"
          grep -Fxq 'guest_acknowledgements=1' "$network_world_result"
          grep -Fxq 'exact_restore_next_quantum_match=true' "$network_world_result"
          grep -Fxq 'checkpoint_packet_continuation=1' "$network_world_result"
          grep -Fxq 'checkpoint_fault_decision_continuation=40' "$network_world_result"

          block_result=${liveBlock}/result
          grep -Fxq PASS "$block_result"
          grep -Fxq 'gate=gate:live-block-io' "$block_result"
          grep -Fxq 'block_backend=crucible-shmem-host-servicer' "$block_result"
          grep -Fxq 'host_wins_race_proven=true' "$block_result"
          grep -Fxq 'guest_wins_race_proven=true' "$block_result"
          grep -Fxq 'canonical_logs_identical=true' "$block_result"

          ninep_result=${liveNineP}/result
          grep -Fxq PASS "$ninep_result"
          grep -Fxq 'gate=gate:live-9p-io' "$ninep_result"
          grep -Fxq 'sim_leg_forwarded=true' "$ninep_result"
          grep -Fxq 'deterministic_under_scheduler_preemption=true' "$ninep_result"

          node_result=${liveNodeLifecycle}/result
          grep -Fxq PASS "$node_result"
          grep -Fxq 'backend=production-qemu-signal-runtime' "$node_result"
          grep -Fxq 'exact_manifest_replay_admitted=true' "$node_result"
          grep -Fxq 'changed_state_precondition_rejected=true' "$node_result"
          grep -Fxq 'corrupt_result_rejected_with_valid_event=true' "$node_result"
          grep -Fxq 'corrupt_event_rejected_with_valid_result=true' "$node_result"
          grep -Fxq 'lifecycle_impulse_committed=true' "$node_result"
          grep -Fxq 'cross_adapter_rejection_rolled_back=true' "$node_result"
          grep -Fxq 'patch=0109-crucible-control-boundary-node-faults.patch' \
            "${patchMicrotests}/per-patch/0109-crucible-control-boundary-node-faults.patch.result"
          grep -Fxq 'patched_fixture_exercised=true' \
            "${patchMicrotests}/per-patch/0109-crucible-control-boundary-node-faults.patch.result"
          lifecycle_matrix_result="${patchMicrotests}/per-patch/0056-crucible-node-lifecycle-faults.patch.result"
          grep -Fxq 'ready_exhaustion=attempts-2,effective-permanent-failure,exit-72' \
            "$lifecycle_matrix_result"
          grep '^production_effect_row=' "$lifecycle_matrix_result" \
            > "$TMPDIR/node-production-effect-rows"
          test "$(wc -l < "$TMPDIR/node-production-effect-rows")" -eq 2
          test "$(sort -u "$TMPDIR/node-production-effect-rows" | wc -l)" -eq 2
          grep -Fxq \
            'production_effect_row=node.hang|node-vcpu-watchdog-recovery|gate:live-node-lifecycle-matrix|actual-patched-qemu|CRUCHNG1+CRUCWDC1+CRUCLIF1' \
            "$TMPDIR/node-production-effect-rows"
          grep -Fxq \
            'production_effect_row=node.lifecycle|reset-ready-exhaustion|gate:live-node-lifecycle-matrix|actual-patched-qemu|CRUCLIF1-ready-exhausted-permanent-failure' \
            "$TMPDIR/node-production-effect-rows"
          vcpu_result="${patchMicrotests}/per-patch/0055-crucible-vcpu-service-control.patch.result"
          grep -Fxq PASS "$vcpu_result"
          grep -Fxq 'live_vcpu_states=online,offline,stalled,recovery' \
            "$vcpu_result"
          grep '^production_effect_row=' "$vcpu_result" \
            > "$TMPDIR/vcpu-production-effect-rows"
          test "$(wc -l < "$TMPDIR/vcpu-production-effect-rows")" -eq 2
          test "$(sort -u "$TMPDIR/vcpu-production-effect-rows" | wc -l)" -eq 2
          grep -Fxq \
            'production_effect_row=cpu.service|service-ratio-ledger|gate:patch-microtests|actual-patched-qemu|CRUCVCS1' \
            "$TMPDIR/vcpu-production-effect-rows"
          grep -Fxq \
            'production_effect_row=cpu.vcpu_state|online-offline-stalled-recovery|gate:patch-microtests|actual-patched-qemu|CRUCVST1' \
            "$TMPDIR/vcpu-production-effect-rows"
          grep -Fq \
            'node.hang|node|node.hang|gate:live-node-lifecycle-matrix|tests/crucible/phase2-qemu-node-lifecycle.nix via gate:patch-microtests|' \
            "$production_matrix"
          grep -Fq \
            'cpu.vcpu_state|node|cpu.vcpu_state|gate:patch-microtests|tests/crucible/phase2-qemu-vcpu-service.nix via gate:patch-microtests|' \
            "$production_matrix"

          hardware_result=${liveFaultHardware}/result
          grep -Fxq PASS "$hardware_result"
          grep -Fxq 'gate=gate:live-fault-hardware' "$hardware_result"
          grep -Fxq 'clock_effect_proof=authenticated-old-plus-offset-equals-new' "$hardware_result"
          grep -Fxq 'clock_occurrences=1' "$hardware_result"
          grep -Fxq 'accelerator_occurrences=1' "$hardware_result"
          grep -Fxq 'clock_source_occurrences=2' "$hardware_result"
          grep -Fxq 'accelerator_lifecycle_occurrences=1' "$hardware_result"
          grep -Fxq 'accelerator_memory_occurrences=1' "$hardware_result"
          grep -Fxq 'accelerator_service_occurrences=3' "$hardware_result"
          grep -Fxq 'accelerator_mutation=tpu-result-42-to-43' "$hardware_result"
          grep -Fxq 'fresh_plugin_restore=true' "$hardware_result"

          node_effect_rows="$TMPDIR/causal-node-production-effect-rows"
          grep '^production_effect_row=' "$lifecycle_matrix_result" > "$node_effect_rows"
          grep '^production_effect_row=' "$vcpu_result" >> "$node_effect_rows"
          for result in \
            "${patchMicrotests}/per-patch/0049-crucible-memory-boundary-mutate.patch.result" \
            "${patchMicrotests}/per-patch/0050-crucible-memory-access-faults.patch.result" \
            "${patchMicrotests}/per-patch/0051-crucible-add-architecture-register-fault-mutations.patch.result" \
            "${patchMicrotests}/per-patch/0052-crucible-instruction-and-exception-faults.patch.result" \
            "${patchMicrotests}/per-patch/0053-crucible-interrupt-faults.patch.result" \
            "${patchMicrotests}/per-patch/0054-crucible-inject-architecture-hardware-errors.patch.result"
          do
            grep '^production_effect_row=' "$result" >> "$node_effect_rows"
          done
          grep '^production_effect_row=' "$hardware_result" >> "$node_effect_rows"
          test "$(wc -l < "$node_effect_rows")" -eq 20
          test "$(sort -u "$node_effect_rows" | wc -l)" -eq 20
          cut -d= -f2- "$node_effect_rows" | cut -d'|' -f1 | sort > "$TMPDIR/causal-node-effect-kinds"
          printf '%s\n' \
            accelerator.lifecycle \
            accelerator.memory_event \
            accelerator.result_transform \
            accelerator.service \
            clock.source_state \
            clock.transform \
            cpu.exception \
            cpu.instruction_transform \
            cpu.register_transform \
            cpu.service \
            cpu.vcpu_state \
            interrupt.disposition \
            interrupt.storm \
            memory.access_transform \
            memory.ecc_event \
            memory.mutation \
            memory.region_state \
            memory.service \
            node.hang \
            node.lifecycle \
            | sort > "$TMPDIR/expected-causal-node-effect-kinds"
          cmp "$TMPDIR/expected-causal-node-effect-kinds" "$TMPDIR/causal-node-effect-kinds"

          shared_result=${sharedCause}/result
          grep -Fxq PASS "$shared_result"
          grep -Fxq 'gate=gate:signal-shared-cause' "$shared_result"
          grep -Fxq 'pre_event_queue_and_volatile_cache=true' "$shared_result"
          grep -Fxq 'network_storage_node_same_event=true' "$shared_result"
          grep -Fxq 'shared_event_effect_records=3' "$shared_result"
          grep -Fxq 'node_effective_icount_authenticated=true' "$shared_result"
          grep -Fxq 'exact_checkpoint_evidence_match=true' "$shared_result"
          grep -Fxq 'locked_effect_replay_evidence_match=true' "$shared_result"
          grep '^terminal_row=' "$shared_result" > "$TMPDIR/terminal-rows"
          test "$(wc -l < "$TMPDIR/terminal-rows")" -eq 2
          test "$(sort -u "$TMPDIR/terminal-rows" | wc -l)" -eq 2
          grep -Fxq 'terminal_row=node-a|transition=power_off|generation_delta=1|service_state=powered_off|scheduler_activity=halted|process_ownership=exact' "$TMPDIR/terminal-rows"
          grep -Fxq 'terminal_row=node-b|transition=permanent_failure|generation_delta=0|service_state=permanently_failed|scheduler_activity=done|process_ownership=absent' "$TMPDIR/terminal-rows"

          patch_result=${patchMicrotests}/result
          grep -Fxq PASS "$patch_result"
          grep -Fxq 'gate=gate:patch-microtests' "$patch_result"
          grep -Fxq 'every_carried_patch_has_microtest=true' "$patch_result"
          grep -Fxq 'every_microtest_has_executable_negative_control=true' "$patch_result"
          grep -Fxq 'diagnostic_only_patches_excluded_from_shipped_qemu=true' "$patch_result"
          grep -Fxq 'patch=0110-crucible-release-halted-rr-turn.patch' \
            "${patchMicrotests}/per-patch/0110-crucible-release-halted-rr-turn.patch.result"
          grep -Fxq 'guest_pause_early_yield_negative=critical-arm-branch-trap-observed-after-AAAB' \
            "${patchMicrotests}/per-patch/0110-crucible-release-halted-rr-turn.patch.result"
          grep -Fxq 'patch=0111-crucible-accelerator-service-schema.patch' \
            "${patchMicrotests}/per-patch/0111-crucible-accelerator-service-schema.patch.result"
          grep -Fxq 'live_evidence=live-typed-accelerator-service-policy' \
            "${patchMicrotests}/per-patch/0111-crucible-accelerator-service-schema.patch.result"
          grep -Fxq 'patch=0112-crucible-compile-affected-clock-sources.patch' \
            "${patchMicrotests}/per-patch/0112-crucible-compile-affected-clock-sources.patch.result"
          grep -Fxq 'live_evidence=live-affected-clock-source-compilation' \
            "${patchMicrotests}/per-patch/0112-crucible-compile-affected-clock-sources.patch.result"
          grep -Fxq 'patch=0113-crucible-restore-accelerator-rule-indexes.patch' \
            "${patchMicrotests}/per-patch/0113-crucible-restore-accelerator-rule-indexes.patch.result"
          grep -Fxq 'live_evidence=live-restored-accelerator-rule-indexes' \
            "${patchMicrotests}/per-patch/0113-crucible-restore-accelerator-rule-indexes.patch.result"

          checkpoint_result=${checkpointMaterialization}/result
          grep -Fxq PASS "$checkpoint_result"
          grep -Fxq 'exact_fat_checkpoint=content-addressed-and-complete' "$checkpoint_result"
          grep -Fxq 'legacy_savevm_hedge=absent' "$checkpoint_result"

          replay_result=${replayOracle}/result
          grep -Fxq PASS "$replay_result"
          search_result=${stateSpaceSearch}/result
          grep -Fxq PASS "$search_result"
          grep -Fxq 'gate=gate:state-space-search' "$search_result"
          cli_result=${cliSearchFuzz}/result
          grep -Fxq PASS "$cli_result"
          grep -Fxq 'contract=search-fuzz-workflow-complete' "$cli_result"

          grep -Fxq PASS ${e2eDeterminism}/result
          grep -Fxq PASS ${campaignContinuity}/result
        '';
      }
      {
        name = "write-result";
        script = ''
          set -eu
          mkdir -p "$out/evidence"
          cp ${liveNetwork}/result "$out/evidence/live-network.result"
          cp ${liveNetwork}/live-world-network.result "$out/evidence/live-world-network.result"
          cp ${liveBlock}/result "$out/evidence/live-block.result"
          cp ${liveNineP}/result "$out/evidence/live-9p.result"
          cp ${liveNodeLifecycle}/result "$out/evidence/live-node-lifecycle.result"
          cp ${liveFaultHardware}/result "$out/evidence/live-fault-hardware.result"
          cp ${sharedCause}/result "$out/evidence/signal-shared-cause.result"
          cp ${patchMicrotests}/result "$out/evidence/patch-microtests.result"
          cp ${checkpointMaterialization}/result "$out/evidence/checkpoint.result"
          cp ${replayOracle}/result "$out/evidence/replay.result"
          cp ${stateSpaceSearch}/result "$out/evidence/search.result"
          cp ${cliSearchFuzz}/result "$out/evidence/cli-search-fuzz.result"
          cp "$TMPDIR/production-effect-matrix" \
            "$out/evidence/production-effect-matrix.txt"
          cp "$TMPDIR/causal-network-production-effect-rows" \
            "$out/evidence/causal-network-production-effects.txt"
          cp "$TMPDIR/causal-storage-production-effect-rows" \
            "$out/evidence/causal-storage-production-effects.txt"
          cp "$TMPDIR/causal-node-production-effect-rows" \
            "$out/evidence/causal-node-production-effects.txt"
          cp "$TMPDIR/rfc0014-taxonomy-ledger.tsv" \
            "$out/evidence/rfc0014-taxonomy-ledger.tsv"

          matrix_network_count=$(grep -c '|network|' \
            "$out/evidence/production-effect-matrix.txt")
          matrix_storage_count=$(grep -c '|storage|' \
            "$out/evidence/production-effect-matrix.txt")
          matrix_node_count=$(grep -c '|node|' \
            "$out/evidence/production-effect-matrix.txt")
          matrix_total_count=$(wc -l \
            < "$out/evidence/production-effect-matrix.txt")

          cat > "$out/result" <<RESULT
          CHECKPOINT
          check=${attrPath}
          gate=gate:signal-fault-system
          tasks=${taskList}
          status=complete
          effect_registry=closed-and-exhaustive
          executable_effect_count=$matrix_total_count
          production_adapters=network,storage,node
          specification_only_domains=sensor,power
          retired_execution_paths=absent
          unfinished_production_paths=absent
          per_kind_metadata=admission,capability,replay-evidence,user-reference
          per_kind_production_execution_matrix=network-$matrix_network_count,storage-$matrix_storage_count,node-$matrix_node_count
          per_kind_production_execution_matrix_artifact=evidence/production-effect-matrix.txt
          causal_network_production_effect_count=31
          causal_network_production_effect_artifact=evidence/causal-network-production-effects.txt
          causal_storage_production_effect_count=20
          causal_storage_production_effect_artifact=evidence/causal-storage-production-effects.txt
          plugin_completed_history_limits=authored-required-predecode-admission
          checkpoint_owned_decode=fallible-text-and-decision-wire
          checkpoint_publication=cleanup-before-rename-and-durable-count-admission
          causal_node_production_effect_count=20
          causal_node_production_effect_artifact=evidence/causal-node-production-effects.txt
          executable_taxonomy_rows=226
          executable_taxonomy_section_counts=wired-76,radio-52,satellite-20,node-41,storage-37
          executable_taxonomy_ledger=exact-section-identity-and-registered-effects
          executable_taxonomy_ledger_artifact=evidence/rfc0014-taxonomy-ledger.tsv
          missing_acceptance=none
          system_evidence=adapter-dispatch,event-log,checkpoint,recomputed-replay,locked-replay,search,negative-tests
          live_boundary_evidence=network,block,9p,node-lifecycle,qemu-fault-patches,clock,accelerator,fresh-plugin-restore
          production_checkpoint=authenticated-round-trip
          final_acceptance_dependencies=e2e-determinism,campaign-continuity
          RESULT
        '';
      }
    ];
  }
