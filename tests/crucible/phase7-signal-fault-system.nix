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
  taskList = builtins.concatStringsSep "," taskIds;
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
              -- --exact --test-threads=1
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
              -- --exact --test-threads=1
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
              -- --exact --test-threads=1
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
              -- --exact --test-threads=1
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
              -- --exact --test-threads=1
          }

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
            node::tests::fault_event_budget::node_set_arms_one_node_from_one_aggregate_fault_event_budget
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
            vm_lifecycle::runtime::tests::durable_run_state::durable_run_state_accepts_manifest_first_intent_and_exits_reaped_windows
          run_exact_api_test \
            vm_lifecycle::runtime::tests::durable_run_state::durable_run_state_rejects_unrelated_quarantined_postcommit_owner
          run_exact_api_test \
            vm_lifecycle::runtime::tests::durable_run_state::durable_run_state_rejects_oversized_json_before_decode
          run_exact_api_test \
            vm_lifecycle::quantum_loop::lifecycle::persistence::tests::fixed_journal_writer_uses_only_reserved_storage
          run_exact_api_test \
            vm_lifecycle::quantum_loop::lifecycle::persistence::tests::fixed_journal_writer_rejects_growth_without_mutation
          run_exact_qemu_test \
            production_fault_runtime::checkpoint_codec::preflight::tests::preflight_applies_event_records_as_one_aggregate_ceiling
          run_exact_qemu_test \
            production_fault_runtime::runtime_tests::recovery_tests::qemu_event_staging_uses_remaining_aggregate_ledger_capacity
          run_exact_qemu_test \
            production_fault_runtime::evaluation::publication::tests::production_evaluation_publication_is_owned_before_commit
          run_exact_qemu_test \
            production_fault_runtime::lifecycle_tests::lifecycle_work_transfer_preserves_buffers_and_holds_checkpoint_barrier_until_ack
          run_exact_qemu_test \
            production_fault_runtime::lifecycle_tests::lifecycle_intent_preview_is_action_exact_and_ignores_active_hang_rules
          run_exact_plugin_test \
            fault_command::tests::bridge_translates_capabilities_and_local_rejections_at_logical_time
          run_exact_plugin_test \
            runtime::live_callbacks::tests::fault_event_control::control_boundary_retries_occurrence_event_after_host_drain_before_ack
          run_exact_qemu_test \
            fault_action_sink::node_payload::tests::memory_bit_flip_rejects_authored_length_before_expanding_mask
          run_exact_qemu_test \
            production_fault_runtime::lifecycle_tests::qemu_action_ledger_retains_impulses_and_removed_rules_for_events
          run_exact_qemu_test \
            node::tests::fault_command::fault_command_applies_at_exact_current_boundary_without_guest_progress
          run_exact_shmem_test \
            fault_command::tests::result_transport_reuses_preallocated_payload_storage_without_consuming_on_short_buffer

          cargo test \
            --frozen \
            --offline \
            --target-dir "$target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-api \
            --lib vm_lifecycle::network_faults \
            -- --test-threads=1
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
            | grep -Ev '\|gate:(live-node-lifecycle-fault|live-fault-hardware|patch-microtests)\|'
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

          hardware_result=${liveFaultHardware}/result
          grep -Fxq PASS "$hardware_result"
          grep -Fxq 'gate=gate:live-fault-hardware' "$hardware_result"
          grep -Fxq 'clock_effect_proof=authenticated-old-plus-offset-equals-new' "$hardware_result"
          grep -Fxq 'clock_occurrences=1' "$hardware_result"
          grep -Fxq 'accelerator_occurrences=1' "$hardware_result"
          grep -Fxq 'accelerator_mutation=tpu-result-42-to-43' "$hardware_result"
          grep -Fxq 'fresh_plugin_restore=true' "$hardware_result"

          shared_result=${sharedCause}/result
          grep -Fxq PASS "$shared_result"
          grep -Fxq 'gate=gate:signal-shared-cause' "$shared_result"
          grep -Fxq 'pre_event_queue_and_volatile_cache=true' "$shared_result"
          grep -Fxq 'network_storage_node_same_event=true' "$shared_result"
          grep -Fxq 'shared_event_effect_records=3' "$shared_result"
          grep -Fxq 'node_effective_icount_authenticated=true' "$shared_result"
          grep -Fxq 'exact_checkpoint_evidence_match=true' "$shared_result"
          grep -Fxq 'locked_effect_replay_evidence_match=true' "$shared_result"

          patch_result=${patchMicrotests}/result
          grep -Fxq PASS "$patch_result"
          grep -Fxq 'gate=gate:patch-microtests' "$patch_result"
          grep -Fxq 'every_carried_patch_has_microtest=true' "$patch_result"
          grep -Fxq 'every_microtest_has_stock_negative_control=true' "$patch_result"
          grep -Fxq 'diagnostic_only_patches_excluded_from_shipped_qemu=true' "$patch_result"

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
