{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.gates.signalFaultSystem",
  taskIds ? [],
  liveNetwork,
  liveBlock,
  liveNineP,
  liveNodeLifecycle,
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

          cargo test \
            --frozen \
            --offline \
            --target-dir "$target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-qemu \
            --test production_fault_checkpoint \
            -- --test-threads=1

          cargo test \
            --frozen \
            --offline \
            --target-dir "$target" \
            --manifest-path crates/Cargo.toml \
            -p crucible \
            --lib signal_fault_frontier_preserves_parent_time_and_typed_candidates \
            -- --test-threads=1

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

          # These names belonged to the replaced execution hierarchy. Keep the
          # check source-only so prose migration guidance does not trip it.
          if grep -R -n -E \
            '\b(FaultPlanEntry|FiniteFault|PermanentFault)\b|pub (enum|struct) Fault[[:space:]]*\{' \
            crates/crucible/src crates/crucible-api/src crates/crucible-qemu/src
          then
            echo 'FAIL: retired fault execution API is present' >&2
            exit 1
          fi
          if grep -R -n -E 'inject_fault|heal_fault|InjectFault|HealFault|FaultPlan|PermanentAt|crucible\.scenario-family\.v1' \
            docs/rfcs/0010-crucible docs/users/crucible \
            | grep -v 'there is no `InjectFault`, `HealFault`, `FaultSpec`' \
            | grep -v 'checks.crucible.phase4.faultPlan'
          then
            echo 'FAIL: retired normative fault or scenario-family vocabulary is present' >&2
            exit 1
          fi
          if grep -R -n -E 'todo!\(|unimplemented!\(' \
            crates/crucible/src/model/fault_signal \
            crates/crucible-api/src/vm_lifecycle/network_faults \
            crates/crucible-api/src/vm_lifecycle/storage_faults \
            crates/crucible-qemu/src/fault_action_sink \
            crates/crucible-qemu/src/production_fault_runtime.rs
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
          grep -Fxq 'deterministic_under_host_load=true' "$network_result"
          grep -Fxq PASS "$network_world_result"
          grep -Fxq 'backend=production-qemu-lifecycle' "$network_world_result"
          grep -Fxq 'search_branch=loss-fire' "$network_world_result"
          grep -Fxq 'branch_decisions_match=true' "$network_world_result"
          grep -Fxq 'exact_restore_next_quantum_match=true' "$network_world_result"

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
          grep -Fxq 'deterministic_under_host_load=true' "$ninep_result"

          node_result=${liveNodeLifecycle}/result
          grep -Fxq PASS "$node_result"
          grep -Fxq 'backend=production-qemu-signal-runtime' "$node_result"
          grep -Fxq 'exact_manifest_replay_admitted=true' "$node_result"
          grep -Fxq 'changed_state_precondition_rejected=true' "$node_result"
          grep -Fxq 'corrupt_result_rejected_with_valid_event=true' "$node_result"
          grep -Fxq 'corrupt_event_rejected_with_valid_result=true' "$node_result"
          grep -Fxq 'lifecycle_impulse_committed=true' "$node_result"
          grep -Fxq 'cross_adapter_rejection_rolled_back=true' "$node_result"

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
          cp ${patchMicrotests}/result "$out/evidence/patch-microtests.result"
          cp ${checkpointMaterialization}/result "$out/evidence/checkpoint.result"
          cp ${replayOracle}/result "$out/evidence/replay.result"
          cp ${stateSpaceSearch}/result "$out/evidence/search.result"
          cp ${cliSearchFuzz}/result "$out/evidence/cli-search-fuzz.result"

          cat > "$out/result" <<RESULT
          CHECKPOINT
          check=${attrPath}
          gate=gate:signal-fault-system
          tasks=${taskList}
          status=implementation-in-progress
          effect_registry=closed-and-exhaustive
          executable_effect_count=71
          production_adapters=network,storage,node
          specification_only_domains=sensor,power
          retired_execution_paths=absent
          unfinished_production_paths=absent
          per_kind_metadata=admission,capability,replay-evidence,user-reference
          missing_acceptance=per-kind-production-execution-matrix,cross-domain-shared-cause-scenario
          system_evidence=adapter-dispatch,event-log,checkpoint,recomputed-replay,locked-replay,search,negative-tests
          live_boundary_evidence=network,block,9p,node-lifecycle,qemu-fault-patches
          production_checkpoint=authenticated-round-trip
          final_acceptance_dependencies=e2e-determinism,campaign-continuity
          RESULT
        '';
      }
    ];
  }
