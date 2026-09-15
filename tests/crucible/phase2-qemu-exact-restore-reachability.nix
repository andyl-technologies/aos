# Proves that production exact restore has one atomic construction and launch route.
{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuExactRestoreReachability",
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
in
  pkgs.mkDerivation {
    pname = "crucible-phase2-qemu-exact-restore-reachability";
    version = "0";
    src = crucibleSrc;
    buildDeps =
      [
        pkgs.coreutils
        pkgs.grep
      ]
      ++ dependencies;
    ATTR_PATH = attrPath;
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
        name = "check-exact-restore-reachability";
        script = ''
          set -eu
          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then cd source; fi

          fail() {
            echo "exact-restore reachability check failed: $*" >&2
            exit 1
          }

          count_crate_occurrences() {
            needle="$1"
            count="$(${pkgs.grep}/bin/grep -RhoF --include='*.rs' -- "$needle" crates 2>/dev/null \
              | ${pkgs.coreutils}/bin/wc -l)"
            printf '%s' "$count" | ${pkgs.coreutils}/bin/tr -d '[:space:]'
          }

          count_file_occurrences() {
            file="$1"
            needle="$2"
            count="$(${pkgs.grep}/bin/grep -Fo -- "$needle" "$file" 2>/dev/null \
              | ${pkgs.coreutils}/bin/wc -l)"
            printf '%s' "$count" | ${pkgs.coreutils}/bin/tr -d '[:space:]'
          }

          count_daemon_production_occurrences() {
            needle="$1"
            count="$(${pkgs.grep}/bin/grep -RhoF --include='*.rs' \
              --exclude='tests.rs' --exclude-dir=tests --exclude-dir=examples \
              -- "$needle" crates/crucible-daemon/src 2>/dev/null \
              | ${pkgs.coreutils}/bin/wc -l)"
            printf '%s' "$count" | ${pkgs.coreutils}/bin/tr -d '[:space:]'
          }

          require_count() {
            expected="$1"
            needle="$2"
            actual="$(count_crate_occurrences "$needle")"
            [ "$actual" = "$expected" ] \
              || fail "expected $expected occurrence(s) of '$needle', found $actual"
          }

          require_file_count() {
            expected="$1"
            file="$2"
            needle="$3"
            actual="$(count_file_occurrences "$file" "$needle")"
            [ "$actual" = "$expected" ] \
              || fail "expected $expected occurrence(s) of '$needle' in $file, found $actual"
          }

          # The API is the sole authority that can construct the complete request.
          require_count 1 'QemuProductionExactRestoreRequest::new('
          require_file_count 1 \
            crates/crucible-api/src/vm_lifecycle.rs \
            'QemuProductionExactRestoreRequest::new('
          require_file_count 1 \
            crates/crucible-api/src/vm_lifecycle.rs \
            'pub fn into_atomic_restore('
          exact_resume_builder='build_production_vm_exact_resume_lifecycle('
          require_count 1 "$exact_resume_builder"
          require_file_count 1 \
            crates/crucible-api/src/vm_lifecycle.rs \
            'pub fn build_production_vm_exact_resume_lifecycle<'
          require_file_count 1 \
            crates/crucible-daemon/src/qemu_campaign_lifecycle.rs \
            "$exact_resume_builder"

          # The daemon has one consuming route from launch_restored to atomic launch.
          require_count 1 '.into_atomic_restore(request, run_directory, process_contract)'
          require_count 1 'atomic.launch()'
          require_file_count 1 \
            crates/crucible-daemon/src/qemu_lifecycle_launcher.rs \
            'fn launch_exact_generation('
          require_file_count 1 \
            crates/crucible-daemon/src/qemu_lifecycle_launcher.rs \
            'fn launch_restored('
          daemon_restored_impls="$(count_daemon_production_occurrences 'fn launch_restored(')"
          [ "$daemon_restored_impls" = 1 ] \
            || fail "expected one production daemon launch_restored implementation, found $daemon_restored_impls"
          # Across the workspace, the remaining definitions are one API trait
          # declaration and six implementations in closed test-only regions.
          require_count 8 'fn launch_restored('
          require_file_count 2 \
            crates/crucible-api/src/vm_lifecycle.rs \
            'fn launch_restored('
          require_file_count 1 \
            crates/crucible-api/src/vm_lifecycle/helpers.rs \
            'fn launch_restored('
          require_file_count 4 \
            crates/crucible-api/src/vm_lifecycle/runtime/tests.rs \
            'fn launch_restored('
          require_file_count 1 \
            crates/crucible-api/src/vm_lifecycle.rs \
            'impl ProductionVmNodeLauncher for PackagedProductionVmNodeLauncher'
          require_file_count 1 \
            crates/crucible-api/src/vm_lifecycle/helpers.rs \
            'mod tests {'

          # Exact restore cannot manufacture missing continuation state at
          # launch time. The plan carries both continuations directly, and its
          # sole constructor receives the complete captured snapshot.
          restore_plan=crates/crucible-qemu/src/node_factory/restore_plan.rs
          require_file_count 1 \
            "$restore_plan" \
            "pub(super) host_io_checkpoint: &'a QemuHostIoCheckpoint,"
          require_file_count 1 \
            "$restore_plan" \
            "pub(super) node_continuation: &'a QemuNodeContinuationCheckpoint,"
          require_file_count 1 \
            "$restore_plan" \
            'pub(crate) fn exact_checkpoint('
          for retired in \
            "host_io_checkpoint: Option<&'a QemuHostIoCheckpoint>" \
            "node_continuation: Option<&'a QemuNodeContinuationCheckpoint>" \
            with_exact_checkpoint \
            no_block_checkpoint \
            'map_or(checkpoint.virtual_time'
          do
            require_count 0 "$retired"
          done
          require_file_count 0 \
            "$restore_plan" \
            'QemuHostIoCheckpoint::without_devices('
          require_file_count 0 \
            crates/crucible-qemu/src/node_factory.rs \
            'QemuHostIoCheckpoint::without_devices('

          # The selected exact root is minted only after the supervisor's
          # durable admission joins. Resource guards can carry or consume this
          # linear token, but they cannot construct one.
          supervisor=crates/crucible-daemon/src/executor_supervisor.rs
          admission=crates/crucible-daemon/src/executor_supervisor/admission.rs
          state=crates/crucible-daemon/src/executor_supervisor/state.rs
          checkpoint_promotion=crates/crucible-daemon/src/executor_supervisor/checkpoint_promotion.rs
          selected_mint='SelectedExactCheckpointRoot::after_durable_admission('
          require_file_count 1 "$supervisor" 'fn after_durable_admission('
          require_file_count 1 "$supervisor" 'fn after_durable_checkpoint('
          require_file_count 1 "$supervisor" 'map(Self::after_durable_checkpoint)'
          require_file_count 0 \
            crates/crucible-daemon/src/qemu_resource_guard.rs \
            "$selected_mint"
          require_count 0 'SelectedExactCheckpointRoot { checkpoint'
          admitted_mints="$(count_file_occurrences "$admission" "$selected_mint")"
          state_mints="$(count_file_occurrences "$state" "$selected_mint")"
          allowed_mints="$((admitted_mints + state_mints))"
          [ "$allowed_mints" -gt 0 ] \
            || fail "supervisor durable-admission modules do not mint a selected exact root"
          all_mints="$(count_crate_occurrences "$selected_mint")"
          [ "$all_mints" = "$allowed_mints" ] \
            || fail "selected exact root has $all_mints mint call(s), but only $allowed_mints are in supervisor admission/state"
          require_file_count 2 \
            "$checkpoint_promotion" \
            'SelectedExactCheckpointRoot::after_durable_checkpoint('
          require_count 2 'SelectedExactCheckpointRoot::after_durable_checkpoint('

          # Raw replay objects and their stream cursors cannot escape the repository.
          for retired in \
            ProductionExactCheckpointReplayCatalog \
            ProductionExactCheckpointReplayTargets \
            ProductionExactCheckpointReplayTarget \
            ProductionExactCheckpointReplayRam \
            ProductionExactCheckpointReplayRamLayer \
            ProductionExactCheckpointReplayArtifact \
            'pub fn open_target_with_boundary(' \
            'pub fn open_target(' \
            'pub fn stream_into_with_boundary(' \
            'pub fn stream_into('
          do
            require_count 0 "$retired"
          done

          # No decomposed materialization or launch capability may coexist with
          # the one-shot request.
          for retired in \
            ProductionVmNodeCheckpointArtifact \
            ProductionVmNodeExactRamLayer \
            ProductionVmNodeExactRamCheckpoint \
            ProductionVmNodeExactRestore \
            build_production_vm_lifecycle_loop_from_exact_closure_with_launcher \
            build_production_vm_lifecycle_loop_from_authenticated_checkpoint_with_launcher \
            QemuExactDeviceStateMaterialization \
            QemuRootOverlayMaterialization \
            QemuGuardedExactRamInputs \
            admit_production_exact_checkpoint_materialization \
            begin_exact_root_overlay_materialization \
            begin_exact_device_state_materialization \
            begin_exact_ram_input_materialization \
            finish_exact_checkpoint_materialization \
            QemuProductionExactRestoreAdmission \
            'launch_qemu_production_exact_checkpoint_paused(' \
            'launch_qemu_production_exact_checkpoint('
          do
            require_count 0 "$retired"
          done

          # Compatibility aliases would recreate a second named authority even
          # if they delegated to the atomic implementation.
          for retired in \
            'type QemuProductionExactRestoreRequest' \
            'as QemuProductionExactRestoreRequest' \
            LegacyProductionExactRestore \
            CompatProductionExactRestore
          do
            require_count 0 "$retired"
          done

          # ResumeSession has one authenticated restore route. Retired thin
          # replay and fat-checkpoint callback factories cannot recreate an
          # ordinary loop-factory fallback around the atomic restore request.
          for retired in \
            with_thin_replay_resume \
            with_fat_checkpoint_resume_factory \
            ThinReplayResume \
            FatCheckpointResume \
            LifecycleResumeLoopFactory \
            resume_session_via_thin_replay \
            resume_via_thin_replay \
            resume_loop_factory \
            'self.loop_factory)(&scenario, Some(&request.scenario)'
          do
            require_count 0 "$retired"
          done

          mkdir -p "$out"
          {
            printf 'PASS\n'
            printf 'attr_path=%s\n' "$ATTR_PATH"
            printf 'request_constructors=1\n'
            printf 'exact_resume_builder_calls=1\n'
            printf 'daemon_atomic_consumers=1\n'
            printf 'launch_restored_definitions=8\n'
            printf 'launch_restored_production_implementations=1\n'
            printf 'launch_restored_trait_declarations=1\n'
            printf 'launch_restored_test_implementations=6\n'
            printf 'exact_restore_required_continuations=host-io,node\n'
            printf 'exact_restore_checkpoint_fallbacks=0\n'
            printf 'selected_root_mints=%s\n' "$allowed_mints"
            printf 'selected_root_mint_scope=executor-supervisor-durable-admission\n'
            printf 'selected_root_checkpoint_promotion_mints=2\n'
            printf 'public_raw_replay_surfaces=0\n'
            printf 'decomposed_restore_surfaces=0\n'
            printf 'compatibility_aliases=0\n'
            printf 'retired_resume_factories=0\n'
          } > "$out/result"
        '';
      }
    ];
  }
