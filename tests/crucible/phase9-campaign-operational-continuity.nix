{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase9.gates.campaignOperationalContinuity",
  taskIds ? ["T-CAM-9.3"],
  campaignStoreEquivalence,
  campaignStoreComposition,
  campaignColdContinuity,
  campaignExactMaintenanceTransfer,
  campaignStorageRecovery,
  campaignMidpointDebug,
  campaignServiceModuleContract,
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
in
  pkgs.mkDerivation {
    pname = "crucible-phase9-campaign-operational-continuity";
    version = "0";
    LIBSQLITE3_SYS_USE_PKG_CONFIG = "1";
    runtimeDeps = [pkgs.sqlite];
    src = crucibleSrc;

    buildDeps =
      [
        pkgs.coreutils
        pkgs.findutils
        pkgs.grep
        pkgs.rust
        pkgs.sed
        campaignStoreEquivalence
        campaignStoreComposition
        campaignColdContinuity
        campaignExactMaintenanceTransfer
        campaignStorageRecovery
        campaignMidpointDebug
        campaignServiceModuleContract

        pkgs.pkg-config
        pkgs.sqlite
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
        name = "run-operational-continuity";
        script = ''
          set -eu
          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi

          require_result_line() {
            result="$1"
            line="$2"
            test "$(grep -Fxc "$line" "$result" || true)" -eq 1
          }

          require_result_line ${campaignServiceModuleContract}/result PASS
          require_result_line \
            ${campaignServiceModuleContract}/result \
            check=checks.crucible.phase9.gates.campaignServiceModuleContract
          require_result_line \
            ${campaignServiceModuleContract}/result \
            loopback_only=true
          require_result_line \
            ${campaignServiceModuleContract}/result \
            socket_path_service_owned=true
          require_result_line \
            ${campaignServiceModuleContract}/result \
            state_directory_service_owned=true

          require_result_line ${campaignStoreEquivalence}/result PASS
          require_result_line \
            ${campaignStoreEquivalence}/result \
            check=checks.crucible.phase5.gates.campaignStoreEquivalence
          require_result_line \
            ${campaignStoreEquivalence}/result \
            s3_live_worked_network_outage_credential_recovery=true
          require_result_line \
            ${campaignStoreEquivalence}/result \
            packed_worked_network_archive_repack_outage_corruption_gc=true
          require_result_line \
            ${campaignStoreEquivalence}/result \
            packed_worked_network_imported_campaign_retained=true
          require_result_line \
            ${campaignStoreEquivalence}/result \
            composed_s3_packed_pause_outage_repack_archive_gc=true
          composed_evidence=${campaignStoreEquivalence}/evidence/live-s3-composed.log
          s3_evidence=${campaignStoreEquivalence}/evidence/live-s3-product.log
          packed_evidence=${campaignStoreEquivalence}/evidence/packed-worked-network.log
          test -f "$s3_evidence"
          test -f "$composed_evidence"
          test -f "$packed_evidence"
          s3_sha256=$(sha256sum "$s3_evidence" | cut -d ' ' -f 1)
          composed_sha256=$(sha256sum "$composed_evidence" | cut -d ' ' -f 1)
          packed_sha256=$(sha256sum "$packed_evidence" | cut -d ' ' -f 1)
          require_result_line \
            ${campaignStoreEquivalence}/result \
            "s3_live_product_evidence_sha256=$s3_sha256"
          require_result_line \
            ${campaignStoreEquivalence}/result \
            "packed_worked_network_evidence_sha256=$packed_sha256"
          require_result_line \
            ${campaignStoreEquivalence}/result \
            "composed_s3_packed_evidence_sha256=$composed_sha256"

          require_result_line ${campaignStoreComposition}/result PASS
          require_result_line \
            ${campaignStoreComposition}/result \
            gate=gate:campaign-store-composition
          require_result_line \
            ${campaignStoreComposition}/result \
            independent_coordinator_executor_restart=true
          require_result_line \
            ${campaignStoreComposition}/result \
            tiers=true
          require_result_line \
            ${campaignStoreComposition}/result \
            tier_promotion_cache_eviction=true
          require_result_line \
            ${campaignStoreComposition}/result \
            write_back=true
          require_result_line \
            ${campaignStoreComposition}/result \
            global_gc=true
          require_result_line \
            ${campaignStoreComposition}/result \
            interrupted_gc_journal=true
          require_result_line \
            ${campaignStoreComposition}/result \
            active_publication_transfer_write_back_gc=true
          require_result_line \
            ${campaignStoreComposition}/result \
            s3_faults_preserve_multiple_refs_and_transfer_gc=true
          require_result_line \
            ${campaignStoreComposition}/result \
            paused_derived_s3_write_back_fault_recovery_gc=true
          require_result_line \
            ${campaignStoreComposition}/result \
            packed_restart_and_repack=true

          require_result_line ${campaignColdContinuity}/result PASS
          require_result_line \
            ${campaignColdContinuity}/result \
            check=checks.crucible.phase5.gates.campaignColdContinuity
          require_result_line \
            ${campaignColdContinuity}/result \
            pause_restart_restore_resume=true
          require_result_line \
            ${campaignColdContinuity}/result \
            exact_checkpoint_closure_authenticated=true

          require_result_line ${campaignExactMaintenanceTransfer}/result PASS
          require_result_line \
            ${campaignExactMaintenanceTransfer}/result \
            gate=gate:campaign-exact-maintenance-transfer
          for transfer_claim in \
            source_active_world_exact_pause_restart=true \
            recipient_executable_archive_authenticated=true \
            recipient_exact_pin_import_authenticated=true \
            recipient_campaign_resume=true \
            incompatible_provenance_rejected_before_guest=true
          do
            require_result_line ${campaignExactMaintenanceTransfer}/result "$transfer_claim"
          done
          transfer_evidence=${campaignExactMaintenanceTransfer}/evidence/exact-maintenance-transfer-vm.output
          test -f "$transfer_evidence"
          sha256sum -c ${campaignExactMaintenanceTransfer}/evidence.sha256

          require_result_line ${campaignStorageRecovery}/result PASS
          require_result_line ${campaignStorageRecovery}/result gate=gate:campaign-storage-recovery
          require_result_line ${campaignStorageRecovery}/result tier=real-packaged-qemu-and-garage
          for recovery_claim in \
            storage_recovery_real_exact_pause=true \
            storage_recovery_outage_refused_before_guest=true \
            storage_recovery_expired_credentials_refused_before_guest=true \
            storage_recovery_exact_origin_preserved=true \
            storage_recovery_scheduler_observed_guest_progress=true \
            storage_recovery_selected_outcome_preserved=true \
            storage_recovery_derived_refs_preserved=2 \
            storage_recovery_final_guest_cleanup=true
          do
            require_result_line ${campaignStorageRecovery}/result "$recovery_claim"
          done
          recovery_evidence=${campaignStorageRecovery}/evidence/storage-recovery-vm.output
          test -f "$recovery_evidence"
          sha256sum -c ${campaignStorageRecovery}/evidence.sha256

          require_result_line ${campaignMidpointDebug}/result PASS
          require_result_line \
            ${campaignMidpointDebug}/result \
            gate=gate:campaign-midpoint-debug
          require_result_line \
            ${campaignMidpointDebug}/result \
            public_finding_midpoint_debug=true
          require_result_line \
            ${campaignMidpointDebug}/result \
            authenticated_exact_checkpoint=true
          require_result_line \
            ${campaignMidpointDebug}/result \
            authenticated_replay_violation_boundary=true
          require_result_line \
            ${campaignMidpointDebug}/result \
            authenticated_replay_selection_sequence=fast,q7
          require_result_line \
            ${campaignMidpointDebug}/result \
            authenticated_replay_marker=selected-fast-q7
          require_result_line \
            ${campaignMidpointDebug}/result \
            retry_session_identity_stable=true
          require_result_line \
            ${campaignMidpointDebug}/result \
            finding_bundle_canonical_branch_executed=true
          require_result_line \
            ${campaignMidpointDebug}/result \
            finding_bundle_source_owner_absent=true
          require_result_line \
            ${campaignMidpointDebug}/result \
            finding_bundle_original_archive_unchanged=true
          test "$(grep -Ec '^authenticated_replay_causal_entries=[1-9][0-9]*$' ${campaignMidpointDebug}/result || true)" -eq 1
          test "$(grep -Ec '^minimization_original_replay=crucible\.campaign\.finding-triage-replay@finding-triage-replay\.[0-9]+\.[0-9a-f]{64}$' ${campaignMidpointDebug}/result || true)" -eq 1
          test "$(grep -Ec '^verification_original_replay=crucible\.campaign\.finding-triage-replay@finding-triage-replay\.[0-9]+\.[0-9a-f]{64}$' ${campaignMidpointDebug}/result || true)" -eq 1

          midpoint_manifest=${campaignMidpointDebug}/evidence.sha256
          test -f "$midpoint_manifest"
          test "$(wc -l < "$midpoint_manifest" | tr -d ' ')" -eq 1
          midpoint_manifest_digest=$(sha256sum "$midpoint_manifest" | cut -d ' ' -f 1)
          require_result_line \
            ${campaignMidpointDebug}/result \
            "evidence_manifest_sha256=$midpoint_manifest_digest"
          sha256sum -c "$midpoint_manifest"

          target="$TMPDIR/crucible-campaign-operational-continuity-target"
          run_exact_process_test() {
            selector="$1"
            evidence_name="$2"
            listing_file="$out/evidence/$evidence_name.listing"
            output_file="$out/evidence/$evidence_name.output"
            cargo test \
              --frozen \
              --offline \
              --target-dir "$target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-cli \
              --test campaign_store_process \
              "$selector" \
              -- --exact --list > "$listing_file"
            grep -Fqx "$selector: test" "$listing_file"

            cargo test \
              --frozen \
              --offline \
              --target-dir "$target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-cli \
              --test campaign_store_process \
              "$selector" \
              -- --exact --test-threads=1 --nocapture > "$output_file" 2>&1
            cat "$output_file"
            grep -Fq \
              'test result: ok. 1 passed; 0 failed; 0 ignored;' \
              "$output_file"
          }

          mkdir -p "$out/evidence"
          run_exact_process_test \
            public_checkpoint_pause_survives_stopped_service_gc_and_cold_resume \
            checkpoint-pause-cold-resume
          run_exact_process_test \
            public_composed_store_flight_evicts_cache_and_flushes_write_back \
            composed-store-maintenance
          grep -Fq \
            'composed_store_derived_refs_after_gc_restart=2' \
            "$out/evidence/composed-store-maintenance.output"
          run_exact_process_test \
            archive_transfer::public_offline_archive_transfer_reports_and_authenticates_sensitive_closure \
            directory-archive-transfer
          grep -Fq \
            'archive_transfer_derived_refs_retained=2' \
            "$out/evidence/directory-archive-transfer.output"
          grep -Fq \
            'archive_transfer_imported_campaign_authenticated=true' \
            "$out/evidence/directory-archive-transfer.output"
          run_exact_process_test \
            archive_transfer::public_archive_transfer_is_backend_neutral_across_compressed_stores \
            compressed-archive-transfer
          grep -Fq \
            'archive_transfer_derived_refs_retained=2' \
            "$out/evidence/compressed-archive-transfer.output"
          grep -Fq \
            'archive_transfer_imported_campaign_authenticated=true' \
            "$out/evidence/compressed-archive-transfer.output"

          cp ${campaignStoreEquivalence}/result \
            "$out/evidence/campaign-store-equivalence.result"
          cp ${campaignStoreEquivalence}/evidence/live-s3-product.log \
            "$out/evidence/live-s3-product.log"
          cp "$composed_evidence" "$out/evidence/live-s3-composed.log"
          cp ${campaignStoreEquivalence}/evidence/packed-worked-network.log \
            "$out/evidence/packed-worked-network.log"
          cp ${campaignStoreComposition}/result \
            "$out/evidence/campaign-store-composition.result"
          cp ${campaignColdContinuity}/result \
            "$out/evidence/campaign-cold-continuity.result"
          cp ${campaignExactMaintenanceTransfer}/result \
            "$out/evidence/campaign-exact-maintenance-transfer.result"
          cp "$transfer_evidence" \
            "$out/evidence/exact-maintenance-transfer-vm.output"
          cp ${campaignStorageRecovery}/result "$out/evidence/campaign-storage-recovery.result"
          cp "$recovery_evidence" "$out/evidence/storage-recovery-vm.output"
          mkdir -p "$out/evidence/campaign-midpoint-debug"
          cp ${campaignMidpointDebug}/result \
            "$out/evidence/campaign-midpoint-debug/result"
          cp ${campaignMidpointDebug}/evidence.sha256 \
            "$out/evidence/campaign-midpoint-debug/evidence.sha256"
          cp ${campaignMidpointDebug}/evidence/public-campaign-midpoint-debug.output \
            "$out/evidence/campaign-midpoint-debug/public-campaign-midpoint-debug.output"
          ${pkgs.findutils}/bin/find "$out/evidence" -type f -print \
            | sort \
            | while IFS= read -r evidence_file; do
              evidence_name=''${evidence_file#"$out/evidence/"}
              evidence_sha256=$(sha256sum "$evidence_file" | cut -d ' ' -f 1)
              printf '%s  %s\n' "$evidence_sha256" "$evidence_name"
            done > "$out/evidence.sha256"
          test "$(wc -l < "$out/evidence.sha256" | tr -d ' ')" -eq 21
          evidence_digest=$(sha256sum "$out/evidence.sha256" | cut -d ' ' -f 1)

          cat > "$out/result" <<RESULT
          PASS
          check=${attrPath}
          gate=gate:campaign-operational-continuity
          tasks=${builtins.concatStringsSep "," taskIds}
          coordinator_executor_restart=true
          exact_pause=true
          real_paused_qemu_s3_outage_credential_recovery=true
          real_recovered_guest_progress_and_exact_origin=true
          public_checkpoint_pause_restart_resume=true
          backend_neutral_archival=true
          offline_maintenance_transfer=true
          fast_midpoint_debug=true
          public_composed_store_process=true
          composed_store_derived_refs_after_gc_restart=2
          public_archive_transfer_process=true
          public_archive_import_process=true
          archive_transfer_derived_refs_retained=2
          exact_maintenance_transfer_and_import=true
          incompatible_provenance_rejected_before_guest=true
          s3_live_worked_network_outage_credential_recovery=true
          composed_s3_packed_pause_outage_repack_archive_gc=true
          packed_worked_network_archive_repack_outage_corruption_gc=true
          packed_worked_network_imported_campaign_retained=true
          tier_promotion_cache_eviction=true
          active_publication_transfer_write_back_gc=true
          s3_faults_preserve_multiple_refs_and_transfer_gc=true
          paused_derived_s3_write_back_fault_recovery_gc=true
          representative_storage_fault_matrix=true
          public_finding_midpoint_debug=true
          authenticated_replay_violation_boundary=true
          authenticated_replay_selection_sequence=fast,q7
          authenticated_replay_marker=selected-fast-q7
          authenticated_original_replay_pair=true
          midpoint_evidence_retained=true
          evidence_retained=true
          evidence_manifest_sha256=$evidence_digest
          RESULT
        '';
      }
    ];
  }
