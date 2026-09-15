{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase9.gates.campaignOperationalContinuity",
  taskIds ? ["T-CAM-9.3"],
  campaignStoreComposition,
  campaignContinuityV2,
  campaignMidpointDebug,
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
in
  pkgs.mkDerivation {
    pname = "crucible-phase9-campaign-operational-continuity";
    version = "0";
    src = crucibleSrc;

    buildDeps =
      [
        pkgs.coreutils
        pkgs.findutils
        pkgs.grep
        pkgs.rust
        pkgs.sed
        campaignStoreComposition
        campaignContinuityV2
        campaignMidpointDebug
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

          require_result_line ${campaignStoreComposition}/result PASS
          require_result_line \
            ${campaignStoreComposition}/result \
            gate=gate:campaign-store-composition
          require_result_line \
            ${campaignStoreComposition}/result \
            independent_coordinator_executor_restart=true
          require_result_line \
            ${campaignStoreComposition}/result \
            global_gc=true
          require_result_line \
            ${campaignStoreComposition}/result \
            interrupted_gc_journal=true

          require_result_line ${campaignContinuityV2}/result PASS
          require_result_line \
            ${campaignContinuityV2}/result \
            check=checks.crucible.phase5.gates.campaignContinuityV2
          require_result_line \
            ${campaignContinuityV2}/result \
            pause_restart_restore_resume=true
          require_result_line \
            ${campaignContinuityV2}/result \
            exact_checkpoint_closure_authenticated=true

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
          test "$(grep -Ec '^authenticated_replay_causal_entries=[1-9][0-9]*$' ${campaignMidpointDebug}/result || true)" -eq 1
          test "$(grep -Ec '^minimization_original_replay=crucible\.campaign\.finding-triage-replay@finding-triage-replay\.[0-9]+\.[0-9a-f]{64}$' ${campaignMidpointDebug}/result || true)" -eq 1
          test "$(grep -Ec '^verification_original_replay=crucible\.campaign\.finding-triage-replay@finding-triage-replay\.[0-9]+\.[0-9a-f]{64}$' ${campaignMidpointDebug}/result || true)" -eq 1
          minimization_original=$(grep -E '^minimization_original_replay=' ${campaignMidpointDebug}/result | cut -d = -f 2-)
          verification_original=$(grep -E '^verification_original_replay=' ${campaignMidpointDebug}/result | cut -d = -f 2-)
          test "$minimization_original" != "$verification_original"

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
              -- --exact --test-threads=1 > "$output_file" 2>&1
            cat "$output_file"
            grep -Fq \
              'test result: ok. 1 passed; 0 failed; 0 ignored;' \
              "$output_file"
          }

          mkdir -p "$out/evidence"
          run_exact_process_test \
            public_composed_store_flight_evicts_cache_and_flushes_write_back \
            composed-store-maintenance
          run_exact_process_test \
            archive_transfer::public_offline_archive_transfer_reports_and_authenticates_sensitive_closure \
            directory-archive-transfer
          run_exact_process_test \
            archive_transfer::public_archive_transfer_is_backend_neutral_across_compressed_stores \
            compressed-archive-transfer

          cp ${campaignStoreComposition}/result \
            "$out/evidence/campaign-store-composition.result"
          cp ${campaignContinuityV2}/result \
            "$out/evidence/campaign-continuity-v2.result"
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
          test "$(wc -l < "$out/evidence.sha256" | tr -d ' ')" -eq 11
          evidence_digest=$(sha256sum "$out/evidence.sha256" | cut -d ' ' -f 1)

          cat > "$out/result" <<RESULT
          PASS
          check=${attrPath}
          gate=gate:campaign-operational-continuity
          tasks=${builtins.concatStringsSep "," taskIds}
          coordinator_executor_restart=true
          exact_pause=true
          backend_neutral_archival=true
          offline_maintenance_transfer=true
          fast_midpoint_debug=true
          public_composed_store_process=true
          public_archive_transfer_process=true
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
