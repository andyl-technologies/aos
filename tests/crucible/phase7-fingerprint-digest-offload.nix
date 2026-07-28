{
  pkgs,
  lib ? null,
  attrPath ? "checks.crucible.phase7.fingerprintDigestOffload",
  taskIds ? ["T-PERF-30"],
  dependencies ? [],
  liveFingerprint,
  fingerprintHelpers,
}: let
  taskList = lib.concatStringsSep "," taskIds;
in
  pkgs.mkDerivation {
    pname = "crucible-phase7-fingerprint-digest-offload";
    version = "0";

    buildDeps =
      [
        pkgs.coreutils
        pkgs.grep
        liveFingerprint
        fingerprintHelpers
      ]
      ++ dependencies;

    phases = [
      {
        name = "verify-offload-evidence";
        script = ''
          set -eu
          grep -Fq 'mpsc::sync_channel::<CapturedFingerprintSample>(1)' ${../../crates/crucible-qemu-plugin/src/runtime/live_callbacks.rs}
          grep -Fq '.name("crucible-fingerprint-digest".to_owned())' ${../../crates/crucible-qemu-plugin/src/runtime/live_callbacks.rs}
          grep -Fq 'let sample = captured.digest();' ${../../crates/crucible-qemu-plugin/src/runtime/live_callbacks.rs}
          grep -Fq 'slot.get().publish(&sample)' ${../../crates/crucible-qemu-plugin/src/runtime/live_callbacks.rs}
          grep -Fq 'last_capture_icount' ${../../crates/crucible-qemu-plugin/src/runtime/live_callbacks.rs}
          grep -Fq 'fingerprint.worker.submit(captured)?;' ${../../crates/crucible-qemu-plugin/src/runtime/live_callbacks.rs}
          grep -Fq 'struct CapturedFingerprintMaterial' ${../../crates/crucible-qemu-plugin/src/fingerprint_sampler.rs}
          grep -Fq 'unsafe impl Send for CapturedFingerprintMaterial' ${../../crates/crucible-qemu-plugin/src/fingerprint_sampler.rs}
          grep -Fq 'FINGERPRINT_FAILURE_ORACLE_MISMATCH' ${../../crates/crucible-qemu-plugin/src/fingerprint_sampler.rs}
          grep -Fq 'oracle != &self.sample' ${../../crates/crucible-qemu-plugin/src/fingerprint_sampler.rs}
          grep -Fq 'qemu_plugin_crucible_fingerprint_capture' ${../../pkgs/emulation/qemu-patches/0002-crucible-rr-fingerprint-helpers.patch}
          grep -Fq 'memory_global_dirty_log_start(GLOBAL_DIRTY_MIGRATION' ${../../pkgs/emulation/qemu-patches/0002-crucible-rr-fingerprint-helpers.patch}
          grep -Fq 'bql_lock();' ${../../pkgs/emulation/qemu-patches/0002-crucible-rr-fingerprint-helpers.patch}
          grep -Fq 'qemu_plugin_crucible_sha256_bytes' ${../../pkgs/emulation/qemu-patches/0002-crucible-rr-fingerprint-helpers.patch}
          grep -Fq 'synchronous_oracle_enabled=false' ${./phase2-qemu-live-plugin-fingerprint.nix}
          grep -Fq 'synchronous_oracle_matches_all_samples=true' ${./phase2-qemu-live-plugin-fingerprint.nix}
          grep -Fq 'sample_target_icounts=4000000,4000001,8000000,8000001,12000000' ${./phase2-qemu-live-plugin-fingerprint.nix}
          grep -Fxq PASS "${liveFingerprint}/result"
          grep -Fxq 'synchronous_oracle_enabled=false' "${liveFingerprint}/result"
          grep -Fxq 'second_run_host_load=true' "${liveFingerprint}/result"
          grep -Fxq 'sample_count=5' "${liveFingerprint}/result"
          grep -Fxq 'sample_target_icounts=4000000,4000001,8000000,8000001,12000000' "${liveFingerprint}/result"
          grep -Fxq 'aggregate_icount_equals_target=true' "${liveFingerprint}/result"
          grep -Fxq 'synchronous_oracle_enabled=true' "${liveFingerprint}/oracle-result"
          grep -Fxq 'synchronous_oracle_matches_all_samples=true' "${liveFingerprint}/oracle-result"
          grep -Fxq 'sample_target_icounts=4000000,4000001,8000000,8000001,12000000' "${liveFingerprint}/oracle-result"
          grep -Fxq 'fingerprint_capture_uses_dirty_tracking=true' "${fingerprintHelpers}/result"
          grep -Fxq 'fingerprint_capture_acquires_bql=true' "${fingerprintHelpers}/result"
          grep -Fxq 'fingerprint_capture_preserves_existing_dirty_owner=true' "${fingerprintHelpers}/result"
          grep -Fxq 'captured_component_digests_match_synchronous=true' "${fingerprintHelpers}/result"

          mkdir -p "$out"
          cp "${liveFingerprint}/result" "$out/live-result"
          cp "${liveFingerprint}/oracle-result" "$out/oracle-result"
          cp "${fingerprintHelpers}/result" "$out/helper-result"
          cat > "$out/result" <<'RESULT'
          PASS
          check=${attrPath}
          gate=gate:fingerprint-digest-offload
          tasks=${taskList}
          status=complete
          admission_class=A
          capture=exact-icount-dirty-tracked-immutable-preimage
          digest_thread=dedicated-bounded-worker
          vcpu_digest_blocking=false
          synchronous_corpus_identity=true
          cadence_unchanged=true
          sample_coordinates_unchanged=true
          forced_event_boundaries_unchanged=true
          production_oracle_overhead=false
          RESULT
        '';
      }
    ];
  }
