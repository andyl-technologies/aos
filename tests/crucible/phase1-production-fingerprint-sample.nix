{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.singleVmFingerprint",
  taskIds ? [],
  openTaskIds ? [],
  dependencies ? [],
  campaignComposition ? null,
}: let
  productionFlight = import ./phase7-production-rust-plugin-flight.nix {
    inherit pkgs lib;
    attrPath = "checks.crucible.phase7.productionRustPluginFlight";
    inherit campaignComposition;
  };
  projectionManifest = import ./phase2-qemu-fingerprint-projection-manifest.nix {inherit pkgs lib;};
  campaignMode =
    if campaignComposition == null
    then null
    else campaignComposition.mode;
  campaignSystem =
    if campaignComposition == null
    then null
    else campaignComposition.system;
  campaignToplevel =
    if campaignSystem == null
    then null
    else campaignSystem.config.system.build.toplevel;
  campaignRuntimeIdentity =
    if campaignSystem == null
    then null
    else campaignSystem.config.aos.services.crucibleCampaign._runtimeIdentity;
  productionFlightResult =
    if campaignComposition == null
    then "${productionFlight}/result"
    else "${productionFlight}/raw-result";
in
  pkgs.mkDerivation {
    pname = "crucible-production-fingerprint-sample";
    version = "0";
    src = null;
    buildDeps = [pkgs.coreutils pkgs.grep productionFlight projectionManifest] ++ dependencies;

    phases = [
      {
        name = "verify-production-fingerprint-evidence";
        script = ''
          set -eu
          flight=${lib.escapeShellArg productionFlightResult}
          manifest="${projectionManifest}/result"

          for line in \
            PASS \
            rust_plugin_loaded=true \
            diskless_multiboot_runs=4 \
            fingerprint_flight_variants=reference,host-preempted,translation-prefetch,translation-prefetch-host-preempted \
            vcpu_count=4 \
            sample_count=4 \
            sample_target_icounts=2000000,2000001,4000000,8000000 \
            sample_stream_restart_identical=true \
            on_demand_boundary_stream_bit_identical=true \
            instruction_exact_window_lower_icount=2000000 \
            instruction_exact_window_upper_icount=2000001 \
            instruction_exact_window_width=1 \
            instruction_exact_rr_successor=true \
            instruction_exact_state_projection_changed=true \
            instruction_exact_fingerprint_changed=true \
            instruction_exact_localization=one-instruction-window \
            bounded_scheduler_preemption_applied=true \
            component_failures=0 \
            per_vcpu_register_files_present=true \
            aggregate_icount_equals_target=true
          do
            grep -Fxq "$line" "$flight"
          done
          grep -Fxq PASS "$manifest"
          grep -Fxq gate=gate:qemu-fingerprint-projection-manifest "$manifest"
          grep -Fxq schema_version=4 "$manifest"
          grep -Fxq integrated_fixed_configuration_runner=true "$manifest"

          mkdir -p "$out"
          cp "$flight" "$out/production-flight-result"
          cp "$manifest" "$out/projection-manifest-result"
          cat > "$out/result" <<'RESULT'
          PASS
          check=${attrPath}
          gate=gate:single-vm-fingerprint
          tasks=${builtins.concatStringsSep "," taskIds}
          open_tasks=${builtins.concatStringsSep "," openTaskIds}
          status=complete
          real_qemu_source=checks.crucible.phase7.productionRustPluginFlight
          projection_source=checks.crucible.phase2.qemuFingerprintProjectionManifest
          scenario=production-diskless-smp4
          host_adversary=bounded-scheduler-preemption
          samples=4
          sample_target_icounts=2000000,2000001,4000000,8000000
          execution_fingerprint=production-FingerprintSample-provider-projection
          sampling_axis=aggregate-node-icount
          observation_mode=loaded-rust-plugin
          restart_stream_identity=true
          mismatch_policy=first-mismatch-is-failure
          mismatch_localization=one-instruction-window
          instruction_exact_window=2000000,2000001
          instruction_exact_rr_cursor=authenticated-owner-and-position
          instruction_exact_state_projection=owning-vcpu-register-digest
          RESULT

          ${lib.optionalString (campaignComposition != null) ''
            cat >> "$out/result" <<RESULT
            authoritative_attr=${attrPath}
            execution_family=qemu-runtime
            campaign_mode=${campaignMode}
            campaign_configuration_identity=${campaignRuntimeIdentity}
            campaign_toplevel=${campaignToplevel}
            executor_derivation=$out
            RESULT
            cp "$out/result" "$out/raw-result"
            {
              printf '%s\n' CAMPAIGN_GATE_RESULT_BEGIN
              cat "$out/raw-result"
              printf '%s\n' CAMPAIGN_GATE_RESULT_END
              printf '%s\n' '--- production-flight-transcript ---'
              cat ${productionFlight}/transcript
              printf '%s\n' '--- projection-manifest-result ---'
              cat ${projectionManifest}/result
            } > "$out/transcript"
          ''}
        '';
      }
    ];
  }
