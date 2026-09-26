{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.gates.layer0Determinism",
  taskIds ? ["T-DET-10"],
  openTaskIds ? [],
  dependencies ? [],
  campaignComposition ? null,
}: let
  productionFingerprint = import ./phase1-production-fingerprint-sample.nix {
    inherit pkgs lib campaignComposition;
    attrPath = "checks.crucible.phase2.gates.singleVmFingerprint";
  };
in
  import ./phase9-campaign-mode-production-evidence.nix {
    inherit pkgs lib campaignComposition attrPath taskIds openTaskIds dependencies;
    authority = productionFingerprint;
    gate = "gate:layer0-determinism";
    executionFamily = "qemu-runtime";
    name = "production-layer0-determinism";
    requiredEvidence = [
      "gate=gate:single-vm-fingerprint"
      "real_qemu_source=checks.crucible.phase7.productionRustPluginFlight"
      "scenario=production-diskless-smp4"
      "host_adversary=bounded-scheduler-preemption"
      "samples=5"
      "sample_target_picoseconds=2000000,2000001,2000051,4000000,8000000"
      "restart_stream_identity=true"
      "mismatch_policy=first-mismatch-is-failure"
      "mismatch_localization=one-instruction-window"
      "instruction_exact_window_picoseconds=2000001,2000051"
      "fractional_phase_window_picoseconds=2000000,2000001"
      "fractional_phase_no_retirement=true"
      "instruction_exact_raw_retirement_successor=true"
    ];
    semanticEvidence = [
      "backend=guarded-production-qemu"
      "real_qemu_required=true"
      "determinism_witness=production-diskless-smp4-fingerprint-stream"
      "samples=5"
      "sample_target_picoseconds=2000000,2000001,2000051,4000000,8000000"
      "restart_stream_identity=true"
      "mismatch_localization=one-instruction-window"
      "fractional_phase_no_retirement=true"
      "host_adversary=bounded-scheduler-preemption"
    ];
  }
