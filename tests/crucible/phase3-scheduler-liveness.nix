{
  pkgs,
  lib,
  testing ? import ../../lib/testing {inherit pkgs lib;},
  attrPath ? "checks.crucible.phase3.gates.schedulerLiveness",
  taskIds ? ["T-HARN-14" "T-SCHED-4"],
  openTaskIds ? [],
  dependencies ? [],
  campaignComposition ? null,
}: let
  productionFlight = import ./phase7-production-rust-plugin-flight.nix {
    inherit pkgs lib testing campaignComposition;
    attrPath = "checks.crucible.phase7.productionRustPluginFlight";
  };
in
  import ./phase9-campaign-mode-production-evidence.nix {
    inherit pkgs lib campaignComposition attrPath taskIds openTaskIds dependencies;
    authority = productionFlight;
    gate = "gate:scheduler-liveness";
    executionFamily = "qemu-runtime";
    name = "production-scheduler-liveness";
    requiredEvidence = [
      "gate=gate:production-rust-plugin-flight"
      "diskless_multiboot_runs=2"
      "sample_target_picoseconds=2000000,2000001,2000051,4000000,8000000"
      "instruction_exact_window_width_picoseconds=50"
      "instruction_exact_raw_retirement_successor=true"
      "fractional_phase_no_retirement=true"
      "sample_logical_picoseconds_equal_target=true"
      "bounded_scheduler_preemption_applied=true"
      "pending_quantum_preemption_certified=true"
      "scheduler_preemption_mailbox_decisions=2"
      "scheduler_vcpu_switch_applied=true"
      "scheduler_interrupt_applied=true"
      "all_vcpus_halted_observed=true"
      "queued_idle_wake_reached_exact_deadline=true"
      "idle_wake_stream_restart_identical=true"
    ];
    semanticEvidence = [
      "backend=guarded-production-qemu"
      "real_qemu_required=true"
      "bounded_progress=sample-targets,pending-quantum-preemption,idle-wake"
      "sample_target_picoseconds=2000000,2000001,2000051,4000000,8000000"
      "fractional_phase_no_retirement=true"
      "pending_quantum_preemption_certified=true"
      "scheduler_preemption_mailbox_decisions=2"
      "all_vcpus_halted_observed=true"
      "queued_idle_wake_reached_exact_deadline=true"
      "idle_wake_stream_restart_identical=true"
    ];
  }
