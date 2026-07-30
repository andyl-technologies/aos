{
  pkgs,
  lib,
}: let
  source = builtins.readFile ./phase0-s13-rr-quantum.c;
  s12PreemptionDecision = import ./phase0-s12.nix {inherit pkgs;};
  s11MultiVcpuFingerprint = import ./phase0-s11.nix {inherit pkgs lib;};
  livePreemptionSweep = import ./phase2-qemu-live-plugin-preemption.nix {
    inherit pkgs lib;
    attrPath = "checks.crucible.phase0.s13RrSwitchQuantumFallback.livePreemptionSweep";
    taskIds = [];
    openTaskIds = [];
    rrSwitchQuantums = ["1024" "2048" "8192" "16384"];
  };
in
  pkgs.mkDerivation {
    pname = "crucible-phase0-s13-rr-switch-quantum";
    version = "0";
    src = null;

    inherit source;
    passAsFile = ["source"];

    buildDeps = [
      pkgs.coreutils
      pkgs.grep
    ];

    S12_RESULT = "${s12PreemptionDecision}/result";
    S11_RESULT = "${s11MultiVcpuFingerprint}/result";
    LIVE_PREEMPTION_SWEEP_RESULT = "${livePreemptionSweep}/result";

    phases = [
      {
        name = "run-s13-rr-switch-quantum-fallback";
        script = ''
          set -eu

          cp "$sourcePath" phase0-s13-rr-quantum.c
          cc -std=c11 -O2 -Wall -Wextra -Werror phase0-s13-rr-quantum.c -o phase0-s13-rr-quantum

          # S12 established the commanded-preemption model and patch surface.
          # The production loaded-QEMU sweep consumed below supplies the missing
          # live race-yield evidence at every candidate quantum.
          grep -q '^PASS$' "$S12_RESULT"
          grep -q '^check=checks.crucible.phase0.s12PreemptionDecision$' "$S12_RESULT"
          grep -q '^preemption_injection_api_available=qemu_plugin_inject_preemption$' "$S12_RESULT"
          grep -q '^commanded_preemption_discriminating=model_race_plus_live_command_application$' "$S12_RESULT"
          grep -q '^live_preemption_rr_switch_quantum=4096$' "$S12_RESULT"
          grep -q '^decision_preemption_exploration_enabled=true$' "$S12_RESULT"
          grep -q '^fallback_adopted=none$' "$S12_RESULT"

          # Consume the real sim-mode S11 proof at the selected four-vCPU
          # quantum so the throughput model cannot select a value that lacks
          # production deterministic-interleaving evidence.
          grep -q '^PASS$' "$S11_RESULT"
          grep -q '^spike=multi-vcpu-rr-sim-tcg-fingerprint$' "$S11_RESULT"
          grep -q '^accelerator=sim,thread=single$' "$S11_RESULT"
          grep -q '^vcpus=4$' "$S11_RESULT"
          grep -q '^block_devices=0$' "$S11_RESULT"
          grep -q '^rr_switch_quantum=4096$' "$S11_RESULT"
          grep -q '^sustained_workload_active=true$' "$S11_RESULT"
          grep -q '^workload_affinity_active=true$' "$S11_RESULT"
          grep -q '^workload_affinity_vcpus=0,1,2,3$' "$S11_RESULT"
          grep -q '^extended_fingerprint_match=true$' "$S11_RESULT"
          grep -q '^horizon_fingerprint_match=true$' "$S11_RESULT"
          grep -q '^fallback=smp1_not_needed$' "$S11_RESULT"

          grep -q '^tested_rr_switch_quantums=1024,2048,8192,16384$' \
            "$LIVE_PREEMPTION_SWEEP_RESULT"
          for quantum in 1024 2048 8192 16384; do
            grep -q "^ipi_rr_switch_quantum=$quantum$" "$LIVE_PREEMPTION_SWEEP_RESULT"
          done
          test "$(grep -c '^PASS$' "$LIVE_PREEMPTION_SWEEP_RESULT")" -eq 4
          test "$(grep -c '^deterministic_under_host_load=true$' "$LIVE_PREEMPTION_SWEEP_RESULT")" -eq 4
          test "$(grep -c '^sim_double_schedule_matches=true$' "$LIVE_PREEMPTION_SWEEP_RESULT")" -eq 4

          mkdir -p "$out"
          ./phase0-s13-rr-quantum > "$out/result"
          grep -q '^PASS$' "$out/result"
          grep -q '^check=checks.crucible.phase0.s13RrSwitchQuantumFallback$' "$out/result"
          grep -q '^candidate_quantums=1024,2048,4096,8192,16384$' "$out/result"
          grep -q '^throughput_metric=modeled_retired_instruction_efficiency_x1000$' "$out/result"
          grep -q '^throughput_measurement_scope=modeled_rr_switch_overhead_default_only$' "$out/result"
          grep -q '^target_efficiency_x1000=980$' "$out/result"
          grep -q '^sample_0_efficiency_x1000=941$' "$out/result"
          grep -q '^sample_2_rr_switch_quantum=4096$' "$out/result"
          grep -q '^sample_2_efficiency_x1000=984$' "$out/result"
          grep -q '^selected_phase0_default_rr_switch_quantum=4096$' "$out/result"
          grep -q '^selected_default_basis=live_race_yield_tie_smallest_quantum_above_throughput_floor$' "$out/result"
          grep -q '^selected_default_efficiency_x1000=984$' "$out/result"
          grep -q '^coarse_baseline_rr_switch_quantum=16384$' "$out/result"
          grep -q '^coarse_baseline_efficiency_x1000=996$' "$out/result"
          grep -q '^selected_vs_coarse_efficiency_x1000=987$' "$out/result"
          grep -q '^race_yield_tested=true$' "$out/result"
          grep -q '^race_yield_source=production_loaded_qemu_commanded_preemption_sweep$' "$out/result"
          grep -q '^s12_decision_entry_consumed=true$' "$out/result"
          grep -q '^s11_result_consumed=true$' "$out/result"
          grep -q '^s11_sim_rerun_green=true$' "$out/result"
          grep -q '^s11_rr_switch_quantum=4096$' "$out/result"
          grep -q '^s11_workload_affinity_active=true$' "$out/result"
          grep -q '^s11_extended_fingerprint_match=true$' "$out/result"
          grep -q '^decision_preemption_exploration_enabled=true$' "$out/result"
          grep -q '^d25_status=resolved_rr_switch_quantum_4096$' "$out/result"
          grep -q '^fallback_adopted=none$' "$out/result"
          grep -q '^s13_complete=true$' "$out/result"
          cp phase0-s13-rr-quantum.c "$out/source.c"
          cp "$S12_RESULT" "$out/s12-result"
          cp "$S11_RESULT" "$out/s11-result"
          cp "$LIVE_PREEMPTION_SWEEP_RESULT" "$out/live-preemption-sweep-result"
        '';
      }
    ];

    meta = {
      description = "Crucible Phase 0 S13 live RR switch quantum spike";
    };
  }
