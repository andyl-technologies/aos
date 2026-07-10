{pkgs, lib}: let
  source = builtins.readFile ./phase0-s13-rr-quantum.c;
  s12PreemptionDecision = import ./phase0-s12.nix {inherit pkgs;};
  s11MultiVcpuFingerprint = import ./phase0-s11.nix {inherit pkgs lib;};
in
  pkgs.mkDerivation {
    pname = "crucible-phase0-s13-rr-switch-quantum-fallback";
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

    phases = [
      {
        name = "run-s13-rr-switch-quantum-fallback";
        script = ''
          set -eu

          cp "$sourcePath" phase0-s13-rr-quantum.c
          cc -std=c11 -O2 -Wall -Wextra -Werror phase0-s13-rr-quantum.c -o phase0-s13-rr-quantum

          # S12 evolved from PASS_WITH_FALLBACK to PASS_WITH_PATCH_SURFACE when
          # the preemption-injection patch surface landed, and its discrimination
          # fields advanced from not_tested to `modeled` once the deterministic
          # model discrimination proof landed. The quantum selection below is a
          # perf/throughput sweep that is independent of the discrimination proof:
          # it still rests on the LIVE campaign explorer remaining disabled
          # (modeled discrimination is not live race-yield enablement), which is
          # why race_yield_tested stays false and d25_status stays open.
          grep -q '^PASS_WITH_PATCH_SURFACE$' "$S12_RESULT"
          grep -q '^check=checks.crucible.phase0.s12PreemptionDecision$' "$S12_RESULT"
          grep -q '^preemption_injection_api_available=qemu_plugin_inject_preemption$' "$S12_RESULT"
          grep -q '^commanded_preemption_discriminating=modeled$' "$S12_RESULT"

          # The fallback quantum is provisional until the real sim-mode S11
          # proof succeeds with the same four-vCPU quantum. Consume that result
          # directly so S13 cannot report completion from the modeled sweep
          # alone.
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

          mkdir -p "$out"
          ./phase0-s13-rr-quantum > "$out/result"
          grep -q '^PASS_WITH_VALIDATED_FALLBACK$' "$out/result"
          grep -q '^check=checks.crucible.phase0.s13RrSwitchQuantumFallback$' "$out/result"
          grep -q '^candidate_quantums=1024,2048,4096,8192,16384$' "$out/result"
          grep -q '^throughput_metric=modeled_retired_instruction_efficiency_x1000$' "$out/result"
          grep -q '^throughput_measurement_scope=modeled_rr_switch_overhead_default_only$' "$out/result"
          grep -q '^target_efficiency_x1000=980$' "$out/result"
          grep -q '^sample_0_efficiency_x1000=941$' "$out/result"
          grep -q '^sample_2_rr_switch_quantum=4096$' "$out/result"
          grep -q '^sample_2_efficiency_x1000=984$' "$out/result"
          grep -q '^selected_phase0_default_rr_switch_quantum=4096$' "$out/result"
          grep -q '^selected_default_basis=s11_validated_modeled_smallest_quantum_above_throughput_floor$' "$out/result"
          grep -q '^selected_default_efficiency_x1000=984$' "$out/result"
          grep -q '^coarse_baseline_rr_switch_quantum=16384$' "$out/result"
          grep -q '^coarse_baseline_efficiency_x1000=996$' "$out/result"
          grep -q '^selected_vs_coarse_efficiency_x1000=987$' "$out/result"
          grep -q '^race_yield_tested=false$' "$out/result"
          grep -q '^race_yield_source=preemption_patch_surface_available_explorer_disabled$' "$out/result"
          grep -q '^s12_decision_entry_consumed=true$' "$out/result"
          grep -q '^s11_result_consumed=true$' "$out/result"
          grep -q '^s11_sim_rerun_green=true$' "$out/result"
          grep -q '^s11_rr_switch_quantum=4096$' "$out/result"
          grep -q '^s11_workload_affinity_active=true$' "$out/result"
          grep -q '^s11_extended_fingerprint_match=true$' "$out/result"
          grep -q '^decision_preemption_exploration_enabled=false$' "$out/result"
          grep -q '^d25_status=open_until_preemption_explorer_enabled$' "$out/result"
          grep -q '^fallback_adopted=s11_validated_modeled_throughput_default_only_quantum_until_preemption_explorer$' "$out/result"
          grep -q '^s13_complete=true$' "$out/result"
          cp phase0-s13-rr-quantum.c "$out/source.c"
          cp "$S12_RESULT" "$out/s12-result"
          cp "$S11_RESULT" "$out/s11-result"
        '';
      }
    ];

    meta = {
      description = "Crucible Phase 0 S13 RR switch quantum fallback spike";
    };
  }
