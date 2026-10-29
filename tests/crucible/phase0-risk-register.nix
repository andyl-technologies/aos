{
  pkgs,
  lib ? pkgs.lib,
}: let
  s11MultiVcpuFingerprint = import ./phase0-s11.nix {inherit pkgs lib;};
  s13RrSwitchQuantum = import ./phase0-s13.nix {inherit pkgs lib;};
in
  pkgs.mkDerivation {
    pname = "crucible-phase0-risk-register-gate";
    version = "0";
    src = null;

    buildDeps = [
      pkgs.coreutils
      pkgs.grep
    ];

    S11_RESULT = "${s11MultiVcpuFingerprint}/result";
    S13_RESULT = "${s13RrSwitchQuantum}/result";

    phases = [
      {
        name = "check-spike-results";
        script = ''
          set -eu

          fail() {
            echo "FAIL: $*" >&2
            exit 1
          }

          require_line() {
            file="$1"
            text="$2"
            grep -F -x -q -- "$text" "$file" || fail "missing exact line '$text' in $file"
          }

          require_regex() {
            file="$1"
            regex="$2"
            grep -E -x -q -- "$regex" "$file" || fail "missing line matching '$regex' in $file"
          }

          require_line "$S11_RESULT" "PASS"
          require_line "$S11_RESULT" "scenario=smp-contended-pthread-spinlock"
          require_line "$S11_RESULT" "accelerator=sim,thread=single"
          require_line "$S11_RESULT" "vcpus=4"
          require_line "$S11_RESULT" "memory_mib=256"
          require_line "$S11_RESULT" "rr_switch_quantum=4096"
          require_line "$S11_RESULT" "cadence=100000000"
          require_line "$S11_RESULT" "horizon_icount=8000000000"
          require_line "$S11_RESULT" "sustained_workload_active=true"
          require_line "$S11_RESULT" "workload_affinity_active=true"
          require_line "$S11_RESULT" "workload_affinity_vcpus=0,1,2,3"
          require_line "$S11_RESULT" "aggregate_fingerprint_match=true"
          require_line "$S11_RESULT" "aggregate_icount_stream_match=true"
          require_line "$S11_RESULT" "rr_switch_trace_match=true"
          require_line "$S11_RESULT" "per_vcpu_delta_trace_match=true"
          require_regex "$S11_RESULT" 'rr_switch_events=[1-9][0-9]*'
          require_line "$S11_RESULT" "horizon_fingerprint_match=true"
          require_line "$S11_RESULT" "horizon_sample_observed_icount=8000000000"
          require_line "$S11_RESULT" "horizon_sample_stop_requested=true"
          require_line "$S11_RESULT" "exact_horizon_authoritative=true"
          require_line "$S11_RESULT" "authoritative_trace_scope=through-exact-horizon"
          require_line "$S11_RESULT" "final_sample_fingerprint_compared=authoritative"
          require_line "$S11_RESULT" "final_sample_semantics=exact-observer-aggregate-before-native-vmstop"
          require_line "$S11_RESULT" "final_sample_exact_horizon=true"
          require_line "$S11_RESULT" "periodic_samples_expected=40"
          require_line "$S11_RESULT" "periodic_samples_observed=40"
          require_line "$S11_RESULT" "samples=41"
          require_regex "$S11_RESULT" 'horizon_register_hash=[0-9a-f]{64}'
          require_regex "$S11_RESULT" 'horizon_ram_hash=[0-9a-f]{64}'
          require_line "$S11_RESULT" "horizon_ram_bytes=268435456"
          require_regex "$S11_RESULT" 'final_aggregate_hash=[0-9a-f]{16}'
          require_regex "$S11_RESULT" 'final_register_hash=[0-9a-f]{64}'
          require_line "$S11_RESULT" 'final_register_counts=[66,66,66,66]'
          require_line "$S11_RESULT" 'final_register_file_bytes=[3868,3868,3868,3868]'
          require_regex "$S11_RESULT" 'final_ram_hash=[0-9a-f]{64}'
          require_line "$S11_RESULT" "final_ram_bytes=268435456"
          require_line "$S11_RESULT" "register_read_failures=0"

          require_line "$S13_RESULT" "PASS"
          require_line "$S13_RESULT" "selected_phase0_default_rr_switch_quantum=4096"
          require_line "$S13_RESULT" "s11_result_consumed=true"
          require_line "$S13_RESULT" "s11_sim_rerun_green=true"
          require_line "$S13_RESULT" "race_yield_tested=true"
          require_line "$S13_RESULT" "d25_status=resolved_rr_switch_quantum_4096"
          require_line "$S13_RESULT" "s13_complete=true"

          mkdir -p "$out"
          {
            echo PASS
            echo spike=phase0-spike-results
            echo s11_result_status=PASS
            echo s13_result_status=PASS
          } > "$out/result"
          cp "$S11_RESULT" "$out/s11-result"
          cp "$S13_RESULT" "$out/s13-result"
        '';
      }
    ];

    meta = {
      description = "Crucible Phase 0 multi-vCPU fingerprint and RR switch-quantum spike result check";
    };
  }
