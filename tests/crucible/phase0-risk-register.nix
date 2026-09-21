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
    src = builtins.path {
      path = ../../docs/rfcs/0010-crucible;
      name = "crucible-rfc0010-docs";
    };

    buildDeps = [
      pkgs.coreutils
      pkgs.gawk
      pkgs.grep
    ];

    S11_RESULT = "${s11MultiVcpuFingerprint}/result";
    S13_RESULT = "${s13RrSwitchQuantum}/result";

    phases = [
      {
        name = "check-risk-register";
        script = ''
          set -eu

          cp -r "$src" source
          chmod -R u+w source
          cd source

          risk_doc="30-risks-spikes.md"
          decision_doc="31-decision-register.md"

          fail() {
            echo "FAIL: $*" >&2
            exit 1
          }

          require_fixed() {
            file="$1"
            text="$2"
            grep -F -q -- "$text" "$file" || fail "missing '$text' in $file"
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
          require_line "$S11_RESULT" "horizon_icount=4000000000"
          require_line "$S11_RESULT" "sustained_workload_active=true"
          require_line "$S11_RESULT" "workload_affinity_active=true"
          require_line "$S11_RESULT" "workload_affinity_vcpus=0,1,2,3"
          require_line "$S11_RESULT" "aggregate_fingerprint_match=true"
          require_line "$S11_RESULT" "aggregate_icount_stream_match=true"
          require_line "$S11_RESULT" "rr_switch_trace_match=true"
          require_line "$S11_RESULT" "per_vcpu_delta_trace_match=true"
          require_regex "$S11_RESULT" 'rr_switch_events=[1-9][0-9]*'
          require_line "$S11_RESULT" "horizon_fingerprint_match=true"
          require_line "$S11_RESULT" "horizon_sample_observed_icount=4000000000"
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

          {
            printf '%s\n' T-RISK-1
            printf '%s\n' T-RISK-2
            printf '%s\n' T-RISK-3
            printf '%s\n' T-RISK-4
            printf '%s\n' T-RISK-5
            printf '%s\n' T-RISK-6
            printf '%s\n' T-RISK-7
            printf '%s\n' T-RISK-8
            printf '%s\n' T-RISK-9
            printf '%s\n' T-RISK-10
            printf '%s\n' T-RISK-11
            printf '%s\n' T-RISK-12
            printf '%s\n' T-RISK-13
            printf '%s\n' T-RISK-14
            printf '%s\n' T-RISK-15
            printf '%s\n' T-RISK-16
            printf '%s\n' T-RISK-17
            printf '%s\n' T-RISK-18
            printf '%s\n' T-RISK-19
            printf '%s\n' T-RISK-20
          } > expected-checked-tasks.txt

          gawk '
            /^- \[x\] \*\*T-RISK-/ {
              if (match($0, /T-RISK-[0-9]+/)) {
                print substr($0, RSTART, RLENGTH)
              }
            }
          ' ./*.md | sort > checked-tasks.txt

          sort expected-checked-tasks.txt > expected-checked-tasks.sorted
          checked_count=$(wc -l < checked-tasks.txt)
          [ "$checked_count" -eq 20 ] || fail "expected 20 checked risk tasks, found $checked_count"
          while read -r task; do
            grep -F -x -q -- "$task" checked-tasks.txt || fail "missing checked task $task"
          done < expected-checked-tasks.sorted
          while read -r task; do
            grep -F -x -q -- "$task" expected-checked-tasks.sorted || fail "unexpected checked task $task"
          done < checked-tasks.txt

          require_fixed "$risk_doc" "**RISK-4 / RISK-5** are retired by \`T-RISK-1\`"
          require_fixed "$risk_doc" "**RISK-6 / RISK-7** are retired by \`T-RISK-2\`:"
          require_fixed "$risk_doc" "**RISK-10 / RISK-11** are retired by \`T-RISK-3\`"
          require_fixed "$risk_doc" "**RISK-8 / RISK-9** are retired by exact checkpoint realization"
          require_fixed "$risk_doc" "\`checks.crucible.phase2.qemuExactSnapshotRestore\` rejects incomplete state"
          require_fixed "$risk_doc" "**RISK-12** is retired by \`T-RISK-5\`"
          require_fixed "$risk_doc" "\`virtual_address_read_result=pass\`"
          require_fixed "$risk_doc" "\`production_whitebox_channel_implemented=false\`"
          require_fixed "$risk_doc" "**RISK-13** is retired by \`T-RISK-6\`"
          require_fixed "$risk_doc" "\`randomization_reenabled_capability=true\`"
          require_fixed "$risk_doc" "\`default_decision=randomization_may_be_enabled_per_image\`"
          require_fixed "$risk_doc" "**RISK-14** has current proof for exact translation-block exit and an explicit"
          require_fixed "$risk_doc" "\`exact_tb_exit_test_passed=true\`"
          require_fixed "$risk_doc" "\`exact_tb_exit_trap_icount=3\`"
          require_fixed "$risk_doc" "\`exact_tb_exit_boundary_icount=4\`"
          require_fixed "$risk_doc" "**RISK-15** is retired by \`T-RISK-8\`"
          require_fixed "$risk_doc" "**RISK-16** is resolved by \`T-RISK-9\` and the Phase-2 regeneration/build-identity"
          require_fixed "$risk_doc" "\`artifact_mismatch_regates=true\`"
          require_fixed "$risk_doc" "\`qemu_version_bump_regate_enforced=true\`"
          require_fixed "$risk_doc" "**RISK-17** is retired by \`T-RISK-10\`"
          require_fixed "$risk_doc" "\`qemu_aarch64_softmmu_target=true\`"
          require_fixed "$risk_doc" "\`aarch64_whitebox_supported=true\`"
          require_fixed "$risk_doc" "\`fallback_adopted=none\`"
          require_fixed "$risk_doc" "**RISK-18** is retired by \`T-RISK-11\`"
          require_fixed "$risk_doc" "**RISK-19** is retired by \`T-RISK-12\`"
          require_fixed "$risk_doc" "**RISK-20** is retired by \`T-RISK-13\`"
          require_fixed "$risk_doc" "**RISK-21** is retired by \`T-RISK-14\`"
          require_fixed "$risk_doc" "**RISK-22** is retired by \`T-RISK-15\`"
          require_fixed "$risk_doc" "**RISK-23 / RISK-24** are enforced as a Phase-0 checklist guard by \`T-RISK-16\`"
          require_fixed "$risk_doc" "**RISK-25** is retired by \`T-RISK-17\`"
          require_fixed "$risk_doc" "\`horizon_icount=4000000000\`"
          require_fixed "$risk_doc" "\`rr_switch_events=731765\`"
          require_fixed "$risk_doc" "**RISK-26** is retired by \`T-RISK-18\` with live preemption"
          require_fixed "$risk_doc" "\`preemption_injection_api_available=qemu_plugin_inject_preemption\`"
          require_fixed "$risk_doc" "\`known_preemption_injection_surface_found=true\`"
          require_fixed "$risk_doc" "\`default_determinism_prereqs_green=true\`"
          require_fixed "$risk_doc" "\`exact_preemption_proof=true\`"
          require_fixed "$risk_doc" "**RISK-27** is resolved by \`T-RISK-19\` with the live"
          require_fixed "$risk_doc" "\`selected_phase0_default_rr_switch_quantum=4096\`"
          require_fixed "$risk_doc" "\`race_yield_tested=true\`"
          require_fixed "$risk_doc" "\`s11_sim_rerun_green=true\`"
          require_fixed "$risk_doc" "\`s13_complete=true\`"
          require_fixed "$risk_doc" "\`d25_status=resolved_rr_switch_quantum_4096\`"
          require_fixed "$risk_doc" "**RISK-28** is retired by \`T-RISK-20\` through live packaged x86_64 and aarch64"
          require_fixed "$risk_doc" "\`checks.crucible.phase7.debuggerLiveArchitectures\`"
          require_fixed "$risk_doc" "\`architectures=x86_64,aarch64\`"
          require_fixed "$risk_doc" "\`repeated_register_reads_neutral=true\`"
          require_fixed "$risk_doc" "\`hardware_breakpoint_packets=true\`"
          require_fixed "$risk_doc" "\`raw_single_step=false\`"

          require_fixed "$decision_doc" "RISK-4 / RISK-5 / T-RISK-1"
          require_fixed "$decision_doc" "RISK-6 / RISK-7 / T-RISK-2"
          require_fixed "$decision_doc" "RISK-10 / RISK-11 / T-RISK-3"
          require_fixed "$decision_doc" "RISK-8 / RISK-9 / T-RISK-4"
          require_fixed "$decision_doc" "RISK-12 / T-RISK-5"
          require_fixed "$decision_doc" "RISK-13 / T-RISK-6"
          require_fixed "$decision_doc" "RISK-14 / T-RISK-7"
          require_fixed "$decision_doc" "RISK-16 / T-RISK-9"
          require_fixed "$decision_doc" "RISK-17 / T-RISK-10"
          require_fixed "$decision_doc" "RISK-15 / T-RISK-8"
          require_fixed "$decision_doc" "RISK-18 / T-RISK-11"
          require_fixed "$decision_doc" "RISK-19 / T-RISK-12"
          require_fixed "$decision_doc" "RISK-20 / T-RISK-13"
          require_fixed "$decision_doc" "RISK-21 / T-RISK-14"
          require_fixed "$decision_doc" "RISK-22 / T-RISK-15"
          require_fixed "$decision_doc" "RISK-23 / RISK-24 / T-RISK-16"
          require_fixed "$decision_doc" "RISK-25 / T-RISK-17"
          require_fixed "$decision_doc" "RISK-26 / T-RISK-18"
          require_fixed "$decision_doc" "RISK-27 / T-RISK-19"
          require_fixed "$decision_doc" "RISK-28 / T-RISK-20"

          require_fixed "$decision_doc" "checks.crucible.phase7.productionRustPluginFlight"
          require_fixed "$decision_doc" "checks.crucible.phase0.s2HltBusyPoll"
          require_fixed "$decision_doc" "checks.crucible.phase0.s4ShmemVisibility"
          require_fixed "$decision_doc" "checks.crucible.phase0.s5VirtualMemory"
          require_fixed "$decision_doc" "qemu_plugin_read_memory_vaddr_available=true"
          require_fixed "$decision_doc" "physical_pinned_fallback_adopted=false"
          require_fixed "$decision_doc" "checks.crucible.phase0.s6KaslrAslr"
          require_fixed "$decision_doc" "randomized_fingerprint_match=true"
          require_fixed "$decision_doc" "randomized_bases_identical=true"
          require_fixed "$decision_doc" "checks.crucible.phase2.gates.patchMicrotests"
          require_fixed "$decision_doc" "exact_tb_exit_trap_icount=3"
          require_fixed "$decision_doc" "exact_tb_exit_boundary_icount=4"
          require_fixed "$decision_doc" "checks.crucible.phase2.qemuPatchRegeneration"
          require_fixed "$decision_doc" "artifact_build_id_match=true"
          require_fixed "$decision_doc" "checks.crucible.phase0.s10Aarch64Doorbell"
          require_fixed "$decision_doc" "aarch64_whitebox_supported=true"
          require_fixed "$decision_doc" "fallback_adopted=none"
          require_fixed "$decision_doc" "checks.crucible.phase0.coverageOverhead"
          require_fixed "$decision_doc" "checks.crucible.phase0.futexStress"
          require_fixed "$decision_doc" "checks.crucible.phase0.lifecycle"
          require_fixed "$decision_doc" "checks.crucible.phase0.searchTreeGrowth"
          require_fixed "$decision_doc" "checks.crucible.phase0.multiVmParallelism"
          require_fixed "$decision_doc" "checks.crucible.phase0.riskRegisterGate"
          require_fixed "$decision_doc" "checked_risk_tasks=20"
          require_fixed "$decision_doc" "retired_decision_entries=20"
          require_fixed "$decision_doc" "phase0_foundational_blockers_open=0"
          require_fixed "$decision_doc" "checks.crucible.phase0.s11MultiVcpuFingerprint"
          require_fixed "$decision_doc" "s11_result_status=PASS"
          require_fixed "$decision_doc" "checks.crucible.phase0.s12PreemptionDecision"
          require_fixed "$decision_doc" "decision_preemption_exploration_enabled=true"
          require_fixed "$decision_doc" "exact_preemption_proof=true"
          require_fixed "$decision_doc" "checks.crucible.phase0.s13RrSwitchQuantum"
          require_fixed "$decision_doc" "selected_phase0_default_rr_switch_quantum=4096"
          require_fixed "$decision_doc" "s11_sim_rerun_green=true"
          require_fixed "$decision_doc" "s13_complete=true"
          require_fixed "$decision_doc" "d25_status=resolved_rr_switch_quantum_4096"
          require_fixed "$decision_doc" "checks.crucible.phase7.debuggerLiveArchitectures"
          require_fixed "$decision_doc" "architectures=x86_64,aarch64"
          require_fixed "$decision_doc" "repeated_register_reads_neutral=true"
          require_fixed "$decision_doc" "hardware_breakpoint_packets=true"
          require_fixed "$decision_doc" "raw_single_step=false"

          mkdir -p "$out"
          {
            echo PASS_REGISTER_CONSISTENCY
            echo spike=risk-register-checklist-guard
            echo checked_risk_tasks=20
            echo checked_task_scope=T-RISK-only
            echo retired_decision_entries=20
            echo phase0_foundational_blockers_open=0
          } > "$out/result"
          cp "$risk_doc" "$out/30-risks-spikes.md"
          cp "$decision_doc" "$out/31-decision-register.md"
          cp "$S11_RESULT" "$out/s11-result"
          cp "$S13_RESULT" "$out/s13-result"
        '';
      }
    ];

    meta = {
      description = "Crucible Phase 0 risk-register and checklist-guard consistency check";
    };
  }
