{pkgs}:
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
          printf '%s\n' T-RISK-18
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
        [ "$checked_count" -eq 18 ] || fail "expected 18 checked risk tasks, found $checked_count"
        while read -r task; do
          grep -F -x -q -- "$task" checked-tasks.txt || fail "missing checked task $task"
        done < expected-checked-tasks.sorted
        while read -r task; do
          grep -F -x -q -- "$task" expected-checked-tasks.sorted || fail "unexpected checked task $task"
        done < checked-tasks.txt

        require_fixed "$risk_doc" "**RISK-4 / RISK-5** are retired by \`T-RISK-1\`"
        require_fixed "$risk_doc" "**RISK-6 / RISK-7** are retired by \`T-RISK-2\`:"
        require_fixed "$risk_doc" "**RISK-10 / RISK-11** are retired by \`T-RISK-3\`"
        require_fixed "$risk_doc" "**RISK-8 / RISK-9** are resolved by \`T-RISK-4\` with the thin/replay fallback"
        require_fixed "$risk_doc" "\`risk8_status=mitigated_by_fallback_not_retired_for_fat_snapshot\`"
        require_fixed "$risk_doc" "\`risk9_status=retired_thin_replay_default\`"
        require_fixed "$risk_doc" "\`full_fat_checkpoint_complete=false\`"
        require_fixed "$risk_doc" "**RISK-12** is retired by \`T-RISK-5\`"
        require_fixed "$risk_doc" "\`virtual_address_read_result=pass\`"
        require_fixed "$risk_doc" "\`production_whitebox_channel_implemented=false\`"
        require_fixed "$risk_doc" "**RISK-13** is retired by \`T-RISK-6\`"
        require_fixed "$risk_doc" "\`randomization_reenabled_capability=true\`"
        require_fixed "$risk_doc" "\`default_decision=randomization_may_be_enabled_per_image\`"
        require_fixed "$risk_doc" "\`fallback_adopted=none\`"
        require_fixed "$risk_doc" "**RISK-14** is resolved by \`T-RISK-7\` with the exact-deadline/TB-split fallback"
        require_fixed "$risk_doc" "\`deadline_api_available=true\`"
        require_fixed "$risk_doc" "\`zero_overshoot_all=false\`"
        require_fixed "$risk_doc" "\`fallback_adopted=tb_split_exact_pause_deadline_export_landed\`"
        require_fixed "$risk_doc" "**RISK-15** is retired by \`T-RISK-8\`"
        require_fixed "$risk_doc" "**RISK-16** is resolved by \`T-RISK-9\` and the Phase-2 regeneration/build-identity"
        require_fixed "$risk_doc" "\`artifact_mismatch_regates=true\`"
        require_fixed "$risk_doc" "\`qemu_version_bump_regate_enforced=true\`"
        require_fixed "$risk_doc" "**RISK-17** is resolved by \`T-RISK-10\` with the aarch64 black-box-only fallback"
        require_fixed "$risk_doc" "\`qemu_aarch64_softmmu_target=false\`"
        require_fixed "$risk_doc" "\`crucible_guest_workspace_member=true\`"
        require_fixed "$risk_doc" "\`fallback_adopted=aarch64_black_box_only_until_qemu_target_and_doorbell\`"
        require_fixed "$risk_doc" "**RISK-18** is retired by \`T-RISK-11\`"
        require_fixed "$risk_doc" "**RISK-19** is retired by \`T-RISK-12\`"
        require_fixed "$risk_doc" "**RISK-20** is retired by \`T-RISK-13\`"
        require_fixed "$risk_doc" "**RISK-21** is retired by \`T-RISK-14\`"
        require_fixed "$risk_doc" "**RISK-22** is retired by \`T-RISK-15\`"
        require_fixed "$risk_doc" "**RISK-23 / RISK-24** are enforced as a Phase-0 checklist guard by \`T-RISK-16\`"
        require_fixed "$risk_doc" "**RISK-25** remains open under \`T-RISK-17\`"
        require_fixed "$risk_doc" "**RISK-26** uses the \`T-RISK-18\` default-only fallback while live preemption"
        require_fixed "$risk_doc" "\`preemption_injection_api_available=qemu_plugin_inject_preemption\`"
        require_fixed "$risk_doc" "\`known_preemption_injection_surface_found=true\`"
        require_fixed "$risk_doc" "\`default_determinism_prereqs_green=false\`"
        require_fixed "$risk_doc" "\`fallback_adopted=preemption_injection_patch_landed_explorer_enablement_pending\`"
        require_fixed "$risk_doc" "**RISK-27** remains open under \`T-RISK-19\`"
        require_fixed "$risk_doc" "\`selected_phase0_default_rr_switch_quantum=4096\`"
        require_fixed "$risk_doc" "\`race_yield_tested=false\`"
        require_fixed "$risk_doc" "\`d25_status=open_until_preemption_explorer_enabled\`"
        require_fixed "$risk_doc" "\`fallback_adopted=modeled_throughput_default_only_quantum_until_preemption_explorer\`"
        require_fixed "$risk_doc" "**RISK-28** is resolved by \`T-RISK-20\` with the read-only/Crucible-driven-step fallback"
        require_fixed "$risk_doc" "\`hermetic_gdb_client_available=false\`"
        require_fixed "$risk_doc" "\`known_aos_qemu_gdbstub_step_hook_detected=false\`"
        require_fixed "$risk_doc" "\`gdb_single_step_policy=disabled_until_s14_green\`"
        require_fixed "$risk_doc" "\`policy_enforcement_runtime=not_implemented\`"
        require_fixed "$risk_doc" "\`fallback_adopted=read_only_attach_crucible_driven_step_until_gdbstub_gate\`"

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

        require_fixed "$decision_doc" "checks.crucible.phase0.s1Fingerprint"
        require_fixed "$decision_doc" "checks.crucible.phase0.s2HltBusyPoll"
        require_fixed "$decision_doc" "checks.crucible.phase0.s4ShmemVisibility"
        require_fixed "$decision_doc" "checks.crucible.phase0.s3SavevmLoadvm"
        require_fixed "$decision_doc" "PASS WITH FALLBACK"
        require_fixed "$decision_doc" "thin_checkpoint_default=true"
        require_fixed "$decision_doc" "fat_snapshot_default=false"
        require_fixed "$decision_doc" "loadvm_branch_enabled=false"
        require_fixed "$decision_doc" "s3_fallback_adopted=true"
        require_fixed "$decision_doc" "checks.crucible.phase0.s5VirtualMemory"
        require_fixed "$decision_doc" "qemu_plugin_read_memory_vaddr_available=true"
        require_fixed "$decision_doc" "physical_pinned_fallback_adopted=false"
        require_fixed "$decision_doc" "checks.crucible.phase0.s6KaslrAslr"
        require_fixed "$decision_doc" "randomized_fingerprint_match=true"
        require_fixed "$decision_doc" "randomized_bases_identical=true"
        require_fixed "$decision_doc" "checks.crucible.phase0.s7DeadlineCeiling"
        require_fixed "$decision_doc" "deadline_api_available=true"
        require_fixed "$decision_doc" "tb_split_exact_pause_deadline_export_landed"
        require_fixed "$decision_doc" "checks.crucible.phase2.qemuPatchRegeneration"
        require_fixed "$decision_doc" "artifact_build_id_match=true"
        require_fixed "$decision_doc" "qemu_inert_gate_status=fallback_pending_upstream_comparison"
        require_fixed "$decision_doc" "checks.crucible.phase0.s10Aarch64Doorbell"
        require_fixed "$decision_doc" "aarch64_whitebox_supported=false"
        require_fixed "$decision_doc" "aarch64_black_box_only_until_qemu_target_and_doorbell"
        require_fixed "$decision_doc" "checks.crucible.phase0.coverageOverhead"
        require_fixed "$decision_doc" "checks.crucible.phase0.abiDrift"
        require_fixed "$decision_doc" "checks.crucible.phase0.futexStress"
        require_fixed "$decision_doc" "checks.crucible.phase0.lifecycle"
        require_fixed "$decision_doc" "checks.crucible.phase0.searchTreeGrowth"
        require_fixed "$decision_doc" "checks.crucible.phase0.multiVmParallelism"
        require_fixed "$decision_doc" "checks.crucible.phase0.riskRegisterGate"
        require_fixed "$decision_doc" "checked_risk_tasks=18"
        require_fixed "$decision_doc" "retired_decision_entries=18"
        require_fixed "$decision_doc" "phase0_foundational_blockers_open=1"
        require_fixed "$decision_doc" "checks.crucible.phase0.s11MultiVcpuFingerprint"
        require_fixed "$decision_doc" "checks.crucible.phase0.s12PreemptionDecision"
        require_fixed "$decision_doc" "decision_preemption_exploration_enabled=false"
        require_fixed "$decision_doc" "preemption_injection_patch_landed_explorer_enablement_pending"
        require_fixed "$decision_doc" "checks.crucible.phase0.s13RrSwitchQuantumFallback"
        require_fixed "$decision_doc" "selected_phase0_default_rr_switch_quantum=4096"
        require_fixed "$decision_doc" "d25_status=open_until_preemption_explorer_enabled"
        require_fixed "$decision_doc" "modeled_throughput_default_only_quantum_until_preemption_explorer"
        require_fixed "$decision_doc" "checks.crucible.phase0.s14GdbstubFallback"
        require_fixed "$decision_doc" "hermetic_gdb_client_available=false"
        require_fixed "$decision_doc" "known_aos_qemu_gdbstub_step_hook_detected=false"
        require_fixed "$decision_doc" "gdb_single_step_policy=disabled_until_s14_green"
        require_fixed "$decision_doc" "read_only_attach_crucible_driven_step_until_gdbstub_gate"

        mkdir -p "$out"
        {
          echo PASS_REGISTER_CONSISTENCY
          echo spike=risk-register-checklist-guard
          echo checked_risk_tasks=18
          echo checked_task_scope=T-RISK-only
          echo retired_decision_entries=18
          echo phase0_foundational_blockers_open=1
        } > "$out/result"
        cp "$risk_doc" "$out/30-risks-spikes.md"
        cp "$decision_doc" "$out/31-decision-register.md"
      '';
    }
  ];

  meta = {
    description = "Crucible Phase 0 risk-register and checklist-guard consistency check";
  };
}
