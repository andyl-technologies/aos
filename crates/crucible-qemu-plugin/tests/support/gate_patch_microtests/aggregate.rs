//! First half of `assert_covers_carried_qemu_patch_series`: the aggregate
//! `phase2-patch-microtests.nix` wiring and the `tests/crucible/default.nix`
//! gate-registration checks.

use std::collections::BTreeSet;
use std::error::Error;
use std::fs;

use super::common::{EXPECTED_PATCHES, assert_contains, patch_files, workspace_root};

/// Asserts the carried-patch roster matches the on-disk series and that the
/// aggregate microtest nix plus `default.nix` register every gate surface.
///
/// # Errors
///
/// Returns an error if any checked source file cannot be read.
pub(super) fn assert_aggregate_and_default() -> Result<(), Box<dyn Error>> {
    let root = workspace_root()?;
    let patch_dir = root.join("pkgs/emulation/qemu-patches");
    let carried_patches = patch_files(&patch_dir)?;
    let expected_patches = EXPECTED_PATCHES.iter().copied().collect::<BTreeSet<_>>();

    assert_eq!(
        carried_patches, expected_patches,
        "the Cargo gate target must be updated when the carried QEMU patch series changes"
    );

    let aggregate = fs::read_to_string(root.join("tests/crucible/phase2-patch-microtests.nix"))?;
    assert_contains(&aggregate, "gate=gate:patch-microtests");
    assert_contains(
        &aggregate,
        "taskIds ? [\"T-PKG-4\" \"T-HARN-20\" \"T-PATCH-2\" \"T-PATCH-20\" \"T-PATCH-21\" \"T-PATCH-22\" \"T-PATCH-23\" \"T-PATCH-24\"]",
    );
    assert_contains(&aggregate, "openTaskIds ? []");
    assert_contains(&aggregate, "open_tasks=${builtins.concatStringsSep");
    assert_contains(&aggregate, "status=complete");
    assert_contains(&aggregate, "drop_one_composition_count=0");
    assert_contains(&aggregate, "structural_fallback_count=0");
    assert_contains(
        &aggregate,
        "qemuPatchSeries = import ./phase2-qemu-patch-series.nix",
    );
    assert_contains(
        &aggregate,
        "qemuPatchRegeneration = import ./phase2-qemu-patch-regeneration.nix",
    );
    assert_contains(
        &aggregate,
        "qemuPluginFailLoud = import ./phase2-plugin-fail-loud.nix",
    );
    assert_contains(
        &aggregate,
        "qemuRrQuantumIcount = import ./phase2-qemu-rr-quantum-icount.nix",
    );
    assert_contains(&aggregate, "qemuDetIpi = import ./phase2-qemu-det-ipi.nix");
    assert_contains(
        &aggregate,
        "qemuVcpuIntrospect = import ./phase2-qemu-vcpu-introspect.nix",
    );
    assert_contains(
        &aggregate,
        "qemuPreemptionInject = import ./phase2-qemu-preemption-inject.nix",
    );
    assert_contains(
        &aggregate,
        "qemuDoorbellNoPatch = import ./phase1-qemu-doorbell-no-patch.nix",
    );
    assert_contains(
        &aggregate,
        "qemuDiagnosticPatchesDevOnly = import ./phase1-qemu-diagnostic-patches-dev-only.nix",
    );
    assert_contains(&aggregate, "tar -xf ${qemuPackage.src}");
    assert_contains(&aggregate, "patch --batch --forward --fuzz=0 -p1");
    assert_contains(&aggregate, "test -x ${qemuPackage}/bin/qemu-system-x86_64");
    assert_contains(&aggregate, "patch_series_gate_passed=true");
    assert_contains(&aggregate, "patch_regeneration_gate_passed=true");
    assert_contains(&aggregate, "patch_regeneration_drift_checked=true");
    assert_contains(&aggregate, "patch_regeneration_result_consumed=true");
    assert_contains(&aggregate, "qemu_build_identity_artifact_checked=true");
    assert_contains(&aggregate, "qemu_version_bump_regate_enforced=true");
    assert_contains(&aggregate, "cp \"${qemuPluginFailLoud}/result\"");
    assert_contains(&aggregate, "grep -q '^missing_capability=distinct-errors$'");
    assert_contains(&aggregate, "grep -q '^wall_clock_fallback=forbidden$'");
    assert_contains(&aggregate, "qemu_plugin_fail_loud_gate_passed=true");
    assert_contains(&aggregate, "missing_required_capability_fails_loud=true");
    assert_contains(&aggregate, "cp \"${qemuRrQuantumIcount}/result\"");
    assert_contains(&aggregate, "grep -q '^vcpus=4$'");
    assert_contains(
        &aggregate,
        "grep -q '^sim_s11_trace_source=checks.crucible.phase0.s11MultiVcpuFingerprint(canonical-long-horizon)$'",
    );
    assert_contains(
        &aggregate,
        "grep -q '^cross_run_switch_icount_trace_match=true$'",
    );
    assert_contains(
        &aggregate,
        "grep -q '^cross_run_per_vcpu_delta_trace_match=true$'",
    );
    assert_contains(
        &aggregate,
        "grep -q '^adaptive_realtime_quantum_negative_control=red$'",
    );
    assert_contains(
        &aggregate,
        "grep -q '^adaptive_rr_switch_trace_negative_control=red$'",
    );
    assert_contains(
        &aggregate,
        "grep -q '^patched_non_sim_rr_switch_trace_negative_control=red$'",
    );
    assert_contains(
        &aggregate,
        "grep -q '^non_sim_rr_switch_quantum_uses_stock_budget=true$'",
    );
    assert_contains(&aggregate, "qemu_rr_quantum_icount_gate_passed=true");
    assert_contains(&aggregate, "cp \"${qemuDetIpi}/result\"");
    assert_contains(
        &aggregate,
        "grep -q '^deterministic_ipi_rr_handoff=queued-drain-before-next-vcpu$'",
    );
    assert_contains(
        &aggregate,
        "grep -q '^deterministic_ipi_fixed_mode_trace=true$'",
    );
    assert_contains(
        &aggregate,
        "grep -q '^deterministic_ipi_init_mode_trace=true$'",
    );
    assert_contains(
        &aggregate,
        "grep -q '^deterministic_ipi_sipi_mode_trace=true$'",
    );
    assert_contains(
        &aggregate,
        "grep -q '^deterministic_ipi_delivery_icount_trace_match=true$'",
    );
    assert_contains(&aggregate, "qemu_det_ipi_gate_passed=true");
    assert_contains(&aggregate, "cp \"${qemuVcpuIntrospect}/result\"");
    assert_contains(
        &aggregate,
        "grep -q '^formal_register_export=qemu_plugin_read_vcpu_regs$'",
    );
    assert_contains(
        &aggregate,
        "grep -q '^formal_cursor_export=qemu_plugin_rr_cursor$'",
    );
    assert_contains(&aggregate, "grep -q '^arbitrary_vcpu_register_read=true$'");
    assert_contains(
        &aggregate,
        "grep -q '^register_read_side_effect_free=true$'",
    );
    assert_contains(
        &aggregate,
        "grep -q '^register_size_mismatch_rejected=true$'",
    );
    assert_contains(&aggregate, "grep -q '^rr_cursor_boundary_rejected=true$'");
    assert_contains(
        &aggregate,
        "grep -q '^rr_cursor_out_of_range_current_vcpu_rejected=true$'",
    );
    assert_contains(&aggregate, "qemu_vcpu_introspect_gate_passed=true");
    assert_contains(&aggregate, "formal_vcpu_register_export_present=true");
    assert_contains(&aggregate, "formal_rr_cursor_export_present=true");
    assert_contains(&aggregate, "cp \"${qemuPreemptionInject}/result\"");
    assert_contains(
        &aggregate,
        "grep -q '^formal_preemption_export=qemu_plugin_inject_preemption$'",
    );
    assert_contains(
        &aggregate,
        "grep -q '^vcpu_switch_cross_run_icount_match=true$'",
    );
    assert_contains(
        &aggregate,
        "grep -q '^interrupt_cross_run_icount_match=true$'",
    );
    assert_contains(
        &aggregate,
        "grep -q '^out_of_window_rejected_distinctly=true$'",
    );
    assert_contains(
        &aggregate,
        "grep -q '^before_deadline_rejected_distinctly=true$'",
    );
    assert_contains(
        &aggregate,
        "grep -q '^preemption_budget_clamped_to_commanded_icount=true$'",
    );
    assert_contains(&aggregate, "qemu_preemption_inject_gate_passed=true");
    assert_contains(&aggregate, "formal_preemption_export_present=true");
    assert_contains(
        &aggregate,
        "before_deadline_preemption_rejected_distinctly=true",
    );
    assert_contains(
        &aggregate,
        "grep -q '^regenerated_patch_bytes_match_committed=true$'",
    );
    assert_contains(&aggregate, "grep -q '^patch_branch_bundle_verified=true$'");
    assert_contains(
        &aggregate,
        "grep -q '^patch_branch_commit_hashes_match_manifest=true$'",
    );
    assert_contains(
        &aggregate,
        "grep -q '^qemu_package_patch_phase_generated_from_manifest=true$'",
    );
    assert_contains(
        &aggregate,
        "grep -q '^qemu_build_identity_metadata_installed=true$'",
    );
    assert_contains(
        &aggregate,
        "grep -q '^artifact_validator_rejects_mismatch=true$'",
    );
    assert_contains(&aggregate, "grep -q '^artifact_mismatch_regates=true$'");
    assert_contains(&aggregate, "qemu_doorbell_no_patch_gate_passed=true");
    assert_contains(
        &aggregate,
        "qemu_diagnostic_patches_dev_only_gate_passed=true",
    );
    assert_contains(&aggregate, "phase0_s5_virtual_read_validated=true");
    assert_contains(&aggregate, "phase0_s2_io_trap_surface_validated=true");
    assert_contains(
        &aggregate,
        "whitebox_mode_off_installs_no_trap_validated=true",
    );
    assert_contains(&aggregate, "apply_clean_pinned_qemu=true");
    assert_contains(&aggregate, "patched_qemu_package_build_passed=true");
    assert_contains(&aggregate, "qemu_package=${qemuPackage}");
    assert_contains(&aggregate, "qemu_package_version=${qemuPackage.version}");
    assert_contains(&aggregate, "nm -D --defined-only");
    assert_contains(&aggregate, "plugin_exports_dynamic_symbols_checked=true");
    assert_contains(&aggregate, "qemu_plugin_clock_deadline_export_present=true");
    assert_contains(&aggregate, "qemu_plugin_net_exports_present=true");
    assert_contains(&aggregate, "qemu_plugin_time_drain_exports_present=true");
    assert_contains(&aggregate, "qemu_plugin_runtime_api_exports_present=true");
    assert_contains(&aggregate, "qemu_plugin_block_exports_present=true");
    assert_contains(&aggregate, "qemu_plugin_9p_exports_present=true");
    assert_contains(&aggregate, "qemu_plugin_icount_raw");
    assert_contains(&aggregate, "qemu_plugin_icount_at_tb_entry");
    assert_contains(&aggregate, "qemu_plugin_force_vcpu_exit");
    assert_contains(&aggregate, "qemu_plugin_register_wake_fd");
    assert_contains(&aggregate, "qemu_plugin_register_tcg_exec_cb");
    assert_contains(&aggregate, "qemu_plugin_register_vcpu_idle_resume_cb");
    assert_contains(&aggregate, "qemu_plugin_register_sim_shmem_dispatch_cb");
    assert_contains(&aggregate, "qemu_plugin_crucible_register_ipi_delivery_cb");
    assert_contains(&aggregate, "qemu_plugin_read_vcpu_regs");
    assert_contains(&aggregate, "qemu_plugin_rr_cursor");
    assert_contains(&aggregate, "qemu_plugin_inject_preemption");
    assert_contains(&aggregate, "qemu_plugin_register_blk_cb");
    assert_contains(&aggregate, "qemu_plugin_register_9p_cb");
    assert_contains(&aggregate, "qemu_plugin_register_net_tx_cb");
    assert_contains(
        &aggregate,
        "qemu_plugin_sim_correctness_exports_present=true",
    );
    assert_contains(&aggregate, "qemu_plugin_det_ipi_exports_present=true");
    assert_contains(
        &aggregate,
        "qemu_plugin_vcpu_introspection_exports_present=true",
    );
    assert_contains(
        &aggregate,
        "qemu_plugin_preemption_inject_export_present=true",
    );
    assert_contains(&aggregate, "qemu_inert_gate_wired=true");
    assert_contains(&aggregate, "qemu_inert_depends_on_patch_microtests=true");
    assert_contains(
        &aggregate,
        "every_microtest_keyed_to_patched_qemu_package=true",
    );
    assert_contains(&aggregate, "every_carried_patch_has_microtest=true");
    assert_contains(
        &aggregate,
        "every_microtest_has_executable_negative_control=true",
    );
    assert_contains(&aggregate, "grep -q '^stock_negative_control=true$'");
    assert_contains(
        &aggregate,
        "grep -q '^exact_drop_one_negative_control=true$'",
    );
    assert_contains(&aggregate, "missing executable negative control");
    assert_contains(&aggregate, "no_patch_decision_has_microtest_gate=true");
    assert_contains(
        &aggregate,
        "diagnostic_only_patches_excluded_from_shipped_qemu=true",
    );

    let default_checks = fs::read_to_string(root.join("tests/crucible/default.nix"))?;
    assert_contains(&default_checks, "patchMicrotests = greenBeforeAdvance {");
    assert_contains(&default_checks, "qemuInert = greenBeforeAdvance {");
    assert_contains(
        &default_checks,
        "gate = import ./phase2-patch-microtests.nix",
    );
    assert_contains(
        &default_checks,
        "taskIds = [\"T-PKG-4\" \"T-HARN-20\" \"T-PATCH-2\"",
    );
    assert_contains(&default_checks, "openTaskIds = []");
    assert_contains(
        &default_checks,
        "taskIds = [\"T-DET-23\" \"T-HARN-21\" \"T-PATCH-3\"]",
    );
    assert_contains(
        &default_checks,
        "qemuBlockShmem = import ./phase1-qemu-block-shmem.nix",
    );
    assert_contains(
        &default_checks,
        "qemuNetTxCallback = import ./phase1-qemu-net-tx-callback.nix",
    );
    assert_contains(
        &default_checks,
        "qemuDoorbellNoPatch = import ./phase1-qemu-doorbell-no-patch.nix",
    );
    assert_contains(
        &default_checks,
        "qemuDiagnosticPatchesDevOnly = import ./phase1-qemu-diagnostic-patches-dev-only.nix",
    );
    assert_contains(
        &default_checks,
        "qemuSimCorrectness = import ./phase1-qemu-sim-correctness.nix",
    );
    assert_contains(
        &default_checks,
        "qemuSimBatchTcgExec = import ./phase1-qemu-sim-batch-tcg-exec.nix",
    );
    assert_contains(
        &default_checks,
        "qemuNinePShmem = import ./phase1-qemu-9p-shmem.nix",
    );
    assert_contains(
        &default_checks,
        "qemuInert = import ./phase2-qemu-inert.nix",
    );
    assert_contains(
        &default_checks,
        "qemuPatchRegeneration = import ./phase2-qemu-patch-regeneration.nix",
    );
    assert_contains(
        &default_checks,
        "qemuRrQuantumIcount = import ./phase2-qemu-rr-quantum-icount.nix",
    );
    assert_contains(
        &default_checks,
        "qemuDetIpi = import ./phase2-qemu-det-ipi.nix",
    );
    assert_contains(
        &default_checks,
        "qemuVcpuIntrospect = import ./phase2-qemu-vcpu-introspect.nix",
    );
    assert_contains(
        &default_checks,
        "qemuPreemptionInject = import ./phase2-qemu-preemption-inject.nix",
    );
    assert_contains(
        &default_checks,
        "qemuPluginFailLoud = import ./phase2-plugin-fail-loud.nix",
    );
    assert_contains(
        &default_checks,
        "attrPath = \"checks.crucible.phase2.gates.qemuInert\";",
    );
    assert_contains(
        &default_checks,
        "patchMicrotests = patchMicrotests.rawGate;",
    );

    let qemu_inert = fs::read_to_string(root.join("tests/crucible/phase2-qemu-inert.nix"))?;
    assert_contains(
        &qemu_inert,
        "taskIds ? [\"T-DET-23\" \"T-HARN-21\" \"T-PATCH-3\"]",
    );
    assert_contains(&qemu_inert, "openTaskIds ? []");
    assert_contains(&qemu_inert, "open_tasks=${builtins.concatStringsSep");
    assert_contains(&qemu_inert, "status=complete");

    Ok(())
}
