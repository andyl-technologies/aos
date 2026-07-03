//! Checks the aggregate `gate:patch-microtests` wiring.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

const EXPECTED_PATCHES: &[&str] = &[
    "0001-crucible-sim-accel.patch",
    "0002-crucible-rr-fingerprint-helpers.patch",
    "0003-crucible-icount-no-realtime.patch",
    "0004-crucible-no-warp-with-plugin.patch",
    "0005-crucible-det-glib-prng.patch",
    "0006-crucible-clock-deadline.patch",
    "0007-crucible-block-rtc-read.patch",
    "0008-crucible-det-getrandom.patch",
    "0009-crucible-net-deterministic.patch",
    "0010-crucible-plugin-time-advance.patch",
    "0011-crucible-plugin-icount-raw.patch",
    "0012-crucible-plugin-vcpu-exit.patch",
    "0013-crucible-plugin-wake-fd.patch",
    "0014-crucible-plugin-tcg-exec-cb.patch",
    "0015-crucible-blk-shmem.patch",
    "0016-crucible-blk-shmem-io-fixes.patch",
    "0017-crucible-blk-write-sentinel.patch",
    "0018-crucible-dev-cb-api.patch",
    "0019-crucible-9p-shmem.patch",
    "0020-crucible-net-tx-callback.patch",
    "0021-crucible-sim-loop-fix.patch",
    "0022-crucible-sim-first-exit.patch",
    "0023-crucible-sim-skip-second-events.patch",
    "0024-crucible-sim-poll-immediate.patch",
    "0025-crucible-sim-idle-callbacks.patch",
    "0026-crucible-sim-shmem-dispatch.patch",
    "0027-crucible-sim-batch-tcg-exec.patch",
    "0028-crucible-det-ipi.patch",
    "0029-crucible-vcpu-introspect.patch",
    "0030-crucible-preemption-inject.patch",
];

#[test]
fn gate_patch_microtests_covers_carried_qemu_patch_series() -> Result<(), Box<dyn Error>> {
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
    assert_contains(&aggregate, "grep -q '^vcpus=2$'");
    assert_contains(
        &aggregate,
        "grep -q '^sim_s11_trace_source=checks.crucible.phase0.s11MultiVcpuFingerprint(accelerator=sim,stop_at=16384)$'",
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
    assert_contains(&aggregate, "qemu_plugin_force_vcpu_exit");
    assert_contains(&aggregate, "qemu_plugin_register_wake_fd");
    assert_contains(&aggregate, "qemu_plugin_main_loop_wait");
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
        "every_microtest_has_stock_negative_control=true",
    );
    assert_contains(&aggregate, "no_patch_decision_has_microtest_gate=true");
    assert_contains(
        &aggregate,
        "diagnostic_only_patches_excluded_from_shipped_qemu=true",
    );

    let default_checks = fs::read_to_string(root.join("tests/crucible/default.nix"))?;
    assert_contains(&default_checks, "patchMicrotests = greenBeforeAdvance {");
    assert_contains(
        &default_checks,
        "gate = import ./phase2-patch-microtests.nix",
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

    let abi = fs::read_to_string(root.join("crates/crucible-qemu-plugin/src/abi.rs"))?;
    assert_contains(&abi, "pub type QemuIcountRawFn");
    assert_contains(&abi, "pub type QemuForceVcpuExitFn");
    assert_contains(&abi, "pub type QemuRegisterWakeFdFn");
    assert_contains(&abi, "pub type QemuMainLoopWaitFn");
    assert_contains(&abi, "pub type QemuRegisterTcgExecCbFn");
    assert_contains(&abi, "pub type QemuRegisterBlkCbFn");
    assert_contains(&abi, "pub type QemuRegisterNinePCbFn");
    assert_contains(&abi, "resolve_qemu_icount_raw_symbol");
    assert_contains(&abi, "resolve_qemu_force_vcpu_exit_symbol");
    assert_contains(&abi, "resolve_qemu_register_wake_fd_symbol");
    assert_contains(&abi, "resolve_qemu_main_loop_wait_symbol");
    assert_contains(&abi, "resolve_qemu_register_tcg_exec_cb_symbol");
    assert_contains(&abi, "resolve_qemu_register_blk_cb_symbol");
    assert_contains(&abi, "resolve_qemu_register_9p_cb_symbol");
    assert_contains(&abi, "PluginRuntimeApis::require");
    assert_contains(&abi, "install_required_runtime_api_scaffold_from_qemu_info");
    assert_contains(&abi, "crucible_qemu_plugin_inert_vcpu_init_cb");
    assert_contains(&abi, "force_vcpu_exit();");

    let network_tx =
        fs::read_to_string(root.join("crates/crucible-qemu-plugin/src/network_tx.rs"))?;
    assert_contains(&network_tx, "pub type QemuNetTxCbFn");
    assert_contains(&network_tx, "pub type QemuRegisterNetTxCbFn");
    assert_contains(&network_tx, "resolve_qemu_register_net_tx_cb_symbol");

    let network_rx =
        fs::read_to_string(root.join("crates/crucible-qemu-plugin/src/network_rx.rs"))?;
    assert_contains(&network_rx, "resolve_qemu_net_send_symbol");
    assert_contains(&network_rx, "resolve_qemu_net_flush_symbol");
    assert_contains(&network_rx, "resolve_qemu_net_can_receive_symbol");

    let whitebox_doorbell =
        fs::read_to_string(root.join("crates/crucible-qemu-plugin/src/whitebox_doorbell.rs"))?;
    assert_contains(&whitebox_doorbell, "QEMU_PLUGIN_DOORBELL_MEM_CB_SYMBOL");
    assert_contains(&whitebox_doorbell, "qemu_plugin_register_vcpu_mem_cb");
    assert_contains(&whitebox_doorbell, "qemu_plugin_read_memory_vaddr");
    assert_contains(
        &whitebox_doorbell,
        "QEMU_PLUGIN_REGISTER_DOORBELL_TRAP_SYMBOL: &str =",
    );
    assert_contains(&whitebox_doorbell, "QEMU_PLUGIN_GUEST_MEMORY_READ_SYMBOL");

    let qemu_patch_series =
        fs::read_to_string(root.join("tests/crucible/phase2-qemu-patch-series.nix"))?;
    assert_contains(
        &qemu_patch_series,
        "series = import ../../pkgs/emulation/qemu-patches/_series.nix",
    );
    assert_contains(
        &qemu_patch_series,
        "patch_manifest_matches_carried_catalog=true",
    );
    assert_contains(
        &qemu_patch_series,
        "decisionRegister = builtins.readFile ../../docs/rfcs/0010-crucible/31-decision-register.md",
    );
    assert_contains(&qemu_patch_series, "qemu_version=10.0.0");
    assert_contains(
        &qemu_patch_series,
        "qemu_source_hash=sha256-IsB1YB/c+MeyZxqDnr3O8dTylz62c1JU/S4b0PMLOJY=",
    );
    assert_contains(
        &qemu_patch_series,
        "qemuPluginFailLoud = import ./phase2-plugin-fail-loud.nix",
    );
    assert_contains(&qemu_patch_series, "cp \"${qemuPluginFailLoud}/result\"");
    assert_contains(
        &qemu_patch_series,
        "grep -q '^missing_capability=distinct-errors$'",
    );
    assert_contains(
        &qemu_patch_series,
        "grep -q '^wall_clock_fallback=forbidden$'",
    );
    assert_contains(&qemu_patch_series, "qemu_plugin_fail_loud_gate_passed=true");
    assert_contains(&qemu_patch_series, "noPatchDecisions");
    assert_contains(
        &qemu_patch_series,
        "checks.crucible.phase1.qemuDoorbellNoPatch",
    );
    assert_contains(&qemu_patch_series, "no_patch_decisions=");

    let qemu_rr_quantum_icount =
        fs::read_to_string(root.join("tests/crucible/phase2-qemu-rr-quantum-icount.nix"))?;
    assert_contains(&qemu_rr_quantum_icount, "T-PATCH-21");
    assert_contains(
        &qemu_rr_quantum_icount,
        "qemu_opt_get_number(opts, \"rr_switch_quantum\", 0)",
    );
    assert_contains(
        &qemu_rr_quantum_icount,
        "return MIN(limit, (int64_t)rr_switch_quantum);",
    );
    assert_contains(
        &qemu_rr_quantum_icount,
        "strcmp(current_accel_name(), \"sim\") != 0",
    );
    assert_contains(&qemu_rr_quantum_icount, "accelerator = \"sim\";");
    assert_contains(&qemu_rr_quantum_icount, "cadence = 4096;");
    assert_contains(&qemu_rr_quantum_icount, "requireGuestPass = false;");
    assert_contains(&qemu_rr_quantum_icount, "stopAt = 16384;");
    assert_contains(&qemu_rr_quantum_icount, "vcpus=2");
    assert_contains(
        &qemu_rr_quantum_icount,
        "require_line \"$s11_result\" \"accelerator=sim\"",
    );
    assert_contains(
        &qemu_rr_quantum_icount,
        "require_line \"$s11_result\" \"run_horizon=plugin-stop_at-16384\"",
    );
    assert_contains(
        &qemu_rr_quantum_icount,
        "require_line \"$s11_result\" \"aggregate_icount_stream_match=true\"",
    );
    assert_contains(&qemu_rr_quantum_icount, "select(.kind == \"rr_switch\")");
    assert_contains(&qemu_rr_quantum_icount, "rr_switch_events=");
    assert_contains(&qemu_rr_quantum_icount, "per_vcpu_delta");
    assert_contains(&qemu_rr_quantum_icount, "RR switch trace mismatch");
    assert_contains(
        &qemu_rr_quantum_icount,
        "per-vCPU icount-delta trace mismatch",
    );
    assert_contains(
        &qemu_rr_quantum_icount,
        "require_line \"$s11_result\" \"rr_switch_trace_match=true\"",
    );
    assert_contains(
        &qemu_rr_quantum_icount,
        "require_line \"$s11_result\" \"per_vcpu_delta_trace_match=true\"",
    );
    assert_contains(
        &qemu_rr_quantum_icount,
        "require_line \"$rr_result\" \"adaptive_rr_switch_trace_negative_control=red\"",
    );
    assert_contains(
        &qemu_rr_quantum_icount,
        "require_line \"$rr_result\" \"patched_non_sim_rr_switch_trace_negative_control=red\"",
    );
    assert_contains(
        &qemu_rr_quantum_icount,
        "require_line \"$rr_result\" \"non_sim_rr_switch_quantum_uses_stock_budget=true\"",
    );
    assert_contains(
        &qemu_rr_quantum_icount,
        "adaptive_realtime_quantum_negative_control=red",
    );
    assert_contains(
        &qemu_rr_quantum_icount,
        "adaptive_rr_switch_trace_negative_control=red",
    );
    assert_contains(
        &qemu_rr_quantum_icount,
        "patched_non_sim_rr_switch_trace_negative_control=red",
    );

    let qemu_det_ipi = fs::read_to_string(root.join("tests/crucible/phase2-qemu-det-ipi.nix"))?;
    assert_contains(&qemu_det_ipi, "T-PATCH-22");
    assert_contains(&qemu_det_ipi, "0028-crucible-det-ipi.patch");
    assert_contains(&qemu_det_ipi, "crucible_sim_det_ipi_enqueue");
    assert_contains(&qemu_det_ipi, "crucible_sim_det_ipi_drain_pending();");
    assert_contains(&qemu_det_ipi, "icount_crucible_rr_switch_quantum() != 0");
    assert_contains(
        &qemu_det_ipi,
        "qemu_plugin_crucible_maybe_fire_ipi_delivery_cb",
    );
    assert_contains(
        &qemu_det_ipi,
        "qemu_plugin_crucible_register_ipi_delivery_cb(on_det_ipi_delivery, NULL)",
    );
    assert_contains(&qemu_det_ipi, "accelerator = \"sim\";");
    assert_contains(&qemu_det_ipi, "stopAt = 32768;");
    assert_contains(&qemu_det_ipi, "select(.kind == \"det_ipi\")");
    assert_contains(&qemu_det_ipi, "any($events[]; .delivery_mode == 0)");
    assert_contains(&qemu_det_ipi, "any($events[]; .delivery_mode == 5)");
    assert_contains(&qemu_det_ipi, "any($events[]; .delivery_mode == 6)");
    assert_contains(&qemu_det_ipi, "deterministic_ipi_fixed_mode_trace=true");
    assert_contains(&qemu_det_ipi, "deterministic_ipi_init_mode_trace=true");
    assert_contains(&qemu_det_ipi, "deterministic_ipi_sipi_mode_trace=true");
    assert_contains(
        &qemu_det_ipi,
        "deterministic_ipi_delivery_icount_trace_match=true",
    );
    assert_contains(
        &qemu_det_ipi,
        "stock_negative_control_scope=non-sim-and-self-IPI-use-upstream-path",
    );

    let qemu_vcpu_introspect =
        fs::read_to_string(root.join("tests/crucible/phase2-qemu-vcpu-introspect.nix"))?;
    assert_contains(&qemu_vcpu_introspect, "T-PATCH-23");
    assert_contains(&qemu_vcpu_introspect, "0029-crucible-vcpu-introspect.patch");
    assert_contains(&qemu_vcpu_introspect, "qemu_plugin_read_vcpu_regs");
    assert_contains(&qemu_vcpu_introspect, "qemu_plugin_rr_cursor");
    assert_contains(&qemu_vcpu_introspect, "aos-qemu-vcpu-regs-v1");
    assert_contains(
        &qemu_vcpu_introspect,
        "register_short_buffer_fails_closed=true",
    );
    assert_contains(&qemu_vcpu_introspect, "register_read_side_effect_free=true");
    assert_contains(
        &qemu_vcpu_introspect,
        "register_size_mismatch_rejected=true",
    );
    assert_contains(&qemu_vcpu_introspect, "rr_cursor_boundary_rejected=true");
    assert_contains(
        &qemu_vcpu_introspect,
        "rr_cursor_out_of_range_current_vcpu_rejected=true",
    );
    assert_contains(&qemu_vcpu_introspect, "qemu-crucible-reference");
    assert_contains(
        &qemu_vcpu_introspect,
        "trace plugin publishes formal cursor validity",
    );
    assert_contains(
        &qemu_vcpu_introspect,
        "dynamic_symbol_qemu_plugin_read_vcpu_regs=true",
    );
    assert_contains(
        &qemu_vcpu_introspect,
        "dynamic_symbol_qemu_plugin_rr_cursor=true",
    );

    let qemu_patch_regeneration =
        fs::read_to_string(root.join("tests/crucible/phase2-qemu-patch-regeneration.nix"))?;
    assert_contains(
        &qemu_patch_regeneration,
        "patch_regeneration_from_tracked_stack=true",
    );
    assert_contains(
        &qemu_patch_regeneration,
        "patch_branch_bundle_verified=true",
    );
    assert_contains(
        &qemu_patch_regeneration,
        "patch_branch_commit_hashes_match_manifest=true",
    );
    assert_contains(
        &qemu_patch_regeneration,
        "regenerated_patch_bytes_match_committed=true",
    );
    assert_contains(
        &qemu_patch_regeneration,
        "regenerated_patch_context_lines=3",
    );
    assert_contains(
        &qemu_patch_regeneration,
        "apply_clean_regenerated_series=true",
    );
    assert_contains(
        &qemu_patch_regeneration,
        "qemu_build_identity_metadata_installed=true",
    );
    assert_contains(
        &qemu_patch_regeneration,
        "qemu_build_id_material_includes=qemu_version,qemu_source_hash,qemu_nix_hash,qemu_configure_flags_hash,patch_series_hash,patch_branch_bundle_hash,patch_branch_material_hash",
    );
    assert_contains(
        &qemu_patch_regeneration,
        "artifact_validator_rejects_mismatch=true",
    );
    assert_contains(
        &qemu_patch_regeneration,
        "qemu_version_bump_regate_enforced=true",
    );
    assert_contains(
        &qemu_patch_regeneration,
        "changed_build_negative_control=mutated_build_id_material",
    );

    let qemu_nix = fs::read_to_string(root.join("pkgs/emulation/qemu.nix"))?;
    assert_contains(&qemu_nix, "series ? import ./qemu-patches/_series.nix");
    assert_contains(&qemu_nix, "version = series.qemuVersion;");
    assert_contains(&qemu_nix, "hash = series.qemuSourceHash;");
    assert_contains(&qemu_nix, "patchCommand = file:");
    assert_contains(
        &qemu_nix,
        "builtins.concatStringsSep \"\" (map patchCommand series.patchFiles)",
    );
    assert_contains(&qemu_nix, "qemu_nix_hash=");
    assert_contains(&qemu_nix, "qemu_configure_flags_hash=");
    assert_contains(&qemu_nix, "qemu_patch_branch_bundle_hash=");
    assert_contains(&qemu_nix, "qemu-build-identity.env");
    assert_contains(&qemu_nix, "qemu_build_id=");

    let setup = fs::read_to_string(root.join("crates/crucible-qemu-plugin/src/setup.rs"))?;
    assert_contains(&setup, "RegisteredWakeFd");
    assert_contains(&setup, "registered_wake_fd");
    assert_contains(&setup, "register_with_qemu");
    assert_contains(&setup, "QemuRegisterWakeFdFn");

    let registration =
        fs::read_to_string(root.join("crates/crucible-qemu-plugin/src/registration.rs"))?;
    assert_contains(&registration, "register_tcg_exec_cb(");
    assert_contains(&registration, "Some(");
    assert_contains(&registration, "crucible_qemu_plugin_coverage_exec_cb");

    for patch in EXPECTED_PATCHES {
        assert_contains(&aggregate, patch);
        assert_contains(&aggregate, "grep -q '^patch=${test.patch}$' \"$result\"");
        assert_contains(&aggregate, "grep -q '^patched_fixture_exercised=true$'");
        assert_contains(&aggregate, "grep -q '^stock_negative_control=true$'");
    }

    Ok(())
}

#[test]
fn per_patch_microtests_publish_required_evidence() -> Result<(), Box<dyn Error>> {
    let root = workspace_root()?;
    let per_patch_checks = [
        (
            "tests/crucible/phase1-sim-accel.nix",
            "",
            "0001-crucible-sim-accel.patch",
        ),
        (
            "tests/crucible/phase1-rr-fingerprint-helpers.nix",
            "tests/crucible/phase1-rr-fingerprint-helpers.c",
            "0002-crucible-rr-fingerprint-helpers.patch",
        ),
        (
            "tests/crucible/phase1-icount-no-realtime.nix",
            "tests/crucible/phase1-icount-no-realtime.c",
            "0003-crucible-icount-no-realtime.patch",
        ),
        (
            "tests/crucible/phase1-no-warp-with-plugin.nix",
            "tests/crucible/phase1-no-warp-with-plugin.c",
            "0004-crucible-no-warp-with-plugin.patch",
        ),
        (
            "tests/crucible/phase1-qemu-deterministic-entropy.nix",
            "tests/crucible/phase1-qemu-deterministic-entropy.c",
            "0005-crucible-det-glib-prng.patch",
        ),
        (
            "tests/crucible/phase1-clock-deadline.nix",
            "tests/crucible/phase1-clock-deadline.c",
            "0006-crucible-clock-deadline.patch",
        ),
        (
            "tests/crucible/phase1-block-rtc-read.nix",
            "tests/crucible/phase1-block-rtc-read.c",
            "0007-crucible-block-rtc-read.patch",
        ),
        (
            "tests/crucible/phase1-qemu-deterministic-getrandom.nix",
            "tests/crucible/phase1-qemu-deterministic-entropy.c",
            "0008-crucible-det-getrandom.patch",
        ),
        (
            "tests/crucible/phase1-qemu-net-deterministic.nix",
            "tests/crucible/phase1-qemu-net-deterministic.c",
            "0009-crucible-net-deterministic.patch",
        ),
        (
            "tests/crucible/phase1-plugin-time-advance.nix",
            "tests/crucible/phase1-plugin-time-advance.c",
            "0010-crucible-plugin-time-advance.patch",
        ),
        (
            "tests/crucible/phase1-plugin-runtime-apis.nix",
            "tests/crucible/phase1-plugin-runtime-apis.c",
            "0011-crucible-plugin-icount-raw.patch",
        ),
        (
            "tests/crucible/phase1-plugin-runtime-apis.nix",
            "tests/crucible/phase1-plugin-runtime-apis.c",
            "0012-crucible-plugin-vcpu-exit.patch",
        ),
        (
            "tests/crucible/phase1-plugin-runtime-apis.nix",
            "tests/crucible/phase1-plugin-runtime-apis.c",
            "0013-crucible-plugin-wake-fd.patch",
        ),
        (
            "tests/crucible/phase1-plugin-runtime-apis.nix",
            "tests/crucible/phase1-plugin-runtime-apis.c",
            "0014-crucible-plugin-tcg-exec-cb.patch",
        ),
        (
            "tests/crucible/phase1-qemu-block-shmem.nix",
            "tests/crucible/phase1-qemu-block-shmem.c",
            "0015-crucible-blk-shmem.patch",
        ),
        (
            "tests/crucible/phase1-qemu-block-shmem.nix",
            "tests/crucible/phase1-qemu-block-shmem.c",
            "0016-crucible-blk-shmem-io-fixes.patch",
        ),
        (
            "tests/crucible/phase1-qemu-block-shmem.nix",
            "tests/crucible/phase1-qemu-block-shmem.c",
            "0017-crucible-blk-write-sentinel.patch",
        ),
        (
            "tests/crucible/phase1-qemu-9p-shmem.nix",
            "tests/crucible/phase1-qemu-9p-shmem.c",
            "0018-crucible-dev-cb-api.patch",
        ),
        (
            "tests/crucible/phase1-qemu-9p-shmem.nix",
            "tests/crucible/phase1-qemu-9p-shmem.c",
            "0019-crucible-9p-shmem.patch",
        ),
        (
            "tests/crucible/phase1-qemu-net-tx-callback.nix",
            "tests/crucible/phase1-qemu-net-tx-callback.c",
            "0020-crucible-net-tx-callback.patch",
        ),
        (
            "tests/crucible/phase1-qemu-sim-correctness.nix",
            "tests/crucible/phase1-qemu-sim-correctness.c",
            "0021-crucible-sim-loop-fix.patch",
        ),
        (
            "tests/crucible/phase1-qemu-sim-correctness.nix",
            "tests/crucible/phase1-qemu-sim-correctness.c",
            "0022-crucible-sim-first-exit.patch",
        ),
        (
            "tests/crucible/phase1-qemu-sim-correctness.nix",
            "tests/crucible/phase1-qemu-sim-correctness.c",
            "0023-crucible-sim-skip-second-events.patch",
        ),
        (
            "tests/crucible/phase1-qemu-sim-correctness.nix",
            "tests/crucible/phase1-qemu-sim-correctness.c",
            "0024-crucible-sim-poll-immediate.patch",
        ),
        (
            "tests/crucible/phase1-qemu-sim-correctness.nix",
            "tests/crucible/phase1-qemu-sim-correctness.c",
            "0025-crucible-sim-idle-callbacks.patch",
        ),
        (
            "tests/crucible/phase1-qemu-sim-correctness.nix",
            "tests/crucible/phase1-qemu-sim-correctness.c",
            "0026-crucible-sim-shmem-dispatch.patch",
        ),
        (
            "tests/crucible/phase1-qemu-sim-batch-tcg-exec.nix",
            "tests/crucible/phase1-qemu-sim-batch-tcg-exec.c",
            "0027-crucible-sim-batch-tcg-exec.patch",
        ),
        (
            "tests/crucible/phase2-qemu-det-ipi.nix",
            "",
            "0028-crucible-det-ipi.patch",
        ),
        (
            "tests/crucible/phase2-qemu-vcpu-introspect.nix",
            "tests/crucible/phase2-qemu-vcpu-introspect.c",
            "0029-crucible-vcpu-introspect.patch",
        ),
    ];

    for (nix_path, c_path, patch) in per_patch_checks {
        let nix_source = fs::read_to_string(root.join(nix_path))?;

        assert_contains(&nix_source, "gate=gate:patch-microtests");
        if nix_path == "tests/crucible/phase1-plugin-runtime-apis.nix" {
            assert_contains(&nix_source, "patch=${patchName}");
            assert_contains(&nix_source, patch);
            assert_contains(&nix_source, "tcg_exec_callback_after_icount_context=true");
        } else if nix_path == "tests/crucible/phase1-qemu-block-shmem.nix" {
            assert_contains(&nix_source, "patch=${patchName}");
            assert_contains(&nix_source, patch);
        } else if nix_path == "tests/crucible/phase1-qemu-9p-shmem.nix" {
            assert_contains(&nix_source, "patch=${patchName}");
            assert_contains(&nix_source, patch);
        } else if nix_path == "tests/crucible/phase1-qemu-net-tx-callback.nix" {
            assert_contains(&nix_source, "patch=${patchName}");
            assert_contains(&nix_source, patch);
        } else if nix_path == "tests/crucible/phase1-qemu-sim-correctness.nix" {
            assert_contains(&nix_source, "patch=${patchName}");
            assert_contains(&nix_source, patch);
            assert_contains(&nix_source, "sim_correctness_fixture_exercised=true");
            assert_contains(&nix_source, "sim_poll_immediate_repoll_microtest=true");
            assert_contains(&nix_source, "sim_poll_immediate_requires_time_control=true");
            assert_contains(
                &nix_source,
                "sim_poll_immediate_drain_bql_guard_validated=true",
            );
            assert_contains(&nix_source, "sim_idle_callbacks_missed_wake_microtest=true");
            assert_contains(&nix_source, "sim_shmem_dispatch_ceiling_microtest=true");
            assert_contains(&nix_source, "sim_shmem_budget_clamp_microtest=true");
        } else if nix_path == "tests/crucible/phase1-qemu-sim-batch-tcg-exec.nix" {
            assert_contains(&nix_source, "patch=${patchName}");
            assert_contains(&nix_source, patch);
            assert_contains(&nix_source, "sim_batch_tcg_exec_fixed_limit=true");
            assert_contains(
                &nix_source,
                "sim_batch_tcg_exec_on_off_icount_trace_identical=true",
            );
            assert_contains(
                &nix_source,
                "sim_batch_tcg_exec_breaks_on_halted_debug_atomic=true",
            );
            assert_contains(&nix_source, "sim_batch_tcg_exec_timer_between_slots=true");
            assert_contains(&nix_source, "sim_batch_tcg_exec_shmem_ceiling_guard=true");
        } else if nix_path == "tests/crucible/phase2-qemu-det-ipi.nix" {
            assert_contains(&nix_source, "patch=${patchName}");
            assert_contains(&nix_source, patch);
            assert_contains(
                &nix_source,
                "deterministic_ipi_rr_handoff=queued-drain-before-next-vcpu",
            );
            assert_contains(&nix_source, "deterministic_ipi_fixed_mode_trace=true");
            assert_contains(&nix_source, "deterministic_ipi_init_mode_trace=true");
            assert_contains(&nix_source, "deterministic_ipi_sipi_mode_trace=true");
            assert_contains(
                &nix_source,
                "deterministic_ipi_delivery_icount_trace_match=true",
            );
            assert_contains(&nix_source, "deterministic_ipi_source_target_distinct=true");
        } else if nix_path == "tests/crucible/phase2-qemu-vcpu-introspect.nix" {
            assert_contains(&nix_source, "patch=${patchName}");
            assert_contains(&nix_source, patch);
            assert_contains(
                &nix_source,
                "formal_register_export=qemu_plugin_read_vcpu_regs",
            );
            assert_contains(&nix_source, "formal_cursor_export=qemu_plugin_rr_cursor");
            assert_contains(&nix_source, "arbitrary_vcpu_register_read=true");
            assert_contains(&nix_source, "register_read_side_effect_free=true");
            assert_contains(&nix_source, "register_short_buffer_fails_closed=true");
            assert_contains(&nix_source, "register_size_mismatch_rejected=true");
            assert_contains(&nix_source, "rr_cursor_boundary_rejected=true");
            assert_contains(
                &nix_source,
                "rr_cursor_out_of_range_current_vcpu_rejected=true",
            );
        } else {
            assert_contains(&nix_source, &format!("patch={patch}"));
        }
        assert_contains(&nix_source, "patched_fixture_exercised=true");
        assert_contains(&nix_source, "stock_negative_control");
        assert_contains(&nix_source, "qemuPackage ?");
        assert_contains(&nix_source, "qemu_package=${qemuPackage}");
        assert_contains(&nix_source, "qemu_package_version=${qemuPackage.version}");
        assert_contains(&nix_source, "patch --batch --fuzz=0 -p1");
        if !c_path.is_empty() {
            let c_source = fs::read_to_string(root.join(c_path))?;
            assert_contains(&c_source, "stock_negative_control");
        }
    }

    Ok(())
}

fn patch_files(path: &Path) -> Result<BTreeSet<&'static str>, Box<dyn Error>> {
    let mut patches = BTreeSet::new();
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.ends_with(".patch") {
            let patch = EXPECTED_PATCHES
                .iter()
                .copied()
                .find(|expected| *expected == name);
            if let Some(patch) = patch {
                patches.insert(patch);
            } else {
                panic!("unexpected carried QEMU patch `{name}`");
            }
        }
    }
    Ok(patches)
}

fn assert_contains(haystack: &str, needle: &str) {
    assert!(
        haystack.contains(needle),
        "expected to find `{needle}` in checked source"
    );
}

fn workspace_root() -> Result<PathBuf, Box<dyn Error>> {
    let mut current = std::env::current_dir()?;
    loop {
        if current.join("crates/Cargo.toml").is_file()
            && current.join("tests/crucible/default.nix").is_file()
        {
            return Ok(current);
        }
        if !current.pop() {
            return Err("could not locate workspace root".into());
        }
    }
}
