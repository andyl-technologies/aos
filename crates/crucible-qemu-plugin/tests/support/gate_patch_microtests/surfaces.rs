//! Second half of `assert_covers_carried_qemu_patch_series`: the plugin ABI
//! surface, per-patch nix fixtures, `qemu.nix`, and the roster-wide aggregate
//! result-line checks.

use std::error::Error;
use std::fs;

use super::common::{EXPECTED_PATCHES, assert_contains, workspace_root};

/// Asserts the plugin ABI, per-patch nix fixtures, `qemu.nix`, and the
/// aggregate result-line contract for every carried patch.
///
/// # Errors
///
/// Returns an error if any checked source file cannot be read.
pub(super) fn assert_plugin_and_series_surfaces() -> Result<(), Box<dyn Error>> {
    let root = workspace_root()?;
    let aggregate = fs::read_to_string(root.join("tests/crucible/phase2-patch-microtests.nix"))?;

    // The ABI module is split across `abi.rs` and the `abi/inert_callbacks.rs`
    // child module (the inert scaffold callbacks live there); concatenate both so
    // needles for either half resolve against a single checked-source haystack.
    let abi = format!(
        "{}\n{}",
        fs::read_to_string(root.join("crates/crucible-qemu-plugin/src/abi.rs"))?,
        fs::read_to_string(root.join("crates/crucible-qemu-plugin/src/abi/inert_callbacks.rs"))?,
    );
    assert_contains(&abi, "pub type QemuIcountRawFn");
    assert_contains(&abi, "pub type QemuForceVcpuExitFn");
    assert_contains(&abi, "pub type QemuRegisterWakeFdFn");
    assert_contains(&abi, "pub type QemuRegisterTcgExecCbFn");
    assert_contains(&abi, "pub type QemuRegisterBlkCbFn");
    assert_contains(&abi, "pub type QemuRegisterNinePCbFn");
    assert_contains(&abi, "resolve_qemu_icount_raw_symbol");
    assert_contains(&abi, "QEMU_PLUGIN_ICOUNT_AT_TB_ENTRY_SYMBOL_C");
    assert_contains(&abi, "resolve_qemu_force_vcpu_exit_symbol");
    assert_contains(&abi, "resolve_qemu_register_wake_fd_symbol");
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
    assert_contains(
        &qemu_rr_quantum_icount,
        "accelerator = \"sim,thread=single\";",
    );
    assert_contains(&qemu_rr_quantum_icount, "cadence = 4096;");
    assert_contains(&qemu_rr_quantum_icount, "requireGuestPass = false;");
    assert_contains(&qemu_rr_quantum_icount, "stopAt = 16384;");
    assert_contains(&qemu_rr_quantum_icount, "vcpus=2");
    assert_contains(
        &qemu_rr_quantum_icount,
        "require_line \"$s11_result\" \"accelerator=sim,thread=single\"",
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
    assert_contains(&qemu_rr_quantum_icount, "rr_switch_trace_match=false");
    assert_contains(&qemu_rr_quantum_icount, "per_vcpu_delta_trace_match=false");
    assert_contains(&qemu_rr_quantum_icount, "localize_first_difference");
    assert_contains(&qemu_rr_quantum_icount, "first_differing_node_icount");
    assert_contains(
        &qemu_rr_quantum_icount,
        "mismatch_localization_vcpu_negative_test=true",
    );
    assert_contains(
        &qemu_rr_quantum_icount,
        "mismatch_localization_rr_cursor_negative_test=true",
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

    let s11 = fs::read_to_string(root.join("tests/crucible/phase0-s11.nix"))?;
    assert_contains(&s11, "diagnose_trace_structure() {");
    assert_contains(
        &s11,
        "limit(10;\n                  inputs\n                  | select((.kind // \"sample\") == \"sample\")",
    );
    assert_contains(
        &s11,
        "limit(10;\n                  inputs\n                  | select(.kind == \"rr_switch\")",
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
    assert_contains(&qemu_det_ipi, "accelerator = \"sim,thread=single\";");
    assert_contains(&qemu_det_ipi, "stopAt = 4194304;");
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
        "qemu_build_id_material_includes=qemu_version,qemu_source_hash,qemu_nix_hash,qemu_configure_flags_hash,patch_series_hash,patch_branch_bundle_hash,patch_branch_material_hash,qemu_shmem_abi_version,qemu_shmem_header_hash",
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

    let coverage = fs::read_to_string(root.join("crates/crucible-qemu-plugin/src/coverage.rs"))?;
    assert_contains(&coverage, "register_tb_trans_cb");
    assert_contains(&coverage, "register_tb_exec_cb");
    assert_contains(&coverage, "icount_at_tb_entry");
    assert_contains(&coverage, "register_flush_cb");

    for patch in EXPECTED_PATCHES {
        assert_contains(&aggregate, patch);
        assert_contains(&aggregate, "grep -q '^patch=${test.patch}$' \"$result\"");
        assert_contains(&aggregate, "grep -q '^patched_fixture_exercised=true$'");
        assert_contains(&aggregate, "grep -q '^stock_negative_control=true$'");
    }

    Ok(())
}
