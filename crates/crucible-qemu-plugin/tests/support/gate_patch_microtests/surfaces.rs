//! Second half of `assert_covers_carried_qemu_patch_series`: the plugin ABI
//! surface, per-patch nix fixtures, `qemu.nix`, and the roster-wide aggregate
//! result-line checks.

use std::error::Error;
use std::fs;

use super::common::{EXPECTED_PATCHES, assert_contains, required, workspace_root};

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
    assert_contains(
        &qemu_patch_series,
        "0035-crucible-process-argv-attestation.patch",
    );
    assert_contains(
        &qemu_patch_series,
        "process-entry raw Unix argc/argv v2 SHA-256 self-attestation",
    );
    assert_contains(&qemu_patch_series, "0036-crucible-raw-state-export.patch");
    assert_contains(
        &qemu_patch_series,
        "GPA-sorted exact guest-RAM export and terminal one-shot serialized non-RAM VMState snapshot",
    );

    let qemu_raw_state_export = fs::read_to_string(
        root.join("pkgs/emulation/qemu-patches/0036-crucible-raw-state-export.patch"),
    )?;
    assert_contains(
        &qemu_raw_state_export,
        "qemu_plugin_crucible_guest_ram_regions(",
    );
    assert_contains(
        &qemu_raw_state_export,
        "qemu_plugin_crucible_guest_ram_region_copy(",
    );
    assert_contains(
        &qemu_raw_state_export,
        "qemu_plugin_crucible_request_terminal_pause(",
    );
    assert_contains(
        &qemu_raw_state_export,
        "view = address_space_to_flatview(&address_space_memory);",
    );
    assert_contains(
        &qemu_raw_state_export,
        "flatview_for_each_section(view, crucible_collect_ram_region, &state);",
    );
    assert_contains(&qemu_raw_state_export, "section->readonly");
    assert_contains(
        &qemu_raw_state_export,
        "+    if (!memory_region_is_ram(mr)) {\n+        return false;\n+    }\n+    if (memory_region_is_protected(mr)) {",
    );
    assert_contains(
        &qemu_raw_state_export,
        "section->readonly || memory_region_is_rom(mr) ||\n+        memory_region_is_ram_device(mr)",
    );
    assert_contains(&qemu_raw_state_export, "return -ESTALE;");
    assert_contains(&qemu_raw_state_export, "return -ERANGE;");
    assert_contains(
        &qemu_raw_state_export,
        "qemu_plugin_crucible_vmstate_snapshot_begin(",
    );
    assert_contains(
        &qemu_raw_state_export,
        "crucible_terminal_vmstate_export_latched = true;",
    );
    assert_contains(
        &qemu_raw_state_export,
        "crucible_terminal_vmstate_export_latched = true;\n+    buffer = qio_channel_buffer_new(4096);",
    );
    assert_contains(
        &qemu_raw_state_export,
        "VM resume rejected after terminal Crucible VMState export",
    );
    assert_contains(
        &qemu_raw_state_export,
        "VM reset rejected after terminal Crucible VMState export",
    );
    assert_contains(
        &qemu_raw_state_export,
        "vCPU execution rejected after terminal Crucible VMState export",
    );
    let incoming_setup_tail = required(
        qemu_raw_state_export.split_once(
            "@@ -697,6 +701,12 @@ migration_incoming_state_setup(MigrationIncomingState *mis, Error **errp)",
        ),
        "raw-state patch must modify incoming migration state setup",
    )
    .1;
    let incoming_setup_hunk = required(
        incoming_setup_tail.split_once("\n@@"),
        "incoming migration setup patch hunk must have a bounded body",
    )
    .0;
    let incoming_state_read = required(
        incoming_setup_hunk.find("MigrationStatus current = mis->state;"),
        "incoming migration setup must retain its initial state read",
    );
    let incoming_seal_guard = required(
        incoming_setup_hunk.find("migration_crucible_raw_state_export_sealed()"),
        "incoming migration setup must reject work after terminal sealing",
    );
    let incoming_first_setup_branch = required(
        incoming_setup_hunk.find("if (current == MIGRATION_STATUS_POSTCOPY_PAUSED)"),
        "incoming migration setup must retain its first pre-existing branch",
    );
    assert!(
        incoming_state_read < incoming_seal_guard
            && incoming_seal_guard < incoming_first_setup_branch,
        "terminal sealing must be checked inside incoming migration setup before any incoming state mutation or transport setup"
    );
    let loadvm_main_tail = required(
        qemu_raw_state_export
            .split_once("int qemu_loadvm_state_main(QEMUFile *f, MigrationIncomingState *mis)"),
        "raw-state patch must modify the central VMState load loop",
    )
    .1;
    let loadvm_main = required(
        loadvm_main_tail.split_once("int qemu_loadvm_state(QEMUFile *f)"),
        "central VMState load-loop patch hunk must have a bounded body",
    )
    .0;
    let load_admission = required(
        loadvm_main.find("migration_crucible_load_begin()"),
        "central VMState load loop must enter migration admission",
    );
    let load_retry = required(
        loadvm_main.find("retry:"),
        "central VMState load loop must retain its retry boundary",
    );
    assert!(
        load_admission < load_retry,
        "migration admission must be entered before central VMState loading"
    );
    assert_eq!(
        loadvm_main
            .matches("migration_crucible_load_begin()")
            .count(),
        1,
        "central VMState load loop must increment its loader count once"
    );
    assert_eq!(
        loadvm_main.matches("migration_crucible_load_end()").count(),
        2,
        "central VMState load loop must balance its normal and latched exits"
    );
    assert_contains(
        &qemu_raw_state_export,
        "crucible_active_loaders != 0 || migration_is_running()",
    );
    assert_contains(
        &qemu_raw_state_export,
        "incoming != MIGRATION_STATUS_NONE &&",
    );
    assert_contains(
        &qemu_raw_state_export,
        "postcopy != POSTCOPY_INCOMING_NONE &&",
    );
    assert!(
        qemu_raw_state_export
            .matches("status = migration_crucible_raw_state_export_admit();")
            .count()
            >= 2,
        "RAM and VMState export must both enforce migration admission"
    );
    assert_contains(
        &qemu_raw_state_export,
        "this is a terminal dump API, not an",
    );

    let qemu_process_argv_attestation =
        fs::read_to_string(root.join("tests/crucible/phase2-qemu-process-argv-attestation.nix"))?;
    assert_contains(
        &qemu_process_argv_attestation,
        "0035-crucible-process-argv-attestation.patch",
    );
    assert_contains(
        &qemu_process_argv_attestation,
        "+    crucible_capture_process_argv(argc, argv);\\n     qemu_init(argc, argv);",
    );
    assert_contains(
        &qemu_process_argv_attestation,
        "crucible.qemu.raw-unix-argv.v2",
    );
    assert_contains(
        &qemu_process_argv_attestation,
        "argv_length_framing_defeats_concatenation_and_empty_ambiguity",
    );
    assert_contains(
        &qemu_process_argv_attestation,
        "raw_non_utf8_and_argv0_bytes_are_bound",
    );
    assert_contains(
        &qemu_process_argv_attestation,
        "qemu_plugin_crucible_process_argv_attestation",
    );
    assert_contains(
        &qemu_process_argv_attestation,
        "invalid process argv self-attestation",
    );
    assert_contains(
        &qemu_process_argv_attestation,
        "crucible.qemu.trace-fingerprint.v6",
    );
    assert_contains(&qemu_process_argv_attestation, "actual_argv_digest=");
    assert_contains(&qemu_process_argv_attestation, "control_digest=");
    assert_contains(&qemu_process_argv_attestation, "invocation_digest=");
    assert_contains(
        &qemu_process_argv_attestation,
        "actual_argv_hash_complete=true",
    );
    assert_contains(&qemu_process_argv_attestation, "process_argv_digest");
    assert_contains(
        &qemu_process_argv_attestation,
        "stock QEMU unexpectedly exposed process argv attestation",
    );
    assert_contains(
        &qemu_process_argv_attestation,
        "circular_identity_digest_in_plugin_argv=false",
    );

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
    assert_contains(&qemu_rr_quantum_icount, "cadence = 1048576;");
    assert_contains(&qemu_rr_quantum_icount, "requireGuestPass = false;");
    assert_contains(&qemu_rr_quantum_icount, "stopAt = 4194304;");
    assert_contains(&qemu_rr_quantum_icount, "vcpus=2");
    assert_contains(
        &qemu_rr_quantum_icount,
        "require_line \"$s11_result\" \"accelerator=sim,thread=single\"",
    );
    assert_contains(
        &qemu_rr_quantum_icount,
        "require_line \"$s11_result\" \"run_horizon=plugin-stop_at-4194304\"",
    );
    assert_contains(
        &qemu_rr_quantum_icount,
        "require_line \"$s11_result\" \"periodic_samples_expected=4\"",
    );
    assert_contains(
        &qemu_rr_quantum_icount,
        "require_line \"$s11_result\" \"periodic_samples_observed=4\"",
    );
    assert_contains(
        &qemu_rr_quantum_icount,
        "require_line \"$s11_result\" \"samples=5\"",
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
    assert_contains(&s11, "select((.kind // \"sample\") == \"sample\")");
    assert_contains(&s11, "select(.kind == \"rr_switch\")");
    assert_contains(&s11, "and (.observed_icount - $stop_at) <= $quantum");
    assert_contains(
        &s11,
        "and (.[-1] | ((.kind // \"sample\") == \"sample\" and .final == true))",
    );
    assert_contains(&s11, "exact_horizon_authoritative=true");
    assert_contains(
        &s11,
        "plugin_exit_semantics=post-stop-request-teardown-observation",
    );
    assert_contains(&s11, "plugin_exit_pause_overshoot_bounded=true");
    assert_contains(&s11, "plugin_exit_fingerprint_compared=diagnostic-only");

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
