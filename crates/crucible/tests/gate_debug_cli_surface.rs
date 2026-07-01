use crucible::DebugCliSurfaceContract;

#[test]
fn debug_cli_surface_contract_covers_t_dbg_8_policy() {
    let contract = DebugCliSurfaceContract::rfc0010();

    assert!(contract.proves_t_dbg_8());
    assert!(contract.coordinate_flags.contains(&"--at"));
    assert!(contract.coordinate_flags.contains(&"--at-event"));
    assert!(contract.coordinate_flags.contains(&"--at-failure"));
    assert!(contract.coordinate_flags.contains(&"--at-checkpoint"));
    assert!(contract.control_flags.contains(&"--node"));
    assert!(contract.control_flags.contains(&"--gdb-listen"));
    assert!(contract.control_flags.contains(&"--read-only"));
    assert!(contract.control_flags.contains(&"--allow-mutate"));
    assert!(contract.control_flags.contains(&"--checkpoint-stride"));
    assert!(contract.interactive_verbs.contains(&"attach-gdb"));
    assert!(contract.interactive_verbs.contains(&"goto"));
    assert!(contract.interactive_verbs.contains(&"reverse-step"));
    assert!(contract.interactive_verbs.contains(&"reverse-continue"));
    assert!(!contract.cli_holds_debug_state);
    assert!(contract.delegates_to_session_commands);
    assert!(contract.delegates_to_gdbstub_proxy);
    assert!(
        contract
            .symbol_resolution
            .proves_no_crucible_symbol_server()
    );
    assert!(contract.multi_vcpu.proves_multi_vcpu_coherence());
    assert!(contract.gdbstub_step.proves_s14_fallback());
    assert!(contract.read_mutate_boundary.proves_read_mutate_boundary());
    assert!(contract.reverse_latency.proves_reverse_latency_policy());
}

#[test]
fn debug_cli_surface_contract_rejects_symbol_server_or_raw_gdb_step() {
    let mut with_symbol_server = DebugCliSurfaceContract::rfc0010();
    with_symbol_server.symbol_resolution.crucible_symbol_server = true;
    assert!(
        !with_symbol_server
            .symbol_resolution
            .proves_no_crucible_symbol_server()
    );
    assert!(!with_symbol_server.proves_t_dbg_8());

    let mut with_raw_gdb_step = DebugCliSurfaceContract::rfc0010();
    with_raw_gdb_step
        .gdbstub_step
        .raw_gdb_single_step_disabled_until_green = false;
    assert!(!with_raw_gdb_step.gdbstub_step.proves_s14_fallback());
    assert!(!with_raw_gdb_step.proves_t_dbg_8());
}
