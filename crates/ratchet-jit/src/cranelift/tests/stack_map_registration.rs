//! Cranelift registration coverage for compiled stack-map helpers.

use super::*;

#[test]
fn forced_artifact_definition_registers_stack_map_brackets() {
    let candidates = with_stack_map_candidates([
        synthetic_address_candidate(
            "aos_env_get",
            RuntimeSymbolKind::Helper(RuntimeHelperRole::EnvironmentAccess),
            3,
        ),
        synthetic_address_candidate(
            "aos_force",
            RuntimeSymbolKind::Helper(RuntimeHelperRole::ForcingControl),
            5,
        ),
    ]);
    let preflight = jit_cranelift_registered_artifact_definition_preflight_with_candidates(
        forced_env_get_artifact(4),
        &candidates,
    )
    .expect("registered forced env-get artifact definition preflight builds");
    assert_eq!(preflight.defined_function().symbol_name(), "aos.jit.ir_root.0.thunk_body");
    assert_eq!(preflight.defined_function().linkage(), Linkage::Export);
    let symbols = preflight
        .artifact_runtime_imports()
        .iter()
        .map(JitModuleArtifactRuntimeImport::symbol_name)
        .collect::<Vec<_>>();
    assert_eq!(symbols, ["aos_env_get", "aos_force", "aos_jit_stack_map_enter", "aos_jit_stack_map_exit"]);
    for (symbol, address) in [("aos_env_get", 3), ("aos_force", 5)] {
        assert!(preflight.imported_symbol_for(symbol).is_some());
        assert_eq!(
            preflight.registered_symbol_for(symbol).expect("helper is registered")
                .address().as_nonzero_usize().get(),
            address
        );
        assert!(preflight.registration_gap_for_symbol(symbol).is_none());
    }
    assert!(!preflight.is_complete());
    assert!(preflight.owns_encapsulated_module());
}
