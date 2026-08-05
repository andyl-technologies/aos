//! Module-readiness coverage for compiled stack-map helper imports.

use super::*;

#[test]
fn forced_env_get_artifact_imports_stack_map_brackets() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::LocalVar,
            Span::new(0, 1),
            EffectClass::pure(),
            IrData::Local { slot: 6 },
        )],
        Vec::new(),
    );
    let artifact = lower_forced_env_get_ir_thunk_body_artifact(&arena, IrId::new(0))
        .expect("forced env-get artifact lowers");
    let preflight =
        jit_module_readiness_preflight_for_artifact(&artifact).expect("module preflight builds");
    let imports = preflight
        .artifact_runtime_imports()
        .iter()
        .map(|runtime_import| {
            (
                runtime_import.symbol_name(),
                runtime_import.user_external_name().clone(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        imports,
        vec![
            ("aos_env_get", clif_external_name_for_aos_env_get()),
            ("aos_force", clif_external_name_for_aos_force()),
            (
                "aos_jit_stack_map_enter",
                clif_external_name_for_aos_jit_stack_map_enter()
            ),
            (
                "aos_jit_stack_map_exit",
                clif_external_name_for_aos_jit_stack_map_exit()
            ),
        ]
    );
    assert!(preflight.artifact_runtime_import_gaps().is_empty());
    for symbol in [
        "aos_env_get",
        "aos_force",
        "aos_jit_stack_map_enter",
        "aos_jit_stack_map_exit",
    ] {
        assert!(preflight.declaration_for_symbol(symbol).is_some());
    }
}
