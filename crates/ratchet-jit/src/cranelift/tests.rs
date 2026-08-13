//! Cranelift finalize/execute tests: shared helpers + first batch (moved verbatim).

use std::{num::NonZeroUsize, ptr::NonNull};

use cranelift_codegen::ir::{ExtFuncData, ExternalName, Function, UserExternalName, UserFuncName};
use ratchet_core::{
    EffectClass, Ir, IrArena, IrAttrPathId, IrAttrPathSegment, IrData, IrFacts, IrId,
    IrInlineCacheSiteId, IrKind, IrNode, RuntimeHelperRole, RuntimeSymbolKind,
    runtime_helper_call_signature, runtime_thunk_call_signature,
    syntax::{BinOpKind, Span, SymbolTable},
};
use ratchet_value::value::Value;

use super::*;
use crate::{
    abi::clif_signature_for_runtime_call,
    lower::{
        AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE, clif_name_for_ir_root,
        lower_apply_local_slots_ir_thunk_body_artifact, lower_constant_ir_thunk_body_artifact,
        lower_constant_thunk_body_artifact, lower_env_get_ir_thunk_body_artifact,
        lower_forced_env_get_ir_thunk_body_artifact,
        lower_update_local_slots_ir_thunk_body_artifact,
    },
    module::{JitModuleReadinessError, jit_module_readiness_preflight_for_artifact},
    tier::{
        DEFAULT_TIER1_INVOCATION_THRESHOLD, JitCompiledCodePointer, JitTier, TierUpCounter,
        TierUpReasons,
    },
};

mod stack_map_registration;

fn synthetic_address(raw: usize) -> JitRuntimeSymbolAddress {
    JitRuntimeSymbolAddress::new(NonZeroUsize::new(raw).expect("test address is non-zero"))
}

fn synthetic_address_candidate(
    symbol_name: &str,
    kind: RuntimeSymbolKind,
    raw: usize,
) -> JitRuntimeSymbolAddressCandidate {
    JitRuntimeSymbolAddressCandidate::new(symbol_name.to_owned(), kind, synthetic_address(raw))
}

fn with_stack_map_candidates<const N: usize>(
    candidates: [JitRuntimeSymbolAddressCandidate; N],
) -> Vec<JitRuntimeSymbolAddressCandidate> {
    let mut candidates = Vec::from(candidates);
    candidates.push(synthetic_address_candidate(
        "aos_jit_stack_map_enter",
        RuntimeSymbolKind::Helper(RuntimeHelperRole::SafepointControl),
        101,
    ));
    candidates.push(synthetic_address_candidate(
        "aos_jit_stack_map_exit",
        RuntimeSymbolKind::Helper(RuntimeHelperRole::SafepointControl),
        103,
    ));
    candidates
}

fn synthetic_runtime_import_target() {}

fn synthetic_runtime_import_address() -> usize {
    synthetic_runtime_import_target as *const () as usize
}

fn env_get_artifact(slot: u32) -> JitClifArtifact {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::LocalVar,
            Span::new(0, 1),
            EffectClass::pure(),
            IrData::Local { slot },
        )],
        Vec::new(),
    );

    lower_env_get_ir_thunk_body_artifact(&arena, IrId::new(0)).expect("env-get artifact lowers")
}

fn forced_env_get_artifact(slot: u32) -> JitClifArtifact {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::LocalVar,
            Span::new(0, 1),
            EffectClass::pure(),
            IrData::Local { slot },
        )],
        Vec::new(),
    );

    lower_forced_env_get_ir_thunk_body_artifact(&arena, IrId::new(0))
        .expect("forced env-get artifact lowers")
}

fn apply_artifact(function_slot: u32, argument_slot: u32) -> JitClifArtifact {
    let arena = apply_arena(function_slot, argument_slot);

    lower_apply_local_slots_ir_thunk_body_artifact(&arena, IrId::new(2))
        .expect("apply artifact lowers")
}

fn update_artifact(left_slot: u32, right_slot: u32) -> JitClifArtifact {
    let arena = update_arena(left_slot, right_slot);

    lower_update_local_slots_ir_thunk_body_artifact(&arena, IrId::new(2))
        .expect("update artifact lowers")
}

fn apply_arena(function_slot: u32, argument_slot: u32) -> IrArena {
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::LocalVar,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Local {
                    slot: function_slot,
                },
            ),
            IrNode::new(
                IrKind::LocalVar,
                Span::new(2, 3),
                EffectClass::pure(),
                IrData::Local {
                    slot: argument_slot,
                },
            ),
            IrNode::new(
                IrKind::Apply,
                Span::new(0, 3),
                EffectClass::pure(),
                IrData::Pair {
                    first: IrId::new(0),
                    second: IrId::new(1),
                },
            ),
        ],
        Vec::new(),
    );

    arena
}

fn update_arena(left_slot: u32, right_slot: u32) -> IrArena {
    IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::LocalVar,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Local { slot: left_slot },
            ),
            IrNode::new(
                IrKind::LocalVar,
                Span::new(2, 3),
                EffectClass::pure(),
                IrData::Local { slot: right_slot },
            ),
            IrNode::new(
                IrKind::BinOp,
                Span::new(0, 3),
                EffectClass::pure(),
                IrData::Binary {
                    op: BinOpKind::Update,
                    lhs: IrId::new(0),
                    rhs: IrId::new(1),
                },
            ),
        ],
        Vec::new(),
    )
}

fn update_ir(left_slot: u32, right_slot: u32) -> Ir {
    let arena = update_arena(left_slot, right_slot);
    let facts = IrFacts::conservative(arena.nodes().len());
    Ir {
        root: IrId::new(2),
        arena,
        facts,
        symbols: SymbolTable::new(),
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: Box::new([]),
        bindings: Box::new([]),
        shapes: Box::new([]),
    }
}

fn static_select_ir(slot: u32) -> Ir {
    let mut symbols = SymbolTable::new();
    let symbol = symbols
        .intern(b"target")
        .expect("test symbol table accepts target");
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::LocalVar,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Local { slot },
            ),
            IrNode::new(
                IrKind::Select,
                Span::new(0, 8),
                EffectClass::pure(),
                IrData::Select {
                    receiver: IrId::new(0),
                    path: IrAttrPathId::new(0),
                    site: IrInlineCacheSiteId::new(11),
                    default: None,
                },
            ),
        ],
        Vec::new(),
    );
    let facts = IrFacts::conservative(arena.nodes().len());
    Ir {
        root: IrId::new(1),
        arena,
        facts,
        symbols,
        frames: Box::new([]),
        with_chains: Box::new([]),
        attr_paths: vec![vec![IrAttrPathSegment::Static(symbol)].into_boxed_slice()]
            .into_boxed_slice(),
        bindings: Box::new([]),
        shapes: Box::new([]),
    }
}

fn wrapped_apply_arena(function_slot: u32, argument_slot: u32) -> IrArena {
    IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::LocalVar,
                Span::new(0, 1),
                EffectClass::pure(),
                IrData::Local {
                    slot: function_slot,
                },
            ),
            IrNode::new(
                IrKind::LocalVar,
                Span::new(2, 3),
                EffectClass::pure(),
                IrData::Local {
                    slot: argument_slot,
                },
            ),
            IrNode::new(
                IrKind::Apply,
                Span::new(0, 3),
                EffectClass::pure(),
                IrData::Pair {
                    first: IrId::new(0),
                    second: IrId::new(1),
                },
            ),
            IrNode::new(
                IrKind::ThunkAlloc,
                Span::new(0, 3),
                EffectClass::pure(),
                IrData::Node(IrId::new(2)),
            ),
        ],
        Vec::new(),
    )
}

fn artifact_with_unknown_runtime_helper_import() -> JitClifArtifact {
    let mut function = Function::with_name_signature(
        UserFuncName::default(),
        clif_signature_for_runtime_call(runtime_thunk_call_signature())
            .expect("thunk signature lowers"),
    );
    let env_get_signature = clif_signature_for_runtime_call(
        runtime_helper_call_signature("aos_env_get")
            .expect("env-get helper signature is core-owned"),
    )
    .expect("env-get signature lowers");
    let signature_ref = function.import_signature(env_get_signature);
    let user_name = function.declare_imported_user_function(UserExternalName::new(
        AOS_RUNTIME_HELPER_FUNCTION_NAMESPACE,
        99,
    ));
    function.import_function(ExtFuncData {
        name: ExternalName::user(user_name),
        signature: signature_ref,
        colocated: false,
    });

    JitClifArtifact::new(
        JitTier::Tier1Baseline,
        JitClifArtifactKind::ThunkBody,
        JitClifArtifactSource::ConstantSmoke,
        function,
    )
}

fn artifact_runtime_import_names(imports: &[JitModuleArtifactRuntimeImport]) -> Vec<&str> {
    imports
        .iter()
        .map(JitModuleArtifactRuntimeImport::symbol_name)
        .collect()
}

#[test]
fn active_cranelift_versions_match_pin() {
    assert_eq!(
        ACTIVE_CRANELIFT_CODEGEN_VERSION,
        PINNED_CRANELIFT_CODEGEN_VERSION
    );
    assert_eq!(ACTIVE_CRANELIFT_JIT_VERSION, PINNED_CRANELIFT_JIT_VERSION);
    assert_eq!(
        ACTIVE_CRANELIFT_MODULE_VERSION,
        PINNED_CRANELIFT_MODULE_VERSION
    );
    assert_eq!(
        ACTIVE_CRANELIFT_NATIVE_VERSION,
        PINNED_CRANELIFT_NATIVE_VERSION
    );
}

#[test]
fn dependency_pin_exposes_exact_cranelift_versions() {
    let pin = jit_cranelift_dependency_pin();

    assert_eq!(pin.codegen_version(), PINNED_CRANELIFT_CODEGEN_VERSION);
    assert_eq!(pin.jit_version(), PINNED_CRANELIFT_JIT_VERSION);
    assert_eq!(pin.module_version(), PINNED_CRANELIFT_MODULE_VERSION);
    assert_eq!(pin.native_version(), PINNED_CRANELIFT_NATIVE_VERSION);
}

#[test]
fn symbol_registration_preflight_builds_module_without_default_registrations() {
    let preflight = jit_cranelift_symbol_registration_preflight_with_candidates(&[])
        .expect("JIT symbol registration preflight builds");

    assert!(preflight.registered_symbols().is_empty());
    assert!(!preflight.is_complete());
    assert!(preflight.owns_encapsulated_module());
    assert!(matches!(
        preflight.gap_for_symbol("aos_alloc_attrs"),
        Some(
            crate::symbols::JitRuntimeSymbolRegistrationGap::MissingNativeAddress {
                kind: RuntimeSymbolKind::Helper(RuntimeHelperRole::Allocation),
                ..
            }
        )
    ));
    assert!(matches!(
        preflight.gap_for_symbol("aos_force"),
        Some(
            crate::symbols::JitRuntimeSymbolRegistrationGap::MissingNativeAddress {
                kind: RuntimeSymbolKind::Helper(RuntimeHelperRole::ForcingControl),
                ..
            }
        )
    ));
}

#[test]
fn symbol_registration_preflight_registers_explicit_candidates_in_manifest_order() {
    let candidates = [
        synthetic_address_candidate(
            "nix.builtin.derivationStrict",
            RuntimeSymbolKind::Builtin,
            2,
        ),
        synthetic_address_candidate(
            "aos_alloc_attrs",
            RuntimeSymbolKind::Helper(RuntimeHelperRole::Allocation),
            1,
        ),
        synthetic_address_candidate(
            "aos_env_get",
            RuntimeSymbolKind::Helper(RuntimeHelperRole::EnvironmentAccess),
            3,
        ),
    ];
    let preflight = jit_cranelift_symbol_registration_preflight_with_candidates(&candidates)
        .expect("JIT symbol registration preflight builds");
    let registered_symbols = preflight
        .registered_symbols()
        .iter()
        .map(JitCraneliftRegisteredSymbol::symbol_name)
        .collect::<Vec<_>>();

    assert_eq!(
        registered_symbols,
        vec![
            "aos_alloc_attrs",
            "aos_env_get",
            "nix.builtin.derivationStrict"
        ]
    );
    assert_eq!(
        preflight
            .registered_symbol_for("aos_alloc_attrs")
            .expect("allocation helper is registered")
            .address()
            .as_nonzero_usize()
            .get(),
        1
    );
    assert!(preflight.gap_for_symbol("aos_alloc_attrs").is_none());
    assert_eq!(
        preflight
            .registered_symbol_for("aos_env_get")
            .expect("environment helper is registered")
            .address()
            .as_nonzero_usize()
            .get(),
        3
    );
    assert!(preflight.gap_for_symbol("aos_env_get").is_none());
    assert!(preflight.owns_encapsulated_module());
}

#[test]
fn symbol_registration_preflight_propagates_registration_metadata_errors() {
    let candidates = [synthetic_address_candidate(
        "aos_not_a_runtime_symbol",
        RuntimeSymbolKind::Builtin,
        1,
    )];
    let Err(error) = jit_cranelift_symbol_registration_preflight_with_candidates(&candidates)
    else {
        panic!("unknown address candidates must be rejected before builder setup");
    };

    assert!(matches!(
        error,
        JitCraneliftModuleSetupError::RuntimeSymbolRegistration(
            crate::symbols::JitRuntimeSymbolRegistrationError::UnknownAddressCandidate {
                symbol_name,
            }
        ) if symbol_name == "aos_not_a_runtime_symbol"
    ));
}

#[test]
fn symbol_registration_preflight_propagates_duplicate_candidate_errors() {
    let candidates = [
        synthetic_address_candidate("aos_alloc_attrs", RuntimeSymbolKind::Builtin, 1),
        synthetic_address_candidate("aos_alloc_attrs", RuntimeSymbolKind::Builtin, 2),
    ];
    let Err(error) = jit_cranelift_symbol_registration_preflight_with_candidates(&candidates)
    else {
        panic!("duplicate address candidates must be rejected before builder setup");
    };

    assert!(matches!(
        error,
        JitCraneliftModuleSetupError::RuntimeSymbolRegistration(
            crate::symbols::JitRuntimeSymbolRegistrationError::DuplicateAddressCandidate {
                symbol_name,
            }
        ) if symbol_name == "aos_alloc_attrs"
    ));
}

#[test]
fn symbol_registration_preflight_preserves_kind_mismatch_gaps() {
    let candidates = [synthetic_address_candidate(
        "aos_alloc_attrs",
        RuntimeSymbolKind::Builtin,
        1,
    )];
    let preflight = jit_cranelift_symbol_registration_preflight_with_candidates(&candidates)
        .expect("JIT symbol registration preflight builds");

    assert!(preflight.registered_symbol_for("aos_alloc_attrs").is_none());
    assert!(matches!(
        preflight.gap_for_symbol("aos_alloc_attrs"),
        Some(
            crate::symbols::JitRuntimeSymbolRegistrationGap::NativeAddressKindMismatch {
                declaration_kind: RuntimeSymbolKind::Helper(RuntimeHelperRole::Allocation),
                candidate_kind: RuntimeSymbolKind::Builtin,
                ..
            }
        )
    ));
}

#[test]
fn registered_artifact_definition_defines_env_get_artifact_with_candidate() {
    let candidates = [synthetic_address_candidate(
        "aos_env_get",
        RuntimeSymbolKind::Helper(RuntimeHelperRole::EnvironmentAccess),
        3,
    )];

    let preflight = jit_cranelift_registered_artifact_definition_preflight_with_candidates(
        env_get_artifact(4),
        &candidates,
    )
    .expect("registered env-get artifact definition preflight builds");

    assert_eq!(
        preflight.defined_function().symbol_name(),
        "aos.jit.ir_root.0.thunk_body"
    );
    assert_eq!(preflight.defined_function().linkage(), Linkage::Export);
    assert_eq!(preflight.artifact_runtime_imports().len(), 1);
    assert_eq!(
        preflight.artifact_runtime_imports()[0].symbol_name(),
        "aos_env_get"
    );
    assert!(preflight.imported_symbol_for("aos_env_get").is_some());
    assert_eq!(
        preflight
            .registered_symbol_for("aos_env_get")
            .expect("env helper is registered")
            .address()
            .as_nonzero_usize()
            .get(),
        3
    );
    assert!(
        preflight
            .registration_gap_for_symbol("aos_env_get")
            .is_none()
    );
    assert!(matches!(
        preflight.registration_gap_for_symbol("aos_force"),
        Some(
            crate::symbols::JitRuntimeSymbolRegistrationGap::MissingNativeAddress {
                kind: RuntimeSymbolKind::Helper(RuntimeHelperRole::ForcingControl),
                ..
            }
        )
    ));
    assert!(!preflight.is_complete());
    assert!(preflight.owns_encapsulated_module());
}

#[test]
fn registered_artifact_definition_defines_apply_artifact_with_candidates() {
    let candidates = [
        synthetic_address_candidate(
            "aos_env_get",
            RuntimeSymbolKind::Helper(RuntimeHelperRole::EnvironmentAccess),
            3,
        ),
        synthetic_address_candidate(
            "aos_apply",
            RuntimeSymbolKind::Helper(RuntimeHelperRole::CallControl),
            7,
        ),
    ];

    let preflight = jit_cranelift_registered_artifact_definition_preflight_with_candidates(
        apply_artifact(4, 6),
        &candidates,
    )
    .expect("registered apply artifact definition preflight builds");

    assert_eq!(
        preflight.defined_function().symbol_name(),
        "aos.jit.ir_root.2.thunk_body"
    );
    assert_eq!(preflight.defined_function().linkage(), Linkage::Export);
    assert_eq!(
        preflight
            .artifact_runtime_imports()
            .iter()
            .map(|runtime_import| runtime_import.symbol_name())
            .collect::<Vec<_>>(),
        ["aos_env_get", "aos_apply"]
    );
    assert!(preflight.imported_symbol_for("aos_env_get").is_some());
    assert!(preflight.imported_symbol_for("aos_apply").is_some());
    assert_eq!(
        preflight
            .registered_symbol_for("aos_env_get")
            .expect("env helper is registered")
            .address()
            .as_nonzero_usize()
            .get(),
        3
    );
    assert_eq!(
        preflight
            .registered_symbol_for("aos_apply")
            .expect("apply helper is registered")
            .address()
            .as_nonzero_usize()
            .get(),
        7
    );
    assert!(
        preflight
            .registration_gap_for_symbol("aos_env_get")
            .is_none()
    );
    assert!(preflight.registration_gap_for_symbol("aos_apply").is_none());
    assert!(!preflight.is_complete());
    assert!(preflight.owns_encapsulated_module());
}

#[test]
fn registered_artifact_definition_defines_update_artifact_with_candidates() {
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
        synthetic_address_candidate(
            "aos_update",
            RuntimeSymbolKind::Helper(RuntimeHelperRole::AttrsetAccess),
            7,
        ),
    ]);

    let preflight = jit_cranelift_registered_artifact_definition_preflight_with_candidates(
        update_artifact(4, 6),
        &candidates,
    )
    .expect("registered update artifact definition preflight builds");

    assert_eq!(
        preflight.defined_function().symbol_name(),
        "aos.jit.ir_root.2.thunk_body"
    );
    assert_eq!(preflight.defined_function().linkage(), Linkage::Export);
    assert_eq!(
        artifact_runtime_import_names(preflight.artifact_runtime_imports()),
        [
            "aos_env_get",
            "aos_force",
            "aos_jit_stack_map_enter",
            "aos_jit_stack_map_exit",
            "aos_update"
        ]
    );
    assert!(preflight.imported_symbol_for("aos_env_get").is_some());
    assert!(preflight.imported_symbol_for("aos_force").is_some());
    assert!(preflight.imported_symbol_for("aos_update").is_some());
    assert_eq!(
        preflight
            .registered_symbol_for("aos_update")
            .expect("update helper is registered")
            .address()
            .as_nonzero_usize()
            .get(),
        7
    );
    assert!(
        preflight
            .registration_gap_for_symbol("aos_update")
            .is_none()
    );
    assert!(!preflight.is_complete());
    assert!(preflight.owns_encapsulated_module());
}

#[test]
fn registered_artifact_definition_requires_candidates_for_artifact_imports() {
    let Err(error) = jit_cranelift_registered_artifact_definition_preflight_with_candidates(
        env_get_artifact(4),
        &[],
    ) else {
        panic!("env-get artifact definition requires registered env helper candidate");
    };

    let JitCraneliftModuleSetupError::ArtifactRuntimeImportsRequireRegistration { symbol_names } =
        error
    else {
        panic!("expected artifact runtime-import registration guard");
    };

    assert_eq!(symbol_names, ["aos_env_get".to_owned()]);
}

#[test]
fn registered_artifact_definition_requires_force_candidate_for_forced_artifacts() {
    let candidates = with_stack_map_candidates([synthetic_address_candidate(
        "aos_env_get",
        RuntimeSymbolKind::Helper(RuntimeHelperRole::EnvironmentAccess),
        3,
    )]);

    let Err(error) = jit_cranelift_registered_artifact_definition_preflight_with_candidates(
        forced_env_get_artifact(4),
        &candidates,
    ) else {
        panic!("forced env-get artifact definition requires registered force helper candidate");
    };

    let JitCraneliftModuleSetupError::ArtifactRuntimeImportsRequireRegistration { symbol_names } =
        error
    else {
        panic!("expected artifact runtime-import registration guard");
    };

    assert_eq!(symbol_names, ["aos_force".to_owned()]);
}

#[test]
fn registered_artifact_definition_preserves_unresolved_artifact_import_readiness() {
    let Err(error) = jit_cranelift_registered_artifact_definition_preflight_with_candidates(
        artifact_with_unknown_runtime_helper_import(),
        &[],
    ) else {
        panic!("unresolved artifact import must stay a readiness error");
    };

    let JitCraneliftModuleSetupError::Readiness(
        JitModuleReadinessError::UnresolvedArtifactRuntimeImports { preflight },
    ) = error
    else {
        panic!("expected unresolved artifact-import readiness error");
    };

    assert!(preflight.artifact_runtime_imports().is_empty());
    assert_eq!(preflight.artifact_runtime_import_gaps().len(), 1);
    assert!(!preflight.is_complete());
}

#[test]
fn registered_artifact_definition_rejects_wrong_kind_candidates_for_artifact_imports() {
    let candidates = [synthetic_address_candidate(
        "aos_env_get",
        RuntimeSymbolKind::Builtin,
        3,
    )];

    let Err(error) = jit_cranelift_registered_artifact_definition_preflight_with_candidates(
        env_get_artifact(4),
        &candidates,
    ) else {
        panic!("wrong-kind env helper candidate must not satisfy artifact imports");
    };

    let JitCraneliftModuleSetupError::ArtifactRuntimeImportsRequireRegistration { symbol_names } =
        error
    else {
        panic!("expected artifact runtime-import registration guard");
    };

    assert_eq!(symbol_names, ["aos_env_get".to_owned()]);
}

#[test]
fn registered_artifact_definition_allows_constant_artifacts_with_registration_gaps() {
    let artifact =
        lower_constant_thunk_body_artifact(Value::int(5)).expect("constant artifact lowers");

    let preflight =
        jit_cranelift_registered_artifact_definition_preflight_with_candidates(artifact, &[])
            .expect("constant artifact does not need runtime imports");

    assert_eq!(
        preflight.defined_function().symbol_name(),
        "aos.jit.constant_smoke.thunk_body"
    );
    assert!(preflight.artifact_runtime_imports().is_empty());
    assert!(preflight.registered_symbols().is_empty());
    assert!(preflight.imported_symbol_for("aos_env_get").is_some());
    assert!(matches!(
        preflight.registration_gap_for_symbol("aos_env_get"),
        Some(
            crate::symbols::JitRuntimeSymbolRegistrationGap::MissingNativeAddress {
                kind: RuntimeSymbolKind::Helper(RuntimeHelperRole::EnvironmentAccess),
                ..
            }
        )
    ));
    assert!(!preflight.is_complete());
    assert!(preflight.owns_encapsulated_module());
}

#[test]
fn registered_artifact_finalization_finalizes_env_get_artifact_with_candidate() {
    let env_get_address = synthetic_runtime_import_address();
    let candidates = [synthetic_address_candidate(
        "aos_env_get",
        RuntimeSymbolKind::Helper(RuntimeHelperRole::EnvironmentAccess),
        env_get_address,
    )];

    let preflight = jit_cranelift_registered_artifact_finalization_preflight_with_candidates(
        env_get_artifact(4),
        &candidates,
    )
    .expect("registered env-get artifact finalization preflight builds");

    assert_eq!(
        preflight.finalized_function().symbol_name(),
        "aos.jit.ir_root.0.thunk_body"
    );
    assert_eq!(
        preflight.finalized_function().defined_function().linkage(),
        Linkage::Export
    );
    assert_ne!(
        preflight.finalized_function().code_ptr().as_ptr() as usize,
        0
    );
    assert_eq!(
        preflight
            .finalized_function()
            .compiled_code_ptr()
            .as_non_null(),
        preflight.finalized_function().code_ptr()
    );
    assert_eq!(preflight.artifact_runtime_imports().len(), 1);
    assert!(preflight.imported_symbol_for("aos_env_get").is_some());
    assert_eq!(
        preflight
            .registered_symbol_for("aos_env_get")
            .expect("env helper is registered")
            .address()
            .as_nonzero_usize()
            .get(),
        env_get_address
    );
    assert!(
        preflight
            .registration_gap_for_symbol("aos_env_get")
            .is_none()
    );
    assert!(matches!(
        preflight.registration_gap_for_symbol("aos_force"),
        Some(
            crate::symbols::JitRuntimeSymbolRegistrationGap::MissingNativeAddress {
                kind: RuntimeSymbolKind::Helper(RuntimeHelperRole::ForcingControl),
                ..
            }
        )
    ));
    assert!(!preflight.is_complete());
    assert!(preflight.owns_encapsulated_module());
}

mod part_1;
mod part_2;
mod part_3;
