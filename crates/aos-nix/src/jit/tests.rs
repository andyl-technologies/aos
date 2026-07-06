use ratchet_core::{
    EffectClass, Ir, IrArena, IrAttrPathId, IrAttrPathSegment, IrData, IrFacts, IrId,
    IrInlineCacheSiteId, IrKind, IrNode,
    syntax::{BinOpKind, Span, SymbolTable},
};
use ratchet_jit::{
    DEFAULT_TIER1_INVOCATION_THRESHOLD, JitCraneliftRegisteredTier1SlotPreflight, JitTier,
    JitTieredCodeSlot, TierUpCounter, TierUpDemandHint, TierUpPolicy,
    jit_cranelift_registered_tier1_promotion_preflight_for_ir_root_with_candidates,
};

use super::*;

mod apply;

fn minimal_ir(root: IrId, arena: IrArena) -> Ir {
    let facts = IrFacts::conservative(arena.nodes().len());
    Ir {
        root,
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

fn static_has_attr_ir(slot: u32) -> Ir {
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
                IrKind::HasAttr,
                Span::new(0, 8),
                EffectClass::pure(),
                IrData::HasAttr {
                    receiver: IrId::new(0),
                    path: IrAttrPathId::new(0),
                    site: IrInlineCacheSiteId::new(11),
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

fn update_ir(left_slot: u32, right_slot: u32) -> Ir {
    let arena = IrArena::from_raw_parts(
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
    );
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

fn apply_ir(function_slot: u32, argument_slot: u32) -> Ir {
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

fn artifact_runtime_import_names(
    preflight: &JitCraneliftRegisteredTier1SlotPreflight,
) -> Vec<&str> {
    preflight
        .finalization()
        .artifact_runtime_imports()
        .iter()
        .map(|artifact_import| artifact_import.symbol_name())
        .collect()
}

fn assert_full_ir_native_call_registration_plan_gap(ir: &Ir, expected_symbols: &[&str]) {
    let result = nix_jit_force_aware_registered_tier1_native_call_preflight_for_lowered_ir_root(
        JitTieredCodeSlot::with_counter(TierUpCounter::new(DEFAULT_TIER1_INVOCATION_THRESHOLD - 1)),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        ir,
        ir.root,
    );

    let Err(error) = result else {
        panic!("incomplete runtime-symbol gates must not reach full-IR native calls");
    };
    assert!(error.decision().should_promote());
    assert_eq!(
        error.slot().invocation_counter().invocations(),
        DEFAULT_TIER1_INVOCATION_THRESHOLD
    );
    assert_eq!(error.slot().current_tier(), JitTier::Tier0Oracle);

    let NixJitRuntimeSymbolRegistrationPlanError::Incomplete {
        missing_count,
        preflight,
    } = error.runtime_symbol_registration_plan_error()
    else {
        panic!("current full-IR native-call gate should fail on incomplete registration metadata");
    };
    assert!(*missing_count > 0);
    assert!(!preflight.is_complete());
    for symbol_name in expected_symbols {
        assert!(
            preflight
                .address_candidate_preflight()
                .address_candidate_for(symbol_name)
                .is_some()
        );
        assert!(
            preflight
                .address_provenance_gap_for_symbol(symbol_name)
                .is_none()
        );
        assert!(
            preflight
                .address_candidate_preflight()
                .address_provenance_for_symbol(symbol_name)
                .is_some_and(NixJitRuntimeSymbolAddressProvenance::is_runtime_ffi_native_wrapper)
        );
    }
}

fn assert_full_ir_native_call_registration_plan_source_failure(ir: &Ir, symbol_name: &'static str) {
    let result =
        nix_jit_force_aware_registered_tier1_native_call_preflight_for_lowered_ir_root_with_registration_plan_source(
            JitTieredCodeSlot::with_counter(TierUpCounter::new(
                DEFAULT_TIER1_INVOCATION_THRESHOLD - 1,
            )),
            TierUpPolicy::default(),
            TierUpDemandHint::NoMultiUseEvidence,
            ir,
            ir.root,
            || {
                Err(NixJitRuntimeSymbolRegistrationPlanError::AddressCandidates(
                    NixJitRuntimeSymbolAddressCandidateError::NullHelperAddress {
                        symbol_name,
                    },
                ))
            },
        );

    let Err(error) = result else {
        panic!("hot full-IR native-call preflight should require registration planning");
    };
    assert!(error.decision().should_promote());
    assert_eq!(
        error.slot().invocation_counter().invocations(),
        DEFAULT_TIER1_INVOCATION_THRESHOLD
    );
    assert_eq!(error.slot().current_tier(), JitTier::Tier0Oracle);
    let NixJitRuntimeSymbolRegistrationPlanError::AddressCandidates(
        NixJitRuntimeSymbolAddressCandidateError::NullHelperAddress {
            symbol_name: actual_symbol,
        },
    ) = error.runtime_symbol_registration_plan_error()
    else {
        panic!("full-IR native-call preflight should preserve registration source failure");
    };
    assert_eq!(*actual_symbol, symbol_name);
}

#[test]
fn jit_runtime_symbol_address_candidates_feed_registered_env_promotion() {
    let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
        .expect("JIT address candidate preflight builds");
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::LocalVar,
            Span::new(0, 4),
            EffectClass::pure(),
            IrData::Local { slot: 1 },
        )],
        Vec::new(),
    );

    let promotion = jit_cranelift_registered_tier1_promotion_preflight_for_ir_root_with_candidates(
        JitTieredCodeSlot::with_counter(TierUpCounter::new(DEFAULT_TIER1_INVOCATION_THRESHOLD - 1)),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &arena,
        IrId::new(0),
        candidate_preflight.address_candidates(),
    )
    .expect("registered env promotion accepts runtime address candidates");

    assert!(promotion.did_compile());
    assert_eq!(promotion.slot().current_tier(), JitTier::Tier1Baseline);
    let promoted = promotion
        .promoted_preflight()
        .expect("promotion owns registered preflight");
    assert!(
        promoted
            .finalization()
            .registered_symbol_for("aos_env_get")
            .is_some_and(|registered| registered.address()
                == candidate_preflight
                    .address_candidate_for("aos_env_get")
                    .expect("env candidate exists")
                    .address())
    );
    assert!(promotion.owns_encapsulated_module());
}

#[test]
fn nix_jit_registered_tier1_promotion_preflight_records_cold_invocation_without_lowering() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::Str,
            Span::new(0, 5),
            EffectClass::pure(),
            IrData::None,
        )],
        Vec::new(),
    );

    let promotion = nix_jit_registered_tier1_promotion_preflight_for_ir_root(
        JitTieredCodeSlot::new(),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &arena,
        IrId::new(0),
    )
    .expect("cold unsupported root does not lower");

    assert!(!promotion.did_compile());
    assert_eq!(promotion.slot().invocation_counter().invocations(), 1);
    assert_eq!(promotion.slot().current_tier(), JitTier::Tier0Oracle);
    assert!(promotion.promoted_preflight().is_none());
    assert!(!promotion.owns_encapsulated_module());
}

#[test]
fn nix_jit_registered_tier1_promotion_preflight_keeps_cold_path_before_candidates() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::Str,
            Span::new(0, 5),
            EffectClass::pure(),
            IrData::None,
        )],
        Vec::new(),
    );

    let promotion = nix_jit_registered_tier1_promotion_preflight_for_ir_root_with_candidate_source(
        JitTieredCodeSlot::new(),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &arena,
        IrId::new(0),
        || {
            Err(
                NixJitRuntimeSymbolAddressCandidateError::NullHelperAddress {
                    symbol_name: "aos_env_get",
                },
            )
        },
    )
    .expect("cold attempt returns before address candidates are needed");

    assert!(!promotion.did_compile());
    assert_eq!(promotion.slot().invocation_counter().invocations(), 1);
    assert_eq!(promotion.slot().current_tier(), JitTier::Tier0Oracle);
}

#[test]
fn nix_jit_registered_tier1_promotion_preflight_reports_candidate_failure_after_promotion() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::LocalVar,
            Span::new(0, 4),
            EffectClass::pure(),
            IrData::Local { slot: 2 },
        )],
        Vec::new(),
    );

    let result = nix_jit_registered_tier1_promotion_preflight_for_ir_root_with_candidate_source(
        JitTieredCodeSlot::with_counter(TierUpCounter::new(DEFAULT_TIER1_INVOCATION_THRESHOLD - 1)),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &arena,
        IrId::new(0),
        || {
            Err(
                NixJitRuntimeSymbolAddressCandidateError::NullHelperAddress {
                    symbol_name: "aos_env_get",
                },
            )
        },
    );

    let Err(error) = result else {
        panic!("promotion should require address candidates");
    };
    assert!(error.decision().should_promote());
    assert_eq!(
        error.slot().invocation_counter().invocations(),
        DEFAULT_TIER1_INVOCATION_THRESHOLD
    );
    assert_eq!(error.slot().current_tier(), JitTier::Tier0Oracle);
    let NixJitRegisteredTier1PromotionError::AddressCandidates { source, .. } = error else {
        panic!("expected address candidate failure");
    };
    assert!(matches!(
        source,
        NixJitRuntimeSymbolAddressCandidateError::NullHelperAddress {
            symbol_name: "aos_env_get"
        }
    ));
}

#[test]
fn nix_jit_registered_tier1_promotion_preflight_uses_runtime_candidates() {
    let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
        .expect("JIT address candidate preflight builds");
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::LocalVar,
            Span::new(0, 4),
            EffectClass::pure(),
            IrData::Local { slot: 2 },
        )],
        Vec::new(),
    );

    let promotion = nix_jit_registered_tier1_promotion_preflight_for_ir_root(
        JitTieredCodeSlot::with_counter(TierUpCounter::new(DEFAULT_TIER1_INVOCATION_THRESHOLD - 1)),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &arena,
        IrId::new(0),
    )
    .expect("aos-nix wrapper promotes env slot with runtime candidates");

    assert!(promotion.did_compile());
    assert_eq!(promotion.slot().current_tier(), JitTier::Tier1Baseline);
    let promoted = promotion
        .promoted_preflight()
        .expect("promotion owns registered preflight");
    assert!(
        promoted
            .finalization()
            .registered_symbol_for("aos_env_get")
            .is_some_and(|registered| registered.address()
                == candidate_preflight
                    .address_candidate_for("aos_env_get")
                    .expect("env candidate exists")
                    .address())
    );
    assert!(promotion.owns_encapsulated_module());
}

#[test]
fn nix_jit_force_aware_registered_tier1_promotion_preflight_keeps_cold_path_before_candidates() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::Str,
            Span::new(0, 5),
            EffectClass::pure(),
            IrData::None,
        )],
        Vec::new(),
    );

    let promotion =
        nix_jit_force_aware_registered_tier1_promotion_preflight_for_ir_root_with_candidate_source(
            JitTieredCodeSlot::new(),
            TierUpPolicy::default(),
            TierUpDemandHint::NoMultiUseEvidence,
            &arena,
            IrId::new(0),
            || {
                Err(
                    NixJitRuntimeSymbolAddressCandidateError::NullHelperAddress {
                        symbol_name: "aos_force",
                    },
                )
            },
        )
        .expect("cold force-aware attempt returns before address candidates are needed");

    assert!(!promotion.did_compile());
    assert_eq!(promotion.slot().invocation_counter().invocations(), 1);
    assert_eq!(promotion.slot().current_tier(), JitTier::Tier0Oracle);
    assert!(promotion.promoted_preflight().is_none());
    assert!(!promotion.owns_encapsulated_module());
}

#[test]
fn nix_jit_force_aware_promotion_reports_candidate_failure_after_promotion() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::LocalVar,
            Span::new(0, 4),
            EffectClass::pure(),
            IrData::Local { slot: 2 },
        )],
        Vec::new(),
    );

    let result =
        nix_jit_force_aware_registered_tier1_promotion_preflight_for_ir_root_with_candidate_source(
            JitTieredCodeSlot::with_counter(TierUpCounter::new(
                DEFAULT_TIER1_INVOCATION_THRESHOLD - 1,
            )),
            TierUpPolicy::default(),
            TierUpDemandHint::NoMultiUseEvidence,
            &arena,
            IrId::new(0),
            || {
                Err(
                    NixJitRuntimeSymbolAddressCandidateError::NullHelperAddress {
                        symbol_name: "aos_force",
                    },
                )
            },
        );

    let Err(error) = result else {
        panic!("promotion should require address candidates");
    };
    assert!(error.decision().should_promote());
    assert_eq!(
        error.slot().invocation_counter().invocations(),
        DEFAULT_TIER1_INVOCATION_THRESHOLD
    );
    assert_eq!(error.slot().current_tier(), JitTier::Tier0Oracle);
    let NixJitRegisteredTier1PromotionError::AddressCandidates { source, .. } = error else {
        panic!("expected address candidate failure");
    };
    assert!(matches!(
        source,
        NixJitRuntimeSymbolAddressCandidateError::NullHelperAddress {
            symbol_name: "aos_force"
        }
    ));
}

#[test]
fn nix_jit_force_aware_registered_tier1_promotion_preflight_promotes_literals() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::Bool,
            Span::new(0, 4),
            EffectClass::pure(),
            IrData::Bool(true),
        )],
        Vec::new(),
    );

    let promotion = nix_jit_force_aware_registered_tier1_promotion_preflight_for_ir_root(
        JitTieredCodeSlot::new(),
        TierUpPolicy::default(),
        TierUpDemandHint::MultiUse,
        &arena,
        IrId::new(0),
    )
    .expect("force-aware literal root promotes through oracle bridge");

    assert!(promotion.did_compile());
    assert_eq!(promotion.slot().current_tier(), JitTier::Tier1Baseline);
    let promoted = promotion
        .promoted_preflight()
        .expect("promotion owns registered preflight");
    assert!(
        promoted
            .finalization()
            .artifact_runtime_imports()
            .is_empty()
    );
    assert!(promotion.owns_encapsulated_module());
}

#[test]
fn nix_jit_force_aware_registered_tier1_promotion_preflight_installs_forced_env_slot() {
    let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
        .expect("JIT address candidate preflight builds");
    assert!(
        candidate_preflight
            .address_candidate_for("aos_env_get")
            .is_some()
    );
    assert!(
        candidate_preflight
            .address_candidate_for("aos_force")
            .is_some()
    );
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::LocalVar,
            Span::new(0, 4),
            EffectClass::pure(),
            IrData::Local { slot: 2 },
        )],
        Vec::new(),
    );

    let promotion = nix_jit_force_aware_registered_tier1_promotion_preflight_for_ir_root(
        JitTieredCodeSlot::with_counter(TierUpCounter::new(DEFAULT_TIER1_INVOCATION_THRESHOLD - 1)),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &arena,
        IrId::new(0),
    )
    .expect("force-aware env-slot promotion finalizes with runtime address candidates");

    assert!(promotion.decision().should_promote());
    assert_eq!(
        promotion.slot().invocation_counter().invocations(),
        DEFAULT_TIER1_INVOCATION_THRESHOLD
    );
    assert_eq!(promotion.slot().current_tier(), JitTier::Tier1Baseline);
    assert!(promotion.did_compile());
    let promoted = promotion
        .promoted_preflight()
        .expect("promotion owns registered preflight");
    assert_eq!(
        promotion.slot().tier1_code_ptr(),
        Some(promoted.finalized_function().compiled_code_ptr())
    );
    assert_eq!(promoted.finalization().artifact_runtime_imports().len(), 2);
    assert!(
        promoted
            .finalization()
            .registered_symbol_for("aos_env_get")
            .is_some_and(|registered| registered.address()
                == candidate_preflight
                    .address_candidate_for("aos_env_get")
                    .expect("env candidate exists")
                    .address())
    );
    assert!(
        promoted
            .finalization()
            .registered_symbol_for("aos_force")
            .is_some_and(|registered| registered.address()
                == candidate_preflight
                    .address_candidate_for("aos_force")
                    .expect("force candidate exists")
                    .address())
    );
    assert!(promotion.owns_encapsulated_module());
}

#[test]
fn nix_jit_registered_full_ir_promotion_keeps_cold_path_before_candidates() {
    let ir = minimal_ir(
        IrId::new(0),
        IrArena::from_raw_parts(
            vec![IrNode::new(
                IrKind::Str,
                Span::new(0, 5),
                EffectClass::pure(),
                IrData::None,
            )],
            Vec::new(),
        ),
    );

    let promotion =
        nix_jit_registered_tier1_promotion_preflight_for_lowered_ir_root_with_candidate_source(
            JitTieredCodeSlot::new(),
            TierUpPolicy::default(),
            TierUpDemandHint::NoMultiUseEvidence,
            &ir,
            ir.root,
            || {
                Err(
                    NixJitRuntimeSymbolAddressCandidateError::NullHelperAddress {
                        symbol_name: "aos_select_ic",
                    },
                )
            },
        )
        .expect("cold full-IR attempt returns before address candidates are needed");

    assert!(!promotion.did_compile());
    assert_eq!(promotion.slot().invocation_counter().invocations(), 1);
    assert_eq!(promotion.slot().current_tier(), JitTier::Tier0Oracle);
    assert!(promotion.promoted_preflight().is_none());
    assert!(!promotion.owns_encapsulated_module());
}

#[test]
fn nix_jit_registered_full_ir_promotion_installs_static_select() {
    let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
        .expect("JIT address candidate preflight builds");
    let ir = static_select_ir(9);

    let promotion = nix_jit_registered_tier1_promotion_preflight_for_lowered_ir_root(
        JitTieredCodeSlot::with_counter(TierUpCounter::new(DEFAULT_TIER1_INVOCATION_THRESHOLD - 1)),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &ir,
        ir.root,
    )
    .expect("full-IR static-select promotion finalizes with runtime address candidates");

    assert!(promotion.decision().should_promote());
    assert_eq!(
        promotion.slot().invocation_counter().invocations(),
        DEFAULT_TIER1_INVOCATION_THRESHOLD
    );
    assert_eq!(promotion.slot().current_tier(), JitTier::Tier1Baseline);
    assert!(promotion.did_compile());
    let promoted = promotion
        .promoted_preflight()
        .expect("promotion owns registered preflight");
    assert_eq!(
        promotion.slot().tier1_code_ptr(),
        Some(promoted.finalized_function().compiled_code_ptr())
    );
    assert_eq!(
        artifact_runtime_import_names(promoted),
        ["aos_env_get", "aos_force", "aos_select_ic"]
    );
    for symbol_name in ["aos_env_get", "aos_force", "aos_select_ic"] {
        assert!(
            promoted
                .finalization()
                .registered_symbol_for(symbol_name)
                .is_some_and(|registered| registered.address()
                    == candidate_preflight
                        .address_candidate_for(symbol_name)
                        .expect("runtime candidate exists")
                        .address()),
            "{symbol_name} should be registered from runtime address candidates"
        );
    }
    assert!(promotion.owns_encapsulated_module());
}

#[test]
fn nix_jit_registered_full_ir_promotion_installs_static_has_attr() {
    let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
        .expect("JIT address candidate preflight builds");
    let ir = static_has_attr_ir(10);

    let promotion = nix_jit_registered_tier1_promotion_preflight_for_lowered_ir_root(
        JitTieredCodeSlot::with_counter(TierUpCounter::new(DEFAULT_TIER1_INVOCATION_THRESHOLD - 1)),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &ir,
        ir.root,
    )
    .expect("full-IR static-hasAttr promotion finalizes with runtime address candidates");

    assert!(promotion.decision().should_promote());
    assert_eq!(
        promotion.slot().invocation_counter().invocations(),
        DEFAULT_TIER1_INVOCATION_THRESHOLD
    );
    assert_eq!(promotion.slot().current_tier(), JitTier::Tier1Baseline);
    assert!(promotion.did_compile());
    let promoted = promotion
        .promoted_preflight()
        .expect("promotion owns registered preflight");
    assert_eq!(
        promotion.slot().tier1_code_ptr(),
        Some(promoted.finalized_function().compiled_code_ptr())
    );
    assert_eq!(
        artifact_runtime_import_names(promoted),
        ["aos_env_get", "aos_force", "aos_has_attr"]
    );
    for symbol_name in ["aos_env_get", "aos_force", "aos_has_attr"] {
        assert!(
            promoted
                .finalization()
                .registered_symbol_for(symbol_name)
                .is_some_and(|registered| registered.address()
                    == candidate_preflight
                        .address_candidate_for(symbol_name)
                        .expect("runtime candidate exists")
                        .address()),
            "{symbol_name} should be registered from runtime address candidates"
        );
    }
    assert!(promotion.owns_encapsulated_module());
}

#[test]
fn nix_jit_registered_promotion_installs_update() {
    let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
        .expect("JIT address candidate preflight builds");
    let ir = update_ir(10, 12);

    let promotion = nix_jit_registered_tier1_promotion_preflight_for_ir_root(
        JitTieredCodeSlot::with_counter(TierUpCounter::new(DEFAULT_TIER1_INVOCATION_THRESHOLD - 1)),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &ir.arena,
        ir.root,
    )
    .expect("update promotion finalizes with runtime address candidates");

    assert!(promotion.decision().should_promote());
    assert_eq!(
        promotion.slot().invocation_counter().invocations(),
        DEFAULT_TIER1_INVOCATION_THRESHOLD
    );
    assert_eq!(promotion.slot().current_tier(), JitTier::Tier1Baseline);
    assert!(promotion.did_compile());
    let promoted = promotion
        .promoted_preflight()
        .expect("promotion owns registered preflight");
    assert_eq!(
        promotion.slot().tier1_code_ptr(),
        Some(promoted.finalized_function().compiled_code_ptr())
    );
    assert_eq!(
        artifact_runtime_import_names(promoted),
        ["aos_env_get", "aos_force", "aos_update"]
    );
    for symbol_name in ["aos_env_get", "aos_force", "aos_update"] {
        assert!(
            promoted
                .finalization()
                .registered_symbol_for(symbol_name)
                .is_some_and(|registered| registered.address()
                    == candidate_preflight
                        .address_candidate_for(symbol_name)
                        .expect("runtime candidate exists")
                        .address()),
            "{symbol_name} should be registered from runtime address candidates"
        );
    }
    assert!(promotion.owns_encapsulated_module());
}

#[test]
fn nix_jit_registered_full_ir_install_plan_carries_static_select_pointer_and_module_owner() {
    let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
        .expect("JIT address candidate preflight builds");
    let ir = static_select_ir(11);

    let plan = nix_jit_registered_tier1_install_plan_for_lowered_ir_root(
        JitTieredCodeSlot::with_counter(TierUpCounter::new(DEFAULT_TIER1_INVOCATION_THRESHOLD - 1)),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &ir,
        ir.root,
    )
    .expect("full-IR static-select install plan finalizes with runtime address candidates");

    assert!(plan.did_compile());
    assert!(plan.is_ready_for_install());
    assert_eq!(
        plan.slot().invocation_counter().invocations(),
        DEFAULT_TIER1_INVOCATION_THRESHOLD
    );
    assert_eq!(plan.slot().current_tier(), JitTier::Tier1Baseline);
    assert!(plan.tier1_code_ptr().is_some());
    let promoted = plan
        .promoted_preflight()
        .expect("install plan owns promoted preflight");
    assert_eq!(
        plan.tier1_code_ptr(),
        Some(promoted.finalized_function().compiled_code_ptr())
    );
    assert_eq!(
        artifact_runtime_import_names(promoted),
        ["aos_env_get", "aos_force", "aos_select_ic"]
    );
    assert!(
        promoted
            .finalization()
            .registered_symbol_for("aos_select_ic")
            .is_some_and(|registered| registered.address()
                == candidate_preflight
                    .address_candidate_for("aos_select_ic")
                    .expect("select candidate exists")
                    .address())
    );
    assert!(plan.owns_encapsulated_module());
}

#[test]
fn nix_jit_force_aware_full_ir_install_plan_carries_static_has_attr_pointer_and_module_owner() {
    let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
        .expect("JIT address candidate preflight builds");
    let ir = static_has_attr_ir(14);

    let plan = nix_jit_force_aware_registered_tier1_install_plan_for_lowered_ir_root(
        JitTieredCodeSlot::with_counter(TierUpCounter::new(DEFAULT_TIER1_INVOCATION_THRESHOLD - 1)),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &ir,
        ir.root,
    )
    .expect("full-IR static-hasAttr install plan finalizes with runtime address candidates");

    assert!(plan.did_compile());
    assert!(plan.is_ready_for_install());
    assert_eq!(
        plan.slot().invocation_counter().invocations(),
        DEFAULT_TIER1_INVOCATION_THRESHOLD
    );
    assert_eq!(plan.slot().current_tier(), JitTier::Tier1Baseline);
    assert!(plan.tier1_code_ptr().is_some());
    let promoted = plan
        .promoted_preflight()
        .expect("install plan owns promoted preflight");
    assert_eq!(
        plan.tier1_code_ptr(),
        Some(promoted.finalized_function().compiled_code_ptr())
    );
    assert_eq!(
        artifact_runtime_import_names(promoted),
        ["aos_env_get", "aos_force", "aos_has_attr"]
    );
    assert!(
        promoted
            .finalization()
            .registered_symbol_for("aos_has_attr")
            .is_some_and(|registered| registered.address()
                == candidate_preflight
                    .address_candidate_for("aos_has_attr")
                    .expect("hasAttr candidate exists")
                    .address())
    );
    assert!(plan.owns_encapsulated_module());
}

#[test]
fn nix_jit_force_aware_full_ir_install_plan_carries_static_select_pointer_and_module_owner() {
    let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
        .expect("JIT address candidate preflight builds");
    let ir = static_select_ir(13);

    let plan = nix_jit_force_aware_registered_tier1_install_plan_for_lowered_ir_root(
        JitTieredCodeSlot::with_counter(TierUpCounter::new(DEFAULT_TIER1_INVOCATION_THRESHOLD - 1)),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &ir,
        ir.root,
    )
    .expect("full-IR static-select install plan finalizes with runtime address candidates");

    assert!(plan.did_compile());
    assert!(plan.is_ready_for_install());
    assert_eq!(
        plan.slot().invocation_counter().invocations(),
        DEFAULT_TIER1_INVOCATION_THRESHOLD
    );
    assert_eq!(plan.slot().current_tier(), JitTier::Tier1Baseline);
    assert!(plan.tier1_code_ptr().is_some());
    let promoted = plan
        .promoted_preflight()
        .expect("install plan owns promoted preflight");
    assert_eq!(
        plan.tier1_code_ptr(),
        Some(promoted.finalized_function().compiled_code_ptr())
    );
    assert_eq!(
        artifact_runtime_import_names(promoted),
        ["aos_env_get", "aos_force", "aos_select_ic"]
    );
    assert!(
        promoted
            .finalization()
            .registered_symbol_for("aos_select_ic")
            .is_some_and(|registered| registered.address()
                == candidate_preflight
                    .address_candidate_for("aos_select_ic")
                    .expect("select candidate exists")
                    .address())
    );
    assert!(plan.owns_encapsulated_module());
}

#[test]
fn nix_jit_force_aware_install_plan_carries_update_pointer_and_module_owner() {
    let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
        .expect("JIT address candidate preflight builds");
    let ir = update_ir(14, 15);

    let plan = nix_jit_force_aware_registered_tier1_install_plan_for_ir_root(
        JitTieredCodeSlot::with_counter(TierUpCounter::new(DEFAULT_TIER1_INVOCATION_THRESHOLD - 1)),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &ir.arena,
        ir.root,
    )
    .expect("update install plan finalizes with runtime address candidates");

    assert!(plan.did_compile());
    assert!(plan.is_ready_for_install());
    assert_eq!(
        plan.slot().invocation_counter().invocations(),
        DEFAULT_TIER1_INVOCATION_THRESHOLD
    );
    assert_eq!(plan.slot().current_tier(), JitTier::Tier1Baseline);
    assert!(plan.tier1_code_ptr().is_some());
    let promoted = plan
        .promoted_preflight()
        .expect("install plan owns promoted preflight");
    assert_eq!(
        plan.tier1_code_ptr(),
        Some(promoted.finalized_function().compiled_code_ptr())
    );
    assert_eq!(
        artifact_runtime_import_names(promoted),
        ["aos_env_get", "aos_force", "aos_update"]
    );
    assert!(
        promoted
            .finalization()
            .registered_symbol_for("aos_update")
            .is_some_and(|registered| registered.address()
                == candidate_preflight
                    .address_candidate_for("aos_update")
                    .expect("update candidate exists")
                    .address())
    );
    assert!(plan.owns_encapsulated_module());
}

#[test]
fn nix_jit_force_aware_promotion_installs_wrapped_forced_env_slot() {
    let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
        .expect("JIT address candidate preflight builds");
    let arena = IrArena::from_raw_parts(
        vec![
            IrNode::new(
                IrKind::ThunkAlloc,
                Span::new(0, 6),
                EffectClass::pure(),
                IrData::Node(IrId::new(1)),
            ),
            IrNode::new(
                IrKind::LocalVar,
                Span::new(1, 5),
                EffectClass::pure(),
                IrData::Local { slot: 11 },
            ),
        ],
        Vec::new(),
    );

    let promotion = nix_jit_force_aware_registered_tier1_promotion_preflight_for_ir_root(
        JitTieredCodeSlot::with_counter(TierUpCounter::new(DEFAULT_TIER1_INVOCATION_THRESHOLD - 1)),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &arena,
        IrId::new(0),
    )
    .expect("wrapped force-aware env-slot promotion finalizes with runtime address candidates");

    assert!(promotion.decision().should_promote());
    assert_eq!(
        promotion.slot().invocation_counter().invocations(),
        DEFAULT_TIER1_INVOCATION_THRESHOLD
    );
    assert_eq!(promotion.slot().current_tier(), JitTier::Tier1Baseline);
    assert!(promotion.did_compile());
    let promoted = promotion
        .promoted_preflight()
        .expect("promotion owns registered preflight");
    assert_eq!(
        promotion.slot().tier1_code_ptr(),
        Some(promoted.finalized_function().compiled_code_ptr())
    );
    assert_eq!(promoted.finalization().artifact_runtime_imports().len(), 2);
    assert!(
        promoted
            .finalization()
            .registered_symbol_for("aos_env_get")
            .is_some_and(|registered| registered.address()
                == candidate_preflight
                    .address_candidate_for("aos_env_get")
                    .expect("env candidate exists")
                    .address())
    );
    assert!(
        promoted
            .finalization()
            .registered_symbol_for("aos_force")
            .is_some_and(|registered| registered.address()
                == candidate_preflight
                    .address_candidate_for("aos_force")
                    .expect("force candidate exists")
                    .address())
    );
    assert!(promotion.owns_encapsulated_module());
}

#[test]
fn nix_jit_registered_tier1_install_plan_records_cold_slot_without_pointer() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::Str,
            Span::new(0, 5),
            EffectClass::pure(),
            IrData::None,
        )],
        Vec::new(),
    );

    let plan = nix_jit_registered_tier1_install_plan_for_ir_root(
        JitTieredCodeSlot::new(),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &arena,
        IrId::new(0),
    )
    .expect("cold unsupported root records slot state");

    assert!(!plan.did_compile());
    assert!(!plan.is_ready_for_install());
    assert_eq!(plan.slot().invocation_counter().invocations(), 1);
    assert_eq!(plan.slot().current_tier(), JitTier::Tier0Oracle);
    assert!(plan.tier1_code_ptr().is_none());
    assert!(plan.promoted_preflight().is_none());
    assert!(!plan.owns_encapsulated_module());
}

#[test]
fn nix_jit_registered_tier1_install_plan_carries_promoted_slot_and_module_owner() {
    let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
        .expect("JIT address candidate preflight builds");
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::LocalVar,
            Span::new(0, 4),
            EffectClass::pure(),
            IrData::Local { slot: 3 },
        )],
        Vec::new(),
    );

    let plan = nix_jit_registered_tier1_install_plan_for_ir_root(
        JitTieredCodeSlot::with_counter(TierUpCounter::new(DEFAULT_TIER1_INVOCATION_THRESHOLD - 1)),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &arena,
        IrId::new(0),
    )
    .expect("env slot root builds a registered install plan");

    assert!(plan.did_compile());
    assert!(plan.is_ready_for_install());
    assert_eq!(plan.slot().current_tier(), JitTier::Tier1Baseline);
    assert!(plan.tier1_code_ptr().is_some());
    let promoted = plan
        .promoted_preflight()
        .expect("install plan owns promoted preflight");
    assert!(
        promoted
            .finalization()
            .registered_symbol_for("aos_env_get")
            .is_some_and(|registered| registered.address()
                == candidate_preflight
                    .address_candidate_for("aos_env_get")
                    .expect("env candidate exists")
                    .address())
    );
    assert!(plan.owns_encapsulated_module());
}

#[test]
fn nix_jit_force_aware_registered_tier1_install_plan_records_cold_slot_without_pointer() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::Str,
            Span::new(0, 5),
            EffectClass::pure(),
            IrData::None,
        )],
        Vec::new(),
    );

    let plan = nix_jit_force_aware_registered_tier1_install_plan_for_ir_root(
        JitTieredCodeSlot::new(),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &arena,
        IrId::new(0),
    )
    .expect("cold force-aware unsupported root records slot state");

    assert!(!plan.did_compile());
    assert!(!plan.is_ready_for_install());
    assert_eq!(plan.slot().invocation_counter().invocations(), 1);
    assert_eq!(plan.slot().current_tier(), JitTier::Tier0Oracle);
    assert!(plan.tier1_code_ptr().is_none());
    assert!(plan.promoted_preflight().is_none());
    assert!(!plan.owns_encapsulated_module());
}

#[test]
fn nix_jit_force_aware_registered_tier1_install_plan_carries_literal_slot_and_module_owner() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::Bool,
            Span::new(0, 4),
            EffectClass::pure(),
            IrData::Bool(true),
        )],
        Vec::new(),
    );

    let plan = nix_jit_force_aware_registered_tier1_install_plan_for_ir_root(
        JitTieredCodeSlot::new(),
        TierUpPolicy::default(),
        TierUpDemandHint::MultiUse,
        &arena,
        IrId::new(0),
    )
    .expect("force-aware literal install plan builds");

    assert!(plan.did_compile());
    assert!(plan.is_ready_for_install());
    assert_eq!(plan.slot().current_tier(), JitTier::Tier1Baseline);
    assert!(plan.tier1_code_ptr().is_some());
    let promoted = plan
        .promoted_preflight()
        .expect("literal install plan owns promoted preflight");
    assert!(
        promoted
            .finalization()
            .artifact_runtime_imports()
            .is_empty()
    );
    assert!(plan.owns_encapsulated_module());
}

#[test]
fn nix_jit_force_aware_registered_tier1_install_plan_carries_forced_env_slot_and_module_owner() {
    let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
        .expect("JIT address candidate preflight builds");
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::LocalVar,
            Span::new(0, 4),
            EffectClass::pure(),
            IrData::Local { slot: 2 },
        )],
        Vec::new(),
    );

    let plan = nix_jit_force_aware_registered_tier1_install_plan_for_ir_root(
        JitTieredCodeSlot::with_counter(TierUpCounter::new(DEFAULT_TIER1_INVOCATION_THRESHOLD - 1)),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &arena,
        IrId::new(0),
    )
    .expect("force-aware env-slot install plan finalizes with runtime address candidates");

    assert!(plan.did_compile());
    assert!(plan.is_ready_for_install());
    assert_eq!(
        plan.slot().invocation_counter().invocations(),
        DEFAULT_TIER1_INVOCATION_THRESHOLD
    );
    assert_eq!(plan.slot().current_tier(), JitTier::Tier1Baseline);
    assert!(plan.tier1_code_ptr().is_some());
    let promoted = plan
        .promoted_preflight()
        .expect("install plan owns promoted preflight");
    assert_eq!(
        plan.tier1_code_ptr(),
        Some(promoted.finalized_function().compiled_code_ptr())
    );
    assert_eq!(promoted.finalization().artifact_runtime_imports().len(), 2);
    assert!(
        promoted
            .finalization()
            .registered_symbol_for("aos_env_get")
            .is_some_and(|registered| registered.address()
                == candidate_preflight
                    .address_candidate_for("aos_env_get")
                    .expect("env candidate exists")
                    .address())
    );
    assert!(
        promoted
            .finalization()
            .registered_symbol_for("aos_force")
            .is_some_and(|registered| registered.address()
                == candidate_preflight
                    .address_candidate_for("aos_force")
                    .expect("force candidate exists")
                    .address())
    );
    assert!(plan.owns_encapsulated_module());
}

#[test]
fn nix_jit_registered_native_call_preflight_keeps_cold_path_before_plan() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::Str,
            Span::new(0, 5),
            EffectClass::pure(),
            IrData::None,
        )],
        Vec::new(),
    );

    let preflight =
        nix_jit_force_aware_registered_tier1_native_call_preflight_for_ir_root_with_registration_plan_source(
            JitTieredCodeSlot::new(),
            TierUpPolicy::default(),
            TierUpDemandHint::NoMultiUseEvidence,
            &arena,
            IrId::new(0),
            || -> NixJitRuntimeSymbolRegistrationPlanResult {
                panic!("registration plan source must not run for a cold native-call preflight");
            },
        )
        .expect("cold native-call preflight returns before registration planning");

    assert!(!preflight.decision().should_promote());
    assert!(!preflight.did_call_native_code());
    assert!(!preflight.has_runtime_symbol_registration_plan());
    assert!(preflight.runtime_symbol_registration_plan().is_none());
    assert_eq!(preflight.slot().invocation_counter().invocations(), 1);
    assert_eq!(preflight.slot().current_tier(), JitTier::Tier0Oracle);
}

#[test]
fn nix_jit_registered_full_ir_native_call_preflight_keeps_cold_path_before_plan() {
    let ir = static_select_ir(17);

    let preflight =
        nix_jit_force_aware_registered_tier1_native_call_preflight_for_lowered_ir_root_with_registration_plan_source(
            JitTieredCodeSlot::new(),
            TierUpPolicy::default(),
            TierUpDemandHint::NoMultiUseEvidence,
            &ir,
            ir.root,
            || -> NixJitRuntimeSymbolRegistrationPlanResult {
                panic!(
                    "registration plan source must not run for a cold full-IR native-call preflight"
                );
            },
        )
        .expect("cold full-IR native-call preflight returns before registration planning");

    assert!(!preflight.decision().should_promote());
    assert!(!preflight.did_call_native_code());
    assert!(!preflight.has_runtime_symbol_registration_plan());
    assert!(preflight.runtime_symbol_registration_plan().is_none());
    assert_eq!(preflight.slot().invocation_counter().invocations(), 1);
    assert_eq!(preflight.slot().current_tier(), JitTier::Tier0Oracle);
}

#[test]
fn nix_jit_registered_native_call_preflight_reports_current_registration_plan_gap() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::LocalVar,
            Span::new(0, 4),
            EffectClass::pure(),
            IrData::Local { slot: 2 },
        )],
        Vec::new(),
    );

    let result = nix_jit_force_aware_registered_tier1_native_call_preflight_for_ir_root(
        JitTieredCodeSlot::with_counter(TierUpCounter::new(DEFAULT_TIER1_INVOCATION_THRESHOLD - 1)),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &arena,
        IrId::new(0),
    );

    let Err(error) = result else {
        panic!("incomplete runtime-symbol gates must not reach native calls");
    };
    assert!(error.decision().should_promote());
    assert_eq!(
        error.slot().invocation_counter().invocations(),
        DEFAULT_TIER1_INVOCATION_THRESHOLD
    );
    assert_eq!(error.slot().current_tier(), JitTier::Tier0Oracle);

    let NixJitRuntimeSymbolRegistrationPlanError::Incomplete {
        missing_count,
        preflight,
    } = error.runtime_symbol_registration_plan_error()
    else {
        panic!("current native-call gate should fail on incomplete registration metadata");
    };
    assert!(*missing_count > 0);
    assert!(!preflight.is_complete());
    assert!(
        preflight
            .address_candidate_preflight()
            .address_candidate_for("aos_env_get")
            .is_some()
    );
    assert!(
        preflight
            .address_candidate_preflight()
            .address_candidate_for("aos_apply")
            .is_some()
    );
    assert!(
        preflight
            .address_candidate_preflight()
            .address_candidate_for("aos_blackhole_check")
            .is_some()
    );
    assert!(
        preflight
            .address_candidate_preflight()
            .address_candidate_for("aos_force")
            .is_some()
    );
    assert!(
        preflight
            .address_candidate_preflight()
            .address_candidate_for("aos_force_deep")
            .is_some()
    );
    assert!(
        preflight
            .address_candidate_preflight()
            .address_candidate_for("aos_gc_write_barrier")
            .is_some()
    );
    for symbol_name in ["aos_has_attr", "aos_select_ic", "aos_update"] {
        assert!(
            preflight
                .address_candidate_preflight()
                .address_candidate_for(symbol_name)
                .is_some()
        );
    }
    for symbol_name in [
        "aos_alloc_attrs",
        "aos_alloc_cons",
        "aos_alloc_lambda",
        "aos_alloc_list",
        "aos_alloc_raw",
        "aos_alloc_string",
        "aos_alloc_thunk",
    ] {
        assert!(
            preflight
                .address_candidate_preflight()
                .address_candidate_for(symbol_name)
                .is_some()
        );
        assert!(
            preflight
                .address_provenance_gap_for_symbol(symbol_name)
                .is_none()
        );
        assert!(
            preflight
                .address_candidate_preflight()
                .address_provenance_for_symbol(symbol_name)
                .is_some_and(NixJitRuntimeSymbolAddressProvenance::is_runtime_ffi_native_wrapper)
        );
    }
    assert!(
        preflight
            .address_provenance_gap_for_symbol("aos_env_get")
            .is_none()
    );
    assert!(
        preflight
            .address_candidate_preflight()
            .address_provenance_for_symbol("aos_env_get")
            .is_some_and(NixJitRuntimeSymbolAddressProvenance::is_runtime_ffi_native_wrapper)
    );
    assert!(
        preflight
            .address_provenance_gap_for_symbol("aos_apply")
            .is_none()
    );
    assert!(
        preflight
            .address_candidate_preflight()
            .address_provenance_for_symbol("aos_apply")
            .is_some_and(NixJitRuntimeSymbolAddressProvenance::is_runtime_ffi_native_wrapper)
    );
    assert!(
        preflight
            .address_provenance_gap_for_symbol("aos_blackhole_check")
            .is_none()
    );
    assert!(
        preflight
            .address_candidate_preflight()
            .address_provenance_for_symbol("aos_blackhole_check")
            .is_some_and(NixJitRuntimeSymbolAddressProvenance::is_runtime_ffi_native_wrapper)
    );
    assert!(
        preflight
            .address_provenance_gap_for_symbol("aos_force")
            .is_none()
    );
    assert!(
        preflight
            .address_candidate_preflight()
            .address_provenance_for_symbol("aos_force")
            .is_some_and(NixJitRuntimeSymbolAddressProvenance::is_runtime_ffi_native_wrapper)
    );
    assert!(
        preflight
            .address_provenance_gap_for_symbol("aos_force_deep")
            .is_none()
    );
    assert!(
        preflight
            .address_candidate_preflight()
            .address_provenance_for_symbol("aos_force_deep")
            .is_some_and(NixJitRuntimeSymbolAddressProvenance::is_runtime_ffi_native_wrapper)
    );
    assert!(
        preflight
            .address_provenance_gap_for_symbol("aos_gc_write_barrier")
            .is_none()
    );
    assert!(
        preflight
            .address_candidate_preflight()
            .address_provenance_for_symbol("aos_gc_write_barrier")
            .is_some_and(NixJitRuntimeSymbolAddressProvenance::is_runtime_ffi_native_wrapper)
    );
    for symbol_name in ["aos_has_attr", "aos_select_ic", "aos_update"] {
        assert!(
            preflight
                .address_provenance_gap_for_symbol(symbol_name)
                .is_none()
        );
        assert!(
            preflight
                .address_candidate_preflight()
                .address_provenance_for_symbol(symbol_name)
                .is_some_and(NixJitRuntimeSymbolAddressProvenance::is_runtime_ffi_native_wrapper)
        );
    }
}

#[test]
fn nix_jit_registered_full_ir_native_call_preflight_reports_current_registration_plan_gap() {
    let ir = static_select_ir(19);

    assert_full_ir_native_call_registration_plan_gap(
        &ir,
        &["aos_env_get", "aos_force", "aos_select_ic"],
    );
}

#[test]
fn nix_jit_registered_full_ir_apply_native_call_preflight_reports_registration_plan_gap() {
    let ir = apply_ir(17, 19);

    assert_full_ir_native_call_registration_plan_gap(&ir, &["aos_env_get", "aos_apply"]);
}

#[test]
fn nix_jit_registered_full_ir_has_attr_native_call_preflight_reports_registration_plan_gap() {
    let ir = static_has_attr_ir(19);

    assert_full_ir_native_call_registration_plan_gap(
        &ir,
        &["aos_env_get", "aos_force", "aos_has_attr"],
    );
}

#[test]
fn nix_jit_registered_full_ir_native_call_preflight_reports_update_registration_plan_gap() {
    let ir = update_ir(19, 21);

    assert_full_ir_native_call_registration_plan_gap(
        &ir,
        &["aos_env_get", "aos_force", "aos_update"],
    );
}

#[test]
fn nix_jit_registered_native_call_preflight_reports_plan_source_failure_after_promotion() {
    let arena = IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::LocalVar,
            Span::new(0, 4),
            EffectClass::pure(),
            IrData::Local { slot: 2 },
        )],
        Vec::new(),
    );

    let result =
        nix_jit_force_aware_registered_tier1_native_call_preflight_for_ir_root_with_registration_plan_source(
            JitTieredCodeSlot::with_counter(TierUpCounter::new(
                DEFAULT_TIER1_INVOCATION_THRESHOLD - 1,
            )),
            TierUpPolicy::default(),
            TierUpDemandHint::NoMultiUseEvidence,
            &arena,
            IrId::new(0),
            || {
                Err(NixJitRuntimeSymbolRegistrationPlanError::AddressCandidates(
                    NixJitRuntimeSymbolAddressCandidateError::NullHelperAddress {
                        symbol_name: "aos_force",
                    },
                ))
            },
        );

    let Err(error) = result else {
        panic!("hot native-call preflight should require registration planning");
    };
    assert!(error.decision().should_promote());
    assert_eq!(
        error.slot().invocation_counter().invocations(),
        DEFAULT_TIER1_INVOCATION_THRESHOLD
    );
    assert_eq!(error.slot().current_tier(), JitTier::Tier0Oracle);
    assert!(matches!(
        error.runtime_symbol_registration_plan_error(),
        NixJitRuntimeSymbolRegistrationPlanError::AddressCandidates(
            NixJitRuntimeSymbolAddressCandidateError::NullHelperAddress {
                symbol_name: "aos_force"
            }
        )
    ));
}

#[test]
fn nix_jit_full_ir_update_native_call_preflight_reports_plan_source_failure_after_promotion() {
    let ir = update_ir(23, 25);

    assert_full_ir_native_call_registration_plan_source_failure(&ir, "aos_update");
}

#[test]
fn nix_jit_full_ir_apply_native_call_preflight_reports_plan_source_failure_after_promotion() {
    let ir = apply_ir(23, 25);

    assert_full_ir_native_call_registration_plan_source_failure(&ir, "aos_apply");
}

#[test]
fn nix_jit_full_ir_has_attr_native_call_preflight_reports_plan_source_failure_after_promotion() {
    let ir = static_has_attr_ir(23);

    assert_full_ir_native_call_registration_plan_source_failure(&ir, "aos_has_attr");
}

#[test]
fn nix_jit_full_ir_select_native_call_preflight_reports_plan_source_failure_after_promotion() {
    let ir = static_select_ir(23);

    assert_full_ir_native_call_registration_plan_source_failure(&ir, "aos_select_ic");
}
