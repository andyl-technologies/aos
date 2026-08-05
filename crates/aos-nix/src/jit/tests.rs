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

fn static_select_scalar_default_ir(slot: u32, default_value: i64) -> Ir {
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
                    default: Some(IrId::new(2)),
                },
            ),
            IrNode::new(
                IrKind::Int,
                Span::new(9, 11),
                EffectClass::pure(),
                IrData::Int(default_value),
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

mod part_1;
mod part_2;
