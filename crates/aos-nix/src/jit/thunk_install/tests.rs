use crate::jit::nix_jit_runtime_symbol_address_candidate_preflight;

use ratchet_core::{
    EffectClass, Ir, IrArena, IrAttrPathId, IrAttrPathSegment, IrData, IrFacts, IrId,
    IrInlineCacheSiteId, IrKind, IrNode,
    syntax::{Span, SymbolTable},
};
use ratchet_jit::{
    DEFAULT_TIER1_INVOCATION_THRESHOLD, JitCompiledCodePointer,
    JitCraneliftRegisteredTier1SlotPreflight, JitTieredCodeSlot, TierUpCounter, TierUpDemandHint,
    TierUpPolicy,
};
use ratchet_oracle::{
    eval::{EvalEnv, EvalModuleId, EvalNodeRef, EvalThunk, ForceClaim, ThunkState},
    value::Value,
};
use std::ptr::NonNull;

use super::*;

fn local_var_arena(slot: u32) -> IrArena {
    IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::LocalVar,
            Span::new(0, 4),
            EffectClass::pure(),
            IrData::Local { slot },
        )],
        Vec::new(),
    )
}

fn apply_arena(function_slot: u32, argument_slot: u32) -> IrArena {
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
        ],
        Vec::new(),
    )
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

fn string_arena() -> IrArena {
    IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::Str,
            Span::new(0, 5),
            EffectClass::pure(),
            IrData::None,
        )],
        Vec::new(),
    )
}

fn bool_arena(value: bool) -> IrArena {
    IrArena::from_raw_parts(
        vec![IrNode::new(
            IrKind::Bool,
            Span::new(0, 4),
            EffectClass::pure(),
            IrData::Bool(value),
        )],
        Vec::new(),
    )
}

fn hot_slot() -> JitTieredCodeSlot {
    JitTieredCodeSlot::with_counter(TierUpCounter::new(DEFAULT_TIER1_INVOCATION_THRESHOLD - 1))
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

#[test]
fn thunk_install_readiness_reports_cold_plan_without_publication_gaps() {
    let arena = string_arena();
    let thunk = EvalThunk::new(IrId::new(0));

    let readiness = nix_jit_registered_tier1_thunk_install_readiness_for_ir_root(
        JitTieredCodeSlot::new(),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &arena,
        IrId::new(0),
        &thunk,
    )
    .expect("cold readiness report builds");

    assert!(!readiness.install_plan().did_compile());
    assert!(!readiness.safe_preconditions_met());
    assert!(!readiness.is_ready_for_evaluator_publish());
    assert_eq!(
        readiness.expected_body(),
        EvalNodeRef::new(EvalModuleId::ROOT, IrId::new(0))
    );
    assert_eq!(
        readiness.target_body_ref(),
        Some(EvalNodeRef::new(EvalModuleId::ROOT, IrId::new(0)))
    );
    assert_eq!(readiness.target_state(), ThunkState::Suspended);
    assert_eq!(
        readiness.gaps(),
        &[NixJitThunkInstallGap::Tier1CodeNotCompiled]
    );
}

#[test]
fn force_aware_thunk_install_readiness_reports_future_publish_gaps_for_apply_root() {
    let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
        .expect("JIT address candidate preflight builds");
    let arena = apply_arena(4, 6);
    let thunk = EvalThunk::new(IrId::new(2));

    let readiness = nix_jit_force_aware_registered_tier1_thunk_install_readiness_for_ir_root(
        hot_slot(),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &arena,
        IrId::new(2),
        &thunk,
    )
    .expect("force-aware apply readiness report builds");

    assert!(readiness.install_plan().is_ready_for_install());
    assert!(readiness.safe_preconditions_met());
    assert!(!readiness.is_ready_for_evaluator_publish());
    assert_eq!(
        readiness
            .install_plan()
            .slot()
            .invocation_counter()
            .invocations(),
        DEFAULT_TIER1_INVOCATION_THRESHOLD
    );
    assert_eq!(
        readiness.gaps(),
        &[
            NixJitThunkInstallGap::EvaluatorThunkTierSlotStorageUnavailable,
            NixJitThunkInstallGap::AtomicThunkStatePublishUnavailable,
            NixJitThunkInstallGap::NativeThunkEntryDispatchUnavailable,
        ]
    );
    let promoted = readiness
        .install_plan()
        .promoted_preflight()
        .expect("readiness owns promoted preflight");
    assert_eq!(
        readiness.install_plan().tier1_code_ptr(),
        Some(promoted.finalized_function().compiled_code_ptr())
    );
    assert_eq!(
        artifact_runtime_import_names(promoted),
        ["aos_env_get", "aos_apply"]
    );
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
            .registered_symbol_for("aos_apply")
            .is_some_and(|registered| registered.address()
                == candidate_preflight
                    .address_candidate_for("aos_apply")
                    .expect("apply candidate exists")
                    .address())
    );
}

#[test]
fn thunk_install_readiness_reports_future_publish_gaps_for_ready_suspended_thunk() {
    let arena = local_var_arena(3);
    let thunk = EvalThunk::new(IrId::new(0));

    let readiness = nix_jit_registered_tier1_thunk_install_readiness_for_ir_root(
        hot_slot(),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &arena,
        IrId::new(0),
        &thunk,
    )
    .expect("promoted readiness report builds");

    assert!(readiness.install_plan().is_ready_for_install());
    assert!(readiness.safe_preconditions_met());
    assert!(!readiness.is_ready_for_evaluator_publish());
    assert_eq!(
        readiness.gaps(),
        &[
            NixJitThunkInstallGap::EvaluatorThunkTierSlotStorageUnavailable,
            NixJitThunkInstallGap::AtomicThunkStatePublishUnavailable,
            NixJitThunkInstallGap::NativeThunkEntryDispatchUnavailable,
        ]
    );
}

#[test]
fn thunk_install_readiness_reports_future_publish_gaps_for_apply_root() {
    let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
        .expect("JIT address candidate preflight builds");
    let arena = apply_arena(4, 6);
    let thunk = EvalThunk::new(IrId::new(2));

    let readiness = nix_jit_registered_tier1_thunk_install_readiness_for_ir_root(
        hot_slot(),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &arena,
        IrId::new(2),
        &thunk,
    )
    .expect("promoted apply readiness report builds");

    assert!(readiness.install_plan().is_ready_for_install());
    assert!(readiness.safe_preconditions_met());
    assert!(!readiness.is_ready_for_evaluator_publish());
    assert_eq!(
        readiness.gaps(),
        &[
            NixJitThunkInstallGap::EvaluatorThunkTierSlotStorageUnavailable,
            NixJitThunkInstallGap::AtomicThunkStatePublishUnavailable,
            NixJitThunkInstallGap::NativeThunkEntryDispatchUnavailable,
        ]
    );
    let promoted = readiness
        .install_plan()
        .promoted_preflight()
        .expect("readiness owns promoted preflight");
    assert_eq!(
        artifact_runtime_import_names(promoted),
        ["aos_env_get", "aos_apply"]
    );
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
            .registered_symbol_for("aos_apply")
            .is_some_and(|registered| registered.address()
                == candidate_preflight
                    .address_candidate_for("aos_apply")
                    .expect("apply candidate exists")
                    .address())
    );
}

#[test]
fn thunk_install_readiness_rejects_non_node_thunk_before_future_publish_gaps() {
    let arena = local_var_arena(4);
    let thunk = EvalThunk::apply(
        EvalModuleId::ROOT,
        IrId::new(1),
        Span::new(0, 1),
        Value::int(1),
        EvalModuleId::ROOT,
        IrId::new(2),
        Value::int(2),
    );

    let readiness = nix_jit_registered_tier1_thunk_install_readiness_for_ir_root(
        hot_slot(),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &arena,
        IrId::new(0),
        &thunk,
    )
    .expect("non-node thunk readiness report builds");

    assert!(readiness.install_plan().is_ready_for_install());
    assert!(!readiness.safe_preconditions_met());
    assert_eq!(
        readiness.gaps(),
        &[NixJitThunkInstallGap::TargetThunkHasNoIrBody]
    );
}

#[test]
fn thunk_install_readiness_rejects_root_mismatch() {
    let arena = local_var_arena(5);
    let thunk = EvalThunk::new(IrId::new(1));

    let readiness = nix_jit_registered_tier1_thunk_install_readiness_for_ir_root(
        hot_slot(),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &arena,
        IrId::new(0),
        &thunk,
    )
    .expect("mismatched thunk readiness report builds");

    assert!(readiness.install_plan().is_ready_for_install());
    assert!(!readiness.safe_preconditions_met());
    assert_eq!(
        readiness.gaps(),
        &[NixJitThunkInstallGap::TargetThunkRootMismatch {
            expected: EvalNodeRef::new(EvalModuleId::ROOT, IrId::new(0)),
            actual: EvalNodeRef::new(EvalModuleId::ROOT, IrId::new(1)),
        }]
    );
}

#[test]
fn thunk_install_readiness_rejects_module_mismatch_for_same_ir_id() {
    let arena = local_var_arena(7);
    let thunk = EvalThunk::with_env(EvalModuleId::new(1), IrId::new(0), EvalEnv::default());

    let readiness = nix_jit_registered_tier1_thunk_install_readiness_for_ir_root(
        hot_slot(),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &arena,
        IrId::new(0),
        &thunk,
    )
    .expect("module-mismatched thunk readiness report builds");

    assert!(readiness.install_plan().is_ready_for_install());
    assert!(!readiness.safe_preconditions_met());
    assert_eq!(
        readiness.gaps(),
        &[NixJitThunkInstallGap::TargetThunkRootMismatch {
            expected: EvalNodeRef::new(EvalModuleId::ROOT, IrId::new(0)),
            actual: EvalNodeRef::new(EvalModuleId::new(1), IrId::new(0)),
        }]
    );
}

#[test]
fn thunk_install_readiness_reports_missing_owner_for_already_installed_slot() {
    let arena = local_var_arena(8);
    let thunk = EvalThunk::new(IrId::new(0));
    let mut slot = JitTieredCodeSlot::new();
    slot.install_tier1_code(JitCompiledCodePointer::from_non_null(NonNull::dangling()))
        .expect("test slot accepts first tier-1 code pointer");

    let readiness = nix_jit_registered_tier1_thunk_install_readiness_for_ir_root(
        slot,
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &arena,
        IrId::new(0),
        &thunk,
    )
    .expect("already-installed slot readiness report builds");

    assert!(!readiness.install_plan().did_compile());
    assert!(readiness.install_plan().tier1_code_ptr().is_some());
    assert!(!readiness.safe_preconditions_met());
    assert_eq!(
        readiness.gaps(),
        &[NixJitThunkInstallGap::CraneliftModuleOwnerMissing]
    );
}

#[test]
fn thunk_install_readiness_rejects_forced_thunk() {
    let arena = local_var_arena(6);
    let thunk = EvalThunk::new(IrId::new(0));
    let ForceClaim::Claimed(guard) = thunk.cell().begin_force().expect("claim succeeds") else {
        panic!("fresh thunk should be claimable");
    };
    guard.finish(Value::int(42)).expect("finish succeeds");

    let readiness = nix_jit_registered_tier1_thunk_install_readiness_for_ir_root(
        hot_slot(),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &arena,
        IrId::new(0),
        &thunk,
    )
    .expect("forced thunk readiness report builds");

    assert!(readiness.install_plan().is_ready_for_install());
    assert!(!readiness.safe_preconditions_met());
    assert_eq!(
        readiness.gaps(),
        &[NixJitThunkInstallGap::TargetThunkNotSuspended {
            state: ThunkState::Forced,
        }]
    );
}

#[test]
fn force_aware_thunk_install_readiness_reports_cold_plan_without_publication_gaps() {
    let arena = string_arena();
    let thunk = EvalThunk::new(IrId::new(0));

    let readiness = nix_jit_force_aware_registered_tier1_thunk_install_readiness_for_ir_root(
        JitTieredCodeSlot::new(),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &arena,
        IrId::new(0),
        &thunk,
    )
    .expect("cold force-aware readiness report builds");

    assert!(!readiness.install_plan().did_compile());
    assert!(!readiness.safe_preconditions_met());
    assert!(!readiness.is_ready_for_evaluator_publish());
    assert_eq!(
        readiness.expected_body(),
        EvalNodeRef::new(EvalModuleId::ROOT, IrId::new(0))
    );
    assert_eq!(
        readiness.target_body_ref(),
        Some(EvalNodeRef::new(EvalModuleId::ROOT, IrId::new(0)))
    );
    assert_eq!(readiness.target_state(), ThunkState::Suspended);
    assert_eq!(
        readiness.gaps(),
        &[NixJitThunkInstallGap::Tier1CodeNotCompiled]
    );
}

#[test]
fn force_aware_thunk_install_readiness_reports_future_publish_gaps_for_literal_root() {
    let arena = bool_arena(true);
    let thunk = EvalThunk::new(IrId::new(0));

    let readiness = nix_jit_force_aware_registered_tier1_thunk_install_readiness_for_ir_root(
        JitTieredCodeSlot::new(),
        TierUpPolicy::default(),
        TierUpDemandHint::MultiUse,
        &arena,
        IrId::new(0),
        &thunk,
    )
    .expect("force-aware literal readiness report builds");

    assert!(readiness.install_plan().is_ready_for_install());
    assert!(readiness.safe_preconditions_met());
    assert!(!readiness.is_ready_for_evaluator_publish());
    assert_eq!(
        readiness.gaps(),
        &[
            NixJitThunkInstallGap::EvaluatorThunkTierSlotStorageUnavailable,
            NixJitThunkInstallGap::AtomicThunkStatePublishUnavailable,
            NixJitThunkInstallGap::NativeThunkEntryDispatchUnavailable,
        ]
    );
}

#[test]
fn force_aware_thunk_install_readiness_reports_future_publish_gaps_for_forced_env_slot() {
    let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
        .expect("JIT address candidate preflight builds");
    let arena = local_var_arena(9);
    let thunk = EvalThunk::new(IrId::new(0));

    let readiness = nix_jit_force_aware_registered_tier1_thunk_install_readiness_for_ir_root(
        hot_slot(),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &arena,
        IrId::new(0),
        &thunk,
    )
    .expect("force-aware env-slot readiness report builds");

    assert!(readiness.install_plan().is_ready_for_install());
    assert!(readiness.safe_preconditions_met());
    assert!(!readiness.is_ready_for_evaluator_publish());
    assert_eq!(
        readiness
            .install_plan()
            .slot()
            .invocation_counter()
            .invocations(),
        DEFAULT_TIER1_INVOCATION_THRESHOLD
    );
    assert_eq!(
        readiness.gaps(),
        &[
            NixJitThunkInstallGap::EvaluatorThunkTierSlotStorageUnavailable,
            NixJitThunkInstallGap::AtomicThunkStatePublishUnavailable,
            NixJitThunkInstallGap::NativeThunkEntryDispatchUnavailable,
        ]
    );
    let promoted = readiness
        .install_plan()
        .promoted_preflight()
        .expect("readiness owns promoted preflight");
    assert_eq!(
        readiness.install_plan().tier1_code_ptr(),
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
}

#[test]
fn force_aware_full_ir_thunk_install_readiness_reports_future_publish_gaps_for_static_select() {
    let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
        .expect("JIT address candidate preflight builds");
    let ir = static_select_ir(12);
    let thunk = EvalThunk::new(ir.root);

    let readiness =
        nix_jit_force_aware_registered_tier1_thunk_install_readiness_for_lowered_ir_root(
            hot_slot(),
            TierUpPolicy::default(),
            TierUpDemandHint::NoMultiUseEvidence,
            &ir,
            ir.root,
            &thunk,
        )
        .expect("force-aware full-IR static-select readiness report builds");

    assert!(readiness.install_plan().is_ready_for_install());
    assert!(readiness.safe_preconditions_met());
    assert!(!readiness.is_ready_for_evaluator_publish());
    assert_eq!(
        readiness.gaps(),
        &[
            NixJitThunkInstallGap::EvaluatorThunkTierSlotStorageUnavailable,
            NixJitThunkInstallGap::AtomicThunkStatePublishUnavailable,
            NixJitThunkInstallGap::NativeThunkEntryDispatchUnavailable,
        ]
    );
    let promoted = readiness
        .install_plan()
        .promoted_preflight()
        .expect("readiness owns promoted preflight");
    assert_eq!(
        readiness.install_plan().tier1_code_ptr(),
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
}

#[test]
fn force_aware_full_ir_thunk_install_readiness_reports_future_publish_gaps_for_static_has_attr() {
    let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
        .expect("JIT address candidate preflight builds");
    let ir = static_has_attr_ir(13);
    let thunk = EvalThunk::new(ir.root);

    let readiness =
        nix_jit_force_aware_registered_tier1_thunk_install_readiness_for_lowered_ir_root(
            hot_slot(),
            TierUpPolicy::default(),
            TierUpDemandHint::NoMultiUseEvidence,
            &ir,
            ir.root,
            &thunk,
        )
        .expect("force-aware full-IR static-hasAttr readiness report builds");

    assert!(readiness.install_plan().is_ready_for_install());
    assert!(readiness.safe_preconditions_met());
    assert!(!readiness.is_ready_for_evaluator_publish());
    assert_eq!(
        readiness.gaps(),
        &[
            NixJitThunkInstallGap::EvaluatorThunkTierSlotStorageUnavailable,
            NixJitThunkInstallGap::AtomicThunkStatePublishUnavailable,
            NixJitThunkInstallGap::NativeThunkEntryDispatchUnavailable,
        ]
    );
    let promoted = readiness
        .install_plan()
        .promoted_preflight()
        .expect("readiness owns promoted preflight");
    assert_eq!(
        readiness.install_plan().tier1_code_ptr(),
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
}

#[test]
fn full_ir_thunk_install_readiness_reports_future_publish_gaps_for_static_select() {
    let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
        .expect("JIT address candidate preflight builds");
    let ir = static_select_ir(10);
    let thunk = EvalThunk::new(ir.root);

    let readiness = nix_jit_registered_tier1_thunk_install_readiness_for_lowered_ir_root(
        hot_slot(),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &ir,
        ir.root,
        &thunk,
    )
    .expect("full-IR static-select readiness report builds");

    assert!(readiness.install_plan().is_ready_for_install());
    assert!(readiness.safe_preconditions_met());
    assert!(!readiness.is_ready_for_evaluator_publish());
    assert_eq!(
        readiness.gaps(),
        &[
            NixJitThunkInstallGap::EvaluatorThunkTierSlotStorageUnavailable,
            NixJitThunkInstallGap::AtomicThunkStatePublishUnavailable,
            NixJitThunkInstallGap::NativeThunkEntryDispatchUnavailable,
        ]
    );
    let promoted = readiness
        .install_plan()
        .promoted_preflight()
        .expect("readiness owns promoted preflight");
    assert_eq!(
        readiness.install_plan().tier1_code_ptr(),
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
}

#[test]
fn full_ir_thunk_install_readiness_reports_future_publish_gaps_for_static_has_attr() {
    let candidate_preflight = nix_jit_runtime_symbol_address_candidate_preflight()
        .expect("JIT address candidate preflight builds");
    let ir = static_has_attr_ir(11);
    let thunk = EvalThunk::new(ir.root);

    let readiness = nix_jit_registered_tier1_thunk_install_readiness_for_lowered_ir_root(
        hot_slot(),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &ir,
        ir.root,
        &thunk,
    )
    .expect("full-IR static-hasAttr readiness report builds");

    assert!(readiness.install_plan().is_ready_for_install());
    assert!(readiness.safe_preconditions_met());
    assert!(!readiness.is_ready_for_evaluator_publish());
    assert_eq!(
        readiness.gaps(),
        &[
            NixJitThunkInstallGap::EvaluatorThunkTierSlotStorageUnavailable,
            NixJitThunkInstallGap::AtomicThunkStatePublishUnavailable,
            NixJitThunkInstallGap::NativeThunkEntryDispatchUnavailable,
        ]
    );
    let promoted = readiness
        .install_plan()
        .promoted_preflight()
        .expect("readiness owns promoted preflight");
    assert_eq!(
        readiness.install_plan().tier1_code_ptr(),
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
}
