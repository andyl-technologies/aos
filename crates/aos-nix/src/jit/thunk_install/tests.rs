use ratchet_core::{EffectClass, IrArena, IrData, IrId, IrKind, IrNode, syntax::Span};
use ratchet_jit::{
    DEFAULT_TIER1_INVOCATION_THRESHOLD, JitCompiledCodePointer, JitCraneliftModuleSetupError,
    JitTieredCodeSlot, TierUpCounter, TierUpDemandHint, TierUpPolicy,
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
fn force_aware_thunk_install_readiness_reports_missing_force_candidate() {
    let arena = local_var_arena(9);
    let thunk = EvalThunk::new(IrId::new(0));

    let result = nix_jit_force_aware_registered_tier1_thunk_install_readiness_for_ir_root(
        hot_slot(),
        TierUpPolicy::default(),
        TierUpDemandHint::NoMultiUseEvidence,
        &arena,
        IrId::new(0),
        &thunk,
    );
    let Err(error) = result else {
        panic!("force-aware env-slot readiness requires an aos_force candidate");
    };

    let NixJitThunkInstallReadinessError::Promotion(
        NixJitRegisteredTier1PromotionError::Cranelift(source),
    ) = error
    else {
        panic!("expected force-aware promotion failure");
    };
    assert!(source.decision().should_promote());
    assert_eq!(
        source.slot().invocation_counter().invocations(),
        DEFAULT_TIER1_INVOCATION_THRESHOLD
    );
    assert!(source.slot().tier1_code_ptr().is_none());
    let JitCraneliftModuleSetupError::ArtifactRuntimeImportsRequireRegistration { symbol_names } =
        source.setup_error()
    else {
        panic!("expected force helper registration guard");
    };
    assert_eq!(symbol_names, &["aos_force".to_owned()]);
}
