//! Installed original-gen1 Create policy-subgate selection and worker join.
//!
//! This child borrows the existing executor's Source/Cache allocations and the
//! same parent-retained normal-Root profile. It adds no listener, actor, signer
//! service, public mutation gate or independent owner graph. The sole Core
//! driver keeps Operation/Effect Applying through exact original clearance.

use std::sync::Arc;

use aos_sandbox::cache_residency::CacheResidentInitializationV1;
use aos_sandbox::normal_root::{NormalRootStartupErrorV1, ProductionControllerNormalRootProfileV1};
use aos_sandbox::reconciler::{EffectFailure, EffectPlan};
use aos_sandbox::Journal;
use aos_sandbox_core::OperationId;

use super::ProductionEffectExecutor;

pub(super) struct OriginalQ04ControllerSelectionV1 {
    profile: Arc<ProductionControllerNormalRootProfileV1>,
    admission: Option<Result<(), NormalRootStartupErrorV1>>,
    initialization: CacheResidentInitializationV1,
    reservation: Option<aos_sandbox::ProjectPreparationReservationAttemptV1>,
}

pub(super) fn select(
    executor: &mut ProductionEffectExecutor,
    profile: Arc<ProductionControllerNormalRootProfileV1>,
) -> Result<(), EffectFailure> {
    if executor.q04.is_some()
        || executor.cache_inventory.is_some()
        || executor.cache_physical.is_some()
    {
        return Err(EffectFailure::Permanent("original Q04 selection is not fresh".to_owned()));
    }

    // Park the genuine parent's original profile and all empty initialization
    // slots before any selected readback/open; no callee-local owner can escape.
    executor.q04 = Some(OriginalQ04ControllerSelectionV1 {
        profile,
        admission: None,
        initialization: CacheResidentInitializationV1::new(),
        reservation: None,
    });
    let Some(selected) = executor.q04.as_mut() else {
        std::process::exit(1);
    };
    selected.admission = Some(selected.profile.recheck());
    if !matches!(selected.admission, Some(Ok(()))) {
        std::process::exit(1);
    }

    if selected.initialization.initialize_once(
        &mut executor.cache_inventory, executor.controller_uid,
    ).is_err() {
        // The actual typed capture cause and partial original files remain in
        // the SAME initializer/executor. No ordinary error drops or retry occur.
        std::process::exit(1);
    }

    let Some(owner) = executor.cache_inventory.as_mut() else {
        std::process::exit(1);
    };
    if selected.initialization.prepare_existing_physical_owner(
        owner, &mut executor.cache_physical, executor.node, super::CACHE_OWNER_MEMORY_BYTES,
    ).is_err() {
        std::process::exit(1);
    }

    let Some(physical) = executor.cache_physical.as_ref() else {
        std::process::exit(1);
    };
    executor.cache_physical_limits = Some(physical.limits());
    Ok(())
}

pub(super) fn reconcile(
    executor: &mut ProductionEffectExecutor,
    operation: OperationId,
    step: u32,
    effect_count: u32,
    plan: &EffectPlan,
    dispatch: Option<&aos_sandbox::reconciler::PreparedAuthorityEffectV1>,
    authority_gate: Option<(aos_sandbox_core::SandboxId, aos_sandbox_core::ObjectDigest)>,
    journal: &mut Journal,
) -> Option<Result<(), EffectFailure>> {
    let selected = executor.q04.as_mut()?;
    if step != 0
        || effect_count != 1
        || dispatch.is_some()
        || authority_gate.is_some()
        || plan.public_mutation_method()
            != Some(aos_sandbox::controller_query::PublicOperationMethodV1::CreateSandbox)
    {
        std::process::exit(1);
    }

    let Some(cache) = executor.cache_inventory.as_mut() else {
        std::process::exit(1);
    };
    let Some(physical) = executor.cache_physical.as_ref() else {
        std::process::exit(1);
    };
    let continued = aos_sandbox::reconciler::continue_original_create_q04_policy_subgate_v1(
        journal,
        &mut executor.source_domains,
        &mut selected.initialization,
        cache,
        physical,
        selected.profile.as_ref(),
        operation,
        executor.request_scope,
        plan,
        executor.resource_bank.as_ref(),
        &mut selected.reservation,
    );
    if continued.is_ok() && !selected.reservation.as_ref()
        .is_some_and(|reservation| reservation.require_terminal_retention().is_ok())
    {
        std::process::exit(1);
    }
    Some(continued)
}
