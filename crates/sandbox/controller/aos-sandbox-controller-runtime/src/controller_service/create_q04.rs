//! Installed original-gen1 Create policy-subgate selection and worker join.
//!
//! This child borrows the existing executor's Source/Cache allocations and the
//! same parent-retained normal-Root profile. It adds no listener, actor, signer
//! service, public mutation gate or independent owner graph. The sole Core
//! driver keeps Operation/Effect Applying through exact original clearance.

use std::sync::Arc;

use aos_sandbox_controller_domain::cache_residency::CacheResidentInitializationV1;
use aos_sandbox_controller_domain::normal_root::ProductionControllerNormalRootProfileV1;
use aos_sandbox_controller_domain::reconciler::{EffectFailure};
use aos_sandbox_protocol::domain_ledger::effect_history::{EffectPlan};
use aos_sandbox_controller_domain::Journal;
use aos_sandbox_model::OperationId;

use super::ProductionEffectExecutor;

pub(super) struct OriginalQ04ControllerSelectionV1 {
    profile: Arc<ProductionControllerNormalRootProfileV1>,
    driver: super::inventory::OriginalCreateStorageDriverV1,
    initialization_result: Option<Result<(), aos_sandbox_controller_domain::cache_residency::CacheResidentUnavailableV1>>,
    initialization: CacheResidentInitializationV1,
    reservation: Option<aos_sandbox_controller_domain::ProjectPreparationReservationAttemptV1>,
    continued: Option<Result<(), EffectFailure>>,
    intake: Option<aos_sandbox_controller_domain::CreateContinuationIntakeAttemptV1>,
    intake_result: Option<Result<(), aos_sandbox_controller_domain::ResourceReservationErrorV1>>,
}

impl OriginalQ04ControllerSelectionV1 {
    pub(in crate::controller_service) fn provisioning_parts_v1(&mut self) -> Option<(
        &mut aos_sandbox_controller_domain::CreateContinuationIntakeAttemptV1,
        &super::inventory::OriginalCreateStorageDriverV1,
        &Arc<ProductionControllerNormalRootProfileV1>,
    )> {
        Some((self.intake.as_mut()?, &self.driver, &self.profile))
    }
}

pub(super) fn select(
    executor: &mut ProductionEffectExecutor,
    controller: &mut Journal,
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
        driver: super::inventory::OriginalCreateStorageDriverV1::new(),
        initialization_result: None,
        initialization: CacheResidentInitializationV1::new(),
        reservation: None,
        continued: None,
        intake: None,
        intake_result: None,
    });
    let Some(selected) = executor.q04.as_mut() else {
        std::process::exit(1);
    };
    let Some(bank) = executor.resource_bank.as_ref() else {
        std::process::exit(1);
    };
    // Actual profile/producer admission runs inside the SAME funded B scope,
    // not the already retained P/I/Q archive from an earlier startup purpose.
    selected.initialization_result = Some(selected.initialization.initialize_selected_once(
        &mut executor.cache_inventory, executor.controller_uid,
        bank, controller, selected.profile.as_ref(),
    ));
    if !matches!(selected.initialization_result, Some(Ok(()))) {
        // The actual typed capture cause and partial original files remain in
        // the SAME initializer/executor. No ordinary error drops or retry occur.
        std::process::exit(1);
    }

    let Some(owner) = executor.cache_inventory.as_mut() else {
        std::process::exit(1);
    };
    if selected.initialization.prepare_existing_physical_owner_selected(
        owner, &mut executor.cache_physical, executor.node, super::CACHE_OWNER_MEMORY_BYTES,
        bank, controller, selected.profile.as_ref(),
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
    dispatch: Option<&aos_sandbox_controller_domain::reconciler::PreparedAuthorityEffectV1>,
    authority_gate: Option<(aos_sandbox_model::SandboxId, aos_sandbox_model::ObjectDigest)>,
    journal: &mut Journal,
) -> Option<Result<(), EffectFailure>> {
    let selected = executor.q04.as_mut()?;
    if step != 0
        || effect_count != 1
        || dispatch.is_some()
        || authority_gate.is_some()
        || plan.public_mutation_method()
            != Some(aos_sandbox_protocol::public_api::PublicOperationMethodV1::CreateSandbox)
    {
        std::process::exit(1);
    }

    if let Some(intake) = selected.intake.as_ref() {
        if matches!(selected.intake_result, Some(Ok(())))
            && intake.require_original_create_terminal_v1(operation).is_ok() {
            // Reconciler retry observes only this same actual completed
            // original. It never readmits J or constructs another Ready.
            return Some(Ok(()));
        }
        std::process::exit(1);
    }
    if selected.continued.is_some() || selected.intake_result.is_some() {
        std::process::exit(1);
    }

    let Some(cache) = executor.cache_inventory.as_mut() else {
        std::process::exit(1);
    };
    let Some(physical) = executor.cache_physical.as_ref() else {
        std::process::exit(1);
    };
    selected.continued = Some(aos_sandbox_controller_domain::reconciler::continue_original_create_q04_policy_subgate_v1(
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
    ));
    if !matches!(selected.continued, Some(Ok(()))) || !selected.reservation.as_ref()
        .is_some_and(|reservation| reservation.require_terminal_retention().is_ok())
    {
        std::process::exit(1);
    }
    let Some(bank) = executor.resource_bank.as_ref() else {
        std::process::exit(1);
    };
    let Some(parent) = selected.reservation.take() else {
        std::process::exit(1);
    };
    selected.intake = Some(aos_sandbox_controller_domain::CreateContinuationIntakeAttemptV1::begin(
        parent, Arc::clone(bank),
    ));
    let Some(intake) = selected.intake.as_mut() else {
        std::process::exit(1);
    };
    selected.intake_result = Some(intake.prepare_once(
        journal, &mut executor.source_domains, selected.profile.as_ref(),
    ));
    if !matches!(selected.intake_result, Some(Ok(()))) {
        // The original parent, full native outcome and independent posts are
        // already in selection before this negative projection/termination.
        std::process::exit(1);
    }
    if intake.produce_original_history_once(
        journal, &mut executor.source_domains, selected.profile.as_ref(),
    ).is_err() {
        // The complete actual native outcome and independent debt are already
        // retained in selected.intake before this process fence.
        std::process::exit(1);
    }
    let mut ready = match intake.borrow_original_ready_once(
        journal, &mut executor.source_domains, selected.profile.as_ref(),
        &mut selected.initialization, cache, physical,
    ) {
        Ok(ready) => ready,
        Err(_) => std::process::exit(1),
    };
    let mut sessions = match executor.sessions.lock() {
        Ok(sessions) => sessions,
        Err(_original) => std::process::exit(1),
    };
    let Some(signer) = executor.broker_plan_signer.as_ref() else {
        std::process::exit(1);
    };
    if selected.driver.run_root_ready_prefix_once(&mut ready, &mut sessions).is_err()
        || selected.driver.run_root_use_prefix_once(&mut ready, &mut sessions, signer).is_err()
        || selected.driver.run_storage_signing_prefix_once(&mut ready, &mut sessions, signer).is_err()
        || selected.driver.run_root_signed_dispatch_once(&mut ready, &mut sessions).is_err()
        || selected.driver.run_storage_request_reservation_once(&mut ready, &mut sessions).is_err()
        || selected.driver.run_storage_request_exchange_once(&mut ready, &mut sessions).is_err()
        || selected.driver.run_storage_outcome_once(&mut ready, &mut sessions).is_err()
        || selected.driver.run_storage_terminal_once(&mut ready).is_err() {
        // The original driver, same Session, native U and every failed/owed
        // destination remain resident before this process-level fence.
        let _cause = selected.driver.failure_with_ready(&sessions, &ready);
        std::process::exit(1);
    }
    // Positive closure is established before any original guard is dropped.
    // The same intake then repeats the exact native terminal/operation gate;
    // a stopping marker or parsed outcome never completes this Effect.
    drop(ready);
    if intake.require_original_create_terminal_v1(operation).is_err() {
        std::process::exit(1);
    }
    Some(Ok(()))
}
