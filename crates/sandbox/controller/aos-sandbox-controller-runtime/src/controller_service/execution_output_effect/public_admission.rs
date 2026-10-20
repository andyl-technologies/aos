//! Transfers the actual serial Runtime C18 to the Node public compiler.
//!
//! The parent retains every Runtime input/result while the entire native
//! custody moves. There is no await, callback or replacement native claim in
//! this interval. Returning without restoring the same owner is fatal.

use std::sync::Arc;

use aos_sandbox_controller_domain::controller_execution_operation::{
    ControllerExecutionPublicCustodyTransferV2, ControllerExecutionRuntimeCustodyV2,
};
use aos_sandbox_controller_domain::{Journal, ResourceReservationErrorV1};
use aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeDemandDataV1 as Demand;

use super::{ControllerExecutionOriginalV1, ProductionEffectExecutor};

pub(in crate::controller_service) fn take_public_custody_once_v2(
    executor: &mut ProductionEffectExecutor,
    controller: &mut Journal,
) -> Result<Option<ControllerExecutionPublicCustodyTransferV2>, ResourceReservationErrorV1> {
    let bad = || ResourceReservationErrorV1::Conflict;
    let bank = Arc::clone(executor.resource_bank.as_ref().ok_or_else(bad)?);
    let profile = Arc::clone(executor.execution_profile.as_ref().ok_or_else(bad)?);
    let directory = executor.execution_credential_directory.as_deref().ok_or_else(bad)?;
    let host = executor.attachment_host.as_ref().ok_or_else(bad)?;
    let fixed = super::super::attachment_target::ControllerAttachmentSourceOriginalV1::
        fixed_receiving_demand_v1(host, directory).ok_or_else(bad)?;

    if executor.execution_original.is_none() {
        let bank_guard = bank.lock()
            .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
        executor.execution_original = Some(ControllerExecutionOriginalV1::claim_once_v1(
            &bank_guard, controller, profile.as_ref(),
        ).map_err(|_| bad())?);
    }
    let original = executor.execution_original.as_mut().ok_or_else(bad)?;
    if original.body.is_some() || original.periodic.is_some() || original.parent.is_some()
        || original.receipt.is_some() || original.specification.is_some()
        || original.availability_scope.is_some() || original.availability_body.is_some()
        || original.availability.failure_v2().is_some()
        || original.financial.as_ref().is_none_or(|custody| custody.failure_v2().is_some())
    {
        return Err(bad());
    }

    let custody = original.financial.take().ok_or_else(bad)?;
    Ok(Some((custody, bank, profile, Demand::from_demand_v1(fixed))))
}

pub(in crate::controller_service) fn retain_public_custody_v2(
    executor: &mut ProductionEffectExecutor,
    custody: ControllerExecutionRuntimeCustodyV2,
) {
    let Some(original) = executor.execution_original.as_mut() else {
        std::process::abort();
    };
    if original.financial.is_some() {
        std::process::abort();
    }
    original.financial = Some(custody);
}

/// Runs all four actual Session turns before returning durable acceptance.
pub(in crate::controller_service) fn admit_public_availability_once_v2(
    executor: &mut ProductionEffectExecutor,
    controller: &mut Journal,
    maximum_pending_operations: usize,
) -> Result<aos_sandbox_controller_domain::AcceptOutcome, ResourceReservationErrorV1> {
    let original = executor
        .execution_original
        .as_mut()
        .ok_or(ResourceReservationErrorV1::Conflict)?;
    if original.body.is_some()
        || original.periodic.is_some()
        || original.availability_scope.is_some()
        || original.availability_body.is_some()
        || original.availability.failure_v2().is_some()
    {
        return Err(ResourceReservationErrorV1::Conflict);
    }
    let custody = original
        .financial
        .as_mut()
        .ok_or(ResourceReservationErrorV1::Conflict)?;
    let scope = match custody.borrow_prepared_public_scope_v2(controller) {
        Ok(scope) => {
            original.availability_scope = Some(Ok(()));
            scope
        }
        Err(cause) => {
            original.availability_scope = Some(Err(cause));
            return Err(ResourceReservationErrorV1::Conflict);
        }
    };

    let returned = (|| {
        let mut sessions = executor
            .sessions
            .lock()
            .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let super::super::ControllerBrokerSessions { host, storage, .. } = &mut *sessions;
        let host = host.as_mut().ok_or(ResourceReservationErrorV1::Conflict)?;
        let storage = storage
            .as_mut()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let host = host.execution_availability_session_v2()?;
        let storage = storage.execution_availability_session_v2()?;
        let mut pair = host
            .borrow_execution_availability_client_once_v2(
                storage,
                scope,
                controller,
                &mut original.availability,
            )
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;

        pair.host_preaccept_once_v2()
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        pair.storage_preaccept_once_v2()
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let accepted = pair
            .admit_prepared_public_request_once_v2(maximum_pending_operations)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        pair.prepare_accepted_bind_once_v2()
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        pair.host_accepted_bind_once_v2()
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        pair.storage_accepted_bind_once_v2()
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let completed = pair
            .finish_accepted_bind_once_v2()
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        if completed != accepted {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        // The same pair and its mutex guard span REQUESTED and both binds.
        // Neither actual Session nor the lower C18 was moved or replaced.
        Ok(completed)
    })();
    original.availability_body = Some(returned);
    original
        .availability_body
        .as_ref()
        .and_then(|value| value.as_ref().ok())
        .copied()
        .ok_or(ResourceReservationErrorV1::Conflict)
}
