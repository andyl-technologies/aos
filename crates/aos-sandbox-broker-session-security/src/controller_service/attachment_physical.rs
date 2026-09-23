//! Reconciles protected attachment intent against fresh authenticated Mount state.
//!
//! The result is nonauthorizing. Ready still requires the existing protected
//! post-attach verification record; this adapter never manufactures one from a
//! successful Apply response or a public projection.

use aos_sandbox::Journal;
use aos_sandbox::attachment_effect_owner::ProtectedAttachmentEffectOwnerV1;
use aos_sandbox::attachment_mount::PreparedCurrentAttachmentMountV1;
use aos_sandbox::attachment_reconciliation::AttachmentReconciliationActionV1;
use aos_sandbox::ownership_authority::ProtectedOwnershipClockError;
use aos_sandbox::runtime_scope::NamespaceTargetOutcome;
use aos_sandbox_core::{AttachmentId, OperationId, SandboxId};

use super::attachment_target::ControllerAttachmentTargetInputsV1;
use super::{
    ControllerBrokerPlanSignerV1, EffectFailure, ProductionEffectExecutor, sample_ownership_clock,
};

pub(super) fn observe(
    executor: &mut ProductionEffectExecutor,
    operation: OperationId,
    attachment: AttachmentId,
    sandbox: SandboxId,
    journal: &mut Journal,
) -> Result<AttachmentReconciliationActionV1, EffectFailure> {
    if drain_pending_before_slot(executor, journal)? {
        return Err(retryable("fresh authenticated Mount inventory is pending"));
    }

    let host = executor
        .attachment_host
        .as_ref()
        .ok_or_else(|| retryable("exact Host attachment identity is unavailable"))?;
    let inputs =
        ControllerAttachmentTargetInputsV1::from_protected_configuration(host, executor.node)
            .map_err(|error| retryable(error.to_string()))?;
    let target = match inputs
        .acquire(journal, sandbox)
        .map_err(|error| retryable(error.to_string()))?
    {
        NamespaceTargetOutcome::Current(target) => *target,
        NamespaceTargetOutcome::AdvanceRequired(_) => {
            return Err(retryable(
                "attachment namespace assignment successor is pending",
            ));
        }
    };

    let mut owner = ProtectedAttachmentEffectOwnerV1::claim(journal)
        .map_err(|error| retryable(error.to_string()))?;
    let desired = owner
        .operation(operation)
        .map_err(|error| retryable(error.to_string()))?
        .ok_or_else(|| retryable("protected attachment generation is pending"))?;
    let current = owner
        .current(attachment)
        .map_err(|error| retryable(error.to_string()))?
        .ok_or_else(|| retryable("current attachment generation is unavailable"))?;
    if desired.record_digest() != current.record_digest() {
        return Err(retryable("attachment generation has a protected successor"));
    }

    let fence = owner
        .begin_authenticated_mount_inventory()
        .map_err(|error| retryable(error.to_string()))?;
    let snapshot = {
        let mut sessions = executor
            .sessions
            .lock()
            .map_err(|_| retryable("broker session lock is poisoned"))?;
        let mount = sessions
            .mount
            .as_mut()
            .ok_or_else(|| retryable("authenticated Mount session is unavailable"))?;
        let outcome = mount
            .current_inventory_observation()
            .map_err(|error| retryable(error.to_string()))?;
        owner
            .complete_authenticated_mount_inventory(fence, &outcome)
            .map_err(|error| retryable(error.to_string()))?
    };
    let mut clock = || sample_ownership_clock().map_err(|_| ProtectedOwnershipClockError);
    let inventory = owner
        .reconcile_current_mount_inventory(target, snapshot, &mut clock)
        .map_err(|error| retryable(error.to_string()))?;
    let reconciliation = owner
        .reconcile_current(desired, inventory, &mut clock)
        .map_err(|error| retryable(error.to_string()))?;
    let action = reconciliation.action();
    if !matches!(
        action,
        AttachmentReconciliationActionV1::Prepare { .. }
            | AttachmentReconciliationActionV1::Install { .. }
            | AttachmentReconciliationActionV1::Replace { .. }
            | AttachmentReconciliationActionV1::Detach { .. }
    ) {
        return Ok(action);
    }

    ensure_mount_policy(executor)?;
    let coordinates = {
        let mut sessions = executor
            .sessions
            .lock()
            .map_err(|_| retryable("broker session lock is poisoned"))?;
        sessions
            .mount
            .as_mut()
            .ok_or_else(|| retryable("authenticated Mount session is unavailable"))?
            .mount_catalog_request_coordinates()
            .map_err(|error| retryable(error.to_string()))?
    };
    let query = owner
        .prepare_authenticated_mount_catalog_query(
            reconciliation,
            coordinates.request_id(),
            coordinates.deadline_boottime_nanoseconds(),
            &mut clock,
        )
        .map_err(|error| retryable(error.to_string()))?;
    executor.pending_attachment_catalog_query = Some(query);
    drop(owner);
    drain_pending_catalog_query(executor, journal)?;
    Err(retryable("fresh authenticated Mount inventory is pending"))
}

pub(super) fn drain_pending_before_slot(
    executor: &mut ProductionEffectExecutor,
    journal: &mut Journal,
) -> Result<bool, EffectFailure> {
    if executor.pending_attachment_mount_attempt.is_some() {
        drain_pending_mount_attempt(executor, journal)?;
        return Ok(true);
    }
    if executor.pending_attachment_catalog_query.is_some() {
        drain_pending_catalog_query(executor, journal)?;
        return Ok(true);
    }
    Ok(false)
}

fn ensure_mount_policy(executor: &ProductionEffectExecutor) -> Result<(), EffectFailure> {
    executor
        .attachment_mount
        .as_ref()
        .ok_or_else(|| retryable("exact Mount attachment identity is unavailable"))?;
    ControllerBrokerPlanSignerV1::mount_trust_anchor_from_process_credentials()
        .map_err(|error| retryable(error.to_string()))?;
    executor
        .broker_plan_signer
        .as_ref()
        .ok_or_else(|| retryable("independent Mount plan signer is unavailable"))?;
    Ok(())
}

fn drain_pending_catalog_query(
    executor: &mut ProductionEffectExecutor,
    journal: &mut Journal,
) -> Result<(), EffectFailure> {
    let query = executor
        .pending_attachment_catalog_query
        .take()
        .ok_or_else(|| retryable("retained Mount catalog query is unavailable"))?;
    let outcome = (|| {
        let mut sessions = executor
            .sessions
            .lock()
            .map_err(|_| retryable("broker session lock is poisoned"))?;
        sessions
            .mount
            .as_mut()
            .ok_or_else(|| retryable("authenticated Mount session is unavailable"))?
            .authenticated_mount_catalog_preparation(query.query())
            .map_err(|error| retryable(error.to_string()))
    })();
    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(error) => {
            executor.pending_attachment_catalog_query = Some(query);
            return Err(error);
        }
    };
    let mut clock = || sample_ownership_clock().map_err(|_| ProtectedOwnershipClockError);
    let prepared = query
        .complete_authenticated(journal, &outcome, &mut clock)
        .map_err(|error| retryable(error.to_string()))?;
    admit_and_dispatch_mount(executor, prepared, journal)
}

fn admit_and_dispatch_mount(
    executor: &mut ProductionEffectExecutor,
    prepared: PreparedCurrentAttachmentMountV1,
    journal: &mut Journal,
) -> Result<(), EffectFailure> {
    ensure_mount_policy(executor)?;
    let signer = executor
        .broker_plan_signer
        .as_ref()
        .ok_or_else(|| retryable("independent Mount plan signer is unavailable"))?;
    let scope = ControllerBrokerPlanSignerV1::mount_revocation_scope_from_process_credentials()
        .map_err(|error| retryable(error.to_string()))?;
    let deadline = prepared.valid_until_boottime_nanoseconds();
    let mut owner = ProtectedAttachmentEffectOwnerV1::claim(journal)
        .map_err(|error| retryable(error.to_string()))?;
    let mut clock = || sample_ownership_clock().map_err(|_| ProtectedOwnershipClockError);
    let plan = owner
        .current_mount_plan(&prepared, scope, &mut clock)
        .map_err(|error| retryable(error.to_string()))?;
    let issued = plan.issued_seconds();
    let signed = signer
        .sign_mount_plan(plan, issued)
        .map_err(|error| retryable(error.to_string()))?;
    let bound = owner
        .bind_current_mount_plan(prepared, signed, &mut clock)
        .map_err(|error| retryable(error.to_string()))?;
    let attempt = owner
        .admit_current_mount_effect(bound, deadline, &mut clock)
        .map_err(|error| retryable(error.to_string()))?;
    executor.pending_attachment_mount_attempt = Some(attempt);
    drop(owner);
    drain_pending_mount_attempt(executor, journal)
}

fn drain_pending_mount_attempt(
    executor: &mut ProductionEffectExecutor,
    journal: &mut Journal,
) -> Result<(), EffectFailure> {
    let attempt = executor
        .pending_attachment_mount_attempt
        .take()
        .ok_or_else(|| retryable("retained Mount Apply attempt is unavailable"))?;
    let outcome = (|| {
        let mut sessions = executor
            .sessions
            .lock()
            .map_err(|_| retryable("broker session lock is poisoned"))?;
        sessions
            .mount
            .as_mut()
            .ok_or_else(|| retryable("authenticated Mount session is unavailable"))?
            .authenticated_mount_apply(attempt.attempt())
            .map_err(|error| retryable(error.to_string()))
    })();
    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(error) => {
            executor.pending_attachment_mount_attempt = Some(attempt);
            return Err(error);
        }
    };
    let mut owner = ProtectedAttachmentEffectOwnerV1::claim(journal)
        .map_err(|error| retryable(error.to_string()))?;
    let mut clock = || sample_ownership_clock().map_err(|_| ProtectedOwnershipClockError);
    owner
        .complete_authenticated_mount_effect(attempt, &outcome, &mut clock)
        .map_err(|error| retryable(error.to_string()))?;
    Ok(())
}

fn retryable(message: impl Into<String>) -> EffectFailure {
    EffectFailure::Retryable(message.into())
}
