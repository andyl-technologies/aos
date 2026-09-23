//! Reconciles protected attachment intent against fresh authenticated Mount state.
//!
//! The result is nonauthorizing. Ready still requires the existing protected
//! post-attach verification record; this adapter never manufactures one from a
//! successful Apply response or a public projection.

use aos_sandbox::Journal;
use aos_sandbox::attachment_effect_owner::ProtectedAttachmentEffectOwnerV1;
use aos_sandbox::attachment_reconciliation::AttachmentReconciliationActionV1;
use aos_sandbox::ownership_authority::ProtectedOwnershipClockError;
use aos_sandbox::runtime_scope::NamespaceTargetOutcome;
use aos_sandbox_core::{AttachmentId, OperationId, SandboxId};

use super::attachment_target::ControllerAttachmentTargetInputsV1;
use super::{EffectFailure, ProductionEffectExecutor, sample_ownership_clock};

pub(super) fn observe(
    executor: &mut ProductionEffectExecutor,
    operation: OperationId,
    attachment: AttachmentId,
    sandbox: SandboxId,
    journal: &mut Journal,
) -> Result<AttachmentReconciliationActionV1, EffectFailure> {
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
    Ok(reconciliation.action())
}

fn retryable(message: impl Into<String>) -> EffectFailure {
    EffectFailure::Retryable(message.into())
}
