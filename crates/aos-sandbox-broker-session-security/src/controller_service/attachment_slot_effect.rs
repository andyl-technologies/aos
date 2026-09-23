//! Advances admitted attachment slots through protected and authenticated Mount custody.
//!
//! A logical slot is committed under a fresh Host namespace target. The retained
//! Mount session then supplies a current physical inventory and carries any
//! separately signed, durably admitted slot effect. Ready is never inferred
//! from an effect response; a later fresh inventory must prove it.

use aos_sandbox::Journal;
use aos_sandbox::attachment_effect_owner::ProtectedAttachmentEffectOwnerV1;
use aos_sandbox::attachment_slot_state::{AttachmentSlotMutationV1, AttachmentSlotPresenceV1};
use aos_sandbox::destination_slot_inventory::DestinationSlotReconciliationActionV1;
use aos_sandbox::ownership_authority::ProtectedOwnershipClockError;
use aos_sandbox::runtime_scope::NamespaceTargetOutcome;
use aos_sandbox_core::{AttachmentSlotId, ObjectDigest, OperationId, Revision, SandboxId};
use sha2::{Digest as _, Sha256};

use super::attachment_target::ControllerAttachmentTargetInputsV1;
use super::{
    ControllerBrokerPlanSignerV1, DormantSandboxRequestKindV1, EffectFailure,
    ProductionEffectExecutor, PublicMutationEffectV1, sample_ownership_clock,
};

const SLOT_REQUEST_DOMAIN: &[u8] = b"aos.sandbox.public-attachment-slot-effect.v1\0";

pub(super) fn advance(
    executor: &mut ProductionEffectExecutor,
    operation: OperationId,
    context: &PublicMutationEffectV1,
    request: &DormantSandboxRequestKindV1,
    sandbox: SandboxId,
    slot_id: AttachmentSlotId,
    journal: &mut Journal,
) -> Result<(), EffectFailure> {
    let host = executor
        .attachment_host
        .as_ref()
        .ok_or_else(|| retryable("exact Host attachment identity is unavailable"))?;
    let _mount = executor
        .attachment_mount
        .as_ref()
        .ok_or_else(|| retryable("exact Mount attachment identity is unavailable"))?;
    let _anchor = ControllerBrokerPlanSignerV1::mount_trust_anchor_from_process_credentials()
        .map_err(|error| retryable(error.to_string()))?;
    let signer = executor
        .broker_plan_signer
        .as_ref()
        .ok_or_else(|| retryable("independent Mount plan signer is unavailable"))?;
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
    let mut clock = || sample_ownership_clock().map_err(|_| ProtectedOwnershipClockError);
    let existing = owner
        .current_slot(slot_id)
        .map_err(|error| retryable(error.to_string()))?;
    let assignment =
        if existing.is_none() && matches!(request, DormantSandboxRequestKindV1::ViewAttach(_)) {
            let mutation = AttachmentSlotMutationV1::new(
                AttachmentSlotPresenceV1::Available,
                slot_id,
                Revision::new(1),
                operation,
                request_digest(context),
                None,
            )
            .map_err(|error| retryable(error.to_string()))?;
            owner
                .commit_current_slot(target, mutation, &mut clock)
                .map_err(|error| retryable(error.to_string()))?
                .into_target()
                .into_assignment_target()
        } else {
            target.into_assignment_target()
        };
    let slot = owner
        .current_slot(slot_id)
        .map_err(|error| retryable(error.to_string()))?
        .ok_or_else(|| retryable("protected destination slot is not yet available"))?;
    if slot.sandbox() != sandbox || slot.presence() != AttachmentSlotPresenceV1::Available {
        return Err(EffectFailure::Permanent(
            "admitted attachment names a different or released destination slot".to_owned(),
        ));
    }

    let fence = owner
        .begin_authenticated_slot_inventory()
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
            .current_destination_slot_observation()
            .map_err(|error| retryable(error.to_string()))?;
        owner
            .complete_authenticated_slot_inventory(fence, &outcome)
            .map_err(|error| retryable(error.to_string()))?
    };
    let reconciliation = owner
        .reconcile_current_slot(slot, snapshot)
        .map_err(|error| retryable(error.to_string()))?;
    match reconciliation.action() {
        DestinationSlotReconciliationActionV1::Ready { .. } => return Ok(()),
        DestinationSlotReconciliationActionV1::Materialize { .. }
        | DestinationSlotReconciliationActionV1::Rematerialize { .. }
        | DestinationSlotReconciliationActionV1::Reap { .. } => {}
        // Pending work needs its original signed plan and attempt bytes. A
        // successor plan would equivocate under the same operation identity.
        _ => return Err(retryable("exact destination-slot recovery is pending")),
    }

    let prepared = owner
        .prepare_current_slot_effect(reconciliation, assignment, &mut clock)
        .map_err(|error| retryable(error.to_string()))?;
    let deadline = prepared.valid_until_boottime_nanoseconds();
    let scope = ControllerBrokerPlanSignerV1::mount_revocation_scope_from_process_credentials()
        .map_err(|error| retryable(error.to_string()))?;
    let plan = owner
        .current_slot_plan(&prepared, scope, &mut clock)
        .map_err(|error| retryable(error.to_string()))?;
    let issued = plan.issued_seconds();
    let signed = signer
        .sign_mount_plan(plan, issued)
        .map_err(|error| retryable(error.to_string()))?;
    let bound = owner
        .bind_current_slot_plan(prepared, signed, &mut clock)
        .map_err(|error| retryable(error.to_string()))?;
    let attempt = owner
        .admit_current_slot_effect(bound, deadline, &mut clock)
        .map_err(|error| retryable(error.to_string()))?;

    let outcome = {
        let mut sessions = executor
            .sessions
            .lock()
            .map_err(|_| retryable("broker session lock is poisoned"))?;
        sessions
            .mount
            .as_mut()
            .ok_or_else(|| retryable("authenticated Mount session is unavailable"))?
            .authenticated_destination_slot_effect(&attempt)
            .map_err(|error| retryable(error.to_string()))?
    };
    owner
        .complete_authenticated_slot_effect(attempt, &outcome, &mut clock)
        .map_err(|error| retryable(error.to_string()))?;

    // Completion proves the operation receipt, not the current physical row.
    Err(retryable(
        "fresh authenticated destination-slot inventory is pending",
    ))
}

fn request_digest(context: &PublicMutationEffectV1) -> ObjectDigest {
    let request = context.canonical_request();
    let digest: [u8; 32] = Sha256::new()
        .chain_update(SLOT_REQUEST_DOMAIN)
        .chain_update(context.caller().as_bytes())
        .chain_update(context.project().as_bytes())
        .chain_update((request.len() as u64).to_be_bytes())
        .chain_update(request)
        .finalize()
        .into();
    ObjectDigest::from_bytes(digest)
}

fn retryable(message: impl Into<String>) -> EffectFailure {
    EffectFailure::Retryable(message.into())
}
