//! Cross-validates runtime-authority audit records against the operation ledger.
//!
//! These read-only checks do not construct a reconciler or load the runtime
//! store recursively. Historical decisions retain their exact activated gate;
//! the runtime store separately validates revision chains and current heads.

use super::*;
use crate::runtime_authority::{RuntimeAuthorityBindingV1, RuntimeAuthorityPendingV1};

pub(crate) fn validate_runtime_authority_pending(
    journal: &Journal,
    pending: &RuntimeAuthorityPendingV1,
) -> Result<(), ReconcilerError> {
    let gate = runtime_gate(journal, pending.operation())?;
    let operation = journal
        .get(RecordNamespace::Operation, pending.operation().as_bytes())
        .ok_or(ReconcilerError::CorruptLedger(
            "runtime authority operation is missing",
        ))
        .and_then(decode_operation)?;
    let plan = gate_plan(&gate);
    if operation.runtime_intent_digest != Some(pending.intent_digest())
        || &plan.request_digest != pending.request_digest()
        || plan.publication_draft.manifest() != pending.manifest()
        || plan.publication_draft_digest() != pending.source_draft_digest()
    {
        return Err(ReconcilerError::CorruptLedger(
            "runtime authority intent does not match its admitted ownership gate",
        ));
    }
    if pending.state() == RuntimeAuthorityStateV1::Revoked {
        if operation.effect_count != 1 {
            return Err(ReconcilerError::CorruptLedger(
                "runtime revocation requires one Stop effect",
            ));
        }
        let effect = journal
            .get(RecordNamespace::Effect, &effect_key(pending.operation(), 0))
            .ok_or(ReconcilerError::CorruptLedger(
                "runtime revocation effect is missing",
            ))
            .and_then(decode_effect)?;
        validate_intent_effects(
            pending.state(),
            pending.operation(),
            plan.publication_draft(),
            &[effect.plan],
        )?;
    }
    if let OwnershipGateStatusV1::Activated {
        publication_digest,
        lease_generation,
        lease_digest,
        ..
    } = gate
    {
        crate::runtime_authority::validate_activated_pending(
            journal,
            pending,
            publication_digest,
            lease_generation,
            lease_digest,
        )?;
    }
    Ok(())
}

/// Requires revocation to name one exact, canonical, assignment-scoped Stop.
pub(super) fn validate_intent_effects(
    state: RuntimeAuthorityStateV1,
    operation: OperationId,
    draft: &AuthorityPublicationDraftV1,
    effects: &[EffectPlan],
) -> Result<(), ReconcilerError> {
    if state == RuntimeAuthorityStateV1::Bound {
        return Ok(());
    }
    let invalid = || {
        ReconcilerError::InvalidPlan("runtime revocation requires one canonical Host Stop effect")
    };
    let [effect] = effects else {
        return Err(invalid());
    };
    let binding = effect.authority().ok_or_else(invalid)?;
    let template = draft
        .templates()
        .iter()
        .find(|template| template.digest() == binding.template_digest)
        .ok_or_else(invalid)?;
    if template.audience() != aos_sandbox_core::BrokerAudience::Host
        || template.method()
            != aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME
        || !template.descriptor_roles().is_empty()
        || draft
            .bind_effect(template.digest())?
            .into_inner(operation, 0)
            != *effect
    {
        return Err(invalid());
    }

    let checked =
        aos_sandbox_protocol::decode_runtime_template_v1(template.body_without_deadline())
            .map_err(|_| invalid())?;
    let canonical =
        aos_sandbox_protocol::semantics::host::canonical_host_template_semantics_v1(&checked)
            .map_err(|_| invalid())?;
    let semantics = template.semantics();
    let manifest = draft.manifest().manifest();
    let fence = checked.fence();
    if canonical.verb() != aos_sandbox_core::BrokerVerb::HostStop
        || canonical.verb() != semantics.verb()
        || canonical.target() != semantics.target()
        || canonical.commitment() != semantics.argument_commitment()
        || fence.sandbox_id() != manifest.sandbox().as_bytes()
        || fence.incarnation_id() != manifest.incarnation().as_bytes()
        || fence.assignment_epoch() != manifest.epoch().get()
        || fence.desired_generation() != manifest.desired_generation().get()
        || fence.assignment_digest() != draft.manifest().digest().as_bytes()
    {
        return Err(invalid());
    }
    Ok(())
}

pub(crate) fn validate_runtime_authority_operations(
    journal: &Journal,
) -> Result<(), ReconcilerError> {
    for (key, bytes) in journal.records(RecordNamespace::Operation) {
        let operation = decode_operation(bytes)?;
        if let Some(digest) = operation.runtime_intent_digest {
            crate::runtime_authority::validate_operation_intent(
                journal,
                decode_operation_key(key)?,
                digest,
            )?;
        }
    }
    Ok(())
}

pub(crate) fn validate_runtime_authority_binding(
    journal: &Journal,
    binding: &RuntimeAuthorityBindingV1,
) -> Result<(), ReconcilerError> {
    let gate = runtime_gate(journal, binding.operation())?;
    let OwnershipGateStatusV1::Activated {
        plan,
        publication_digest,
        lease_generation,
        lease_digest,
    } = gate
    else {
        return Err(ReconcilerError::CorruptLedger(
            "runtime authority decision precedes ownership activation",
        ));
    };
    if &plan.request_digest != binding.request_digest()
        || plan.publication_draft.manifest() != binding.manifest()
        || plan.publication_draft_digest() != binding.source_draft_digest()
        || publication_digest != binding.publication_digest()
        || lease_generation != binding.lease_generation()
        || lease_digest != binding.lease_digest()
    {
        return Err(ReconcilerError::CorruptLedger(
            "runtime authority decision does not match its activated ownership gate",
        ));
    }
    validate_durable_gate_publication(
        journal,
        publication_digest,
        plan.publication_draft(),
        plan.claim(),
        lease_generation,
        lease_digest,
    )
    .map_err(|_| ReconcilerError::CorruptLedger("runtime authority publication is corrupt"))
}

fn gate_plan(gate: &OwnershipGateStatusV1) -> &OwnershipGatePlanV1 {
    match gate {
        OwnershipGateStatusV1::Pending(plan) | OwnershipGateStatusV1::Activated { plan, .. } => {
            plan
        }
    }
}

fn runtime_gate(
    journal: &Journal,
    operation_id: OperationId,
) -> Result<OwnershipGateStatusV1, ReconcilerError> {
    let operation = journal
        .get(RecordNamespace::Operation, operation_id.as_bytes())
        .ok_or(ReconcilerError::CorruptLedger(
            "runtime authority operation is missing",
        ))
        .and_then(decode_operation)?;
    let gate = journal
        .get(RecordNamespace::OwnershipGate, operation_id.as_bytes())
        .ok_or(ReconcilerError::CorruptLedger(
            "runtime authority gate is missing",
        ))
        .and_then(decode_ownership_gate)?;
    let plan = gate_plan(&gate);
    if !operation.ownership_gated
        || plan.operation_id != operation_id
        || journal.check_idempotency(&plan.idempotency_key, plan.request_digest)
            != IdempotencyOutcome::Replay(operation_id)
        || !matches!(
            (&gate, operation.state),
            (
                OwnershipGateStatusV1::Pending(_),
                OperationState::OwnershipPending
            ) | (
                OwnershipGateStatusV1::Activated { .. },
                OperationState::Accepted
                    | OperationState::Applying
                    | OperationState::Succeeded
                    | OperationState::PermanentlyBlocked
            )
        )
    {
        return Err(ReconcilerError::CorruptLedger(
            "runtime authority gate and operation disagree",
        ));
    }
    Ok(gate)
}
