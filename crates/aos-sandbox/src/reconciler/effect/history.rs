//! Joins complete historical Effect DATA to Native capacity and Delete custody.

use aos_sandbox_core::OperationId;
use aos_sandbox_protocol::domain_ledger::delete_batch::DeleteBatchViewV1;
use aos_sandbox_protocol::domain_ledger::effect_history::{
    EffectLedgerRecord, EffectState, decode_effect, encode_effect,
};
use aos_sandbox_protocol::domain_ledger::project_admission_metadata::ProjectAdmissionMetadataV1 as ProjectAdmissionMetadata;

use super::super::ReconcilerError;
use super::super::delete_gate_history::DeleteGateHistoryV1;

/// Holds the original decoded prior once while Journal checks the next row.
pub(crate) struct OriginalCapacityEffectHistoryV1(EffectLedgerRecord);

/// Preserves the prior decode before the caller inspects transaction records.
///
/// # Errors
///
/// Returns ProtectedBoundary when the original Effect bytes fail decoding.
pub(crate) fn decode_capacity_effect_history(
    bytes: &[u8],
) -> Result<OriginalCapacityEffectHistoryV1, crate::journal::JournalError> {
    let prior = decode_effect(bytes)
        .map_err(ReconcilerError::from)
        .map_err(|_| crate::journal::JournalError::ProtectedBoundary)?;
    Ok(OriginalCapacityEffectHistoryV1(prior))
}

/// Compares the next row only after the caller's original row/key frontier.
///
/// # Errors
///
/// Returns ProtectedBoundary for an absent or malformed next value, differing
/// plan/state/dispatch, or absent project-admission metadata.
pub(crate) fn compare_capacity_effect_history(
    prior: OriginalCapacityEffectHistoryV1,
    next: &crate::journal::JournalRecord,
) -> Result<(ProjectAdmissionMetadata, ProjectAdmissionMetadata), crate::journal::JournalError> {
    use crate::journal::JournalError;

    let prior = prior.0.into_parts();
    let next = decode_effect(next.value().ok_or(JournalError::ProtectedBoundary)?)
        .map_err(ReconcilerError::from)
        .map_err(|_| JournalError::ProtectedBoundary)?
        .into_parts();
    if next.0 != prior.0 || next.1 != prior.1 || next.2 != prior.2 {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok((
        prior.3.ok_or(JournalError::ProtectedBoundary)?,
        next.3.ok_or(JournalError::ProtectedBoundary)?,
    ))
}

/// Validates the complete per-row Delete Effect relation with original errors.
///
/// # Errors
///
/// Returns the original history/context error or Native publication error when
/// the complete Effect, request, Gate template, or bound-plan relation is invalid.
pub(crate) fn validate_delete_effect_record(
    row: &crate::journal::JournalRecord,
    gate: &Option<DeleteGateHistoryV1>,
    operation_id: OperationId,
    step: u32,
    batch: DeleteBatchViewV1<'_>,
    root: &[u8],
    delete_effects: &mut usize,
) -> Result<(), ReconcilerError> {
    use aos_sandbox_protocol::domain_ledger::ownership_gate::OwnershipGateStatusV1;
    use aos_sandbox_protocol::public_api::PublicOperationMethodV1;

    let invalid = || ReconcilerError::CorruptLedger("invalid Delete batch admission metadata");
    let effect = decode_effect(row.value().ok_or_else(invalid)?).map_err(ReconcilerError::from)?;
    if effect.state() != &EffectState::Planned
        || effect.dispatch().is_some()
        || effect.project_admission().is_some()
        || encode_effect(&effect)
            .map_err(ReconcilerError::from)?
            .as_slice()
            != row.value().ok_or_else(invalid)?
    {
        return Err(invalid());
    }
    if effect.plan().public_mutation_method() == Some(PublicOperationMethodV1::DeleteSandbox) {
        let context = effect
            .plan()
            .public_mutation_context()
            .map_err(ReconcilerError::from)?
            .ok_or_else(invalid)?;
        let aos_sandbox_protocol::public_api::request::DormantSandboxRequestKindV1::Delete(request) =
            context.validated_request().map_err(ReconcilerError::from)?
        else {
            return Err(invalid());
        };
        if context.project() != batch.project()
            || request.sandbox_id.as_slice() != root
            || request.expected_plan_digest.as_slice() != batch.graph_plan().as_slice()
            || request.cascade != (batch.flags() & 1 != 0)
            || request.force != (batch.flags() & 2 != 0)
        {
            return Err(invalid());
        }
        // The original counter advances before this decoded Effect is dropped.
        // Keep it inside the relation instead of returning a deferred Boolean.
        *delete_effects += 1;
    } else {
        let binding = effect.plan().authority().ok_or_else(invalid)?;
        let Some(DeleteGateHistoryV1(OwnershipGateStatusV1::Pending(gate))) = gate.as_ref() else {
            return Err(invalid());
        };
        if aos_sandbox_protocol::publication::bind_authority_publication_effect(
            gate.publication_draft(),
            binding.template_digest(),
        )
        .map_err(crate::publication::AuthorityPublicationError::from)?
        .into_inner(operation_id, step)
        .map_err(ReconcilerError::from)?
            != *effect.plan()
        {
            return Err(invalid());
        }
    }
    Ok(())
}
