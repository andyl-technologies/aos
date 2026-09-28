//! Rejoins original FUSE provenance to the actual protected effect ledger.

use super::*;
use crate::controller_fuse_admission::ControllerFuseAdmissionCarrierV1;
use crate::controller_query::PublicOperationMethodV1;

/// Rejoins exact historical admission bytes to the protected operation ledger.
///
/// # Errors
///
/// Rejects lost protected names or inconsistent operation/effect, public scope
/// and idempotency lineage. Legacy admissions return no FUSE provenance.
pub(crate) fn accepted_fuse_admission_v1(
    journal: &Journal,
    operation_id: OperationId,
) -> Result<Option<ControllerFuseAdmissionCarrierV1>, ReconcilerError> {
    journal.validate_held_protected_names()?;
    if recovered_public_operation_resource_v1(journal, operation_id)?.is_none() {
        return Ok(None);
    }
    let operation_bytes = journal
        .get(RecordNamespace::Operation, operation_id.as_bytes())
        .ok_or(ReconcilerError::CorruptLedger(
            "missing FUSE admission operation",
        ))?;
    let operation = decode_operation(operation_bytes)?;
    if operation.effect_count != 1
        || operation.ownership_gated
        || operation.runtime_intent_digest.is_some()
        || !matches!(
            operation.state,
            OperationState::Accepted | OperationState::Applying | OperationState::Succeeded
        )
    {
        return Ok(None);
    }
    let effect_bytes = journal
        .get(RecordNamespace::Effect, &effect_key(operation_id, 0))
        .ok_or(ReconcilerError::CorruptLedger(
            "missing FUSE admission effect",
        ))?;
    let effect = decode_effect(effect_bytes)?;
    if !matches!(
        effect.plan.public_mutation_method(),
        Some(PublicOperationMethodV1::AttachView | PublicOperationMethodV1::ReplaceAttachment)
    ) {
        return Ok(None);
    }
    let context = effect
        .plan
        .public_mutation_context()?
        .ok_or(ReconcilerError::CorruptLedger(
            "missing FUSE admission context",
        ))?;
    let Some(carrier) = context.fuse_admission() else {
        // Legacy history remains readable but cannot establish a new worker
        // grant: no capability or key is inferred from its target resources.
        return Ok(None);
    };
    let public = recovered_public_operation_admission_v1(journal, operation_id)?.ok_or(
        ReconcilerError::CorruptLedger("missing FUSE public admission"),
    )?;
    let request = crate::public_mutation_compiler::ResolvedPublicMutationRequestV1::decode(
        context.canonical_request(),
    )
    .map_err(|_| ReconcilerError::CorruptLedger("invalid FUSE original request"))?;
    if carrier.operation() != operation_id
        || public.project() != carrier.project()
        || public.authorization().resource_kind() != request.resource_kind()
        || Some(public.authorization().selector()) != request.selector()
        || journal.check_idempotency(
            request.idempotency_key(),
            *carrier.request_digest().as_bytes(),
        ) != IdempotencyOutcome::Replay(operation_id)
        || public.method()
            != effect
                .plan
                .public_mutation_method()
                .ok_or(ReconcilerError::CorruptLedger("missing FUSE method"))?
        || public.accepted_wall_seconds() != context.accepted_wall_seconds()
    {
        return Err(ReconcilerError::CorruptLedger(
            "FUSE admission operation mismatch",
        ));
    }
    Ok(Some(carrier.clone()))
}
