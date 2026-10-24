//! Compares complete historical public Create admission records and index DATA.
//!
//! These recipes preserve the Operation, Effect, authorization and idempotency
//! joins. Supplied rows establish neither protected provenance nor live admission;
//! genuine owners retain their native guards and independently owed observations.

use aos_sandbox_model::{ObjectDigest, OperationId, RecordNamespace};
use super::effect_history::{EffectHistoryDataError, EffectLedgerRecord, EffectState, decode_effect, encode_effect};
use super::operation::{OperationRecord, decode_operation, effect_key, encode_operation_record};
use super::public_operation::{OperationState, PublicOperationAdmissionV1, PublicOperationAuthorizationV1, PublicOperationDataError, resource_version};
use super::readonly::{HistoricalLedgerComparisonV2, HistoricalLedgerRowsDataV2, IdempotencyOutcome};

/// Reports the original flat historical Operation or Effect refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CreateAdmissionDataErrorV1 {
    /// An Operation or Effect plan violates its established bounds.
    #[error("invalid reconciliation plan: {0}")]
    InvalidPlan(&'static str),
    /// Retained records or their idempotency decision disagree.
    #[error("corrupt durable effect ledger: {0}")]
    CorruptLedger(&'static str),
    /// Retained Effect output exceeds its established contract.
    #[error("effect executor violated its output contract: {0}")]
    InvalidExecutorOutput(&'static str),
    /// A public transition has an invalid wall-clock observation.
    #[error("public operation clock observation is missing or invalid")]
    PublicOperationClock,
    /// The public observation sequence is exhausted.
    #[error("public operation observation sequence is exhausted")]
    PublicOperationSequenceExhausted,
}

impl From<PublicOperationDataError> for CreateAdmissionDataErrorV1 {
    fn from(error: PublicOperationDataError) -> Self {
        match error {
            PublicOperationDataError::InvalidPlan(reason) => Self::InvalidPlan(reason),
            PublicOperationDataError::CorruptLedger(reason) => Self::CorruptLedger(reason),
            PublicOperationDataError::PublicOperationClock => Self::PublicOperationClock,
            PublicOperationDataError::PublicOperationSequenceExhausted => Self::PublicOperationSequenceExhausted,
        }
    }
}

impl From<EffectHistoryDataError> for CreateAdmissionDataErrorV1 {
    fn from(error: EffectHistoryDataError) -> Self {
        match error {
            EffectHistoryDataError::InvalidPlan(reason) => Self::InvalidPlan(reason),
            EffectHistoryDataError::CorruptLedger(reason) => Self::CorruptLedger(reason),
            EffectHistoryDataError::InvalidExecutorOutput(reason) => Self::InvalidExecutorOutput(reason),
        }
    }
}

/// Recovers the original public admission and its required authorization row.
///
/// # Errors
/// Returns the original malformed Operation or missing/invalid authorization cause.
pub fn recovered_public_operation_admission_from_rows_v1(
    rows: HistoricalLedgerRowsDataV2<'_>,
    operation_id: OperationId,
) -> Result<Option<PublicOperationAdmissionV1>, CreateAdmissionDataErrorV1> {
    let journal = HistoricalLedgerComparisonV2::Rows(rows);
    let Some(operation_bytes) = journal.get(RecordNamespace::Operation, operation_id.as_bytes())
    else {
        return Ok(None);
    };
    let operation = decode_operation(operation_bytes)?;
    let Some(public) = operation.public_operation() else {
        return Ok(None);
    };
    let authorization = journal
        .get(
            RecordNamespace::PublicOperationAuthorization,
            operation_id.as_bytes(),
        )
        .map(PublicOperationAuthorizationV1::decode)
        .transpose()?
        .ok_or(CreateAdmissionDataErrorV1::CorruptLedger(
            "public operation has no authorization scope",
        ))?;

    Ok(Some(public.into_admission(authorization)))
}

/// Reconstructs the admitted Create revision from its complete historical join.
///
/// `allow_terminal_history` admits only the established paired terminal states.
/// This comparison grants no live Create, protected-current or execution authority.
///
/// # Errors
/// Returns the original Operation, Effect, request or idempotency consistency cause.
pub fn retained_create_sandbox_admission_from_rows_v1(
    rows: HistoricalLedgerRowsDataV2<'_>,
    operation_id: OperationId,
    allow_terminal_history: bool,
) -> Result<Option<(ObjectDigest, u64, [u8; 32])>, CreateAdmissionDataErrorV1> {
    let journal = HistoricalLedgerComparisonV2::Rows(rows);
    let Some(operation_bytes) = journal.get(RecordNamespace::Operation, operation_id.as_bytes())
    else {
        return Ok(None);
    };
    let operation = decode_operation(operation_bytes)?;
    let Some(public) = operation.public_operation() else {
        return Ok(None);
    };
    // Production Create admission installs its immutable first generation.
    if operation.effect_count() != 1
        || operation.ownership_gated()
        || operation.runtime_intent_digest().is_some()
        || public.method()
            != crate::public_api::PublicOperationMethodV1::CreateSandbox
        || public.accepted_generation() != 1
        || (!allow_terminal_history
            && !matches!(
                operation.state(),
                OperationState::Accepted | OperationState::Applying
            ))
    {
        return Ok(None);
    }

    let effect_bytes = journal
        .get(RecordNamespace::Effect, &effect_key(operation_id, 0))
        .ok_or(CreateAdmissionDataErrorV1::CorruptLedger(
            "live Create effect is absent",
        ))?;
    let effect = decode_effect(effect_bytes)
        .map_err(CreateAdmissionDataErrorV1::from)?
        .into_parts();
    let matching_live_state = matches!(
        (&operation.state(), &effect.1),
        (OperationState::Accepted, EffectState::Planned)
            | (OperationState::Applying, EffectState::Applying { .. })
    );
    let matching_terminal_history = allow_terminal_history
        && matches!(
            (&operation.state(), &effect.1),
            (
                OperationState::Succeeded
                    | OperationState::CanceledBeforeCommit
                    | OperationState::FailedBeforeCommit,
                EffectState::Applied { .. }
            ) | (
                OperationState::PermanentlyBlocked,
                EffectState::PermanentlyBlocked { .. }
            )
        );
    if (!matching_live_state && !matching_terminal_history)
        || effect.0.public_mutation_method()
            != Some(crate::public_api::PublicOperationMethodV1::CreateSandbox)
    {
        return Ok(None);
    }
    let Some(context) = effect
        .0
        .public_mutation_context()
        .map_err(CreateAdmissionDataErrorV1::from)?
    else {
        return Ok(None);
    };
    let admission = recovered_public_operation_admission_from_rows_v1(rows, operation_id)?.ok_or(
        CreateAdmissionDataErrorV1::CorruptLedger("live Create admission is absent"),
    )?;
    let request = crate::public_api::mutation::ResolvedPublicMutationRequestV1::decode(
        context.canonical_request(),
    )
    .map_err(|_| CreateAdmissionDataErrorV1::CorruptLedger("live Create request is invalid"))?;
    if !matches!(
        request.request(),
        crate::public_api::request::DormantSandboxRequestKindV1::Create(_)
    ) || request.operation_method()
        != crate::public_api::PublicOperationMethodV1::CreateSandbox
        || admission.project() != context.project()
        || admission.accepted_wall_seconds() != context.accepted_wall_seconds()
        || admission.authorization().resource_kind()
            != aos_sandbox_model::ResourceKind::ChildDelegation
        || request.selector() != Some(admission.authorization().selector())
        || request.target_project() != Some(admission.project())
    {
        return Ok(None);
    }
    let decision = journal
        .get(
            RecordNamespace::Idempotency,
            request.idempotency_key().as_bytes(),
        )
        .ok_or(CreateAdmissionDataErrorV1::CorruptLedger(
            "live Create idempotency decision is absent",
        ))?;
    if decision.len() != 48 || decision[32..] != *operation_id.as_bytes() {
        return Err(CreateAdmissionDataErrorV1::CorruptLedger(
            "live Create idempotency decision disagrees",
        ));
    }
    let request_digest: [u8; 32] = decision[..32]
        .try_into()
        .map_err(|_| CreateAdmissionDataErrorV1::CorruptLedger("live Create request digest is invalid"))?;
    if request_digest == [0; 32]
        || journal.check_idempotency(request.idempotency_key(), request_digest)
            != IdempotencyOutcome::Replay(operation_id)
    {
        return Err(CreateAdmissionDataErrorV1::CorruptLedger(
            "live Create request digest disagrees",
        ));
    }

    let admitted_operation = encode_operation_record(OperationRecord::new(
        OperationState::Accepted,
        1,
        false,
        None,
        Some(admission.durable()),
    ));
    let admitted_effect = encode_effect(&EffectLedgerRecord::from_parts((
        effect.0,
        EffectState::Planned,
        None,
        None,
    )))
    .map_err(CreateAdmissionDataErrorV1::from)?;
    let revision = resource_version(operation_id, &admitted_operation, &[&admitted_effect]);

    Ok(Some((
        ObjectDigest::from_bytes(revision),
        public.accepted_generation(),
        request_digest,
    )))
}
