//! Joins immutable accepted Start coordinates to the sole canonical public Effect.
//!
//! Reconnect replay borrows this historical row; it cannot replace its clock,
//! original peer cutoff, signed timeout or protected capability/policy limits.

use aos_sandbox_model::OperationId;
use aos_sandbox_protocol::domain_ledger::operation::{
    AcceptedStartOriginDataV1, decode_operation, decode_operation_key, effect_key,
};
use aos_sandbox_protocol::domain_ledger::effect_history::decode_effect;
use aos_sandbox_protocol::public_api::{PublicOperationMethodV1,
    request::DormantSandboxRequestKindV1};
use crate::{Journal, RecordNamespace, ReconcilerError};

pub(crate) fn accepted_start_origin_from_journal_v1(journal: &Journal, operation: OperationId)
    -> Result<Option<AcceptedStartOriginDataV1>, ReconcilerError>
{
    let record = journal.get(RecordNamespace::Operation, operation.as_bytes())
        .ok_or(ReconcilerError::CorruptLedger("accepted Start operation missing"))?;
    let record = decode_operation(record)?;
    let Some(origin) = record.accepted_start_origin_v1() else { return Ok(None); };
    if record.effect_count() != 1 || record.ownership_gated() || record.runtime_intent_digest().is_some() {
        return Err(ReconcilerError::CorruptLedger("accepted Start operation shape differs"));
    }
    let bytes = journal.get(RecordNamespace::Effect, &effect_key(operation, 0))
        .ok_or(ReconcilerError::CorruptLedger("accepted Start effect missing"))?;
    let effect = decode_effect(bytes).map_err(ReconcilerError::from)?;
    if effect.plan().public_mutation_method() != Some(PublicOperationMethodV1::StartSandbox) {
        return Err(ReconcilerError::CorruptLedger("accepted Start effect method differs"));
    }
    let context = effect.plan().public_mutation_context().map_err(ReconcilerError::from)?
        .ok_or(ReconcilerError::CorruptLedger("accepted Start context missing"))?;
    let DormantSandboxRequestKindV1::Start(request) = context.validated_request().map_err(ReconcilerError::from)? else {
        return Err(ReconcilerError::CorruptLedger("accepted Start request method differs"));
    };
    let timeout = request.mutation.as_option().and_then(|mutation| mutation.operation_timeout.as_option())
        .ok_or(ReconcilerError::CorruptLedger("accepted Start timeout missing"))?;
    if context.accepted_wall_seconds() != origin.accepted_clock_v1().wall_seconds()
        || timeout.nanoseconds != origin.signed_timeout_nanoseconds_v1()
    { return Err(ReconcilerError::CorruptLedger("accepted Start original coordinates differ")); }
    Ok(Some(origin))
}

pub(super) fn validate_all_v1(journal: &Journal) -> Result<(), ReconcilerError> {
    for (key, bytes) in journal.records(RecordNamespace::Operation) {
        let record = decode_operation(bytes)?;
        if record.accepted_start_origin_v1().is_some() {
            accepted_start_origin_from_journal_v1(journal, decode_operation_key(key)?)?;
        }
    }
    Ok(())
}
