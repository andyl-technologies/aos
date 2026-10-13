//! Compares a complete historical Gate with its selected native Delete batch.
//!
//! Protocol owns the Gate model and V1 codec. This private relation retains
//! Lifecycle's original batch view and projects errors before native callers
//! receive a Result; it does not activate ownership or grant an effect.

use aos_sandbox_core::OperationId;
use aos_sandbox_protocol::domain_ledger::delete_batch::DeleteBatchViewV1;
use aos_sandbox_protocol::domain_ledger::ownership_gate::{
    OwnershipGateStatusV1, decode_ownership_gate, encode_ownership_gate,
};

use super::ReconcilerError;

/// Holds one original Gate across Journal row checks without exposing its plan.
pub(crate) struct DeleteGateHistoryV1(pub(super) OwnershipGateStatusV1);

/// Decodes and compares the complete original Delete ownership-gate row.
///
/// # Errors
///
/// Returns the original Reconciler error when the row, Pending tag, metadata,
/// or canonical bytes do not match the selected Delete batch.
pub(crate) fn decode_delete_gate(
    gate_row: &crate::journal::JournalRecord,
    operation_id: OperationId,
    batch: DeleteBatchViewV1<'_>,
    idempotency: &crate::journal::JournalRecord,
) -> Result<DeleteGateHistoryV1, ReconcilerError> {
    use crate::journal::RecordNamespace;

    let invalid = || ReconcilerError::CorruptLedger("invalid Delete batch admission metadata");
    if gate_row.namespace() != RecordNamespace::OwnershipGate
        || gate_row.key() != operation_id.as_bytes()
    {
        return Err(invalid());
    }
    let gate = decode_ownership_gate(gate_row.value().ok_or_else(invalid)?)
        .map_err(ReconcilerError::from)?;
    let OwnershipGateStatusV1::Pending(plan) = &gate else {
        return Err(invalid());
    };
    if plan.operation_id() != operation_id
        || plan.request_digest() != batch.request_digest()
        || plan.idempotency_key().as_bytes() != idempotency.key()
        || encode_ownership_gate(&gate)
            .map_err(ReconcilerError::from)?
            .as_slice()
            != gate_row.value().ok_or_else(invalid)?
    {
        return Err(invalid());
    }
    Ok(DeleteGateHistoryV1(gate))
}
