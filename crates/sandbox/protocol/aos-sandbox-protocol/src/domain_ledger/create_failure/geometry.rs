//! Prices the existing failed-Create reducer from the same held row DATA.

use super::*;
use aos_sandbox_model::{ResourceDimension, ResourceVector};
use aos_sandbox_journal::framing::FrameError;

/// Preserves exact materialized framing errors separately from overflow.
#[derive(Debug, thiserror::Error)]
pub enum CreateFailureGeometryErrorV2 {
    /// The same native materialized representation cannot be encoded.
    #[error(transparent)]
    Frame(#[from] FrameError),
    /// A checked receiving total cannot be represented.
    #[error("failed-Create receiving geometry overflows")]
    Overflow,
}

/// Prices retained accepted Effect models using their exact encoded extent.
///
/// Returns `None` when checked arithmetic exceeds the receiving representation.
pub fn accepted_effect_models_receiving_bytes_v4(encoded: usize) -> Option<usize> {
    use crate::domain_ledger::effect_history::EffectLedgerRecord;
    use crate::domain_ledger::operation::MAXIMUM_EFFECTS;
    use aos_sandbox_api::aos::sandbox::v1::Feature;
    use std::mem::size_of;
    let bytes = (|| {
        let effects = MAXIMUM_EFFECTS.checked_mul(size_of::<EffectLedgerRecord>())?;
        let atom = size_of::<buffa::UnknownField>()
            .checked_add(size_of::<Feature>())?
            .checked_add(size_of::<Vec<u8>>())?;
        encoded.checked_mul(atom)?.checked_mul(8)?.checked_add(effects)?
            .checked_add(crate::domain_ledger::delete_batch::new_use::
                public_mutation_new_use_receiving_bytes_v2())
    })();
    let controls = size_of::<usize>().checked_mul(2)?
        .checked_add(size_of::<Option<usize>>().checked_mul(3)?)?
        .checked_add(size_of::<&usize>().checked_mul(2)?)?;
    bytes?.checked_add(controls)
}

/// Prices the complete existing reducer before any row copies or decoding.
///
/// # Errors
/// Preserves the materialized framing error and rejects checked overflow.
pub fn closed_create_failure_receiving_demand_data_v2(
    journal: crate::domain_ledger::readonly::HistoricalLedgerRowsDataV2<'_>,
) -> Result<ResourceVector, CreateFailureGeometryErrorV2> {
    use std::mem::size_of;
    use aos_sandbox_journal::geometry::{RecordShape, encoded_transaction_append_bytes};
    let records = journal.materialized_state_data_v2().iter().map(|((_, key), value)| RecordShape {
        key_bytes: key.len(), value_bytes: Some(value.len()),
    });
    let encoded = usize::try_from(encoded_transaction_append_bytes(records)?)
        .map_err(|_| CreateFailureGeometryErrorV2::Overflow)?;
    let accepted = accepted_effect_models_receiving_bytes_v4(encoded)
        .ok_or(CreateFailureGeometryErrorV2::Overflow)?;
    let memory = (|| {
        let mut rows = 0_usize;
        let mut effect_width = 0_usize;
        for namespace in [
            RecordNamespace::Effect,
            RecordNamespace::Operation,
            RecordNamespace::DesiredState,
        ] {
            let maximum = journal
                .records_data_v2(namespace)
                .try_fold(0_usize, |maximum, (key, value)| {
                    Some(maximum.max(key.len().checked_add(value.len())?))
                })?;
            rows = rows.checked_add(maximum)?;
            if namespace == RecordNamespace::Effect {
                effect_width = maximum;
            }
        }
        let effect = crate::domain_ledger::effect_history::
            effect_decoding_receiving_bytes_v1(effect_width)?;
        let projections = crate::public_api::projection::geometry::
            execution_source_receiving_bytes_v1(journal)?
            .checked_add(crate::public_api::projection::geometry::
                sandbox_source_receiving_bytes_v1(journal)?)?
            .checked_add(crate::public_api::projection::geometry::
                metadata_source_receiving_bytes_v2(journal)?)?;
        let authorization = crate::domain_ledger::public_operation::
            PublicOperationAuthorizationV1::maximum_receiving_bytes_v1();
        // Three old/new row pairs coexist with decoder inputs and growing
        // canonical outputs. Four complete pairs cover those destinations.
        let row_buffers = rows.checked_mul(2)?.checked_mul(4)?;
        let receipt_buffers = super::receipt::RECEIPT_BYTES_V2.checked_mul(4)?;
        let prepare_buffers = crate::host_execution_no_apply::closed_controller::CLOSED_CREATE_FAILURE_PREPARE_BYTES_V2.checked_mul(3)?;
        let carriers = size_of::<ClosedCreateFailurePlanDataV2>()
            .checked_mul(2)?
            .checked_add(size_of::<JournalRecord>().checked_mul(6)?)?;
        let bytes = accepted
            .checked_add(effect)?
            .checked_add(authorization)?
            .checked_add(row_buffers)?
            .checked_add(receipt_buffers)?
            .checked_add(prepare_buffers)?
            .checked_add(carriers)?
            .checked_add(interface_control_bytes_data_v2(journal)?)?;
        u64::try_from(bytes).ok()?.checked_add(projections)
    })()
    .ok_or(CreateFailureGeometryErrorV2::Overflow)?;
    Ok(ResourceVector::ZERO.with(ResourceDimension::MemoryBytes, memory))
}
