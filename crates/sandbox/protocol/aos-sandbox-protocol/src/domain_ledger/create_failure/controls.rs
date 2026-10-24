//! Prices the new borrowed interfaces without adding another model backing.

use super::*;
use std::mem::size_of;

/// Prices explicit DATA constructor, argument and return planes.
///
/// It covers the additional snapshot and typed pure entry boundary; the old
/// complete Effect/projection/row-buffer quote remains separate and unchanged.
/// No supplied DATA or receiving scalar establishes native ownership.
#[must_use]
pub fn interface_control_bytes_data_v2(
    actual: crate::domain_ledger::readonly::HistoricalLedgerRowsDataV2<'_>,
) -> Option<usize> {
    use crate::domain_ledger::readonly::{HistoricalLedgerRowsDataV2, IdempotencyDecisionV1};
    use crate::public_api::projection::{PublicProjectionError, PublicProjectionRecordV1};
    use crate::domain_ledger::effect_history::EffectLedgerRecord;
    type Rows = HistoricalLedgerRowsDataV2<'static>;
    type Historical = CreateFailureHistoricalDataV2<'static>;
    type Error = CreateFailureDataErrorV2;

    // Diagnostic construction is one complete value, not a second materialized
    // map. Each method group names actual arguments and return/control planes.
    let snapshot = size_of::<(Rows, bool, bool)>().checked_mul(2)?
        .checked_add(size_of::<Historical>().checked_mul(3)?)?;
    let snapshot_queries = size_of::<(&Historical, RecordNamespace, &[u8])>()
        .checked_add(size_of::<Option<&[u8]>>().checked_mul(3)?)?
        .checked_add(size_of::<(&Historical, RecordNamespace)>())?
        .checked_add(size_of::<(&Historical,)>())?
        .checked_add(size_of::<Result<(), Error>>().checked_mul(3)?.checked_mul(2)?)?;
    let iterator = actual.records_data_v2(RecordNamespace::Effect);
    let iterator_controls = std::mem::size_of_val(&iterator).checked_mul(3)?;
    let row_queries = size_of::<(Rows, RecordNamespace, &[u8])>()
        .checked_add(size_of::<Option<&[u8]>>().checked_mul(3)?)?
        .checked_add(size_of::<(Rows, RecordNamespace)>())?
        .checked_add(iterator_controls)?
        .checked_add(size_of::<(Rows, &[u8])>())?
        .checked_add(size_of::<Option<&IdempotencyDecisionV1>>().checked_mul(3)?)?
        .checked_add(size_of::<Rows>().checked_mul(3)?)?;
    let planner_entries = size_of::<(&Historical, OperationId, CreateFailurePlanIdentityV2<'static>, i64)>()
        .checked_add(size_of::<(&Historical, ClosedBeforeArgumentNoApplyRecordV2, ObjectDigest, ObjectDigest, i64)>())?
        .checked_add(size_of::<Result<PlannedCreateFailureV1, Error>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<ClosedCreateFailurePlanDataV2, Error>>().checked_mul(3)?)?;
    let terminal_entries = size_of::<(&Historical, OperationId, OperationRecord)>()
        .checked_add(size_of::<(&Historical, OperationId, OperationRecord, &EffectLedgerRecord, u32, ClosedCreateFailureReceiptV2)>())?
        .checked_add(size_of::<(&Historical, &[u8], &[u8])>())?
        .checked_add(size_of::<Result<(), Error>>().checked_mul(3)?.checked_mul(3)?)?;
    let floor_entries = size_of::<(&Historical, OperationId)>().checked_mul(2)?
        .checked_add(size_of::<(&Historical,)>())?
        .checked_add(size_of::<Result<Option<CreateFailurePrepareV1>, Error>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<ClosedCreateFailurePrepareDataV2, Error>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<(), Error>>().checked_mul(3)?)?;
    let record_entries = size_of::<(&Historical, ClosedCreateFailurePrepareDataV2)>().checked_mul(2)?
        .checked_add(size_of::<Result<[JournalRecord; 3], Error>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<[ObjectDigest; 3], Error>>().checked_mul(3)?)?;
    let projection_entries = size_of::<(&Historical, PublicProjectionKindV1, [u8; 16])>()
        .checked_add(size_of::<Result<Option<PublicProjectionRecordV1>, PublicProjectionError>>().checked_mul(3)?)?
        .checked_add(size_of::<(&Historical, [u8; 16])>())?
        .checked_add(size_of::<Result<Vec<u8>, Error>>().checked_mul(3)?)?;
    let accepted_digest_entry = size_of::<(&Historical, ClosedBeforeArgumentNoApplyRecordV2)>()
        .checked_add(size_of::<Result<(), Error>>().checked_mul(3)?)?;
    let geometry_entry = size_of::<Rows>().checked_mul(2)?
        .checked_add(size_of::<Result<aos_sandbox_model::ResourceVector,
            CreateFailureGeometryErrorV2>>().checked_mul(3)?)?
        .checked_add(size_of::<Option<usize>>().checked_mul(3)?)?;
    // The sole preexisting admission decoder adds this actual borrowed call
    // and its owning typed return/projection planes at the failed-Create entry.
    let admission = size_of::<(Rows, OperationId)>().checked_mul(2)?
        .checked_add(size_of::<crate::domain_ledger::readonly::HistoricalLedgerComparisonV2<'static>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<Option<PublicOperationAdmissionV1>,
            crate::domain_ledger::create_admission::CreateAdmissionDataErrorV1>>().checked_mul(3)?)?
        .checked_add(size_of::<crate::domain_ledger::create_admission::CreateAdmissionDataErrorV1>().checked_mul(2)?)?
        .checked_add(size_of::<Error>().checked_mul(3)?)?;
    snapshot.checked_add(admission)?.checked_add(snapshot_queries)?.checked_add(row_queries)?
        .checked_add(planner_entries)?.checked_add(terminal_entries)?
        .checked_add(floor_entries)?.checked_add(record_entries)?
        .checked_add(projection_entries)?.checked_add(accepted_digest_entry)?
        .checked_add(geometry_entry)
}
