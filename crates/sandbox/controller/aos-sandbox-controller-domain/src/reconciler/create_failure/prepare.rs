//! Retains actual live Host proof checks and native cross-owner floor joins.

use super::*;
use crate::runtime_execution::no_apply_settlement::{HostSettlementRecordV1,
    HostSettlementStageV1, validate_history};
pub(super) use aos_sandbox_protocol::domain_ledger::create_failure::CreateFailurePrepareV1;

pub(super) fn from_plan(
    operation_id: OperationId,
    proof: &CreateFailureSettlementProofV1,
    wall_seconds: i64,
    predecessor: [ObjectDigest; 3],
    successor: [ObjectDigest; 3],
) -> Result<CreateFailurePrepareV1, ReconcilerError> {
    if proof.host_lease_epoch == 0
        || proof.host_lease_head.as_bytes() == &[0; 32]
        || proof.archive_head.as_bytes() == &[0; 32]
        || proof.signed_outcome.as_bytes() == &[0; 32]
        || proof.current_host_cut.as_bytes() == &[0; 32]
        || predecessor
            .iter()
            .any(|digest| digest.as_bytes() == &[0; 32])
        || successor.iter().any(|digest| digest.as_bytes() == &[0; 32])
    {
        return Err(invalid_settlement());
    }
    Ok(CreateFailurePrepareV1 {
        operation_id,
        marker: proof.marker,
        archive_head: proof.archive_head,
        signed_outcome: proof.signed_outcome,
        current_host_cut: proof.current_host_cut,
        host_lease_epoch: proof.host_lease_epoch,
        host_lease_head: proof.host_lease_head,
        wall_seconds,
        predecessor,
        successor,
    })
}

pub(super) fn load_floor(journal: &Journal, operation_id: OperationId)
    -> Result<Option<CreateFailurePrepareV1>, ReconcilerError> {
    let historical = super::observation::historical_data_v2(
        crate::journal::historical_observation::HistoricalObservationV1::from_journal_v1(journal),
    )?;
    aos_sandbox_protocol::domain_ledger::create_failure::load_floor(&historical, operation_id)
        .map_err(ReconcilerError::from)
}

pub(super) fn validate_all_floors(journal: &Journal) -> Result<(), ReconcilerError> {
    let historical = super::observation::historical_data_v2(
        crate::journal::historical_observation::HistoricalObservationV1::from_journal_v1(journal),
    )?;
    aos_sandbox_protocol::domain_ledger::create_failure::validate_all_floors(&historical)
        .map_err(ReconcilerError::from)
}

#[allow(dead_code, reason = "signed cross-owner Host transport remains closed")]
pub(super) fn validate_historical_host_floor_join(
    floor: CreateFailurePrepareV1,
    preliminary: HostSettlementRecordV1,
    sealed: HostSettlementRecordV1,
    protected_host_sequence: u64,
) -> Result<(), ReconcilerError> {
    if validate_history(
        floor.marker,
        Some(preliminary),
        Some(sealed),
        None,
        protected_host_sequence,
    )
    .map_err(|_| invalid_settlement())?
        != Some(HostSettlementStageV1::FloorSealed)
        || preliminary.execution.as_bytes() != &floor.marker.fields().execution_id
        || preliminary.operation != floor.operation_id
        || preliminary.archives.original_h_head != floor.archive_head
        || preliminary.archives.signed_terminal_outcome != floor.signed_outcome
        || preliminary.pre_lease_cut != floor.current_host_cut
        || preliminary.epoch != floor.host_lease_epoch
        || preliminary.digest() != floor.host_lease_head
        || sealed.controller_floor != Some(floor.digest())
    {
        return Err(invalid_settlement());
    }
    Ok(())
}

#[allow(dead_code, reason = "signed cross-owner Host transport remains closed")]
pub(super) fn validate_settled_host_floor_join(
    journal: &Journal,
    floor: CreateFailurePrepareV1,
    preliminary: HostSettlementRecordV1,
    sealed: HostSettlementRecordV1,
    retained: HostSettlementRecordV1,
    protected_host_sequence: u64,
) -> Result<(), ReconcilerError> {
    validate_historical_host_floor_join(floor, preliminary, sealed, protected_host_sequence)?;
    if validate_history(
        floor.marker,
        Some(preliminary),
        Some(sealed),
        Some(retained),
        protected_host_sequence,
    )
    .map_err(|_| invalid_settlement())?
        != Some(HostSettlementStageV1::AckRetained)
        || retained.controller_cas != Some(floor.settled_cas_digest())
    {
        return Err(invalid_settlement());
    }

    validate_all_floors(journal)?;
    let operation_bytes = journal
        .get(RecordNamespace::Operation, floor.operation_id.as_bytes())
        .ok_or_else(invalid_settlement)?;
    if aos_sandbox_protocol::domain_ledger::operation::decode_operation(operation_bytes)?.state() != OperationState::FailedBeforeCommit {
        return Err(invalid_settlement());
    }
    Ok(())
}
