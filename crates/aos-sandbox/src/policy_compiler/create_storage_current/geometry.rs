//! Accounts for fixed RootOpen history, Hello and prospective Native copies.

use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_sandbox_journal::geometry::{RecordShape, encoded_transaction_append_bytes};
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    KEY_BYTES, HEAD_BYTES, RECORD_OVERHEAD_BYTES, root_open::ROOT_OPEN_BODY_BYTES_V1,
    transport::FRAME_HEADER_BYTES,
};

use crate::journal::{JournalError, JournalRecord, ProtectedJournalPreopenReplayExtentV1};

use super::OriginalRootCreateStorageCurrentAttemptV1;

impl OriginalRootCreateStorageCurrentAttemptV1<'_, '_, '_> {
    pub(crate) fn root_open_append_demand(
        held: &ProtectedJournalPreopenReplayExtentV1,
    ) -> Result<ResourceVector, JournalError> {
        fixed_root_history_append_demand_v1(held, ROOT_OPEN_BODY_BYTES_V1,
            FRAME_HEADER_BYTES + RECORD_OVERHEAD_BYTES + ROOT_OPEN_BODY_BYTES_V1, 0)
    }

    pub(crate) fn root_use_authorized_append_demand_v1(
        held: &ProtectedJournalPreopenReplayExtentV1,
    ) -> Result<ResourceVector, JournalError> {
        use super::use_authorized::RootCurrentUseAuthorizedStateV1;
        use aos_sandbox_protocol::domain_ledger::create_storage_history::use_authorized::{
            USE_AUTHORIZED_BODY_BYTES_V1, USE_AUTHORIZED_FRAME_BYTES_V1,
        };
        // Actual boxed state and its construction temporary coexist; the
        // derived five-extents DATA and recipe construction remain bounded too.
        let owner = std::mem::size_of::<RootCurrentUseAuthorizedStateV1>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
                crate::controller_resource_reservation::CreateStorageCacheCurrentExtentsDataV1>()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
                crate::journal::broker_session_receiving::StorageCreateUseSecurityShapeDataV1>()))
            .ok_or(JournalError::JournalTooLarge)?;
        fixed_root_history_append_demand_v1(held, USE_AUTHORIZED_BODY_BYTES_V1,
            USE_AUTHORIZED_FRAME_BYTES_V1, owner)
    }
}

pub(super) fn fixed_root_history_append_demand_v1(
    held: &ProtectedJournalPreopenReplayExtentV1,
    body_bytes: usize,
    wire_bytes: usize,
    owner_bytes: usize,
) -> Result<ResourceVector, JournalError> {
    let invalid = || JournalError::LimitExceeded("fixed RootOpen append geometry");
    let record = RECORD_OVERHEAD_BYTES.checked_add(body_bytes).ok_or_else(invalid)?;
    let append = encoded_transaction_append_bytes([
        RecordShape { key_bytes: KEY_BYTES, value_bytes: Some(record) },
        RecordShape { key_bytes: KEY_BYTES, value_bytes: Some(HEAD_BYTES) },
    ].into_iter()).map_err(|_| invalid())?;
    let cell = std::mem::size_of::<(JournalRecord, [u8; 16], [usize; 3])>() as u64;
    let cells = 2u64 * 32;
    let memory = append.checked_mul(16)
        .and_then(|bytes| bytes.checked_add(cells.checked_mul(cell)?))
        .and_then(|bytes| bytes.checked_add(64 * 1024))
        .and_then(|bytes| bytes.checked_add(u64::try_from(owner_bytes).ok()?)).ok_or_else(invalid)?;
    let hello = u64::try_from(wire_bytes)
        .map_err(|_| invalid())?;
    let fixed = ResourceVector::ZERO.with(D::MemoryBytes, memory)
        .with(D::StorageBytes, append)
        // The transaction introduces its record key and the shared head key.
        // Construction copies above remain Memory, not additional key names.
        .with(D::MetadataEntries, 2).with(D::PublicationStagingBytes, memory)
        .with(D::OutputBytes, memory.checked_add(hello).ok_or_else(invalid)?)
        .with(D::NetworkBytes, hello);
    // Actual previous maps remain resident while the sole Native appender
    // validates/materializes its prospective after cut. This is additional
    // to initial replay, with no hypothetical future retirement credit.
    let history = super::super::create_q04::inert_root_open_history_scan_demand_v1()?;
    let names = super::root_open::history_native_receiving_demand_v1()?;
    let clock = super::root_open::history_clock_receiving_demand_v1()?;
    let clocks = clock.checked_add(clock).and_then(|value| value.checked_add(clock)).map_err(|_| invalid())?;
    let owed = super::root_open::RootCurrentHistoryPostsV1::additional_owed_demand_v1()?;
    let owed = owed.checked_add(owed).and_then(|value| value.checked_add(owed)).map_err(|_| invalid())?;
    held.dominant_native_receiving_demand_v1()?
        .checked_add(held.dominant_semantic_receiving_demand_v1()?)
        .and_then(|demand| demand.checked_add(fixed))
        .and_then(|demand| demand.checked_add(history))
        .and_then(|demand| demand.checked_add(names))
        .and_then(|demand| demand.checked_add(owed))
        .and_then(|demand| demand.checked_add(clocks)).map_err(|_| invalid())
}
