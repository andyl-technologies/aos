//! Accounts for fixed RootOpen history, Hello and prospective Native copies.

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_journal::geometry::{RecordShape, encoded_transaction_append_bytes};
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    RECORD_OVERHEAD_BYTES, root_open::ROOT_OPEN_BODY_BYTES_V1,
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
                aos_sandbox_policy::storage_create_use_data::StorageCreateUseSecurityShapeDataV1>()))
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
    aos_sandbox_protocol::fixed_root_history_append_demand_data_v1! {
        extent: held,
        body_bytes: body_bytes,
        wire_bytes: wire_bytes,
        owner_bytes: owner_bytes,
        resource_vector: ResourceVector,
        dimension: D,
        record: JournalRecord,
        record_shape: RecordShape,
        append_bytes: encoded_transaction_append_bytes,
        history: aos_sandbox_policy::q04_data::inert_root_open_history_scan_demand_v1()
            .map_err(|_| crate::journal::JournalError::JournalTooLarge),
        names: super::root_open::history_native_receiving_demand_v1(),
        clock: super::root_open::history_clock_receiving_demand_v1(),
        owed: super::root_open::RootCurrentHistoryPostsV1::additional_owed_demand_v1(),
        error: JournalError::LimitExceeded("fixed RootOpen append geometry"),
    }
}
