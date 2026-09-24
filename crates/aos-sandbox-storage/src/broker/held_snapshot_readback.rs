//! Protected catalog cut for nonauthorizing physical held-snapshot readback.
//!
//! The coordinator retains the exclusive Storage journal lock while the
//! caller dispatches a read-only one-shot worker. A second cut after worker
//! quiescence must match before the physical sample can be retained.

use aos_sandbox_protocol::semantics::CatalogBindingV1;

use crate::snapshot_metadata::CheckedSnapshotMetadataRecordV1;
use crate::state::VerifiedStorageResolverJournalV1;
use crate::{CatalogPlanV1, HoldId, ResolvedSnapshot};

use super::{StorageAdmissionCoordinator, StorageBrokerError};

/// Selects one exact protected snapshot and physical pool identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StorageHeldSnapshotSelectorV1 {
    /// The exact Storage physical-catalog head requested by the caller.
    pub(crate) catalog: CatalogBindingV1,
    /// The opaque protected dataset handle.
    pub(crate) storage_handle: [u8; 32],
    /// The opaque immutable snapshot handle.
    pub(crate) version_handle: [u8; 32],
    /// The catalogued source dataset GUID.
    pub(crate) source_guid: u64,
    /// The catalogued immutable snapshot GUID.
    pub(crate) snapshot_guid: u64,
    /// The exact durable OpenZFS hold identity.
    pub(crate) hold_id: HoldId,
    /// The physical pool GUID that the worker must observe twice.
    pub(crate) pool_guid: u64,
}

/// Carries a freshly reloaded catalog identity but no SourceRoot authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StorageHeldSnapshotCatalogCutV1 {
    pub(crate) snapshot: ResolvedSnapshot,
    pub(crate) metadata: CheckedSnapshotMetadataRecordV1,
    pub(crate) catalog: CatalogBindingV1,
    pub(crate) authority_sequence: u64,
}

impl StorageAdmissionCoordinator {
    /// Rejoins an exact held snapshot to the fresh authenticated physical head.
    ///
    /// # Errors
    ///
    /// Rejects changed catalog head, missing or inconsistent Snapshot operation,
    /// mismatched GUIDs or metadata, missing hold, or unreadable journal custody.
    pub(crate) fn held_snapshot_catalog_cut(
        &self,
        selector: StorageHeldSnapshotSelectorV1,
    ) -> Result<StorageHeldSnapshotCatalogCutV1, StorageBrokerError> {
        self.transactions.ensure_authority_readable()?;
        if selector.pool_guid == 0 {
            return Err(StorageBrokerError::Request);
        }
        let journal = self.transactions.verified_resolver_journal()?;
        if journal.physical().binding() != selector.catalog {
            return Err(StorageBrokerError::Request);
        }
        let (snapshot, metadata) = select_from_verified_journal(&journal, selector)?;
        let authority_sequence = self.transactions.authority_head_sequence()?;

        Ok(StorageHeldSnapshotCatalogCutV1 {
            snapshot,
            metadata,
            catalog: journal.physical().binding(),
            authority_sequence,
        })
    }
}

fn select_from_verified_journal(
    journal: &VerifiedStorageResolverJournalV1,
    selector: StorageHeldSnapshotSelectorV1,
) -> Result<(ResolvedSnapshot, CheckedSnapshotMetadataRecordV1), StorageBrokerError> {
    let physical = journal.physical();
    let mut matching = physical
        .snapshots()
        .iter()
        .filter(|row| row.guid() == selector.snapshot_guid);
    let row = matching.next().ok_or(StorageBrokerError::Request)?;
    if matching.next().is_some()
        || physical
            .snapshots()
            .iter()
            .filter(|candidate| candidate.name() == row.name())
            .count()
            != 1
    {
        return Err(StorageBrokerError::Request);
    }
    let operation_id = row.created_by().ok_or(StorageBrokerError::Request)?;
    let operation = journal
        .operation(&operation_id)
        .ok_or(StorageBrokerError::Request)?;
    let CatalogPlanV1::Snapshot {
        source,
        destination,
    } = operation.catalog().plan()
    else {
        return Err(StorageBrokerError::Request);
    };
    let result = operation.result();
    if row.name() != destination.name()
        || row.source_name() != source.name()
        || row.source_guid() != source.guid()
        || source.guid() != selector.source_guid
        || source.storage_handle() != selector.storage_handle
        || result.object_guid() != Some(selector.snapshot_guid)
        || result.storage_handle() != Some(selector.storage_handle)
        || result.immutable_version_handle() != Some(selector.version_handle)
        || !physical.roots().contains(source.root())
        || !physical
            .holds()
            .contains(&(selector.snapshot_guid, selector.hold_id.as_bytes()))
    {
        return Err(StorageBrokerError::Request);
    }
    let mut matching_source = physical
        .datasets()
        .iter()
        .filter(|dataset| dataset.name() == source.name());
    let source_row = matching_source.next().ok_or(StorageBrokerError::Request)?;
    if matching_source.next().is_some()
        || source_row.guid() != source.guid()
        || source_row.root() != source.root()
        || source_row.domains() != source.domains()
        || !source_row_matches_operation(journal, source_row, source)
    {
        return Err(StorageBrokerError::Request);
    }
    let metadata = row.metadata().ok_or(StorageBrokerError::Request)?;
    if metadata.operation_id() != operation_id
        || metadata.request_catalog() != operation.catalog().binding()
        || metadata.snapshot_guid() != selector.snapshot_guid
        || metadata.source_dataset_guid() != selector.source_guid
        || metadata.source_storage_handle() != selector.storage_handle
        || source_row.created_by() != Some(metadata.source_creation_operation_id())
    {
        return Err(StorageBrokerError::Request);
    }
    let snapshot = ResolvedSnapshot::from_catalog(
        source.clone(),
        destination.component(),
        selector.snapshot_guid,
        selector.version_handle,
    )
    .map_err(|_| StorageBrokerError::Request)?;
    Ok((snapshot, metadata))
}

fn source_row_matches_operation(
    journal: &VerifiedStorageResolverJournalV1,
    row: &crate::catalog_transition::VerifiedPhysicalDatasetV1,
    source: &crate::ResolvedDataset,
) -> bool {
    let Some(operation_id) = row.created_by() else {
        return false;
    };
    let Some(operation) = journal.operation(&operation_id) else {
        return false;
    };
    let destination = match operation.catalog().plan() {
        CatalogPlanV1::CreateWorkspace { destination, .. }
        | CatalogPlanV1::Clone { destination, .. } => destination,
        _ => return false,
    };
    let result = operation.result();
    row.name() == destination.name()
        && row.guid() == result.object_guid().unwrap_or(0)
        && row.root() == destination.root()
        && row.domains() == destination.domains()
        && result.storage_handle() == Some(source.storage_handle())
        && result.immutable_version_handle().is_none()
}
