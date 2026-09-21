//! Controller-state fencing for authenticated Storage inventory observations.
//!
//! The transport owner must issue a fresh query after capturing this fence and
//! recheck its protected terminal outcome immediately before completion. This
//! module persists observations only; it grants no broker or effect authority.

use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodResultV1,
    AuthenticatedBrokerOutcomeDirectionV1,
};

use super::{
    BrokerMethod, DurableStorageResourceInventorySnapshotV1, InventoryDomain, Journal,
    ResourceInventoryError, SnapshotHistory, SnapshotRecord, ValidatedResourceInventory,
    controller_state_digest, persist_snapshot,
};

/// Retains the protected controller state preceding a Storage inventory query.
#[must_use = "complete the fresh query against this controller state"]
pub struct StorageInventoryObservationFenceV1 {
    sequence: u64,
    controller_state: [u8; 32],
}

impl StorageInventoryObservationFenceV1 {
    fn recheck(&self, journal: &mut Journal) -> Result<(), ResourceInventoryError> {
        journal.ensure_protected_authority()?;
        if journal.snapshot_sequence() != self.sequence
            || controller_state_digest(journal)? != self.controller_state
        {
            return Err(ResourceInventoryError::Conflict);
        }
        Ok(())
    }
}

pub(crate) fn begin_storage_observation(
    journal: &mut Journal,
) -> Result<StorageInventoryObservationFenceV1, ResourceInventoryError> {
    journal.ensure_protected_authority()?;
    SnapshotHistory::load(journal, InventoryDomain::Storage)?;
    Ok(StorageInventoryObservationFenceV1 {
        sequence: journal.snapshot_sequence(),
        controller_state: controller_state_digest(journal)?,
    })
}

pub(crate) fn complete_storage_observation(
    journal: &mut Journal,
    fence: StorageInventoryObservationFenceV1,
    outcome: &AuthenticatedBrokerMethodOutcomeV1,
) -> Result<DurableStorageResourceInventorySnapshotV1, ResourceInventoryError> {
    fence.recheck(journal)?;
    if outcome.direction() != AuthenticatedBrokerOutcomeDirectionV1::ClientReceive
        || outcome.method() != BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES
    {
        return Err(ResourceInventoryError::Conflict);
    }

    let body = match outcome.result() {
        AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } => exact_body,
        AuthenticatedBrokerMethodResultV1::Error(error) => {
            return Err(ResourceInventoryError::BrokerRejected {
                code: error.code(),
                retryable: error.retryable(),
            });
        }
    };
    let history = SnapshotHistory::load(journal, InventoryDomain::Storage)?;
    let (record, inventory) = SnapshotRecord::from_query(
        InventoryDomain::Storage,
        fence.controller_state,
        outcome.request().exact_body().to_vec(),
        body.clone(),
    )?;
    let recorded = persist_snapshot(journal, history, record, inventory)?;
    let ValidatedResourceInventory::Storage(inventory) = recorded.inventory else {
        return Err(ResourceInventoryError::CorruptState);
    };

    Ok(DurableStorageResourceInventorySnapshotV1 {
        record: recorded.record,
        inventory,
        outcome: recorded.outcome,
    })
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;
    use crate::{JournalError, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace};

    fn protected_journal(directory: &tempfile::TempDir) -> Journal {
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        Journal::open_protected_at_uid(
            directory.path(),
            "inventory.journal",
            JournalLimits::default(),
            rustix::process::getuid().as_raw(),
        )
        .unwrap()
        .0
    }

    #[test]
    fn unchanged_protected_controller_state_preserves_the_fence() {
        let directory = tempfile::tempdir().unwrap();
        let mut journal = protected_journal(&directory);

        let fence = begin_storage_observation(&mut journal).unwrap();

        fence.recheck(&mut journal).unwrap();
    }

    #[test]
    fn unprotected_journal_cannot_begin_an_authenticated_observation() {
        let directory = tempfile::tempdir().unwrap();
        let (mut journal, _) =
            Journal::open(directory.path().join("journal"), JournalLimits::default()).unwrap();

        assert!(matches!(
            begin_storage_observation(&mut journal),
            Err(ResourceInventoryError::Journal(
                JournalError::ProtectedBoundary
            ))
        ));
    }

    #[test]
    fn intervening_journal_commit_invalidates_the_fence() {
        let directory = tempfile::tempdir().unwrap();
        let mut journal = protected_journal(&directory);
        let fence = begin_storage_observation(&mut journal).unwrap();
        let change = JournalTransaction::new(
            [1; 16],
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                b"changed".to_vec(),
                vec![1],
            )],
        )
        .unwrap();

        journal.commit(&change).unwrap();

        assert!(matches!(
            fence.recheck(&mut journal),
            Err(ResourceInventoryError::Conflict)
        ));
    }
}
