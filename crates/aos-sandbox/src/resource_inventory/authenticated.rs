//! Controller-state fencing for authenticated resource inventory observations.
//!
//! The transport owner must issue a fresh query after capturing this fence and
//! recheck its protected terminal outcome immediately before completion. This
//! module persists observations only; it grants no broker or effect authority.

use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodResultV1,
    AuthenticatedBrokerOutcomeDirectionV1,
};

use super::{
    DurableNetworkResourceInventorySnapshotV1, DurableStorageResourceInventorySnapshotV1,
    InventoryDomain, Journal, RecordedSnapshot, ResourceInventoryError, SnapshotHistory,
    SnapshotRecord, ValidatedResourceInventory, controller_state_digest, persist_snapshot,
};

/// Retains the protected controller state preceding a Storage inventory query.
#[must_use = "complete the fresh query against this controller state"]
pub struct StorageInventoryObservationFenceV1(ObservationFence);

/// Retains the protected controller state preceding a Network inventory query.
#[must_use = "complete the fresh query against this controller state"]
pub struct NetworkInventoryObservationFenceV1(ObservationFence);

struct ObservationFence {
    domain: InventoryDomain,
    sequence: u64,
    controller_state: [u8; 32],
}

impl ObservationFence {
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
    begin_observation(journal, InventoryDomain::Storage).map(StorageInventoryObservationFenceV1)
}

pub(crate) fn begin_network_observation(
    journal: &mut Journal,
) -> Result<NetworkInventoryObservationFenceV1, ResourceInventoryError> {
    begin_observation(journal, InventoryDomain::Network).map(NetworkInventoryObservationFenceV1)
}

fn begin_observation(
    journal: &mut Journal,
    domain: InventoryDomain,
) -> Result<ObservationFence, ResourceInventoryError> {
    journal.ensure_protected_authority()?;
    let history = SnapshotHistory::load(journal, domain)?;
    if history.network_checkpoint.is_some() {
        return Err(ResourceInventoryError::Conflict);
    }
    Ok(ObservationFence {
        domain,
        sequence: journal.snapshot_sequence(),
        controller_state: controller_state_digest(journal)?,
    })
}

fn complete_observation(
    journal: &mut Journal,
    fence: ObservationFence,
    outcome: &AuthenticatedBrokerMethodOutcomeV1,
) -> Result<RecordedSnapshot, ResourceInventoryError> {
    fence.recheck(journal)?;
    if outcome.direction() != AuthenticatedBrokerOutcomeDirectionV1::ClientReceive
        || outcome.method() != fence.domain.method()
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
    let history = SnapshotHistory::load(journal, fence.domain)?;
    let (record, inventory) = SnapshotRecord::from_query(
        fence.domain,
        fence.controller_state,
        outcome.request().exact_body().to_vec(),
        body.clone(),
    )?;
    persist_snapshot(journal, history, record, inventory)
}

pub(crate) fn complete_storage_observation(
    journal: &mut Journal,
    fence: StorageInventoryObservationFenceV1,
    outcome: &AuthenticatedBrokerMethodOutcomeV1,
) -> Result<DurableStorageResourceInventorySnapshotV1, ResourceInventoryError> {
    let recorded = complete_observation(journal, fence.0, outcome)?;
    let ValidatedResourceInventory::Storage(inventory) = recorded.inventory else {
        return Err(ResourceInventoryError::CorruptState);
    };

    Ok(DurableStorageResourceInventorySnapshotV1 {
        record: recorded.record,
        inventory,
        outcome: recorded.outcome,
    })
}

pub(crate) fn complete_network_observation(
    journal: &mut Journal,
    fence: NetworkInventoryObservationFenceV1,
    outcome: &AuthenticatedBrokerMethodOutcomeV1,
) -> Result<DurableNetworkResourceInventorySnapshotV1, ResourceInventoryError> {
    let recorded = complete_observation(journal, fence.0, outcome)?;
    let ValidatedResourceInventory::Network(inventory) = recorded.inventory else {
        return Err(ResourceInventoryError::CorruptState);
    };
    Ok(DurableNetworkResourceInventorySnapshotV1 {
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
    fn network_fence_rejects_an_intervening_commit() {
        let directory = tempfile::tempdir().unwrap();
        let mut journal = protected_journal(&directory);
        let fence = begin_network_observation(&mut journal).unwrap();
        fence.0.recheck(&mut journal).unwrap();
        let change = JournalTransaction::new(
            [2; 16],
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                b"changed".to_vec(),
                vec![2],
            )],
        )
        .unwrap();

        journal.commit(&change).unwrap();

        assert!(matches!(
            fence.0.recheck(&mut journal),
            Err(ResourceInventoryError::Conflict)
        ));
    }

    #[test]
    fn network_query_does_not_overwrite_invalid_prior_history() {
        let directory = tempfile::tempdir().unwrap();
        let mut journal = protected_journal(&directory);
        let change = JournalTransaction::new(
            [3; 16],
            vec![JournalRecord::put(
                InventoryDomain::Network.namespace(),
                b"unexpected".to_vec(),
                vec![1],
            )],
        )
        .unwrap();
        journal.commit(&change).unwrap();
        let sequence = journal.snapshot_sequence();

        assert!(begin_network_observation(&mut journal).is_err());

        assert_eq!(journal.snapshot_sequence(), sequence);
    }

    #[test]
    fn unchanged_protected_controller_state_preserves_the_fence() {
        let directory = tempfile::tempdir().unwrap();
        let mut journal = protected_journal(&directory);

        let fence = begin_storage_observation(&mut journal).unwrap();

        fence.0.recheck(&mut journal).unwrap();
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
            fence.0.recheck(&mut journal),
            Err(ResourceInventoryError::Conflict)
        ));
    }
}
