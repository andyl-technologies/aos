//! Protected controller-state fencing for authenticated destination-slot inventory.
//!
//! The transport owner rechecks terminal session currentness before completion.
//! These snapshots remain observations, not descriptor or effect authority.

use super::{
    DurableDestinationSlotInventorySnapshotV1, Journal, METHOD, MountAttemptError, SnapshotHistory,
    SnapshotRecord, mount_controller_state_digest,
};
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodResultV1,
    AuthenticatedBrokerOutcomeDirectionV1,
};

/// Retains controller state preceding a fresh authenticated destination-slot query.
#[must_use = "complete the fresh query against this controller state"]
pub struct DestinationSlotInventoryObservationFenceV1 {
    sequence: u64,
    controller_state: [u8; 32],
}

impl DestinationSlotInventoryObservationFenceV1 {
    fn recheck(&self, journal: &mut Journal) -> Result<(), MountAttemptError> {
        journal.ensure_protected_authority()?;
        if journal.snapshot_sequence() != self.sequence
            || mount_controller_state_digest(journal)? != self.controller_state
        {
            return Err(MountAttemptError::Conflict);
        }
        Ok(())
    }
}

pub(crate) fn begin_observation(
    journal: &mut Journal,
) -> Result<DestinationSlotInventoryObservationFenceV1, MountAttemptError> {
    journal.ensure_protected_authority()?;
    SnapshotHistory::load(journal)?;
    Ok(DestinationSlotInventoryObservationFenceV1 {
        sequence: journal.snapshot_sequence(),
        controller_state: mount_controller_state_digest(journal)?,
    })
}

pub(crate) fn complete_observation(
    journal: &mut Journal,
    fence: DestinationSlotInventoryObservationFenceV1,
    outcome: &AuthenticatedBrokerMethodOutcomeV1,
) -> Result<DurableDestinationSlotInventorySnapshotV1, MountAttemptError> {
    complete_observation_with_commit_v2(
        journal,
        fence,
        outcome,
        &mut crate::mount_inventory_snapshot::MountInventorySnapshotRetainedV2::new(),
        |journal, transaction, _recipe| journal.commit(transaction).map_err(Into::into),
    )
}

pub(crate) fn complete_observation_with_commit_v2(
    journal: &mut Journal,
    fence: DestinationSlotInventoryObservationFenceV1,
    outcome: &AuthenticatedBrokerMethodOutcomeV1,
    retained: &mut crate::mount_inventory_snapshot::MountInventorySnapshotRetainedV2<
        super::DestinationSlotInventoryKind,
    >,
    commit: impl FnMut(
        &mut Journal,
        &crate::JournalTransaction,
        &crate::mount_inventory_snapshot::MountInventoryCommitRecipeV2<'_>,
    ) -> Result<crate::CommitResult, MountAttemptError>,
) -> Result<DurableDestinationSlotInventorySnapshotV1, MountAttemptError> {
    fence.recheck(journal)?;
    if outcome.direction() != AuthenticatedBrokerOutcomeDirectionV1::ClientReceive
        || outcome.method() != METHOD
    {
        return Err(MountAttemptError::Conflict);
    }
    let body = match outcome.result() {
        AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } => exact_body,
        AuthenticatedBrokerMethodResultV1::Error(error) => {
            return Err(MountAttemptError::BrokerRejected {
                code: error.code(),
                retryable: error.retryable(),
            });
        }
    };
    let history = SnapshotHistory::load(journal)?;
    let (record, inventory) = SnapshotRecord::from_query(
        fence.controller_state,
        outcome.request().exact_body().to_vec(),
        body.clone(),
    )?;
    let (record, inventory, recorded) =
        crate::mount_inventory_snapshot::persist_snapshot_retaining_with_commit_v2(
            journal, history, record, inventory, retained, commit,
        )?;
    Ok(DurableDestinationSlotInventorySnapshotV1 {
        record,
        inventory,
        outcome: if recorded {
            super::DestinationSlotInventorySnapshotOutcomeV1::Recorded
        } else {
            super::DestinationSlotInventorySnapshotOutcomeV1::Replay
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{JournalLimits, JournalRecord, JournalTransaction, RecordNamespace};
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn protected_observation_rejects_intervening_journal_changes() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let (mut journal, _) = Journal::open_protected_at_uid(
            directory.path(),
            "journal",
            JournalLimits::default(),
            rustix::process::getuid().as_raw(),
        )
        .unwrap();
        let fence = begin_observation(&mut journal).unwrap();
        fence.recheck(&mut journal).unwrap();
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
            Err(MountAttemptError::Conflict)
        ));
    }
}
