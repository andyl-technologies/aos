//! Protected controller-state fencing for authenticated Mount source inventory.
//!
//! This records only signed, complete source-acquisition observations from the
//! retained Mount session. The snapshot is nonauthorizing until paired with a
//! resource snapshot at the same Mount journal boundary.

use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodResultV1,
    AuthenticatedBrokerOutcomeDirectionV1,
};

use super::{
    DurableMountSourceAcquisitionInventorySnapshotV1, Journal, METHOD,
    MountSourceAcquisitionInventoryError, SnapshotHistory, SnapshotRecord,
    current_controller_state_digest, persist_snapshot,
};

/// Retains controller state preceding one fresh authenticated source query.
#[must_use = "complete the exact authenticated source-acquisition query"]
pub struct MountSourceAcquisitionInventoryObservationFenceV1 {
    sequence: u64,
    controller_state: [u8; 32],
}

impl MountSourceAcquisitionInventoryObservationFenceV1 {
    fn recheck(&self, journal: &mut Journal) -> Result<(), MountSourceAcquisitionInventoryError> {
        journal.ensure_protected_authority()?;
        if journal.snapshot_sequence() != self.sequence
            || current_controller_state_digest(journal)? != self.controller_state
        {
            return Err(MountSourceAcquisitionInventoryError::Conflict);
        }
        Ok(())
    }
}

pub(crate) fn begin_observation(
    journal: &mut Journal,
) -> Result<MountSourceAcquisitionInventoryObservationFenceV1, MountSourceAcquisitionInventoryError>
{
    journal.ensure_protected_authority()?;
    SnapshotHistory::load(journal)?;
    Ok(MountSourceAcquisitionInventoryObservationFenceV1 {
        sequence: journal.snapshot_sequence(),
        controller_state: current_controller_state_digest(journal)?,
    })
}

pub(crate) fn complete_observation(
    journal: &mut Journal,
    fence: MountSourceAcquisitionInventoryObservationFenceV1,
    outcome: &AuthenticatedBrokerMethodOutcomeV1,
) -> Result<DurableMountSourceAcquisitionInventorySnapshotV1, MountSourceAcquisitionInventoryError>
{
    fence.recheck(journal)?;
    if outcome.direction() != AuthenticatedBrokerOutcomeDirectionV1::ClientReceive
        || outcome.method() != METHOD
    {
        return Err(MountSourceAcquisitionInventoryError::Conflict);
    }
    let body = match outcome.result() {
        AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } => exact_body,
        AuthenticatedBrokerMethodResultV1::Error(error) => {
            return Err(MountSourceAcquisitionInventoryError::BrokerRejected {
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
    persist_snapshot(journal, history, record, inventory)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{JournalLimits, JournalRecord, JournalTransaction, RecordNamespace};
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn protected_source_observation_rejects_intervening_journal_changes() {
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
            Err(MountSourceAcquisitionInventoryError::Conflict)
        ));
    }
}
