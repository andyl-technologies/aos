//! Joins exact Mount inventories at one protected broker-journal boundary.
//!
//! Mount's resource table and source-acquisition table are queried separately.
//! Neither snapshot alone proves that its companion table was observed at the
//! same point. This module joins only snapshots that name the same controller
//! state, kernel boot, Mount process instance, and Mount journal sequence.
//! The joined value remains read-only observation evidence: it carries no file
//! descriptors, signed authority, retry permission, or cleanup permission.

use aos_sandbox_core::ObjectDigest;

use crate::mount_attempt::{DurableMountInventorySnapshotV1, MountAttemptError};
use crate::mount_source_acquisition_inventory::{
    DurableMountSourceAcquisitionInventorySnapshotV1, MountSourceAcquisitionInventoryError,
};
use crate::{Journal, JournalError};

/// Identifies one exact temporal boundary in Mount's durable journal.
///
/// Equality is meaningful only after each containing snapshot has independently
/// passed its format, controller-state, and latest-record checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MountJournalObservationIdentityV1 {
    controller_state_digest: [u8; 32],
    kernel_boot_id: [u8; 16],
    broker_instance_id: [u8; 16],
    journal_sequence: u64,
}

impl MountJournalObservationIdentityV1 {
    pub(crate) const fn new(
        controller_state_digest: [u8; 32],
        kernel_boot_id: [u8; 16],
        broker_instance_id: [u8; 16],
        journal_sequence: u64,
    ) -> Self {
        Self {
            controller_state_digest,
            kernel_boot_id,
            broker_instance_id,
            journal_sequence,
        }
    }

    /// Returns the exact protected controller-state digest observed before both queries.
    #[must_use]
    pub const fn controller_state_digest(self) -> ObjectDigest {
        ObjectDigest::from_bytes(self.controller_state_digest)
    }

    /// Returns the kernel boot identity claimed by Mount.
    #[must_use]
    pub const fn kernel_boot_id(&self) -> &[u8; 16] {
        &self.kernel_boot_id
    }

    /// Returns the Mount process instance that emitted both snapshots.
    #[must_use]
    pub const fn broker_instance_id(&self) -> &[u8; 16] {
        &self.broker_instance_id
    }

    /// Returns the shared next-frame Mount journal boundary.
    #[must_use]
    pub const fn journal_sequence(self) -> u64 {
        self.journal_sequence
    }
}

/// Retains complete Mount resource and source inventories at one exact boundary.
///
/// This value is deliberately nonauthorizing. Callers must revalidate it before
/// planning from it, and every later effect must acquire independent current
/// assignment, lease, plan, descriptor, and durable-attempt authority.
pub struct CurrentMountFilesystemInventoryV1 {
    identity: MountJournalObservationIdentityV1,
    resources: DurableMountInventorySnapshotV1,
    source_acquisitions: DurableMountSourceAcquisitionInventorySnapshotV1,
}

impl CurrentMountFilesystemInventoryV1 {
    /// Joins two latest protected snapshots from one exact Mount journal boundary.
    ///
    /// Both snapshots are checked before and after comparison. The controller
    /// journal must retain protected-open provenance, and both snapshots must
    /// name the same controller digest, kernel boot, broker instance, and Mount
    /// journal sequence.
    ///
    /// # Errors
    ///
    /// Returns [`MountFilesystemInventoryError`] when protected provenance is
    /// absent, either snapshot is stale or corrupt, or their temporal identities
    /// differ.
    pub fn join(
        journal: &mut Journal,
        resources: DurableMountInventorySnapshotV1,
        source_acquisitions: DurableMountSourceAcquisitionInventorySnapshotV1,
    ) -> Result<Self, MountFilesystemInventoryError> {
        journal.ensure_protected_authority()?;
        resources.recheck(journal)?;
        source_acquisitions.recheck(journal)?;

        let identity = resources.observation_identity();
        if source_acquisitions.observation_identity() != identity {
            return Err(MountFilesystemInventoryError::TemporalMismatch);
        }

        resources.recheck(journal)?;
        source_acquisitions.recheck(journal)?;
        Ok(Self {
            identity,
            resources,
            source_acquisitions,
        })
    }

    /// Returns the exact shared controller and Mount journal identity.
    #[must_use]
    pub const fn observation_identity(&self) -> MountJournalObservationIdentityV1 {
        self.identity
    }

    /// Borrows the complete exact Mount resource snapshot.
    #[must_use]
    pub const fn resources(&self) -> &DurableMountInventorySnapshotV1 {
        &self.resources
    }

    pub(crate) fn into_resources(self) -> DurableMountInventorySnapshotV1 {
        self.resources
    }

    /// Borrows the complete exact Mount source-acquisition snapshot.
    #[must_use]
    pub const fn source_acquisitions(&self) -> &DurableMountSourceAcquisitionInventorySnapshotV1 {
        &self.source_acquisitions
    }

    /// Revalidates protected provenance, latest records, and the exact temporal join.
    ///
    /// # Errors
    ///
    /// Returns [`MountFilesystemInventoryError`] when either snapshot is no
    /// longer current, the controller journal is unhealthy or unprotected, or
    /// the retained temporal identities no longer agree.
    pub fn recheck(&self, journal: &mut Journal) -> Result<(), MountFilesystemInventoryError> {
        journal.ensure_protected_authority()?;
        self.resources.recheck(journal)?;
        self.source_acquisitions.recheck(journal)?;
        if self.resources.observation_identity() != self.identity
            || self.source_acquisitions.observation_identity() != self.identity
        {
            return Err(MountFilesystemInventoryError::TemporalMismatch);
        }
        Ok(())
    }
}

/// Reports why complete Mount filesystem observations could not be joined.
#[derive(Debug, thiserror::Error)]
pub enum MountFilesystemInventoryError {
    /// The Mount resource inventory is stale, conflicting, or corrupt.
    #[error("Mount resource inventory is not current: {0}")]
    Resource(#[from] MountAttemptError),
    /// The Mount source-acquisition inventory is stale, conflicting, or corrupt.
    #[error("Mount source-acquisition inventory is not current: {0}")]
    SourceAcquisition(#[from] MountSourceAcquisitionInventoryError),
    /// The two inventories do not name one exact Mount journal boundary.
    #[error("Mount filesystem inventories name different temporal boundaries")]
    TemporalMismatch,
    /// The controller journal lacks protected current-state provenance.
    #[error(transparent)]
    Journal(#[from] JournalError),
}
