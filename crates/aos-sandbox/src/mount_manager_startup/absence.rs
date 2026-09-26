//! Move-only SourceRoot presence and startup absence capabilities.

use std::os::fd::OwnedFd;

use aos_sandbox_protocol::mount_manager_startup::{
    ExpectedStartupDescriptorV1, StartupCleanupSourceSubjectV1, StartupExecutionIdentityV1,
    StartupPersistedCustodyOwnerV1, StartupTerminalSourceSubjectV1,
};
use aos_sandbox_protocol::mount_source_acquisition_state::RecordRefV2;

use super::MountManagerExecutionDeathKindV1;
use crate::{JournalError, ProtectedJournalAuthority};

/// Identifies the non-interchangeable proof path for manager source presence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagerSourcePresenceOriginV1 {
    /// Presence came from the complete immutable startup descriptor table.
    StartupCapture,
    /// Presence came from signed fresh handoff and distinct readback.
    FreshControlReadback,
}

/// Owns one startup-rebound SourceRoot proven by a complete recorded FD table.
pub struct StartupManagerSourcePresenceV1 {
    descriptor: OwnedFd,
    projection: StartupManagerSourcePresenceProjectionV1,
}

/// Projects the fields common to startup and fresh manager presence evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagerSourcePresenceEvidenceProjectionV1 {
    /// Non-interchangeable proof origin.
    pub origin: ManagerSourcePresenceOriginV1,
    /// Current protected Mount-manager execution.
    pub manager_execution: StartupExecutionIdentityV1,
    /// Commitment to the complete manager execution identity.
    pub manager_execution_commitment: [u8; 32],
    /// Gap-free immutable capture sequence.
    pub capture_sequence: u64,
    /// Immutable startup capture identity.
    pub capture_id: [u8; 32],
    /// Exact `AOSMMCAP1` record digest.
    pub capture_record_digest: [u8; 32],
    /// Full initial descriptor-table count.
    pub descriptor_count: u32,
    /// Exact activation-label count.
    pub activation_count: u32,
    /// Protected expected-descriptor count.
    pub expected_descriptor_count: u32,
    /// Total cleanup and terminal source-subject count.
    pub source_subject_count: u32,
    /// Cleanup-only source-subject count.
    pub cleanup_subject_count: u32,
    /// Terminal source-subject count.
    pub terminal_subject_count: u32,
    /// Exact AOSMSA acquisition identity.
    pub acquisition_id: [u8; 32],
    /// Exact AOSMSA acquisition revision.
    pub acquisition_revision: u64,
    /// Exact AOSMSA acquisition record digest.
    pub acquisition_record_digest: [u8; 32],
    /// Stable SourceRoot realization handle.
    pub source_realization_handle: [u8; 32],
    /// Exact SourceRoot descriptor commitment.
    pub descriptor_commitment: [u8; 32],
    /// Exact descriptor number held by the manager.
    pub manager_descriptor_number: u32,
    /// SourceRoot kernel boot.
    pub source_kernel_boot_id: [u8; 16],
    /// SourceRoot device.
    pub source_device: u64,
    /// SourceRoot inode.
    pub source_inode: u64,
    /// SourceRoot unique Mount ID.
    pub source_unique_mount_id: u64,
    /// Commitment joining capture, expectation, label, and physical entry.
    pub source_entry_commitment: [u8; 32],
}

/// Projects the manager evidence and exact startup-only descriptor entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartupManagerSourcePresenceProjectionV1 {
    /// Common exact custody evidence projection.
    pub evidence: ManagerSourcePresenceEvidenceProjectionV1,
    /// Exact protected SourceRoot expectation.
    pub expected: ExpectedStartupDescriptorV1,
    /// Canonical singleton expectation digest.
    pub expected_entry_digest: [u8; 32],
    /// Physical commitment of the captured descriptor observation.
    pub descriptor_physical_commitment: [u8; 32],
}

/// Compatibility name for the startup-only presence capability.
pub type ManagerSourcePresenceV1 = StartupManagerSourcePresenceV1;

/// Proves one exact pre-Release SourceRoot lost from manager custody.
pub struct LostMountSourceCustodyV1 {
    projection: LostMountSourceCustodyProjectionV1,
}

/// Projects the exact durable, process-death, and complete-table absence proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LostMountSourceCustodyProjectionV1 {
    /// Exact pre-Release AOSMSA cleanup subject.
    pub subject: StartupCleanupSourceSubjectV1,
    /// Immutable startup capture identity.
    pub capture_id: [u8; 32],
    /// Exact `AOSMMCAP1` record digest committing the full descriptor table.
    pub capture_record_digest: [u8; 32],
    /// Persisted last-custody owner, absent before descriptor handoff.
    pub last_custody_owner: Option<StartupPersistedCustodyOwnerV1>,
    /// Exact closed process-death proof class when custody was handed off.
    pub death_kind: Option<MountManagerExecutionDeathKindV1>,
    /// Commitment to all preceding loss-proof fields.
    pub death_commitment: [u8; 32],
}

/// Proves one terminal Releasing SourceRoot absent after prior-manager death.
pub struct TerminalMountSourceAbsenceV1 {
    projection: TerminalMountSourceAbsenceProjectionV1,
}

/// Projects one exact terminal Release absence proof for SourceProvider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminalMountSourceAbsenceProjectionV1 {
    /// Exact terminal Releasing subject.
    pub subject: StartupTerminalSourceSubjectV1,
    /// Immutable complete-table capture identity.
    pub capture_id: [u8; 32],
    /// Exact capture record digest.
    pub capture_record_digest: [u8; 32],
    /// Exact terminal Release/Inventory proof attempt.
    pub terminal_proof_attempt: RecordRefV2,
    /// Session carrying the exact terminal Release/Inventory proof attempt.
    pub terminal_proof_session_id: [u8; 32],
    /// Exact terminal proof session record digest.
    pub terminal_proof_session_digest: [u8; 32],
    /// Exact last Release attempt owned by the prior manager.
    pub last_custody_attempt: RecordRefV2,
    /// Persisted last-custody session identity.
    pub last_custody_session_id: [u8; 32],
    /// Persisted session record digest.
    pub last_custody_session_digest: [u8; 32],
    /// Persisted session boot.
    pub last_custody_kernel_boot_id: [u8; 16],
    /// Prior Mount-manager thread-group leader.
    pub last_custody_tgid: u32,
    /// Prior Mount-manager start time.
    pub last_custody_start_time_ticks: u64,
    /// Prior Mount-manager cgroup commitment.
    pub last_custody_cgroup_digest: [u8; 32],
    /// Exact closed death proof class.
    pub death_kind: MountManagerExecutionDeathKindV1,
    /// Commitment to all preceding terminal proof fields.
    pub death_commitment: [u8; 32],
}

/// Carries the exact one-shot canonical Releasing absence batch.
pub struct ReleasingSourceAbsenceBatchV1 {
    absences: Vec<TerminalMountSourceAbsenceV1>,
    capture_id: [u8; 32],
    capture_record_digest: [u8; 32],
}

impl TerminalMountSourceAbsenceV1 {
    pub(super) const fn new(projection: TerminalMountSourceAbsenceProjectionV1) -> Self {
        Self { projection }
    }

    /// Returns the exact terminal absence projection for SourceProvider.
    #[must_use]
    pub const fn projection(&self) -> &TerminalMountSourceAbsenceProjectionV1 {
        &self.projection
    }

    /// Revalidates the exact target row and startup capture as current.
    ///
    /// # Errors
    ///
    /// Returns an error after target-row mutation, capture-history loss or
    /// corruption, or use with an unrelated authority.
    pub fn validate_current(
        &self,
        authority: &ProtectedJournalAuthority<'_>,
    ) -> Result<(), JournalError> {
        authority.validate_mount_manager_source_proof_current_v1(
            self.projection.subject.acquisition_id,
            self.projection.subject.acquisition_revision,
            self.projection.subject.acquisition_record_digest,
            self.projection.capture_id,
            self.projection.capture_record_digest,
        )
    }
}

impl StartupManagerSourcePresenceV1 {
    pub(super) fn new(
        descriptor: OwnedFd,
        projection: StartupManagerSourcePresenceProjectionV1,
    ) -> Self {
        Self {
            descriptor,
            projection,
        }
    }

    /// Returns the exact startup presence projection while retaining custody.
    #[must_use]
    pub const fn projection(&self) -> &StartupManagerSourcePresenceProjectionV1 {
        &self.projection
    }

    /// Returns the common compact custody-evidence projection.
    #[must_use]
    pub const fn custody_evidence(&self) -> &ManagerSourcePresenceEvidenceProjectionV1 {
        &self.projection.evidence
    }

    /// Returns the protected SourceRoot expectation satisfied by this owner.
    #[must_use]
    pub const fn expected(&self) -> &ExpectedStartupDescriptorV1 {
        &self.projection.expected
    }

    /// Returns the immutable startup capture identity.
    #[must_use]
    pub const fn capture_id(&self) -> [u8; 32] {
        self.projection.evidence.capture_id
    }

    /// Revalidates the exact source row and capture before custody admission.
    ///
    /// # Errors
    ///
    /// Returns an error after target-row mutation, capture-history loss or
    /// corruption, or use with an unrelated protected authority.
    pub fn validate_current(
        &self,
        authority: &ProtectedJournalAuthority<'_>,
    ) -> Result<(), JournalError> {
        let evidence = &self.projection.evidence;
        authority.validate_mount_manager_source_proof_current_v1(
            evidence.acquisition_id,
            evidence.acquisition_revision,
            evidence.acquisition_record_digest,
            evidence.capture_id,
            evidence.capture_record_digest,
        )
    }

    /// Consumes the capability into its descriptor and immutable projection.
    #[must_use]
    pub fn into_parts(self) -> (OwnedFd, StartupManagerSourcePresenceProjectionV1) {
        (self.descriptor, self.projection)
    }
}

impl LostMountSourceCustodyV1 {
    pub(super) const fn new(projection: LostMountSourceCustodyProjectionV1) -> Self {
        Self { projection }
    }

    /// Returns the exact proof projection intended for SourceProvider recovery.
    #[must_use]
    pub const fn projection(&self) -> &LostMountSourceCustodyProjectionV1 {
        &self.projection
    }

    /// Revalidates the exact target row and startup capture as current.
    ///
    /// # Errors
    ///
    /// Returns an error after target-row mutation, capture-history loss or
    /// corruption, or use with an unrelated authority.
    pub fn validate_current(
        &self,
        authority: &ProtectedJournalAuthority<'_>,
    ) -> Result<(), JournalError> {
        authority.validate_mount_manager_source_proof_current_v1(
            self.projection.subject.acquisition_id,
            self.projection.subject.acquisition_revision,
            self.projection.subject.acquisition_record_digest,
            self.projection.capture_id,
            self.projection.capture_record_digest,
        )
    }
}

impl ReleasingSourceAbsenceBatchV1 {
    pub(super) fn new(
        projections: Vec<TerminalMountSourceAbsenceProjectionV1>,
        capture_id: [u8; 32],
        capture_record_digest: [u8; 32],
    ) -> Self {
        let absences = projections
            .into_iter()
            .map(TerminalMountSourceAbsenceV1::new)
            .collect();
        Self {
            absences,
            capture_id,
            capture_record_digest,
        }
    }

    /// Returns the number of exact absence capabilities in this batch.
    #[must_use]
    pub fn len(&self) -> usize {
        self.absences.len()
    }

    /// Reports whether this exact batch is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.absences.is_empty()
    }

    /// Returns the immutable capture identity and record digest.
    #[must_use]
    pub const fn capture(&self) -> ([u8; 32], [u8; 32]) {
        (self.capture_id, self.capture_record_digest)
    }

    /// Consumes the batch into individually move-only absence capabilities.
    #[must_use]
    pub fn into_absences(self) -> Vec<TerminalMountSourceAbsenceV1> {
        self.absences
    }
}

/// Compatibility name for one startup absence capability.
pub type MountManagerSourceAbsenceV1 = TerminalMountSourceAbsenceV1;
/// Compatibility name for the portable absence projection.
pub type MountManagerSourceAbsenceProjectionV1 = TerminalMountSourceAbsenceProjectionV1;
