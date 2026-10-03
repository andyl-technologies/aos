//! Retains original authenticated filesystem-attachment admission provenance.
//!
//! Only the authenticated Controller compiler constructs a carrier. It stores
//! the carrier inside the same effect admitted atomically with the desired
//! Attachment, operation and idempotency decision. Historical provenance is
//! not current Tree/CacheRead permission, a Mount flight, or backing authority.
//!
//! The private format wraps unchanged `AOSPME01` bytes:
//!
//! ```text
//! AOSFCA01 | version:u16be=1 | reserved:6 | json-length:u32be |
//! canonical bounded JSON | domain-separated SHA256:32
//! ```
//!
//! JSON retains the actual immutable capability, observed holder/key binding,
//! protected authorization revision, original Attachment desired record and
//! original View record. Decoding alone never constructs a held owner token.

use aos_proto::aos::sandbox::v1::{Attachment, AttachmentPhase, ViewPhase};
use aos_sandbox_core::{ObjectDigest, OperationId};

use crate::Journal;
use crate::controller_service::public_projection::{
    PublicProjectionKindV1, PublicProjectionResourceV1, PublicProjectionStoreV1,
};

mod authority;
mod carrier;

pub(crate) use authority::AdmissionAuthorityV1;
pub use carrier::ControllerFuseAdmissionCarrierV1;

const CONTROLLER_STATE_DIRECTORY: &str = "/var/lib/aos/sandboxd";
const CONTROLLER_JOURNAL: &str = "controller.journal";

#[derive(Default)]
struct ControllerAdmissionLocationV1 {
    #[cfg(test)]
    fixture_root: Option<std::path::PathBuf>,
}

impl ControllerAdmissionLocationV1 {
    fn recheck(&self, journal: &Journal) -> Result<(), crate::JournalError> {
        #[cfg(test)]
        if let Some(root) = &self.fixture_root {
            return journal.validate_held_protected_at_uid_for_test(
                root,
                CONTROLLER_JOURNAL,
                journal.protected_owner_uid()?,
            );
        }
        journal.require_protected_named_location(
            std::path::Path::new(CONTROLLER_STATE_DIRECTORY),
            CONTROLLER_JOURNAL,
            journal.protected_owner_uid()?,
            crate::controller_service::journal::production_journal_limits(),
        )
    }
}

/// Rejects invalid provenance, changed desired state or lost protected custody.
#[derive(Debug, thiserror::Error)]
pub enum ControllerFuseAdmissionErrorV1 {
    /// The carrier or its exact protected owner join is unavailable or invalid.
    #[error("Controller FUSE admission is unavailable or changed")]
    Rejected,
    /// Protected journal custody or current names failed validation.
    #[error(transparent)]
    Journal(#[from] crate::JournalError),
    /// The operation/effect ledger failed its production replay checks.
    #[error(transparent)]
    Ledger(#[from] crate::ReconcilerError),
}

/// Borrows original admission provenance from the current protected Controller.
///
/// The borrow excludes Controller mutations through a later owner cut. This
/// token proves only the exact accepted Attach/Replace lineage and continued
/// membership of its original desired Attachment. A read producer must still
/// join current disclosure capability, Policy, Cache and a genuine held Mount
/// flight. There is no decoded-bytes or scalar constructor.
pub struct AcceptedControllerFuseAdmissionV1<'controller> {
    journal: &'controller Journal,
    carrier: ControllerFuseAdmissionCarrierV1,
    sequence: u64,
    location: ControllerAdmissionLocationV1,
}

impl<'controller> AcceptedControllerFuseAdmissionV1<'controller> {
    /// Reads one exact accepted original Attach/Replace under its held writer.
    ///
    /// Legacy admissions without the versioned carrier return `None`, never
    /// inferred capability or holder bindings. The writer must retain the
    /// existing fixed Controller path, original UID and production limits;
    /// another protected journal cannot substitute for that owner.
    ///
    /// # Errors
    ///
    /// Rejects foreign or lost journal custody, corrupt ledger joins, changed Attachment
    /// desired state or a released original View.
    pub fn read(
        journal: &'controller Journal,
        operation: OperationId,
    ) -> Result<Option<Self>, ControllerFuseAdmissionErrorV1> {
        Self::read_at_location(journal, operation, ControllerAdmissionLocationV1::default())
    }

    fn read_at_location(
        journal: &'controller Journal,
        operation: OperationId,
        location: ControllerAdmissionLocationV1,
    ) -> Result<Option<Self>, ControllerFuseAdmissionErrorV1> {
        location.recheck(journal)?;
        let Some(carrier) = crate::reconciler::accepted_fuse_admission_v1(journal, operation)?
        else {
            return Ok(None);
        };
        let accepted = Self {
            journal,
            carrier,
            sequence: journal.snapshot_sequence(),
            location,
        };
        accepted.recheck()?;
        Ok(Some(accepted))
    }

    /// Returns the exact retained original carrier, not current read permission.
    #[must_use]
    pub const fn carrier(&self) -> &ControllerFuseAdmissionCarrierV1 {
        &self.carrier
    }

    /// Returns exact canonical bytes for authenticated flight comparison.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        self.carrier.canonical_bytes()
    }

    /// Returns the immutable carrier commitment for flight comparison.
    #[must_use]
    pub fn digest(&self) -> ObjectDigest {
        self.carrier.digest()
    }

    /// Rejoins the unchanged protected ledger and current original Attachment.
    ///
    /// This does not require that the original View is the latest revision.
    /// The retained original record supplies its exact historical descriptor.
    ///
    /// # Errors
    ///
    /// Rejects changed names, sequence, operation/effect, Attachment desired
    /// membership or an original View that is no longer retained for use.
    pub fn recheck(&self) -> Result<(), ControllerFuseAdmissionErrorV1> {
        self.location.recheck(self.journal)?;
        if self.sequence != self.journal.snapshot_sequence()
            || crate::reconciler::accepted_fuse_admission_v1(
                self.journal,
                self.carrier.operation(),
            )?
            .as_ref()
                != Some(&self.carrier)
        {
            return Err(ControllerFuseAdmissionErrorV1::Rejected);
        }

        let store = PublicProjectionStoreV1::new(self.journal);
        let original = self.carrier.attachment();
        let current = store
            .get(
                PublicProjectionKindV1::Attachment,
                exact_id(&original.attachment_id)?,
            )
            .map_err(|_| ControllerFuseAdmissionErrorV1::Rejected)?
            .ok_or(ControllerFuseAdmissionErrorV1::Rejected)?;
        let PublicProjectionResourceV1::Attachment(current_attachment) = current.resource() else {
            return Err(ControllerFuseAdmissionErrorV1::Rejected);
        };
        if current.project() != self.carrier.project()
            || current.operation() != self.carrier.operation()
            || !same_attachment_desired(original, current_attachment)
            || !matches!(
                current_attachment.phase.as_known(),
                Some(
                    AttachmentPhase::ATTACHMENT_PHASE_REQUESTED
                        | AttachmentPhase::ATTACHMENT_PHASE_PREPARING
                        | AttachmentPhase::ATTACHMENT_PHASE_READY
                        | AttachmentPhase::ATTACHMENT_PHASE_REPLACING
                )
            )
        {
            return Err(ControllerFuseAdmissionErrorV1::Rejected);
        }

        let view = store
            .get(
                PublicProjectionKindV1::FilesystemView,
                exact_id(&original.source_view_id)?,
            )
            .map_err(|_| ControllerFuseAdmissionErrorV1::Rejected)?
            .ok_or(ControllerFuseAdmissionErrorV1::Rejected)?;
        let PublicProjectionResourceV1::FilesystemView(view) = view.resource() else {
            return Err(ControllerFuseAdmissionErrorV1::Rejected);
        };
        if view.project_id.as_slice() != self.carrier.project().as_bytes()
            || !matches!(
                view.phase.as_known(),
                Some(
                    ViewPhase::VIEW_PHASE_REQUESTED
                        | ViewPhase::VIEW_PHASE_VALIDATING
                        | ViewPhase::VIEW_PHASE_INDEXING
                        | ViewPhase::VIEW_PHASE_READY
                        | ViewPhase::VIEW_PHASE_DEGRADED
                )
            )
        {
            return Err(ControllerFuseAdmissionErrorV1::Rejected);
        }
        self.location.recheck(self.journal)?;
        Ok(())
    }
}

fn same_attachment_desired(original: &Attachment, current: &Attachment) -> bool {
    original.attachment_id == current.attachment_id
        && original.sandbox_id == current.sandbox_id
        && original.source_view_id == current.source_view_id
        && original.destination_slot_id == current.destination_slot_id
        && original.view_revision == current.view_revision
        && original.mutation == current.mutation
        && original.desired_generation == current.desired_generation
        && original.source_generation == current.source_generation
        && original.assignment_epoch == current.assignment_epoch
}

fn exact_id(bytes: &[u8]) -> Result<[u8; 16], ControllerFuseAdmissionErrorV1> {
    bytes
        .try_into()
        .map_err(|_| ControllerFuseAdmissionErrorV1::Rejected)
}
