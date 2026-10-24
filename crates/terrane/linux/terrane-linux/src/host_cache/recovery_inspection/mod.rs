//! Owns readonly native recovery candidate inspection under actual custody.
//!
//! Inputs originate from authenticated native cache preparation, never caller
//! files, identities asserted as proof, callbacks or a validity boolean. This
//! module may enumerate and verify candidates, including deriving an index
//! repair plan. It does not mutate state or namespaces, adopt sealed objects,
//! issue retention/completed-recovery receipts, release pins or send Resume.
//! Registered publisher inspections can synchronize publisher-owned names and
//! retirement leases; their failures remain unresolved owner-recovery work.

use super::{NativeCachePreparation, NativeHostLayout};
use crate::{publisher_local::client::Client, quota_confinement::Installed};
use std::{fs::File, io, sync::Arc};
use terrane_sdk::host::cache::{HostDomainLocation, HostReadLimits};

mod collection;
mod files;
mod inspection;
mod manifest;
mod quarantine;
mod verification;

#[cfg(test)]
mod tests;

pub use inspection::{NativeRecoveryCandidate, NativeRecoveryInspection, RecoveryIssue};
pub(in crate::host_cache) use manifest::VerifiedRecoveryManifest;
pub use quarantine::NativeQuarantinedInode;
pub use verification::{
    DerivedIndexRepair, DetachedIndexStatus, VerifiedEncodedBody, VerifiedStandaloneChunk,
};

/// Retains genuine native inputs for bounded readonly recovery inspection.
///
/// Construction preserves the actual authenticated publisher session and its
/// configured domain, root guard and process confinement. This is read context,
/// not proof of complete recovery or authority to serve or mutate a candidate.
/// Publisher-issued observations remain scoped to their actual drain epoch;
/// the physical owner must reject stale observations before lifecycle effects.
#[derive(Clone)]
pub struct NativeRecoveryInspector {
    session: Arc<Client<HostDomainLocation>>,
    layout: Arc<NativeHostLayout<HostDomainLocation>>,
    confinement: Arc<Installed>,
    reads: HostReadLimits,
    max_candidates: usize,
    charge_owner: String,
    project_id: u32,
    publisher_uid: u32,
    custody: ContentCustody,
}

/// Keeps configured custody separate from mutable observed inode metadata.
#[derive(Clone, Copy)]
struct ContentCustody {
    uid: u32,
    gid: u32,
    directory_mode: u32,
}

impl NativeRecoveryInspector {
    /// Preserves actual native preparation without minting completion authority.
    pub(super) fn from_preparation(preparation: &NativeCachePreparation) -> Self {
        let observation = preparation.quota().observation();
        let config = preparation.inspection_config();
        Self {
            session: preparation.publisher_session(),
            layout: Arc::clone(preparation.layout()),
            confinement: Arc::clone(preparation.inspection_confinement()),
            reads: config.reads,
            max_candidates: config.inventory_entries,
            charge_owner: observation.owner_id.clone(),
            project_id: observation.project_id,
            publisher_uid: config.publisher.identities.publish_uid,
            custody: ContentCustody {
                uid: config.content_uid,
                gid: config.content_gid,
                // Preparation independently requires this exact shared class.
                directory_mode: 0o2770,
            },
        }
    }

    /// Borrows actual retained domain roots and their provisioning guard.
    pub fn layout(&self) -> &Arc<NativeHostLayout<HostDomainLocation>> {
        &self.layout
    }

    /// Returns the configured per-allocation encoded read and plaintext decode budget.
    pub fn read_limits(&self) -> HostReadLimits {
        self.reads
    }

    /// Returns the configured maximum candidate inventory, not a format limit.
    pub fn max_candidates(&self) -> usize {
        self.max_candidates
    }

    /// Borrows the charge owner from the actual authenticated preparation query.
    pub fn charge_owner(&self) -> &str {
        &self.charge_owner
    }

    /// Returns the actual helper-verified domain project assignment.
    pub fn project_id(&self) -> u32 {
        self.project_id
    }

    /// Rechecks process confinement, domain-root incarnations and configured custody.
    ///
    /// # Errors
    /// Refuses another process, failed confinement or changed roots or content custody.
    pub fn check_current(&self) -> io::Result<()> {
        self.confinement.check_current()?;
        self.layout.recheck()?;
        for label in ["chunks", "objects", "quarantine"] {
            let root = self
                .layout
                .directories
                .get(label)
                .ok_or_else(|| files::invalid("missing retained shared-content root"))?;
            let metadata = File::from(root.try_clone()?).metadata()?;
            self.custody.check(&metadata, true)?;
        }
        Ok(())
    }
}
