//! Derives allocation units only from original completed native publications.
//!
//! Canonical metadata supplies actual dependency edges. Policy rows can protect
//! an already verified unit but cannot create one, select an inode or supply a
//! reconstruction manifest. Duplicate publication receipts share one unit.

use super::super::{PublicationJob, invalid, residence, state};
use crate::{
    host_cache::{
        RetainedManifest,
        owner::{consumer::state as policy, retention::NativeOwnerExecutor},
    },
    publisher_local::client::PeerPublishedObject,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    os::unix::fs::MetadataExt,
    sync::{Arc, Mutex},
};
use terrane_sdk::host::cache::HostDomainLocation;

/// Retains one actual native allocation and all original publication jobs.
///
/// This inventory grants no retirement authority. Producer-funded jobs remain
/// protected; physical transitions require the separate actual cache permit.
pub(super) struct Unit {
    /// Earliest actual admission among original aliases of this allocation.
    pub(super) order: u64,
    /// Process-local allocation identity, never a durable object or namespace key.
    pub(super) key: String,
    /// Original verified readonly body, including its native root custody.
    pub(super) body: Arc<PeerPublishedObject<HostDomainLocation>>,
    /// Original complete jobs whose body descriptions must close after deletion.
    pub(super) members: Vec<Arc<Mutex<PublicationJob>>>,
    /// Exact synchronized allocated blocks of this inode alone.
    pub(super) allocated: u64,
    /// Durable content promises other than this unit's own reconstruction pins.
    pub(super) protected: bool,
    /// Chunks whose actual residence another cached object's manifest references.
    pub(super) shared_chunks: BTreeSet<String>,
    /// Original metadata promises owned by the actual dependent publications.
    pub(super) metadata: BTreeMap<[u8; 16], Arc<RetainedManifest>>,
    reconstruction: BTreeSet<String>,
    pub(super) chunks: BTreeSet<String>,
}

/// Captures and synchronizes genuine cached units under physical exclusion.
///
/// # Errors
/// Refuses stale Running or cache custody, changed native bodies, unavailable
/// source synchronization and inconsistent duplicate allocation identities.
pub(super) fn capture(executor: &NativeOwnerExecutor) -> io::Result<Vec<Unit>> {
    let running = executor.admission_context()?;
    running.check_current().map_err(io::Error::other)?;
    let custody = Arc::clone(executor.custody());
    let (mut units, project, publisher_uid) = {
        let owner = custody
            .lock()
            .map_err(|_| invalid("eviction custody poisoned"))?;
        policy::check_ready(executor, &owner)?;
        policy::check_bootstrap(&owner, &running)?;
        let mut units = Vec::<Unit>::new();
        let mut by_inode = BTreeMap::new();
        let mut references = Vec::new();
        for resource in executor.publication_jobs() {
            let job = resource
                .lock()
                .map_err(|_| invalid("eviction publication poisoned"))?;
            if !job.started || !job.complete {
                continue;
            }
            let cached = job.cached.as_ref();
            let body = residence::registered_body(&owner, &job)?;
            let metadata = body.handle().metadata()?;
            let inode = (metadata.dev(), metadata.ino());
            let hash = state::hex(body.claim().descriptor().digest());
            let index = if let Some(index) = by_inode.get(&inode) {
                *index
            } else {
                let index = units.len();
                by_inode.insert(inode, index);
                units.push(Unit {
                    order: job.order,
                    key: format!("{}:{}", inode.0, inode.1),
                    body: Arc::clone(body),
                    members: Vec::new(),
                    allocated: 0,
                    protected: false,
                    shared_chunks: BTreeSet::new(),
                    metadata: BTreeMap::new(),
                    reconstruction: BTreeSet::new(),
                    chunks: owner
                        .state
                        .residences
                        .iter()
                        .filter(|row| row.object == hash)
                        .map(|row| row.chunk.clone())
                        .collect(),
                });
                index
            };
            let unit = &mut units[index];
            unit.order = unit.order.min(job.order);
            if unit.body.claim().descriptor() != body.claim().descriptor()
                || unit.body.incarnation() != body.incarnation()
            {
                return Err(invalid(
                    "cached aliases disagree about original native body",
                ));
            }
            unit.members.push(Arc::clone(resource));
            if let Some(owner) = cached.and_then(|cached| cached.reconstruction_pin_owner()) {
                unit.reconstruction.insert(owner);
            }
            if let Some(metadata) = cached.and_then(|cached| cached.reconstruction()) {
                unit.metadata
                    .insert(*metadata.retention_id(), Arc::clone(metadata));
            }
            if let Some(manifest) = job.claim.manifest() {
                references.push((
                    hash,
                    manifest
                        .chunks
                        .iter()
                        .map(|chunk| state::hex(&chunk.digest))
                        .collect::<BTreeSet<_>>(),
                ));
            }
        }
        for unit in &mut units {
            let hash = state::hex(unit.body.claim().descriptor().digest());
            unit.protected = owner.state.pins.iter().any(|pin| {
                (pin.hash == hash || unit.chunks.contains(&pin.hash))
                    && !(pin.hash == hash && unit.reconstruction.contains(&pin.owner))
            });
            for (_, chunks) in references.iter().filter(|(object, _)| object != &hash) {
                unit.shared_chunks
                    .extend(unit.chunks.intersection(chunks).cloned());
            }
        }
        (
            units,
            owner.preparation.config.project_id,
            owner.preparation.config.publisher.identities.publish_uid,
        )
    };

    // Native synchronization and descriptor drops never hold embedded policy.
    for unit in &mut units {
        unit.allocated = residence::synchronize_body(&unit.body, project, publisher_uid)?;
    }
    running.check_current().map_err(io::Error::other)?;
    Ok(units)
}
