//! Binds standalone consumers to original chunk and packed dictionary custody.
//!
//! Construction selects one actual cached standalone admission and retains its
//! complete inode-bound source closure. Reads verify positioned original bytes
//! without policy locks; each dependency and containing pack remains protected
//! until the independent consumer releases it.

use super::{AdmissionJob, Input, dictionary_read::DictionaryRead};
use crate::{
    host_cache::{
        NativeHostLayout,
        owner::retention::{Custody, NativeOwnerExecutor},
    },
    host_quota::synchronized_allocated_bytes,
};
use rustix::fs::{self, Mode, OFlags};
use std::{
    fs::File,
    io,
    os::unix::fs::MetadataExt,
    sync::{Arc, Mutex},
};
use terrane_format::identity::{Identity, IdentityKind, TERRANE_V1};
use terrane_sdk::host::cache::HostDomainLocation;

/// Retains a standalone root and its complete original dictionary source closure.
pub(in crate::host_cache::owner) struct AdmittedRead {
    layout: Arc<NativeHostLayout<HostDomainLocation>>,
    source: DictionaryRead,
}

impl AdmittedRead {
    /// Selects only an actual completed cached standalone admission.
    ///
    /// # Errors
    /// Refuses another worker, absent custody, unavailable cache handoff,
    /// changed original inodes, invalid content or exceeded finite bounds.
    pub(in crate::host_cache::owner) fn prepare(
        executor: &NativeOwnerExecutor,
        identity: Identity,
    ) -> io::Result<Self> {
        executor.check_physical_worker()?;
        let context = executor.admission_context()?;
        context.check_current().map_err(io::Error::other)?;
        if identity.kind() != IdentityKind::Chunk || identity.profile() != TERRANE_V1.name() {
            return Err(invalid(
                "consumer admission requires a registered chunk identity",
            ));
        }
        let digest = identity.digest().try_into().map_err(io::Error::other)?;
        let read = {
            let owner = executor
                .custody()
                .lock()
                .map_err(|_| invalid("admitted read custody poisoned"))?;
            let mut selected = None;
            for resource in executor.admission_jobs() {
                let job = super::backing::lock(resource)?;
                let Input::Chunk { descriptor, .. } = &job.input else {
                    continue;
                };
                if !job.complete || descriptor.digest() != identity.digest() {
                    continue;
                }
                if job.cached.is_none() {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "consumer source has not entered cache custody",
                    ));
                }
                drop(job);
                let mut source = DictionaryRead::prepare(executor, &owner, resource, &digest)?;
                source.require_object_boundary();
                selected = Some(source);
                break;
            }
            Self {
                layout: Arc::clone(owner.preparation.layout()),
                source: selected
                    .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, MissingCachedChunk))?,
            }
        };
        // Decode outside embedded policy custody, retaining only original
        // source descriptors and immutable input allocations.
        drop(read.read_verified()?);
        context.check_current().map_err(io::Error::other)?;
        let owner = executor
            .custody()
            .lock()
            .map_err(|_| invalid("admitted read custody poisoned"))?;
        read.check_protected(&owner)?;
        Ok(read)
    }

    /// Borrows the original admitted root identity.
    pub(in crate::host_cache::owner) fn identity(&self) -> &Identity {
        self.source.identity()
    }

    /// Checks original registration and protection before independent handoff.
    ///
    /// # Errors
    /// Refuses changed custody, native backing or durable producer promises.
    pub(in crate::host_cache::owner) fn check_protected(&self, owner: &Custody) -> io::Result<()> {
        self.source.check_protected(owner)
    }

    /// Checks consumer-held original backing after producer funding changes.
    ///
    /// # Errors
    /// Refuses another root, stale snapshot or changed original native members.
    pub(in crate::host_cache::owner) fn check_consumer_backing(
        &self,
        owner: &Custody,
    ) -> io::Result<()> {
        self.source.check_consumer_backing(owner)
    }

    /// Reads and verifies the original body through all actual dictionary sources.
    ///
    /// # Errors
    /// Refuses changed bytes or custody, invalid content and exceeded read bounds.
    pub(in crate::host_cache::owner) fn read_verified(&self) -> io::Result<Vec<u8>> {
        self.source.read_verified()
    }

    /// Returns the exact original root encoding after complete verification.
    ///
    /// # Errors
    /// Refuses changed bytes or custody, invalid boundaries or exceeded bounds.
    pub(in crate::host_cache::owner) fn read_encoded(&self) -> io::Result<Vec<u8>> {
        self.source.read_encoded()
    }

    /// Recognizes every actual retained source job until the consumer closes.
    pub(in crate::host_cache::owner) fn retains(&self, job: &Arc<Mutex<AdmissionJob>>) -> bool {
        self.source.retains(job)
    }

    /// Iterates body, dictionary and original pack-container protection digests.
    pub(in crate::host_cache::owner) fn digests(&self) -> impl Iterator<Item = &[u8]> {
        self.source.digests()
    }

    /// Iterates distinct original members and their actual admission order.
    pub(in crate::host_cache::owner) fn original_allocations(
        &self,
    ) -> impl Iterator<Item = ((u64, u64), u64)> {
        self.source.original_allocations()
    }

    /// Synchronizes and measures every original body, dictionary and index inode.
    ///
    /// # Errors
    /// Refuses changed native custody, synchronization failure or size overflow.
    pub(in crate::host_cache::owner) fn synchronize_pin_backing(&self) -> io::Result<u64> {
        self.check_native()?;
        let root = File::from(fs::openat(
            &self.layout.root,
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let metadata = root.metadata()?;
        if (metadata.dev(), metadata.ino()) != self.layout.directory_binding("layout-root")? {
            return Err(invalid("admitted read synchronization root changed"));
        }
        fs::syncfs(&root)?;
        let mut allocated = 0_u64;
        let mut seen = Vec::new();
        seen.try_reserve_exact(self.source.original_files().count())
            .map_err(io::Error::other)?;
        for file in self.source.original_files() {
            let metadata = file.metadata()?;
            let inode = (metadata.dev(), metadata.ino());
            if !seen.contains(&inode) {
                allocated = allocated
                    .checked_add(synchronized_allocated_bytes(file)?)
                    .ok_or_else(|| invalid("admitted allocation overflow"))?;
                seen.push(inode);
            }
        }
        self.check_native()?;
        Ok(allocated)
    }

    /// Bounds the retained original source closure without copying its payloads.
    ///
    /// # Errors
    /// Refuses overflow in configured source and domain storage.
    pub(in crate::host_cache::owner) fn storage_bytes(
        domain: usize,
        max_members: usize,
    ) -> io::Result<usize> {
        std::mem::size_of::<Self>()
            .checked_add(DictionaryRead::storage_bytes(domain, max_members)?)
            .ok_or_else(|| invalid("admitted read header storage overflow"))
    }

    /// Checks all original native members without acquiring policy or job locks.
    ///
    /// # Errors
    /// Refuses changed original observations, roots, metadata or file access.
    pub(super) fn check_native(&self) -> io::Result<()> {
        self.source.check_native()
    }
}

/// Finds the original owned admission behind a verified metadata source.
///
/// Read-only recovery or lower-tier sources outside this admission registry
/// have no managed allocation to promote. They acquire scheduling state only
/// after actual physical adoption, never merely from an opened filename.
///
/// # Errors
/// Refuses another worker/root, changed actual admission custody or native bytes,
/// poisoned jobs and descriptors differing from the original pack/index pair.
pub(in crate::host_cache::owner) fn metadata_activity_order(
    executor: &NativeOwnerExecutor,
    owner: &Custody,
    source: &crate::host_cache::NativeManifestSource,
) -> io::Result<Option<u64>> {
    executor.check_physical_worker()?;
    if !Arc::ptr_eq(source.layout(), owner.preparation.layout()) {
        return Err(invalid("metadata activity has another native root"));
    }
    for resource in executor.admission_jobs() {
        let job = super::backing::lock(resource)?;
        let Input::Metadata { expected_id, .. } = &job.input else {
            continue;
        };
        if !job.complete || *expected_id != source.pack_id() {
            continue;
        }
        if !Arc::ptr_eq(&job.custody, executor.custody()) {
            return Err(invalid(
                "metadata activity changed original admission custody",
            ));
        }
        for (file, original) in [source.files().1, source.files().0]
            .into_iter()
            .zip(&job.files)
        {
            let actual = file.metadata()?;
            let original = original
                .readonly
                .as_ref()
                .ok_or_else(|| invalid("metadata activity original descriptor absent"))?
                .metadata()?;
            if (actual.dev(), actual.ino()) != (original.dev(), original.ino()) {
                return Err(invalid(
                    "metadata activity changed its original native pair",
                ));
            }
        }
        if let Some(observation) = &job.read_observation {
            source.bind_read_observation(Arc::clone(observation))?;
        }
        super::reconcile::verify(owner, &job)?;
        source.recheck()?;
        return Ok(Some(job.order));
    }
    source.recheck()?;
    Ok(None)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::other(message)
}

/// Distinguishes a complete registry miss from failed original native backing.
#[derive(Debug)]
struct MissingCachedChunk;

impl std::fmt::Display for MissingCachedChunk {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("actual cached standalone admission absent")
    }
}

impl std::error::Error for MissingCachedChunk {}

/// Recognizes only absence established by a complete actual standalone lookup.
pub(in crate::host_cache::owner) fn cache_absent(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|source| source.is::<MissingCachedChunk>())
}
