//! Binds metadata and packed-chunk consumers to original completed native pairs.
//!
//! Immutable admitted bytes select a record; they never replace native reads.
//! Both original descriptors are checked and read before returning a body. A
//! failure permanently rejects their shared publisher observation, so restoring
//! bytes cannot revive an alias or substitute another pair for quarantine.

use super::{AdmissionJob, Input, read_member::ReadMember as Member, state};
use crate::{
    host_cache::{
        NativeHostLayout,
        owner::{
            publication::residence::check_snapshot,
            retention::{Custody, NativeOwnerExecutor},
        },
    },
    host_quota::synchronized_allocated_bytes,
    publisher_local::client::EncodedReadObservation,
};
use rustix::fs::{self, Mode, OFlags};
use std::{
    fs::File,
    io,
    ops::Range,
    os::unix::fs::{FileExt, MetadataExt},
    sync::{Arc, Mutex},
};
use terrane_format::{
    chunking::ChunkProfile,
    identity::{Identity, IdentityKind, TERRANE_V1},
};
use terrane_sdk::{
    host::cache::{HostDomainLocation, HostReadLimits},
    pack::PackReader,
};

/// Retains one genuine cache admission and both original native members.
pub(in crate::host_cache) struct AdmittedPackRead {
    layout: Arc<NativeHostLayout<HostDomainLocation>>,
    job: Arc<Mutex<AdmissionJob>>,
    observation: Arc<EncodedReadObservation>,
    identity: Identity,
    pack_identity: Identity,
    range: Range<usize>,
    members: [Member; 2],
    order: u64,
    project: u32,
    uid: u32,
    gid: u32,
    chunk: Option<ChunkRead>,
    dictionaries: Vec<super::dictionary_read::DictionaryRead>,
}

struct ChunkRead {
    profile: ChunkProfile,
    limits: HostReadLimits,
    max_entries: usize,
    length: usize,
}

impl AdmittedPackRead {
    /// Selects only a verified record in a completed, physically registered pair.
    ///
    /// # Errors
    /// Refuses absent cache custody, changed original backing or invalid context.
    pub(in crate::host_cache::owner) fn prepare(
        executor: &NativeOwnerExecutor,
        identity: Identity,
    ) -> io::Result<Self> {
        Self::prepare_owned(executor, identity, true)
    }

    /// Borrows original producer protection only within the physical retention turn.
    ///
    /// # Errors
    /// Refuses absent original custody or any invalid native/publisher binding.
    pub(in crate::host_cache::owner) fn prepare_retention(
        executor: &NativeOwnerExecutor,
        identity: Identity,
    ) -> io::Result<Self> {
        Self::prepare_owned(executor, identity, false)
    }

    fn prepare_owned(
        executor: &NativeOwnerExecutor,
        identity: Identity,
        require_cached: bool,
    ) -> io::Result<Self> {
        executor.check_physical_worker()?;
        let context = executor.admission_context()?;
        context.check_current().map_err(io::Error::other)?;
        let read = {
            let owner = executor
                .custody()
                .lock()
                .map_err(|_| invalid("pack read custody poisoned"))?;
            Self::prepare_registered(executor, &owner, identity, require_cached)?
        };
        context.check_current().map_err(io::Error::other)?;
        Ok(read)
    }

    /// Retains an actual cached pair during the worker's publication selection.
    ///
    /// The caller already holds this owner's policy lock and checks publisher
    /// phase outside it. This checks the actual retained Running registration
    /// without nesting the publisher's connection mutex under owner custody.
    ///
    /// # Errors
    /// Refuses stale Running custody, absent admission or changed original bytes.
    pub(in crate::host_cache::owner) fn prepare_publication(
        executor: &NativeOwnerExecutor,
        owner: &Custody,
        identity: Identity,
    ) -> io::Result<Self> {
        executor.admission_context_locked(owner)?;
        Self::prepare_registered(executor, owner, identity, true)
    }

    fn prepare_registered(
        executor: &NativeOwnerExecutor,
        owner: &Custody,
        identity: Identity,
        require_cached: bool,
    ) -> io::Result<Self> {
        if identity.kind() == IdentityKind::Pack || identity.profile() != TERRANE_V1.name() {
            return Err(invalid(
                "pack consumer requires a canonical chunk or metadata identity",
            ));
        }
        check_snapshot(owner)?;
        for resource in executor.admission_jobs() {
            let job = super::backing::lock(resource)?;
            let (pack, index, chunk) = match &job.input {
                Input::Metadata { pack, index, .. } if identity.kind() != IdentityKind::Chunk => {
                    (pack, index, false)
                }
                Input::DataPack { pack, index, .. } if identity.kind() == IdentityKind::Chunk => {
                    (pack, index, true)
                }
                _ => continue,
            };
            if !job.complete {
                continue;
            }
            let reader = PackReader::open(pack).map_err(io::Error::other)?;
            let Some(entry) = reader.entries().iter().find(|entry| {
                entry.kind().identity_kind() == identity.kind()
                    && entry.hash().as_slice() == identity.digest()
            }) else {
                continue;
            };
            if require_cached && job.cached.is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "metadata consumer source has not entered cache custody",
                ));
            }
            state::check_registration(owner, &job)?;
            if job.files.len() != 2 || !Arc::ptr_eq(&job.custody, executor.custody()) {
                return Err(invalid(
                    "metadata read lost original completed pair custody",
                ));
            }
            let observation =
                Arc::clone(job.read_observation.as_ref().ok_or_else(|| {
                    invalid("metadata read lacks original publisher observation")
                })?);
            observation.check_readable()?;
            let member = |position: usize, expected: &Arc<Vec<u8>>| -> io::Result<Member> {
                let original = &job.files[position];
                let stamp = original
                    .read_stamp(owner)
                    .inspect_err(|_| observation.reject(1))?;
                Member::bind(original, Arc::clone(expected), stamp)
            };
            let start = usize::try_from(entry.offset()).map_err(io::Error::other)?;
            let end = start
                .checked_add(usize::try_from(entry.body_len()).map_err(io::Error::other)?)
                .ok_or_else(|| invalid("metadata body range overflow"))?;
            if pack.get(start..end).is_none() {
                return Err(invalid("metadata body exceeds original pack"));
            }
            let mut dictionaries = Vec::new();
            let roots = super::dictionary_read::roots(owner, &job)?;
            dictionaries
                .try_reserve_exact(roots.len())
                .map_err(io::Error::other)?;
            for (digest, dependency) in roots {
                dictionaries.push(super::dictionary_read::DictionaryRead::prepare(
                    executor,
                    owner,
                    &dependency,
                    &digest,
                )?);
            }
            let read = Self {
                layout: Arc::clone(owner.preparation.layout()),
                job: Arc::clone(resource),
                observation: Arc::clone(&observation),
                identity,
                pack_identity: TERRANE_V1
                    .calculate(IdentityKind::Pack, pack)
                    .map_err(io::Error::other)?,
                range: start..end,
                members: [member(0, index)?, member(1, pack)?],
                order: job.order,
                project: owner.preparation.config.project_id,
                uid: owner.preparation.config.content_uid,
                gid: owner.preparation.config.content_gid,
                chunk: chunk.then(|| ChunkRead {
                    length: entry.plaintext_len() as usize,
                    profile: owner.preparation.config.location.chunk_profile().clone(),
                    limits: owner.preparation.config.reads,
                    max_entries: owner
                        .preparation
                        .config
                        .state
                        .records
                        .min(owner.preparation.config.inventory_entries),
                }),
                dictionaries,
            };
            drop(job);
            read.check_native()?;
            return Ok(read);
        }
        Err(io::Error::new(io::ErrorKind::NotFound, MissingCachedPack))
    }

    /// Borrows the selected canonical chunk or metadata identity.
    pub(in crate::host_cache) fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Borrows actual admitted chunk parameters for ordered reassembly.
    ///
    /// # Errors
    /// Refuses metadata records, which cannot supply a plaintext chunk source.
    pub(in crate::host_cache) fn chunk_parameters(
        &self,
    ) -> io::Result<(&str, &ChunkProfile, usize, usize)> {
        let policy = self
            .chunk
            .as_ref()
            .ok_or_else(|| invalid("metadata pair is not an ordered chunk source"))?;
        Ok((
            self.layout.layout().domain(),
            &policy.profile,
            policy.length,
            policy.limits.max_allocation_bytes,
        ))
    }

    /// Checks the actual original admission and its durable cache registration.
    ///
    /// # Errors
    /// Refuses changed native resources, registration or root binding.
    pub(in crate::host_cache::owner) fn check_protected(&self, owner: &Custody) -> io::Result<()> {
        self.check_consumer_backing(owner)?;
        let job = super::backing::lock(&self.job)?;
        state::check_registration(owner, &job)?;
        drop(job);
        for dictionary in &self.dictionaries {
            dictionary.check_protected(owner)?;
        }
        Ok(())
    }

    /// Checks original backing independently of producer funding after handoff.
    ///
    /// # Errors
    /// Refuses another root/project or changed original descriptors.
    pub(in crate::host_cache::owner) fn check_consumer_backing(
        &self,
        owner: &Custody,
    ) -> io::Result<()> {
        check_snapshot(owner)?;
        if !Arc::ptr_eq(&self.layout, owner.preparation.layout())
            || self.project != owner.preparation.config.project_id
        {
            return Err(invalid("metadata consumer belongs to another native root"));
        }
        self.check_native()
    }

    /// Verifies every original pair byte before reading the selected canonical body.
    ///
    /// # Errors
    /// Refuses changed custody, corrupt pack/index bytes, allocation or read errors.
    pub(in crate::host_cache) fn read_verified(&self) -> io::Result<Vec<u8>> {
        self.check_native()?;
        let result = (|| {
            self.check_bytes()?;
            let body = match &self.chunk {
                Some(policy) => super::packed_body::decode_with_dictionaries(
                    &self.members[1].expected,
                    &self.identity,
                    &policy.profile,
                    policy.limits,
                    policy.max_entries,
                    |range| self.read_range(range),
                    |digest| {
                        self.dictionaries
                            .iter()
                            .find(|source| source.identity().digest() == digest)
                            .ok_or_else(|| {
                                invalid("pack read lost its original dictionary source")
                            })?
                            .read_verified()
                    },
                )?,
                None => {
                    let body = self.read_range(self.range.clone())?;
                    if TERRANE_V1
                        .calculate(self.identity.kind(), &body)
                        .map_err(io::Error::other)?
                        != self.identity
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "original metadata body identity changed",
                        ));
                    }
                    body
                }
            };
            self.check_bytes()?;
            Ok(body)
        })();
        if let Err(error) = &result
            && !matches!(
                error.kind(),
                io::ErrorKind::OutOfMemory | io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
            )
        {
            self.observation.reject(2);
        }
        let body = result?;
        self.check_native()?;
        Ok(body)
    }

    /// Returns the original stored envelope after verifying its complete native chain.
    ///
    /// # Errors
    /// Refuses changed pair or dictionary bytes, invalid content, exhausted
    /// allocation bounds, and failure to read the original selected range.
    pub(in crate::host_cache) fn read_encoded(&self) -> io::Result<Vec<u8>> {
        if self.chunk.is_none() {
            return self.read_verified();
        }
        drop(self.read_verified()?);
        let body = self.read_range(self.range.clone()).inspect_err(|error| {
            if !matches!(
                error.kind(),
                io::ErrorKind::OutOfMemory | io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
            ) {
                self.observation.reject(2);
            }
        })?;
        if self.members[1].expected.get(self.range.clone()) != Some(body.as_slice()) {
            self.observation.reject(2);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "original data envelope changed after verification",
            ));
        }
        self.check_native()?;
        Ok(body)
    }

    fn read_range(&self, range: Range<usize>) -> io::Result<Vec<u8>> {
        if self.members[1].expected.get(range.clone()).is_none() {
            return Err(invalid("selected body exceeds original pack"));
        }
        let mut body = Vec::new();
        body.try_reserve_exact(range.len())
            .map_err(|error| io::Error::new(io::ErrorKind::OutOfMemory, error))?;
        body.resize(range.len(), 0);
        self.members[1].file.read_exact_at(
            &mut body,
            u64::try_from(range.start).map_err(io::Error::other)?,
        )?;
        Ok(body)
    }

    fn check_bytes(&self) -> io::Result<()> {
        for member in &self.members {
            member.check_bytes()?;
        }
        Ok(())
    }

    /// Recognizes the actual original job while consumer custody exists.
    pub(in crate::host_cache::owner) fn retains(&self, job: &Arc<Mutex<AdmissionJob>>) -> bool {
        Arc::ptr_eq(&self.job, job) || self.dictionaries.iter().any(|source| source.retains(job))
    }

    /// Iterates metadata and complete-container digests for independent pins.
    pub(in crate::host_cache::owner) fn digests(&self) -> impl Iterator<Item = &[u8]> {
        [self.identity.digest(), self.pack_identity.digest()]
            .into_iter()
            .chain(self.dictionaries.iter().flat_map(|source| source.digests()))
    }

    /// Iterates both original allocations and their physical registration order.
    pub(in crate::host_cache::owner) fn original_allocations(
        &self,
    ) -> impl Iterator<Item = ((u64, u64), u64)> {
        self.members
            .iter()
            .map(|member| ((member.inode.0, member.inode.1), self.order))
            .chain(
                self.dictionaries
                    .iter()
                    .flat_map(|source| source.original_allocations()),
            )
    }

    /// Synchronizes and measures both distinct original member allocations.
    ///
    /// # Errors
    /// Refuses changed root/backing, filesystem sync failure or overflow.
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
            return Err(invalid("metadata synchronization root changed"));
        }
        fs::syncfs(&root)?;
        if self.members[0].inode.0 == self.members[1].inode.0
            && self.members[0].inode.1 == self.members[1].inode.1
        {
            return Err(invalid("metadata pair aliases one inode"));
        }
        let mut allocations = std::collections::BTreeMap::new();
        for file in self.members.iter().map(|member| &member.file).chain(
            self.dictionaries
                .iter()
                .flat_map(|source| source.original_files()),
        ) {
            let metadata = file.metadata()?;
            allocations.insert(
                (metadata.dev(), metadata.ino()),
                synchronized_allocated_bytes(file)?,
            );
        }
        let bytes = allocations.values().try_fold(0_u64, |total, bytes| {
            total
                .checked_add(*bytes)
                .ok_or_else(|| invalid("metadata allocation overflow"))
        })?;
        self.check_native()?;
        Ok(bytes)
    }

    /// Bounds retained original handles and identity buffers, sharing admitted bytes.
    ///
    /// # Errors
    /// Refuses overflow in fixed header storage accounting.
    pub(in crate::host_cache::owner) fn storage_bytes(
        domain: usize,
        records: usize,
    ) -> io::Result<usize> {
        let dictionaries = super::dictionary_read::DictionaryRead::storage_bytes(domain, records)?
            .checked_mul(records)
            .ok_or_else(|| invalid("pack dictionary storage overflow"))?;
        std::mem::size_of::<Self>()
            .checked_add(2 * (TERRANE_V1.name().len() + TERRANE_V1.digest_len()))
            .and_then(|bytes| bytes.checked_add(dictionaries))
            .ok_or_else(|| invalid("metadata read header storage overflow"))
    }

    fn check_native(&self) -> io::Result<()> {
        self.observation.check_readable()?;
        for dictionary in &self.dictionaries {
            dictionary.check_native()?;
        }
        let checked = (|| {
            self.layout.recheck()?;
            for member in &self.members {
                member.check_native(&self.layout, self.project, self.uid, self.gid)?;
            }
            self.layout.recheck()
        })();
        checked.inspect_err(|_| self.observation.reject(1))?;
        self.observation.check_readable()
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::other(message)
}

/// Distinguishes an exhausted actual registry from missing or damaged backing.
#[derive(Debug)]
struct MissingCachedPack;

impl std::fmt::Display for MissingCachedPack {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("actual cached pack admission absent")
    }
}

impl std::error::Error for MissingCachedPack {}

/// Recognizes only absence established by a complete actual admission lookup.
pub(in crate::host_cache::owner) fn cache_absent(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|source| source.is::<MissingCachedPack>())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_absence_never_masks_native_missing_or_corrupt_backing() {
        let absent = io::Error::new(io::ErrorKind::NotFound, MissingCachedPack);
        assert!(cache_absent(&absent));

        for error in [
            io::Error::from_raw_os_error(2),
            io::Error::new(
                io::ErrorKind::NotFound,
                "original metadata descriptor disappeared",
            ),
            io::Error::new(
                io::ErrorKind::InvalidData,
                "original metadata index changed",
            ),
            io::Error::other(absent),
        ] {
            assert!(!cache_absent(&error));
        }
    }
}
