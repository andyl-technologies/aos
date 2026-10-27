//! Binds metadata consumers to the original completed pack and detached index.
//!
//! Immutable admitted bytes select a record; they never replace native reads.
//! Both original descriptors are checked and read before returning a body. A
//! failure permanently rejects their shared publisher observation, so restoring
//! bytes cannot revive an alias or substitute another pair for quarantine.

use super::{AdmissionJob, Input, io as native, state};
use crate::{
    host_cache::{
        NativeHostLayout,
        owner::{
            publication::residence::check_snapshot,
            retention::{Custody, NativeOwnerExecutor},
        },
    },
    host_quota::{NativeProject, synchronized_allocated_bytes},
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
use terrane_format::identity::{Identity, IdentityKind, TERRANE_V1};
use terrane_sdk::{host::cache::HostDomainLocation, pack::PackReader};

/// Retains one genuine cache admission and both original native members.
pub(in crate::host_cache::owner) struct AdmittedMetadataRead {
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
}

struct Member {
    file: File,
    stamp: native::FileStamp,
    inode: (u64, u64, u64),
    expected: Arc<Vec<u8>>,
    mode: u32,
}

impl AdmittedMetadataRead {
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
        if matches!(identity.kind(), IdentityKind::Chunk | IdentityKind::Pack)
            || identity.profile() != TERRANE_V1.name()
        {
            return Err(invalid(
                "metadata consumer requires a canonical metadata identity",
            ));
        }
        let owner = executor
            .custody()
            .lock()
            .map_err(|_| invalid("metadata read custody poisoned"))?;
        check_snapshot(&owner)?;
        for resource in executor.admission_jobs() {
            let job = super::backing::lock(resource)?;
            let Input::Metadata { pack, index, .. } = &job.input else {
                continue;
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
            state::check_registration(&owner, &job)?;
            if job.files.len() != 2
                || !job.dependencies.is_empty()
                || !Arc::ptr_eq(&job.custody, executor.custody())
            {
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
                    .read_stamp(&owner)
                    .inspect_err(|_| observation.reject(1))?;
                let file = original
                    .readonly
                    .as_ref()
                    .ok_or_else(|| invalid("metadata read original descriptor absent"))?
                    .try_clone()?;
                let metadata = file.metadata()?;
                Ok(Member {
                    file,
                    stamp,
                    inode: (metadata.dev(), metadata.ino(), metadata.len()),
                    expected: Arc::clone(expected),
                    mode: metadata.mode() & 0o7777,
                })
            };
            let start = usize::try_from(entry.offset()).map_err(io::Error::other)?;
            let end = start
                .checked_add(usize::try_from(entry.body_len()).map_err(io::Error::other)?)
                .ok_or_else(|| invalid("metadata body range overflow"))?;
            if pack.get(start..end).is_none() {
                return Err(invalid("metadata body exceeds original pack"));
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
            };
            drop(job);
            drop(owner);
            read.check_native()?;
            context.check_current().map_err(io::Error::other)?;
            return Ok(read);
        }
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            MissingCachedMetadata,
        ))
    }

    /// Borrows the selected canonical metadata identity.
    pub(in crate::host_cache::owner) fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Checks the actual original admission and its durable cache registration.
    ///
    /// # Errors
    /// Refuses changed native resources, registration or root binding.
    pub(in crate::host_cache::owner) fn check_protected(&self, owner: &Custody) -> io::Result<()> {
        self.check_consumer_backing(owner)?;
        let job = super::backing::lock(&self.job)?;
        state::check_registration(owner, &job)
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
    pub(in crate::host_cache::owner) fn read_verified(&self) -> io::Result<Vec<u8>> {
        self.check_native()?;
        let result = (|| {
            let mut scratch = [0_u8; 8192];
            for member in &self.members {
                for (position, expected) in member.expected.chunks(scratch.len()).enumerate() {
                    let offset = position
                        .checked_mul(scratch.len())
                        .and_then(|offset| u64::try_from(offset).ok())
                        .ok_or_else(|| invalid("metadata verification offset overflow"))?;
                    member
                        .file
                        .read_exact_at(&mut scratch[..expected.len()], offset)?;
                    if &scratch[..expected.len()] != expected {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "original metadata pair bytes changed",
                        ));
                    }
                }
            }
            let mut body = Vec::new();
            body.try_reserve_exact(self.range.len())
                .map_err(|error| io::Error::new(io::ErrorKind::OutOfMemory, error))?;
            body.resize(self.range.len(), 0);
            self.members[1].file.read_exact_at(
                &mut body,
                u64::try_from(self.range.start).map_err(io::Error::other)?,
            )?;
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

    /// Recognizes the actual original job while consumer custody exists.
    pub(in crate::host_cache::owner) fn retains(&self, job: &Arc<Mutex<AdmissionJob>>) -> bool {
        Arc::ptr_eq(&self.job, job)
    }

    /// Iterates metadata and complete-container digests for independent pins.
    pub(in crate::host_cache::owner) fn digests(&self) -> impl Iterator<Item = &[u8]> {
        [self.identity.digest(), self.pack_identity.digest()].into_iter()
    }

    /// Iterates both original allocations and their physical registration order.
    pub(in crate::host_cache::owner) fn original_allocations(
        &self,
    ) -> impl Iterator<Item = ((u64, u64), u64)> {
        self.members
            .iter()
            .map(|member| ((member.inode.0, member.inode.1), self.order))
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
        let bytes = synchronized_allocated_bytes(&self.members[0].file)?
            .checked_add(synchronized_allocated_bytes(&self.members[1].file)?)
            .ok_or_else(|| invalid("metadata allocation overflow"))?;
        self.check_native()?;
        Ok(bytes)
    }

    /// Bounds retained original handles and identity buffers, sharing admitted bytes.
    ///
    /// # Errors
    /// Refuses overflow in fixed header storage accounting.
    pub(in crate::host_cache::owner) fn storage_bytes() -> io::Result<usize> {
        std::mem::size_of::<Self>()
            .checked_add(2 * (TERRANE_V1.name().len() + TERRANE_V1.digest_len()))
            .ok_or_else(|| invalid("metadata read header storage overflow"))
    }

    fn check_native(&self) -> io::Result<()> {
        self.observation.check_readable()?;
        let checked = (|| {
            self.layout.recheck()?;
            for member in &self.members {
                member.stamp.check(&member.file)?;
                let metadata = member.file.metadata()?;
                if member.inode.0 != self.layout.directory_binding("layout-root")?.0
                    || (metadata.dev(), metadata.ino(), metadata.len()) != member.inode
                    || usize::try_from(metadata.len()).ok() != Some(member.expected.len())
                    || metadata.uid() != self.uid
                    || metadata.gid() != self.gid
                    || !metadata.is_file()
                    || metadata.nlink() != 1
                    || !matches!(member.mode, 0o640 | 0o660)
                    || metadata.mode() & 0o7777 != member.mode
                    || fs::fcntl_getfl(&member.file)?
                        .intersects(OFlags::WRONLY | OFlags::RDWR | OFlags::PATH)
                    || NativeProject::inspect(&member.file)?.project_id != self.project
                {
                    return Err(invalid("metadata consumer changed original native pair"));
                }
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
struct MissingCachedMetadata;

impl std::fmt::Display for MissingCachedMetadata {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("actual cached metadata admission absent")
    }
}

impl std::error::Error for MissingCachedMetadata {}

/// Recognizes only absence established by a complete actual admission lookup.
pub(in crate::host_cache::owner) fn cache_absent(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|source| source.is::<MissingCachedMetadata>())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_absence_never_masks_native_missing_or_corrupt_backing() {
        let absent = io::Error::new(io::ErrorKind::NotFound, MissingCachedMetadata);
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
