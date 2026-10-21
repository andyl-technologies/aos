//! Binds consumer reads to original completed canonical admission jobs.
//!
//! A policy row or opened pathname never creates custody. Construction retains
//! the actual body and dictionary jobs, then binds independently opened read
//! handles to their original inodes. Reads use only immutable handles and native
//! root checks, without admission-job or embedded-state locks.

use super::{AdmissionJob, Input, io as native, state};
use crate::{
    host_cache::owner::{
        publication::residence::check_snapshot,
        retention::{Custody, NativeOwnerExecutor},
    },
    host_cache::{NativeChunkSource, NativeHostLayout},
    host_quota::{NativeProject, synchronized_allocated_bytes},
};
use rustix::fs::{self, Mode, OFlags};
use std::{
    fs::File,
    io,
    os::unix::fs::MetadataExt,
    sync::{Arc, Mutex},
};
use terrane_format::identity::{Identity, IdentityKind, TERRANE_V1};
use terrane_sdk::{host::cache::HostDomainLocation, store::ChunkPosition};

/// Retains genuine body and one-hop dictionary custody for independent consumers.
pub(in crate::host_cache::owner) struct AdmittedRead {
    layout: Arc<NativeHostLayout<HostDomainLocation>>,
    source: NativeChunkSource,
    members: Vec<Member>,
    project: u32,
}

struct Member {
    job: Arc<Mutex<AdmissionJob>>,
    order: u64,
    identity: Identity,
    length: usize,
    inode: (u64, u64, u64),
    stamp: native::FileStamp,
    uid: u32,
    gid: u32,
}

impl AdmittedRead {
    /// Opens only actual completed cache admissions on this physical executor.
    ///
    /// # Errors
    /// Refuses absent custody, changed registration, unavailable native handles,
    /// invalid source bytes or bindings to any other body or dictionary inode.
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
        let (layout, project, length, final_chunk, limit, members) = {
            let owner = executor
                .custody()
                .lock()
                .map_err(|_| invalid("admitted read custody poisoned"))?;
            check_snapshot(&owner)?;
            let mut selected = None;
            for resource in executor.admission_jobs() {
                let job = super::backing::lock(resource)?;
                let Input::Chunk {
                    descriptor,
                    position,
                    ..
                } = &job.input
                else {
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
                if job.dependencies.len() > 1 {
                    return Err(invalid("consumer admission exceeds one dictionary"));
                }
                let mut members = Vec::new();
                members.try_reserve_exact(2).map_err(io::Error::other)?;
                members.push(member(executor, &owner, resource, &job)?);
                for dependency in &job.dependencies {
                    let dictionary = super::backing::lock(dependency)?;
                    if !dictionary.dependencies.is_empty() {
                        return Err(invalid("consumer dictionary is not one hop"));
                    }
                    members.push(member(executor, &owner, dependency, &dictionary)?);
                }
                selected = Some((
                    usize::try_from(descriptor.size()).map_err(io::Error::other)?,
                    matches!(position, ChunkPosition::Final),
                    members,
                ));
                break;
            }
            let (length, final_chunk, members) = selected.ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "actual cached admission absent")
            })?;
            (
                Arc::clone(owner.preparation.layout()),
                owner.preparation.config.project_id,
                length,
                final_chunk,
                owner.preparation.config.reads.max_allocation_bytes,
                members,
            )
        };
        // Canonical open and decompression happen without embedded custody held.
        let source =
            NativeChunkSource::open_bounded(&layout, identity, length, final_chunk, limit)?;
        let read = Self {
            layout,
            source,
            members,
            project,
        };
        read.check_native()?;
        context.check_current().map_err(io::Error::other)?;
        let owner = executor
            .custody()
            .lock()
            .map_err(|_| invalid("admitted read custody poisoned"))?;
        read.check_protected(&owner)?;
        Ok(read)
    }

    /// Borrows the original body identity checked against actual admission custody.
    pub(in crate::host_cache::owner) fn identity(&self) -> &Identity {
        self.source.identity()
    }

    /// Rechecks producer promises before synchronizing independent consumer pins.
    ///
    /// # Errors
    /// Refuses changed original root, admission registration or cache protection.
    pub(in crate::host_cache::owner) fn check_protected(&self, owner: &Custody) -> io::Result<()> {
        self.check_consumer_backing(owner)?;
        for member in &self.members {
            let job = super::backing::lock(&member.job)?;
            state::check_registration(owner, &job)?;
        }
        Ok(())
    }

    /// Checks actual backing independently of producer funding after handoff.
    ///
    /// # Errors
    /// Refuses another root/project, changed descriptors or native inode metadata.
    pub(in crate::host_cache::owner) fn check_consumer_backing(
        &self,
        owner: &Custody,
    ) -> io::Result<()> {
        check_snapshot(owner)?;
        if !Arc::ptr_eq(&self.layout, owner.preparation.layout())
            || self.project != owner.preparation.config.project_id
        {
            return Err(invalid("admitted consumer belongs to another native root"));
        }
        self.check_native()
    }

    /// Reads actual verified body and dictionary bytes without policy or job locks.
    ///
    /// # Errors
    /// Refuses changed native backing, identity or boundary and bounded decode failures.
    pub(in crate::host_cache::owner) fn read_verified(&self) -> io::Result<Vec<u8>> {
        self.check_native()?;
        let bytes = self.source.read_verified_at()?;
        self.check_native()?;
        Ok(bytes)
    }

    /// Returns the original envelope after full native and content verification.
    ///
    /// # Errors
    /// Refuses changed backing or dictionary custody, corrupt bytes, invalid
    /// boundaries and reads exceeding the configured allocation window.
    pub(in crate::host_cache::owner) fn read_encoded(&self) -> io::Result<Vec<u8>> {
        self.check_native()?;
        let bytes = self.source.read_encoded_at()?;
        self.check_native()?;
        Ok(bytes)
    }

    /// Recognizes the actual original job while consumer custody still exists.
    pub(in crate::host_cache::owner) fn retains(&self, job: &Arc<Mutex<AdmissionJob>>) -> bool {
        self.members
            .iter()
            .any(|member| Arc::ptr_eq(&member.job, job))
    }

    /// Iterates exact body and dictionary digests for independent durable protection.
    pub(in crate::host_cache::owner) fn digests(&self) -> impl Iterator<Item = &[u8]> {
        self.members.iter().map(|member| member.identity.digest())
    }

    /// Iterates original body/dictionary inodes and their physical admission order.
    pub(in crate::host_cache::owner) fn original_allocations(
        &self,
    ) -> impl Iterator<Item = ((u64, u64), u64)> {
        self.members
            .iter()
            .map(|member| ((member.inode.0, member.inode.1), member.order))
    }

    /// Synchronizes and measures distinct original body and dictionary allocations.
    ///
    /// # Errors
    /// Refuses changed native root/backing, filesystem sync failure or overflow.
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
        seen.try_reserve_exact(2).map_err(io::Error::other)?;
        for (_, _, file) in self.source.handles() {
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

    /// Bounds retained body, one-hop dictionary and original member headers.
    ///
    /// # Errors
    /// Refuses overflow in trusted domain-label storage arithmetic.
    pub(in crate::host_cache::owner) fn storage_bytes(domain: usize) -> io::Result<usize> {
        // The inline source owns its ChunkProfile table; the boxed dictionary
        // owns another complete source, not merely one pointer-sized slot.
        std::mem::size_of::<Self>()
            .checked_add(std::mem::size_of::<NativeChunkSource>())
            .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<Member>()))
            .and_then(|bytes| bytes.checked_add(domain.checked_mul(2)?))
            // Two source identities and two original member identities own
            // their registered profile labels and digest buffers.
            .and_then(|bytes| {
                bytes.checked_add(4 * (TERRANE_V1.name().len() + TERRANE_V1.digest_len()))
            })
            .and_then(|bytes| bytes.checked_add(8 * std::mem::size_of::<usize>()))
            .ok_or_else(|| invalid("admitted read header storage overflow"))
    }

    fn check_native(&self) -> io::Result<()> {
        self.layout.recheck()?;
        if self.source.handles().count() != self.members.len() {
            return Err(invalid("admitted read changed actual member count"));
        }
        for (identity, length, file) in self.source.handles() {
            let member = self
                .members
                .iter()
                .find(|member| member.identity == *identity && member.length == length)
                .ok_or_else(|| invalid("admitted read lost original member binding"))?;
            member.stamp.check(file)?;
            let metadata = file.metadata()?;
            if member.inode.0 != self.layout.directory_binding("layout-root")?.0
                || (metadata.dev(), metadata.ino(), metadata.len()) != member.inode
                || metadata.uid() != member.uid
                || metadata.gid() != member.gid
                || !metadata.is_file()
                || metadata.nlink() != 1
                || metadata.mode() & 0o7777 != 0o640
                || fs::fcntl_getfl(file)?.intersects(OFlags::WRONLY | OFlags::RDWR | OFlags::PATH)
                || NativeProject::inspect(file)?.project_id != self.project
            {
                return Err(invalid(
                    "admitted consumer changed its original native backing",
                ));
            }
        }
        self.layout.recheck()
    }
}

fn member(
    executor: &NativeOwnerExecutor,
    owner: &Custody,
    resource: &Arc<Mutex<AdmissionJob>>,
    job: &AdmissionJob,
) -> io::Result<Member> {
    if !job.complete
        || job.files.len() != 1
        || !Arc::ptr_eq(&job.custody, executor.custody())
        || !executor
            .admission_jobs()
            .iter()
            .any(|registered| Arc::ptr_eq(registered, resource))
    {
        return Err(invalid("admitted read lost actual completed job custody"));
    }
    state::check_registration(owner, job)?;
    let Input::Chunk { descriptor, .. } = &job.input else {
        return Err(invalid("admitted read member is not a chunk"));
    };
    let stamp = job.files[0].read_stamp(owner)?;
    let file = job.files[0]
        .readonly
        .as_ref()
        .ok_or_else(|| invalid("admitted read original descriptor absent"))?;
    let metadata = file.metadata()?;
    Ok(Member {
        job: Arc::clone(resource),
        order: job.order,
        identity: TERRANE_V1
            .from_digest(IdentityKind::Chunk, descriptor.digest())
            .map_err(io::Error::other)?,
        length: usize::try_from(descriptor.size()).map_err(io::Error::other)?,
        inode: (metadata.dev(), metadata.ino(), metadata.len()),
        stamp,
        uid: owner.preparation.config.content_uid,
        gid: owner.preparation.config.content_gid,
    })
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
    source.recheck()?;
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
        super::reconcile::verify(owner, &job)?;
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
        return Ok(Some(job.order));
    }
    Ok(None)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::other(message)
}
