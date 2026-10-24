//! Retains an anonymous plaintext source and measures actual sealed completion.
//!
//! No scratch pathname is published or accepted from a caller. The source's
//! real project, ownership, inode and writer closure remain checked under the
//! physical owner; kernel quotas bound allocation beyond the logical hold.

use super::{PublicationJob, invalid, state};
use crate::{
    host_cache::{NativeHostLayout, owner::retention::Custody},
    host_quota::NativeProject,
};
use rustix::fs::{self, AtFlags, Mode, OFlags};
use std::{
    fs::File,
    io::{self, Write},
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    sync::{Arc, Mutex},
};
use terrane_sdk::host::cache::HostDomainLocation;

/// Refuses a canonical standalone copy pending coordinated residence transfer.
///
/// # Errors
/// Refuses any present encoding variant, unsafe shard or unavailable inspection.
pub(super) fn refuse_standalone(owner: &Custody, digest: &[u8]) -> io::Result<()> {
    scan_standalone(owner, digest, None)
}

/// Refuses every other encoding beside the actual selected admission.
///
/// # Errors
/// Refuses another canonical encoding, unsafe namespace or unavailable inspection.
pub(super) fn refuse_other_standalone(
    owner: &Custody,
    digest: &[u8],
    codec: u32,
) -> io::Result<()> {
    scan_standalone(owner, digest, Some(codec))
}

fn scan_standalone(owner: &Custody, digest: &[u8], retained_codec: Option<u32>) -> io::Result<()> {
    owner.check_current()?;
    let chunks = owner
        .preparation
        .layout()
        .directories
        .get("chunks")
        .ok_or_else(|| invalid("publication chunk root absent"))?;
    let hash = state::hex(digest);
    let shard = match fs::openat(
        chunks,
        &hash[..2],
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(shard) => shard,
        Err(rustix::io::Errno::NOENT) => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    for codec in 0..=2 {
        if retained_codec == Some(codec) {
            continue;
        }
        match fs::statat(&shard, format!("{hash}.{codec}"), AtFlags::SYMLINK_NOFOLLOW) {
            Err(rustix::io::Errno::NOENT) => {}
            Err(error) => return Err(error.into()),
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "standalone residence requires coordinated transfer before publication",
                ));
            }
        }
    }
    owner.check_current()
}

/// Retains native output bindings captured from the actual synchronized job.
///
/// Construction checks genuine funding under the physical owner's policy lock.
/// Only immutable native bindings cross into the copying phase; this scope
/// accepts no caller-selected path, descriptor, hold or validity assertion.
pub(super) struct SourceContext {
    custody: Arc<Mutex<Custody>>,
    token: String,
    generation: u64,
    hold: u64,
    size: u64,
    layout: Arc<NativeHostLayout<HostDomainLocation>>,
    content_uid: u32,
    content_gid: u32,
    project: u32,
}

impl SourceContext {
    /// Captures the actual native bindings only after synchronized funding.
    ///
    /// # Errors
    /// Refuses stale or absent funding, changed native custody, unavailable quota
    /// observations and actual charge plus holds beyond the policy ceiling.
    pub(super) fn funded(owner: &mut Custody, job: &PublicationJob) -> io::Result<Self> {
        state::check_funding(
            owner,
            &job.token,
            &state::hex(job.claim.descriptor().digest()),
            job.hold,
            job.generation,
        )?;
        owner.preparation.recheck()?;
        state::check_charge(owner)?;
        Ok(Self {
            custody: Arc::clone(&job.custody),
            token: job.token.clone(),
            generation: job.generation,
            hold: job.hold,
            size: job.claim.plaintext_size(),
            layout: Arc::clone(owner.preparation.layout()),
            content_uid: owner.preparation.config.content_uid,
            content_gid: owner.preparation.config.content_gid,
            project: owner.preparation.config.project_id,
        })
    }
}

/// Creates and synchronizes actual anonymous output without an embedded guard.
///
/// The caller retains its registered physical job and exclusive executor turn.
/// Source and pin registrations are checked before and after copying. Any
/// partial output stays in that same job on error or waiter cancellation.
///
/// # Errors
/// Refuses unsupported anonymous files, changed native bindings, invalid source
/// bytes, write/sync failures or missing actual writer closure.
pub(super) fn prepare_source(scope: &SourceContext, job: &mut PublicationJob) -> io::Result<()> {
    if !Arc::ptr_eq(&scope.custody, &job.custody)
        || scope.token != job.token
        || scope.generation != job.generation
        || scope.hold != job.hold
        || scope.size != job.claim.plaintext_size()
        || !job.started
        || job.complete
        || job.writer.is_some()
        || job.reader.is_some()
    {
        return Err(invalid(
            "anonymous output scope differs from its original funded job",
        ));
    }
    scope.layout.recheck()?;
    let objects = scope
        .layout
        .directories
        .get("objects")
        .ok_or_else(|| invalid("publication objects root absent"))?;
    job.writer = Some(File::from(fs::openat(
        objects,
        ".",
        OFlags::TMPFILE | OFlags::WRONLY | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )?));
    let writer = job
        .writer
        .as_mut()
        .ok_or_else(|| invalid("publication writer absent"))?;
    check_source(scope, writer)?;
    if let Some(input) = &mut job.manifest {
        input
            .plan
            .as_mut()
            .ok_or_else(|| invalid("publication reassembly sources already closed"))?
            .copy_verified(writer)?;
    } else {
        writer.write_all(&job.plaintext)?;
    }
    fs::fchmod(&*writer, Mode::from_raw_mode(0o400))?;
    writer.sync_all()?;
    check_source(scope, writer)?;
    let before = writer.metadata()?;
    let reader = File::from(fs::open(
        format!("/proc/self/fd/{}", writer.as_raw_fd()),
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    let after = reader.metadata()?;
    if (before.dev(), before.ino(), before.len()) != (after.dev(), after.ino(), after.len())
        || after.len() != job.claim.plaintext_size()
    {
        return Err(invalid(
            "publication source reopening changed inode or length",
        ));
    }
    job.reader = Some(reader);
    // Both fields retain the actual inode before closing its only writer.
    // The publisher additionally re-verifies every copied byte and kernel seal.
    drop(job.writer.take());
    let reader = job
        .reader
        .as_ref()
        .ok_or_else(|| invalid("publication reader absent"))?;
    check_source(scope, reader)?;
    if fs::fcntl_getfl(reader)?.intersects(OFlags::WRONLY | OFlags::RDWR | OFlags::PATH) {
        return Err(invalid("publication source is not independently read-only"));
    }
    scope.layout.recheck()
}

fn check_source(scope: &SourceContext, file: &File) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.nlink() != 0
        || metadata.uid() != scope.content_uid
        || metadata.gid() != scope.content_gid
        || metadata.dev() != scope.layout.directory_binding("layout-root")?.0
        || NativeProject::inspect(file)?.project_id != scope.project
    {
        return Err(invalid(
            "anonymous publication source has invalid native custody",
        ));
    }
    Ok(())
}

/// Measures synchronized actual allocation without an embedded-state read callback.
///
/// # Errors
/// Refuses changed root/body/project/verity custody or failed synchronization.
pub(super) fn observe(owner: &Custody, job: &PublicationJob) -> io::Result<u64> {
    if let Some(input) = &job.manifest {
        input.check_retired(owner)?;
    } else {
        refuse_standalone(owner, job.claim.descriptor().digest())?;
    }
    if job.writer.is_some() || job.reader.is_some() {
        return Err(invalid("publication still retains a source description"));
    }
    let body = job
        .body
        .as_ref()
        .ok_or_else(|| invalid("publication body absent"))?;
    body.layout().recheck()?;
    let root = File::from(fs::openat(
        &owner.preparation.layout().root,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    fs::syncfs(&root)?;
    let metadata = body.handle().metadata()?;
    if metadata.uid() != owner.preparation.config.publisher.identities.publish_uid
        || metadata.len() != job.claim.plaintext_size()
        || metadata.nlink() == 0
        || metadata.mode() & 0o7777 != 0o400
        || NativeProject::inspect(body.handle())?.project_id != owner.preparation.config.project_id
        || crate::verity::measure(body.handle())? != *body.binding()
    {
        return Err(invalid(
            "publication completion changed native body custody",
        ));
    }
    crate::host_quota::synchronized_allocated_bytes(body.handle())
}
