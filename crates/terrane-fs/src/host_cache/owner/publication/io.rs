//! Retains an anonymous plaintext source and measures actual sealed completion.
//!
//! No scratch pathname is published or accepted from a caller. The source's
//! real project, ownership, inode and writer closure remain checked under the
//! physical owner; kernel quotas bound allocation beyond the logical hold.

use super::{InlineJob, invalid, state};
use crate::{host_cache::owner::retention::Custody, host_quota::NativeProject};
use rustix::fs::{self, AtFlags, Mode, OFlags};
use std::{
    fs::File,
    io::{self, Write},
    os::{fd::AsRawFd, unix::fs::MetadataExt},
};

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

/// Creates and synchronizes one project-inheriting anonymous plaintext inode.
///
/// # Errors
/// Refuses missing synchronized funding, unsupported anonymous files, changed
/// inode/project custody, write/sync failures or missing actual writer closure.
pub(super) fn prepare_source(owner: &Custody, job: &mut InlineJob) -> io::Result<()> {
    state::check_funding(
        owner,
        &job.token,
        &state::hex(job.claim.descriptor().digest()),
        job.hold,
        job.generation,
    )?;
    let objects = owner
        .preparation
        .layout()
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
    check_source(owner, writer)?;
    writer.write_all(&job.plaintext)?;
    fs::fchmod(&*writer, Mode::from_raw_mode(0o400))?;
    writer.sync_all()?;
    check_source(owner, writer)?;
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
    check_source(owner, reader)?;
    if fs::fcntl_getfl(reader)?.intersects(OFlags::WRONLY | OFlags::RDWR | OFlags::PATH) {
        return Err(invalid("publication source is not independently read-only"));
    }
    owner.check_current()
}

fn check_source(owner: &Custody, file: &File) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.nlink() != 0
        || metadata.uid() != owner.preparation.config.content_uid
        || metadata.gid() != owner.preparation.config.content_gid
        || metadata.dev()
            != owner
                .preparation
                .layout()
                .directory_binding("layout-root")?
                .0
        || NativeProject::inspect(file)?.project_id != owner.preparation.config.project_id
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
pub(super) fn observe(owner: &Custody, job: &InlineJob) -> io::Result<u64> {
    refuse_standalone(owner, job.claim.descriptor().digest())?;
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
