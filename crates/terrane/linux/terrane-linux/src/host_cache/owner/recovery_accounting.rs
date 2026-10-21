//! Observes synchronized allocation separately from charged quota and holds.
//!
//! A genuine readable layout-root descriptor supplies one filesystem syncfs
//! barrier. This intentionally flushes the entire underlying filesystem and can
//! wait for unrelated writers. Only after success are retained O_PATH directory
//! observations used for st_blocks. The sum covers the named retained inodes,
//! not all filesystem metadata or every private publisher inode; authenticated
//! charged-and-reserved quota usage remains a distinct full-owner observation.

use super::{
    recovery_inline::AdoptedInline, recovery_namespace::SharedNamespaceObservation,
    recovery_state_parent::StateParentObservation, retention::Custody,
};
use rustix::fs::{Mode, OFlags, openat, syncfs};
use std::{collections::BTreeMap, fs::File, io, os::unix::fs::MetadataExt};

/// Contains a deduplicated observation of the explicitly retained native inodes.
pub(super) struct SynchronizedAllocation {
    /// Synchronized inode blocks multiplied by the kernel's 512-byte unit.
    pub(super) retained_inode_bytes: u64,
    /// Number of distinct device/inode pairs included in that scoped sum.
    pub(super) retained_inodes: usize,
    /// Actual opaque quarantine subset, already included in retained_inode_bytes.
    pub(super) quarantined_inode_bytes: u64,
    /// Number of distinct quarantined inodes included in the synchronized census.
    pub(super) quarantined_inodes: usize,
}

/// Synchronizes the genuine filesystem and measures each retained inode once.
///
/// The serialized physical owner retains its namespace/exclusive state guards
/// across this fixed effect. It separately verifies its actual publisher drain
/// context before and after, then obtains fresh authenticated quota charges.
///
/// # Errors
/// Refuses changed layout/state, a mismatched readable root, failed syncfs,
/// absent durable state, changed measured inodes and arithmetic overflow. The
/// caller retains faulted custody and cannot acknowledge completion on error.
pub(super) fn observe(
    owner: &Custody,
    shared: &SharedNamespaceObservation,
    state_parent: &StateParentObservation,
    adopted_inline: &[AdoptedInline],
    adopted_manifests: &[std::sync::Arc<
        crate::publisher_local::client::PeerPublishedObject<
            terrane_sdk::host::cache::HostDomainLocation,
        >,
    >],
) -> io::Result<SynchronizedAllocation> {
    owner.check_current()?;
    let layout = owner.preparation.layout();
    let readable = File::from(openat(
        &layout.root,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    let metadata = readable.metadata()?;
    if (metadata.dev(), metadata.ino()) != layout.directory_binding("layout-root")? {
        return Err(invalid(
            "readable recovery root differs from retained native root",
        ));
    }
    syncfs(&readable)?;
    owner.check_current()?;

    let mut measured = BTreeMap::new();
    measure(&readable, &mut measured)?;
    for directory in layout.directories.values() {
        measure(&File::from(directory.try_clone()?), &mut measured)?;
    }
    if let Some((_, directory)) = &layout.administrative_root {
        measure(&File::from(directory.try_clone()?), &mut measured)?;
    }
    measure(&owner.directory, &mut measured)?;
    for file in shared.retained_inodes() {
        measure(file, &mut measured)?;
    }
    for file in state_parent.retained_inodes() {
        measure(file, &mut measured)?;
    }
    measure(owner.preparation.probe_handle(), &mut measured)?;
    for body in adopted_inline.iter().chain(adopted_manifests) {
        measure(body.handle(), &mut measured)?;
    }
    let (snapshot, _) = owner
        .snapshot
        .as_ref()
        .ok_or_else(|| invalid("synchronized recovery snapshot is absent"))?;
    measure(snapshot, &mut measured)?;
    let retained_inode_bytes = measured.values().try_fold(0_u64, |total, bytes| {
        total
            .checked_add(*bytes)
            .ok_or_else(|| invalid("synchronized allocation sum overflow"))
    })?;
    let (quarantined_inode_bytes, quarantined_inodes) = shared.quarantine_allocation(&measured)?;
    owner.check_current()?;
    Ok(SynchronizedAllocation {
        retained_inode_bytes,
        retained_inodes: measured.len(),
        quarantined_inode_bytes,
        quarantined_inodes,
    })
}

fn measure(file: &File, measured: &mut BTreeMap<(u64, u64), u64>) -> io::Result<()> {
    let before = file.metadata()?;
    let bytes = before
        .blocks()
        .checked_mul(512)
        .ok_or_else(|| invalid("native inode allocation overflow"))?;
    let after = file.metadata()?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.blocks() != after.blocks()
        || before.len() != after.len()
        || before.mode() != after.mode()
        || before.uid() != after.uid()
        || before.gid() != after.gid()
    {
        return Err(invalid(
            "native inode allocation changed during observation",
        ));
    }
    if measured
        .insert((before.dev(), before.ino()), bytes)
        .is_some_and(|previous| previous != bytes)
    {
        return Err(invalid(
            "duplicate native inode has inconsistent allocation observations",
        ));
    }
    Ok(())
}

fn invalid(error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}
