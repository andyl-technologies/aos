//! Retires unused derived indexes through the original funded physical queue.
//!
//! Admission receipts retain the original inode and block retirement. This is
//! cache maintenance, not an exposure lease or a revocation mechanism. Unlink
//! never establishes closure of external descriptors or kernel mappings.

use super::{NativeMetadataOwner, invalid, reuse};
use crate::{
    host_cache::owner::{
        consumer::state,
        retention::{Command, Custody, NativeOwnerExecutor},
        snapshot,
    },
    structural_index::IndexKey,
};
use rustix::fs::{AtFlags, Mode, OFlags, openat, statat, unlinkat};
use std::{
    fs::File,
    io,
    os::unix::fs::MetadataExt,
    sync::{Arc, mpsc},
};
use tokio::sync::oneshot;

impl NativeMetadataOwner {
    /// Retires one cached surface index when no admission receipt retains it.
    ///
    /// Returns `false` when this owner has no such entry. Success synchronizes
    /// removal of the original name before removing its durable copy hold. It
    /// does not report freed bytes: external mappings can remain charged.
    /// Cancellation after enqueue leaves the physical owner responsible for
    /// completing or retaining the attempted effects.
    ///
    /// # Errors
    /// Refuses disabled admission, a full or stopped queue, absent Running
    /// custody, a retained receipt, changed native backing, IO or accounting.
    /// Attempted effects fault writes until completion or genuine recovery.
    pub async fn evict_surface_index(&self, key: IndexKey) -> io::Result<bool> {
        if self.surface_policy.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "surface index admission disabled",
            ));
        }
        let (response, receive) = oneshot::channel();
        self.commands
            .as_ref()
            .ok_or_else(|| invalid("native owner stopped"))?
            .try_send(Command::EvictSurfaceIndex { key, response })
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => {
                    io::Error::new(io::ErrorKind::WouldBlock, "native owner queue full")
                }
                mpsc::TrySendError::Disconnected(_) => {
                    io::Error::new(io::ErrorKind::BrokenPipe, "native owner stopped")
                }
            })?;
        receive
            .await
            .map_err(|_| invalid("native owner stopped before surface retirement"))?
    }
}

/// Completes checked namespace retirement before releasing the future copy hold.
pub(in crate::host_cache::owner) async fn retire(
    executor: &NativeOwnerExecutor,
    key: IndexKey,
) -> io::Result<bool> {
    let running = executor.admission_context()?;
    let custody = executor.custody();
    let (generation, write) = {
        let mut owner = custody
            .lock()
            .map_err(|_| invalid("surface custody poisoned"))?;
        state::check_ready(executor, &owner)?;
        let Some(job) = owner.surface_indexes.get(&key) else {
            return Ok(false);
        };
        let backing = job
            .backing
            .as_ref()
            .ok_or_else(|| invalid("surface retirement found unresolved admission"))?;
        // The registry owns one Arc. Any receipt or its clone is a real retained
        // reference; denial performs no durable or namespace mutation.
        if Arc::strong_count(backing) != 1 {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "surface admission receipt still retains the inode",
            ));
        }
        if let Err(error) = reuse(&owner, job, &job.compiled) {
            owner.faulted = true;
            return Err(error);
        }
        let next = owner.state.clone();
        let write = state::begin(executor, &mut owner, &running, next, 0, None)?;
        (owner.generation, write)
    };
    snapshot::persist(executor, write).await?;
    running.check_current().map_err(io::Error::other)?;

    let write = {
        let mut owner = custody
            .lock()
            .map_err(|_| invalid("surface custody poisoned"))?;
        owner.check_current()?;
        state::check_bootstrap(&owner, &running)?;
        if !owner.faulted || owner.generation != generation {
            return Err(invalid("surface retirement lost funded physical turn"));
        }

        unlink_owned(&mut owner, key)?;
        snapshot::prepare(executor, &mut owner)?
    };
    snapshot::persist(executor, write).await?;
    running.check_current().map_err(io::Error::other)?;
    let mut owner = custody
        .lock()
        .map_err(|_| invalid("surface custody poisoned"))?;
    state::finish(&mut owner, generation)?;
    owner.surface_indexes.remove(&key);
    Ok(true)
}

/// Preserves copy funding until checked unlink, descriptor closure and fresh quota.
fn unlink_owned(owner: &mut Custody, key: IndexKey) -> io::Result<()> {
    let layout = Arc::clone(owner.preparation.layout());
    let parent = layout
        .directories
        .get("objects")
        .ok_or_else(|| invalid("surface objects root absent"))?;
    let directory = File::from(openat(
        parent,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    let job = owner
        .surface_indexes
        .get(&key)
        .ok_or_else(|| invalid("surface retirement lost original job"))?;
    drop(reuse(owner, job, &job.compiled)?);
    let backing = job
        .backing
        .as_ref()
        .ok_or_else(|| invalid("surface retirement backing absent"))?;
    if Arc::strong_count(backing) != 1 {
        return Err(invalid("surface retirement gained an unexpected reference"));
    }
    let original = backing.file.metadata()?;
    unlinkat(parent, &job.canonical, AtFlags::empty())?;
    directory.sync_all()?;
    let after = backing.file.metadata()?;
    if after.nlink() != 0
        || original.nlink() != 1
        || after.dev() != original.dev()
        || after.ino() != original.ino()
        || after.len() != original.len()
        || after.mode() != original.mode()
        || after.uid() != original.uid()
        || after.gid() != original.gid()
    {
        return Err(invalid("surface retirement changed original inode custody"));
    }
    match statat(parent, &job.canonical, AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => {}
        Err(error) => return Err(error.into()),
        Ok(_) => return Err(invalid("surface retirement name survived or was replaced")),
    }
    let reservation = job.reservation.clone();
    let hold = job.hold;
    let job = owner
        .surface_indexes
        .get_mut(&key)
        .ok_or_else(|| invalid("surface retirement job disappeared"))?;
    // All original local descriptors close only after checked unlink and
    // parent synchronization. Any external reference stays in kernel quota.
    job.backing = None;
    job.reader = None;
    owner.preparation.recheck()?;
    crate::host_cache::owner::recovery::check_charge(owner, 0)?;
    let quota_owner = &owner.preparation.config.quota_owner;
    if owner
        .state
        .reservations
        .iter()
        .filter(|row| row.id == reservation)
        .count()
        != 1
        || !owner
            .state
            .reservations
            .iter()
            .any(|row| row.id == reservation && row.owner == *quota_owner && row.bytes == hold)
    {
        return Err(invalid("surface retirement lost original copy hold"));
    }
    owner.state.reservations.retain(|row| row.id != reservation);
    Ok(())
}
