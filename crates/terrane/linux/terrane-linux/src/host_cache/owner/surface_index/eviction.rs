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
use terrane_sdk::host::cache::{ExposureBackingKind, ExposurePhase};
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
        self.submit_surface_retirement(key, false).await
    }

    /// Unlinks an index retained only by durably draining exposures.
    ///
    /// Every original admission receipt must already be dropped. This closes
    /// local descriptors and removes the future copy hold, but preserves every
    /// exposure obligation until a separate authenticated closure observation.
    /// Cancellation after enqueue does not cancel physical execution.
    ///
    /// # Errors
    /// Refuses live exposures, retained receipts, changed original bindings,
    /// unavailable Running custody, queue exhaustion, accounting or native IO.
    pub async fn retire_draining_surface_index(&self, key: IndexKey) -> io::Result<bool> {
        self.submit_surface_retirement(key, true).await
    }

    async fn submit_surface_retirement(&self, key: IndexKey, draining: bool) -> io::Result<bool> {
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
            .try_send(Command::EvictSurfaceIndex {
                key,
                draining,
                response,
            })
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
    draining: bool,
) -> io::Result<bool> {
    let running = executor.admission_context()?;
    let custody = executor.custody();
    let (generation, write) = {
        let mut owner = custody
            .lock()
            .map_err(|_| invalid("surface custody poisoned"))?;
        state::check_ready(executor, &owner)?;
        if !draining && retains_index(&owner.state, key) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "durable exposure retains the surface index",
            ));
        }
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
        check_exposure_retirement(&owner, key, draining)?;
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

        check_exposure_retirement(&owner, key, draining)?;
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
    owner
        .surface_queue
        .as_ref()
        .ok_or_else(|| invalid("surface FIFO absent"))?
        .removed(key)?;
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

/// Treats a durable obligation as protection even after every receipt is dropped.
fn retains_index(state: &terrane_sdk::host::cache::CacheState, key: IndexKey) -> bool {
    let root = state::hex(&key.root());
    state
        .exposures
        .iter()
        .any(|row| row.root == root && row.index_version == key.version())
}

/// Binds every draining obligation to the original inode before unlink effects.
fn check_exposure_retirement(owner: &Custody, key: IndexKey, draining: bool) -> io::Result<()> {
    let root = state::hex(&key.root());
    let records: Vec<_> = owner
        .state
        .exposures
        .iter()
        .filter(|row| row.root == root && row.index_version == key.version())
        .collect();
    if records.is_empty() {
        return Ok(());
    }
    if !draining
        || records
            .iter()
            .any(|row| row.phase != ExposurePhase::Draining)
    {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "live exposure retains index custody",
        ));
    }
    let backing = owner
        .surface_indexes
        .get(&key)
        .and_then(|job| job.backing.as_ref())
        .ok_or_else(|| invalid("draining index lost original backing"))?;
    let binding = super::bindings::capture(
        owner,
        &backing.file,
        ExposureBackingKind::Index,
        &key.root(),
    )?;
    if records.iter().any(|row| {
        row.backings
            .iter()
            .find(|item| item.kind == ExposureBackingKind::Index)
            != Some(&binding)
    }) {
        return Err(invalid(
            "draining exposure differs from original index incarnation",
        ));
    }
    Ok(())
}
