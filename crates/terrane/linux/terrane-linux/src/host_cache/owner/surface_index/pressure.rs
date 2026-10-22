//! Plans bounded S3-FIFO index retirement without crediting unlinked mappings.
//!
//! Scheduling is reconstructible. Original jobs, durable exposure rows, retained
//! receipts and fresh project accounting remain the authority for every effect.

use super::{Job, allocation_bound, eviction, invalid};
use crate::{
    host_cache::owner::{
        consumer::state,
        publication::eviction::{Allocation, ReadActivity, ReadOrigin},
        retention::{Custody, NativeOwnerExecutor},
    },
    host_cache::{NativeCacheOwnerConfig, SurfaceIndexPolicy},
    structural_index::IndexKey,
};
use std::{
    collections::BTreeMap,
    io,
    os::unix::fs::MetadataExt,
    sync::{Arc, Mutex},
    time::Duration,
};
use terrane_sdk::{
    host::cache::{CacheEntry, CachePolicy},
    store::{Clock, TokioClock},
};

struct Entry {
    allocation: String,
    pinned: bool,
    protected_until: Duration,
}

struct Schedule {
    policy: CachePolicy,
    entries: BTreeMap<IndexKey, Entry>,
    owner: String,
    release_grace: Duration,
}

/// Shares read promotion independently of physical custody and native IO.
#[derive(Clone)]
pub(in crate::host_cache::owner) struct Queue(Arc<Mutex<Schedule>>);

/// Records use of one original admitted allocation, without granting a lease.
pub(super) struct Activity {
    queue: Queue,
    allocation: String,
    global: Arc<ReadActivity>,
}

impl Activity {
    /// Records a successful original-index check in actual call order.
    ///
    /// # Errors
    /// Refuses a poisoned scheduling lock without changing native custody.
    pub(super) fn record(&self) -> io::Result<()> {
        self.queue
            .0
            .lock()
            .map_err(|_| invalid("surface FIFO poisoned"))?
            .policy
            .touch(&self.allocation);
        self.global.record()
    }
}

impl Queue {
    /// Uses the host policy with bounds clamped to the separate index cap.
    ///
    /// # Errors
    /// Rejects invalid finite policy bounds before creating scheduling state.
    pub(in crate::host_cache::owner) fn new(
        config: &NativeCacheOwnerConfig,
        surface: SurfaceIndexPolicy,
    ) -> io::Result<Self> {
        let mut policy = config.policy;
        policy.capacity = surface.capacity_bytes;
        policy.low_watermark = policy.low_watermark.min(policy.capacity);
        policy.probation_bytes = policy.probation_bytes.min(policy.capacity);
        Ok(Self(Arc::new(Mutex::new(Schedule {
            policy: CachePolicy::new(policy).map_err(io::Error::other)?,
            entries: BTreeMap::new(),
            owner: config.quota_owner.clone(),
            release_grace: config.policy.release_grace,
        }))))
    }

    /// Registers actual sealed allocation only after native admission checks.
    ///
    /// # Errors
    /// Refuses a poisoned lock, duplicate root, zero allocation or policy budget.
    pub(super) fn admit(
        &self,
        key: IndexKey,
        device: u64,
        inode: u64,
        allocated: u64,
        global: Arc<ReadActivity>,
    ) -> io::Result<Activity> {
        let mut schedule = self
            .0
            .lock()
            .map_err(|_| invalid("surface FIFO poisoned"))?;
        if allocated == 0 || schedule.entries.contains_key(&key) {
            return Err(invalid("surface FIFO repeats a root or has no allocation"));
        }
        let allocation = format!("{device}:{inode}");
        let owner = schedule.owner.clone();
        schedule
            .policy
            .reserve(allocation.clone(), owner.clone(), allocated)
            .map_err(io::Error::other)?;
        schedule
            .policy
            .admit(
                &allocation,
                CacheEntry::new(allocation.clone(), allocated, owner),
            )
            .map_err(io::Error::other)?;
        // The initial completion receipt is about to retain the original Arc.
        // This conservative planner pin grants no durable consumer authority.
        schedule.policy.pin(&allocation).map_err(io::Error::other)?;
        schedule.entries.insert(
            key,
            Entry {
                allocation: allocation.clone(),
                pinned: true,
                protected_until: Duration::ZERO,
            },
        );
        Ok(Activity {
            queue: self.clone(),
            allocation,
            global,
        })
    }

    /// Removes bookkeeping only after checked native retirement completes.
    ///
    /// # Errors
    /// Refuses a poisoned scheduling lock; physical charge is never inferred.
    pub(super) fn removed(&self, key: IndexKey) -> io::Result<()> {
        let mut schedule = self
            .0
            .lock()
            .map_err(|_| invalid("surface FIFO poisoned"))?;
        if let Some(entry) = schedule.entries.remove(&key) {
            // External mappings can still be charged. This changes only the
            // planner; admission always samples the complete actual project.
            schedule.policy.forget_allocation(&entry.allocation);
        }
        Ok(())
    }

    fn candidate(&self, owner: &Custody) -> io::Result<Option<IndexKey>> {
        let mut schedule = self
            .0
            .lock()
            .map_err(|_| invalid("surface FIFO poisoned"))?;
        let now = TokioClock.monotonic();
        refresh(&mut schedule, owner, now)?;
        // One victim keeps the entire attempt within the configured S3-FIFO
        // scan bound. If it cannot meet the target, admission refuses and a
        // later request can retry after real kernel retirement progresses.
        let candidates = schedule.policy.eviction_candidates_to_reclaim(1, now);
        let Some(allocation) = candidates.first() else {
            return Ok(None);
        };
        Ok(schedule
            .entries
            .iter()
            .find_map(|(key, entry)| (&entry.allocation == allocation).then_some(*key)))
    }

    fn refused(&self, key: IndexKey) -> io::Result<()> {
        let mut schedule = self
            .0
            .lock()
            .map_err(|_| invalid("surface FIFO poisoned"))?;
        if let Some(entry) = schedule.entries.get(&key) {
            let allocation = entry.allocation.clone();
            // Restore a refused candidate conservatively. Promotion can delay
            // eviction, but never establishes closure or available capacity.
            schedule.policy.touch(&allocation);
        }
        Ok(())
    }
}

/// Captures verified original allocations for the shared host FIFO.
///
/// # Errors
/// Refuses unavailable custody, changed backing, scheduling bounds or grace.
pub(in crate::host_cache::owner) fn inventory(
    executor: &NativeOwnerExecutor,
) -> io::Result<Vec<(IndexKey, Allocation)>> {
    let owner = executor
        .custody()
        .lock()
        .map_err(|_| invalid("surface custody poisoned"))?;
    state::check_ready(executor, &owner)?;
    let Some(queue) = &owner.surface_queue else {
        return Ok(Vec::new());
    };
    let mut schedule = queue
        .0
        .lock()
        .map_err(|_| invalid("surface FIFO poisoned"))?;
    let now = TokioClock.monotonic();
    refresh(&mut schedule, &owner, now)?;
    let mut allocations = Vec::new();
    allocations
        .try_reserve_exact(owner.surface_indexes.len())
        .map_err(io::Error::other)?;
    for (key, job) in &owner.surface_indexes {
        let entry = schedule
            .entries
            .get(key)
            .ok_or_else(|| invalid("surface FIFO registration absent"))?;
        let protected = entry.pinned || now < entry.protected_until;
        // Inspection verifies original custody without recording consumer use.
        drop(super::reuse(&owner, job, &job.compiled)?);
        let backing = job
            .backing
            .as_ref()
            .ok_or_else(|| invalid("surface FIFO backing absent"))?;
        let allocation = format!("{}:{}", backing.metadata.dev(), backing.metadata.ino());
        if allocation != entry.allocation || backing.activity.is_none() {
            return Err(invalid("surface FIFO changed original registration"));
        }
        allocations.push((
            *key,
            Allocation {
                order: job.order,
                key: allocation,
                allocated: backing.allocated,
                protected,
                origin: ReadOrigin::Admission(job.order),
            },
        ));
    }
    Ok(allocations)
}

fn refresh(schedule: &mut Schedule, owner: &Custody, now: Duration) -> io::Result<()> {
    let keys: Vec<_> = schedule.entries.keys().copied().collect();
    for key in keys {
        let Some(job) = owner.surface_indexes.get(&key) else {
            let entry = schedule
                .entries
                .remove(&key)
                .ok_or_else(|| invalid("surface FIFO entry disappeared"))?;
            schedule.policy.forget_allocation(&entry.allocation);
            continue;
        };
        let protected = protects(owner, key, job)?;
        let entry = schedule
            .entries
            .get(&key)
            .ok_or_else(|| invalid("surface FIFO entry absent"))?;
        let allocation = entry.allocation.clone();
        if protected && !entry.pinned {
            schedule.policy.pin(&allocation).map_err(io::Error::other)?;
        } else if !protected && entry.pinned {
            // Receipt release is observed conservatively on this scan.
            // The host's real grace must elapse before automatic eviction.
            schedule
                .policy
                .release(&allocation, now)
                .map_err(io::Error::other)?;
        }
        let grace = schedule.release_grace;
        let entry = schedule
            .entries
            .get_mut(&key)
            .ok_or_else(|| invalid("surface FIFO entry disappeared"))?;
        if !protected && entry.pinned {
            entry.protected_until = now
                .checked_add(grace)
                .ok_or_else(|| invalid("surface release grace overflows"))?;
        }
        entry.pinned = protected;
    }
    Ok(())
}

fn protects(owner: &Custody, key: IndexKey, job: &Job) -> io::Result<bool> {
    let backing = job
        .backing
        .as_ref()
        .ok_or_else(|| invalid("surface FIFO found unresolved job"))?;
    let root = state::hex(&key.root());
    Ok(Arc::strong_count(backing) != 1
        || owner
            .state
            .exposures
            .iter()
            .any(|row| row.root == root && row.index_version == key.version()))
}

/// Attempts one actual retirement before funding a new index under cap pressure.
///
/// # Errors
/// Refuses stale custody, unavailable policy or quota, protected candidates,
/// failed funded retirement or a target not met by fresh project accounting.
pub(super) async fn prepare(executor: &NativeOwnerExecutor, incoming: usize) -> io::Result<()> {
    let incoming = u64::try_from(incoming).map_err(io::Error::other)?;
    let (queue, target, victim) = {
        let mut owner = executor
            .custody()
            .lock()
            .map_err(|_| invalid("surface custody poisoned"))?;
        state::check_ready(executor, &owner)?;
        owner.preparation.recheck()?;
        let surface = owner
            .preparation
            .config
            .surface_index
            .ok_or_else(|| invalid("surface policy absent"))?;
        if allocation_bound(&owner)?
            .checked_add(incoming)
            .is_some_and(|total| total <= surface.capacity_bytes)
            && owner.surface_indexes.len() < owner.preparation.config.state.records
        {
            return Ok(());
        }
        if incoming > surface.capacity_bytes {
            return Err(capacity());
        }
        let queue = owner
            .surface_queue
            .as_ref()
            .ok_or_else(|| invalid("surface FIFO absent"))?
            .clone();
        let target = surface
            .capacity_bytes
            .min(owner.preparation.config.policy.low_watermark)
            .min(surface.capacity_bytes - incoming);
        let victim = queue.candidate(&owner)?.ok_or_else(capacity)?;
        (queue, target, victim)
    };
    if let Err(error) = eviction::retire(executor, victim, false).await {
        queue.refused(victim)?;
        return Err(error);
    }
    let mut owner = executor
        .custody()
        .lock()
        .map_err(|_| invalid("surface custody poisoned"))?;
    state::check_ready(executor, &owner)?;
    owner.preparation.recheck()?;
    if allocation_bound(&owner)? > target
        || owner.surface_indexes.len() >= owner.preparation.config.state.records
    {
        return Err(capacity());
    }
    Ok(())
}

fn capacity() -> io::Error {
    io::Error::new(
        io::ErrorKind::StorageFull,
        "surface admission cannot fit after bounded original-index eviction",
    )
}
