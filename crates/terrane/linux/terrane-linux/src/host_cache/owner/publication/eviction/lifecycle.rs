//! Executes actual cached-body retirement and restoration on the physical owner.
//!
//! Original jobs retain body and metadata custody through the final publisher
//! acknowledgement and synchronized policy removal. Kernel usage is queried
//! after real resource closure, independently of the FIFO's logical inventory.

use super::super::{invalid, state};
use super::{
    graph::{self, Unit},
    permit::{CachePermit, Transition},
    queue::Queue,
    reextract,
};
use crate::{
    host_cache::owner::{
        admission::eviction as encoded,
        consumer::{clock, state as policy},
        recovery,
        retention::{Command, NativeMetadataOwner, NativeOwnerExecutor},
        snapshot,
    },
    publisher_local::client::{CacheBodyCompletion, PendingCacheBody},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    sync::Arc,
    time::Duration,
};
use terrane_format::identity::{Identity, IdentityKind, TERRANE_V1};
use terrane_sdk::store::{Clock, TokioClock};
use tokio::sync::oneshot;

impl NativeMetadataOwner {
    /// Retires eligible original cached publications under actual quota pressure.
    ///
    /// `incoming` is a requested future hold, not an allocation or permission.
    /// Selected units keep their charge through pending retirement. Periodic
    /// completion uses the publisher's authoritative deadline; re-pinning
    /// restores actual canonical names first. Shared residences require their
    /// extraction transition and remain protected until it completes. This
    /// command supplies neither a content handle nor full-tier readiness.
    ///
    /// # Errors
    /// Refuses a full/stopped queue, stale custody, excessive incoming holds,
    /// failed native synchronization or an uncertain publisher exchange.
    pub async fn evict_cached(&self, incoming: u64) -> io::Result<NativeCacheEvictionReport> {
        let (response, receive) = oneshot::channel();
        self.commands
            .as_ref()
            .ok_or_else(|| invalid("cache eviction owner stopped"))?
            .try_send(Command::EvictCache { incoming, response })
            .map_err(|error| match error {
                std::sync::mpsc::TrySendError::Full(_) => {
                    io::Error::new(io::ErrorKind::WouldBlock, "cache eviction queue full")
                }
                std::sync::mpsc::TrySendError::Disconnected(_) => {
                    io::Error::new(io::ErrorKind::BrokenPipe, "cache eviction owner stopped")
                }
            })?;
        receive
            .await
            .map_err(|_| invalid("cache eviction worker terminated"))?
    }
}

/// Reports actual cache transitions separately from complete project usage.
#[derive(Clone, Copy, Debug)]
pub struct NativeCacheEvictionReport {
    /// Original native allocations renamed into pending retirement in this command.
    pub retired_allocations: usize,
    /// Fresh charged-and-reserved quota usage after actual synchronization.
    pub charged_reserved_bytes: u64,
    /// Distinct future policy holds, separate from measured quota usage.
    pub future_hold_bytes: u64,
    /// Reports whether actual usage and the requested hold fit the selected target.
    pub target_met: bool,
}

/// Schedules a bounded local check of the publisher's authoritative deadline.
#[derive(Clone, Copy)]
pub(in crate::host_cache::owner) struct Schedule {
    wall: u64,
    monotonic: Duration,
}

impl Schedule {
    /// Captures a finite local schedule without replacing the publisher deadline.
    ///
    /// # Errors
    /// Refuses unavailable clocks and overflowing wall or monotonic schedules.
    pub(in crate::host_cache::owner) fn after(interval: Duration) -> io::Result<Self> {
        Ok(Self {
            wall: clock::grace_end(None, interval)?,
            monotonic: TokioClock
                .monotonic()
                .checked_add(interval)
                .and_then(|end| end.checked_add(Duration::from_secs(1)))
                .ok_or_else(|| invalid("cache retirement schedule overflows"))?,
        })
    }

    /// Reports that a local scheduling cut is due for publisher verification.
    ///
    /// # Errors
    /// Refuses an unavailable actual wall clock.
    pub(in crate::host_cache::owner) fn due(self) -> io::Result<bool> {
        Ok(clock::now_seconds()? >= self.wall || TokioClock.monotonic() >= self.monotonic)
    }
}

/// Keeps real accepted transition receipts even when later cleanup fails.
pub(super) struct Pending {
    unit: Option<Arc<Unit>>,
    receipt: Arc<PendingCacheBody>,
    schedule: Option<Schedule>,
    completion: Option<Arc<CacheBodyCompletion>>,
}

/// Captures only original retirement receipts already due before queue draining.
pub(in crate::host_cache::owner) struct DueRetirements(
    Vec<(String, Arc<PendingCacheBody>)>,
    encoded::DueRetirements,
);

impl DueRetirements {
    /// Reports whether any original retirement was due at the captured clock cut.
    pub(in crate::host_cache::owner) fn is_empty(&self) -> bool {
        self.0.is_empty() && self.1.is_empty()
    }
}

/// Plans from actual quota pressure and submits only original native allocations.
///
/// # Errors
/// Refuses stale custody, excessive incoming holds, changed native allocation,
/// uncertain namespace exchanges and failed synchronization or quota evidence.
pub(in crate::host_cache::owner) async fn run(
    executor: &mut NativeOwnerExecutor,
    incoming: u64,
) -> io::Result<NativeCacheEvictionReport> {
    let units = graph::capture(executor)?;
    let encoded_units = encoded::capture(executor)?;
    let (config, owner) = {
        let custody = executor
            .custody()
            .lock()
            .map_err(|_| invalid("FIFO configuration poisoned"))?;
        (
            custody.preparation.config.policy,
            custody.preparation.config.quota_owner.clone(),
        )
    };
    if incoming > config.capacity {
        return Err(io::Error::new(
            io::ErrorKind::StorageFull,
            "incoming hold exceeds cache capacity",
        ));
    }
    if executor.cache.queue.is_none() {
        executor.cache.queue = Some(Queue::new(config, owner)?);
    }
    let pending = executor
        .cache
        .pending
        .keys()
        .map(String::as_str)
        .chain(encoded::pending_keys(executor))
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    {
        let mut activities = executor
            .cache
            .activities
            .lock()
            .map_err(|_| invalid("FIFO activity poisoned"))?;
        executor
            .cache
            .queue
            .as_mut()
            .ok_or_else(|| invalid("native FIFO absent"))?
            .refresh(&units, &encoded_units, &pending, &mut activities)?;
    }
    policy::synchronize_policy(executor)?;
    let before = observe(executor)?;
    let total = before
        .charged
        .checked_add(before.future)
        .ok_or_else(|| invalid("cache pressure overflows"))?;
    let pressured = total
        .checked_add(incoming)
        .is_none_or(|sum| sum > config.capacity);
    let target = if pressured {
        config.low_watermark.min(config.capacity - incoming)
    } else {
        config.capacity - incoming
    };
    let required = total.saturating_sub(target);
    let candidates = executor
        .cache
        .queue
        .as_mut()
        .ok_or_else(|| invalid("native FIFO absent"))?
        .candidates(required);
    let mut units: BTreeMap<_, _> = units
        .into_iter()
        .map(|unit| (unit.key.clone(), unit))
        .collect();
    let mut retired = 0;
    let mut encoded_units: BTreeMap<_, _> = encoded_units
        .into_iter()
        .map(|unit| (unit.key().to_owned(), unit))
        .collect();
    for key in candidates {
        if executor.cache.pending.contains_key(&key) || encoded::contains_key(executor, &key) {
            continue;
        }
        if units.remove(&key).is_some() {
            // An earlier extraction in this command can change residences and
            // durable protection. Never retire using the initial census.
            let fresh = graph::capture(executor)?;
            let unit = fresh
                .iter()
                .find(|unit| unit.key == key)
                .ok_or_else(|| invalid("FIFO candidate lost original sealed allocation"))?;
            if unit.protected || !unit.shared_chunks.is_empty() {
                if !unit.protected {
                    reextract::run(executor, unit).await?;
                }
                // Copy handoff adds ordinary release grace to the original
                // object. Refresh cancels this scheduling proposal; retirement
                // must wait for a later, independently eligible command.
                let fresh = graph::capture(executor)?;
                let encoded = encoded::capture(executor)?;
                let pending = executor
                    .cache
                    .pending
                    .keys()
                    .map(String::as_str)
                    .chain(encoded::pending_keys(executor))
                    .map(str::to_owned)
                    .collect();
                let mut activities = executor
                    .cache
                    .activities
                    .lock()
                    .map_err(|_| invalid("FIFO activity poisoned"))?;
                executor
                    .cache
                    .queue
                    .as_mut()
                    .ok_or_else(|| invalid("native FIFO absent"))?
                    .refresh(&fresh, &encoded, &pending, &mut activities)?;
                continue;
            }
            let unit = fresh
                .into_iter()
                .find(|unit| unit.key == key)
                .ok_or_else(|| invalid("FIFO candidate lost original sealed allocation"))?;
            retire(executor, Arc::new(unit)).await?;
        } else {
            let unit = encoded_units
                .remove(&key)
                .ok_or_else(|| invalid("FIFO candidate lost actual native unit"))?;
            encoded::retire(executor, unit)?;
        }
        retired += 1;
    }
    let after = observe(executor)?;
    Ok(NativeCacheEvictionReport {
        retired_allocations: retired,
        charged_reserved_bytes: after.charged,
        future_hold_bytes: after.future,
        target_met: after
            .charged
            .checked_add(after.future)
            .is_some_and(|total| total <= target),
    })
}

async fn retire(executor: &mut NativeOwnerExecutor, unit: Arc<Unit>) -> io::Result<()> {
    let running = executor.admission_context()?;
    let interval = executor
        .custody()
        .lock()
        .map_err(|_| invalid("cache retirement configuration poisoned"))?
        .preparation
        .config
        .retirement_interval;
    let permit = CachePermit::begin(executor, &unit, Transition::Retire)?;
    let receipt = running
        .publisher_session()
        .retire_cached_body(&running, &mut executor.cache_retirement_turn(&permit)?)
        .map_err(io::Error::other)?;
    drop(permit);
    let key = unit.key.clone();
    // Retain the actual acknowledgement before a fallible clock or quota check.
    executor.cache.pending.insert(
        key.clone(),
        Pending {
            unit: Some(unit),
            receipt: Arc::new(receipt),
            schedule: None,
            completion: None,
        },
    );
    let schedule = Schedule::after(interval)?;
    executor
        .cache
        .pending
        .get_mut(&key)
        .ok_or_else(|| invalid("actual pending cache unit absent"))?
        .schedule = Some(schedule);
    reconcile(executor)?;
    Ok(())
}

/// Restores actual pending backing before acquiring a new consumer or source.
///
/// # Errors
/// Refuses invalid identities, changed original custody and uncertain exchanges.
pub(in crate::host_cache::owner) async fn restore_for(
    executor: &mut NativeOwnerExecutor,
    identity: &Identity,
) -> io::Result<()> {
    if identity.kind() == IdentityKind::Pack || identity.profile() != TERRANE_V1.name() {
        return Err(invalid(
            "cache restoration requires a registered content identity",
        ));
    }
    let hash = state::hex(identity.digest());
    encoded::restore_for(executor, &hash)?;
    if identity.kind() != IdentityKind::Chunk {
        return Ok(());
    }
    let keys: Vec<_> = executor
        .cache
        .pending
        .iter()
        .filter_map(|(key, pending)| {
            pending
                .unit
                .as_ref()
                .filter(|unit| unit.chunks.contains(&hash))
                .map(|_| key.clone())
        })
        .collect();
    for key in keys {
        restore(executor, &key).await?;
    }
    Ok(())
}

async fn restore(executor: &mut NativeOwnerExecutor, key: &str) -> io::Result<()> {
    let (unit, receipt) = retained_pending(executor, key)?;
    let running = executor.admission_context()?;
    let permit = CachePermit::begin(executor, &unit, Transition::Restore(Arc::clone(&receipt)))?;
    let completion = Arc::new(
        running
            .publisher_session()
            .restore_cached_body(
                &running,
                &mut executor.cache_retirement_turn(&permit)?,
                &receipt,
            )
            .map_err(io::Error::other)?,
    );
    drop(permit);
    executor
        .cache
        .pending
        .get_mut(key)
        .ok_or_else(|| invalid("restored cache receipt absent"))?
        .completion = Some(Arc::clone(&completion));
    completion.check_restored(&receipt)?;
    reconcile(executor)?;
    executor
        .cache
        .queue
        .as_mut()
        .ok_or_else(|| invalid("restored native FIFO absent"))?
        .restored(key);
    executor.cache.pending.remove(key);
    Ok(())
}

/// Restores the exact original object before duplicate publication can create a copy.
///
/// # Errors
/// Refuses changed original cached custody or an uncertain restoration exchange.
pub(in crate::host_cache::owner) async fn restore_publication(
    executor: &mut NativeOwnerExecutor,
    descriptor: &terrane_format::identity::Descriptor,
) -> io::Result<()> {
    let keys: Vec<_> = executor
        .cache
        .pending
        .iter()
        .filter_map(|(key, pending)| {
            pending
                .unit
                .as_ref()
                .filter(|unit| unit.body.claim().descriptor() == descriptor)
                .map(|_| key.clone())
        })
        .collect();
    for key in keys {
        restore(executor, &key).await?;
    }
    Ok(())
}

/// Captures original receipts already due before the accepted queue is drained.
///
/// # Errors
/// Refuses uncertain custody, unavailable clocks, changed protection and failed IO.
pub(in crate::host_cache::owner) fn due_retirements(
    executor: &NativeOwnerExecutor,
) -> io::Result<DueRetirements> {
    let mut due = Vec::new();
    for (key, pending) in &executor.cache.pending {
        if pending
            .schedule
            .ok_or_else(|| invalid("cache retirement lacks its actual schedule"))?
            .due()?
        {
            due.push((key.clone(), Arc::clone(&pending.receipt)));
        }
    }
    Ok(DueRetirements(due, encoded::due_retirements(executor)?))
}

/// Finishes captured due receipts after the bounded preexisting queue batch drains.
///
/// # Errors
/// Refuses uncertain custody, changed protection and failed native transitions.
pub(in crate::host_cache::owner) async fn finish_due(
    executor: &mut NativeOwnerExecutor,
    due: DueRetirements,
) -> io::Result<usize> {
    let mut completed = 0;
    for (key, receipt) in due.0 {
        // A queued read may restore and retire this same allocation again. Its
        // new actual acknowledgement and deadline must not inherit the old cut.
        if !executor
            .cache
            .pending
            .get(&key)
            .is_some_and(|pending| Arc::ptr_eq(&pending.receipt, &receipt))
        {
            continue;
        }
        if finish(executor, &key).await? {
            completed += 1;
        }
    }
    Ok(completed + encoded::finish_due(executor, due.1).await?)
}

fn retained_pending(
    executor: &NativeOwnerExecutor,
    key: &str,
) -> io::Result<(Arc<Unit>, Arc<PendingCacheBody>)> {
    let pending = executor
        .cache
        .pending
        .get(key)
        .ok_or_else(|| invalid("pending native cache receipt absent"))?;
    if pending.completion.is_some() {
        return Err(invalid(
            "uncertain completed cache transition requires recovery",
        ));
    }
    Ok((
        Arc::clone(
            pending
                .unit
                .as_ref()
                .ok_or_else(|| invalid("pending cache body already released"))?,
        ),
        Arc::clone(&pending.receipt),
    ))
}

async fn finish(executor: &mut NativeOwnerExecutor, key: &str) -> io::Result<bool> {
    let (original, receipt) = retained_pending(executor, key)?;
    let unit = graph::capture(executor)?
        .into_iter()
        .find(|unit| unit.key == key)
        .ok_or_else(|| invalid("pending cache unit lost current custody"))?;
    if !Arc::ptr_eq(&original.body, &unit.body) {
        return Err(invalid("pending cache unit changed original body"));
    }
    if unit.protected || !unit.shared_chunks.is_empty() {
        drop(unit);
        drop(original);
        restore(executor, key).await?;
        return Ok(false);
    }
    drop(unit);
    let running = executor.admission_context()?;
    let permit = CachePermit::begin(
        executor,
        &original,
        Transition::Finish(Arc::clone(&receipt)),
    )?;
    let completion = Arc::new(
        running
            .publisher_session()
            .finish_cached_body(
                &running,
                &mut executor.cache_retirement_turn(&permit)?,
                &receipt,
            )
            .map_err(io::Error::other)?,
    );
    drop(permit);
    executor
        .cache
        .pending
        .get_mut(key)
        .ok_or_else(|| invalid("removed cache receipt absent"))?
        .completion = Some(Arc::clone(&completion));
    completion.check_removed_body(&receipt)?;
    finish_policy(executor, &original, &completion).await?;
    release_members(executor, &original, &receipt, &completion)?;
    executor.unregister_retired_publications(&original.members, &receipt, &completion)?;
    executor
        .cache
        .pending
        .get_mut(key)
        .ok_or_else(|| invalid("removed cache receipt absent"))?
        .unit = None;
    let metadata = original.body.handle().metadata()?;
    use std::os::unix::fs::MetadataExt;
    let inode = (metadata.dev(), metadata.ino());
    drop(original);
    executor
        .cache
        .activities
        .lock()
        .map_err(|_| invalid("removed activity poisoned"))?
        .remove(inode);
    executor
        .cache
        .queue
        .as_mut()
        .ok_or_else(|| invalid("removed FIFO absent"))?
        .removed(key)?;
    reconcile(executor)?;
    executor.cache.pending.remove(key);
    Ok(true)
}

fn release_members(
    executor: &NativeOwnerExecutor,
    unit: &Unit,
    receipt: &Arc<PendingCacheBody>,
    completion: &Arc<CacheBodyCompletion>,
) -> io::Result<()> {
    executor.check_physical_worker()?;
    completion.check_removed(receipt)?;
    let session = executor
        .custody()
        .lock()
        .map_err(|_| invalid("retired cache custody poisoned"))?
        .preparation
        .publisher_session();
    let mut resources = Vec::new();
    resources
        .try_reserve_exact(unit.members.len())
        .map_err(io::Error::other)?;
    for resource in &unit.members {
        let mut job = resource
            .lock()
            .map_err(|_| invalid("retired cache job poisoned"))?;
        receipt.check_alias(
            &session,
            job.body
                .as_ref()
                .ok_or_else(|| invalid("retired cache body absent"))?,
        )?;
        resources.push((
            job.body.take(),
            job.cached.take(),
            job.synchronized.take(),
            job.manifest.take(),
        ));
        job.complete = false;
    }
    // All actual native body and metadata descriptions close outside both
    // embedded state and job locks, before a fresh complete-project quota query.
    drop(resources);
    Ok(())
}

async fn finish_policy(
    executor: &NativeOwnerExecutor,
    unit: &Unit,
    completion: &CacheBodyCompletion,
) -> io::Result<()> {
    let custody = Arc::clone(executor.custody());
    let hash = state::hex(unit.body.claim().descriptor().digest());
    let write = {
        let mut owner = custody
            .lock()
            .map_err(|_| invalid("retired cache policy poisoned"))?;
        super::super::residence::check_snapshot(&owner)?;
        let mut next = owner.state.clone();
        next.residences.retain(|row| row.object != hash);
        for (id, metadata) in &unit.metadata {
            metadata.check_registration(&owner)?;
            let token = state::hex(id);
            let purpose = format!("metadata:{token}");
            next.pins.retain(|pin| pin.owner != purpose);
            next.leases.retain(|lease| lease.owner != purpose);
            next.reservations.retain(|hold| hold.id != token);
        }
        next.encoded_len(owner.preparation.config.state)
            .map_err(io::Error::other)?;
        owner.begin_mutation()?;
        owner.state = next;
        snapshot::prepare(executor, &mut owner)?
    };
    snapshot::persist(executor, write).await?;
    let released = {
        let mut owner = custody
            .lock()
            .map_err(|_| invalid("retired metadata custody poisoned"))?;
        owner.release_retired_metadata(
            &unit.metadata.values().cloned().collect::<Vec<_>>(),
            completion,
        )?
    };
    drop(released);
    Ok(())
}

/// Reconciles synchronized policy and actual project charge after a physical turn.
///
/// # Errors
/// Refuses failed synchronization, stale custody and invalid native quota evidence.
pub(in crate::host_cache::owner) fn reconcile(
    executor: &NativeOwnerExecutor,
) -> io::Result<policy::PolicyObservation> {
    policy::synchronize_policy(executor)?;
    let mut owner = executor
        .custody()
        .lock()
        .map_err(|_| invalid("cache reconciliation poisoned"))?;
    let generation = owner.generation;
    policy::finish(&mut owner, generation)
}

/// Marks restored FIFO membership only after the original canonical unit returns.
///
/// # Errors
/// Refuses an absent original native FIFO.
pub(in crate::host_cache::owner) fn encoded_restored(
    executor: &mut NativeOwnerExecutor,
    key: &str,
) -> io::Result<()> {
    executor
        .cache
        .queue
        .as_mut()
        .ok_or_else(|| invalid("restored encoded FIFO absent"))?
        .restored(key);
    Ok(())
}

/// Removes encoded activity and FIFO membership after actual acknowledged closure.
///
/// # Errors
/// Refuses poisoned activity storage, absent FIFO or changed retirement membership.
pub(in crate::host_cache::owner) fn encoded_finished(
    executor: &mut NativeOwnerExecutor,
    key: &str,
    inodes: &[(u64, u64)],
) -> io::Result<()> {
    let mut activities = executor
        .cache
        .activities
        .lock()
        .map_err(|_| invalid("removed encoded activity poisoned"))?;
    for inode in inodes {
        activities.remove(*inode);
    }
    drop(activities);
    executor
        .cache
        .queue
        .as_mut()
        .ok_or_else(|| invalid("removed encoded FIFO absent"))?
        .removed(key)
}

fn observe(executor: &NativeOwnerExecutor) -> io::Result<policy::PolicyObservation> {
    let mut owner = executor
        .custody()
        .lock()
        .map_err(|_| invalid("cache observation poisoned"))?;
    policy::check_ready(executor, &owner)?;
    owner.preparation.recheck()?;
    recovery::check_charge(&owner, 0)?;
    let future = owner
        .state
        .reservations
        .iter()
        .try_fold(0_u64, |sum, hold| {
            sum.checked_add(hold.bytes)
                .ok_or_else(|| invalid("cache future holds overflow"))
        })?;
    Ok(policy::PolicyObservation {
        charged: owner
            .preparation
            .quota()
            .observation()
            .charged_reserved_bytes,
        future,
    })
}
