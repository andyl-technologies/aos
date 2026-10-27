//! Keeps original encoded resources through acknowledged two-phase retirement.
//!
//! Capturing due work precedes draining the bounded accepted command queue.
//! New readers restore original names before acquiring their promises. Final
//! removal releases policy only after the real publisher reply and every member
//! becoming unlinked; quota is observed after actual descriptor closure.

use super::{
    EncodedAllocation, backing, invalid,
    turn::{PublisherEncodedCacheTurn, Transition},
};
use crate::{
    host_cache::owner::{
        admission::AdmissionJob,
        publication::eviction::{self, Schedule},
        retention::NativeOwnerExecutor,
        snapshot,
    },
    publisher_local::{
        client::{EncodedCacheCompletion, EncodedCacheReceipt},
        socket::ReceivedPacket,
        wire::Operation,
    },
};
use std::{
    collections::BTreeMap,
    fs::File,
    io,
    sync::{Arc, Mutex},
};

/// Retains every accepted transition before its first native exchange.
#[derive(Default)]
pub(in crate::host_cache::owner) struct Runtime {
    pending: BTreeMap<String, Arc<Mutex<Pending>>>,
}

struct Pending {
    unit: Arc<EncodedAllocation>,
    reply: Option<ReceivedPacket>,
    receipt: Option<Arc<EncodedCacheReceipt>>,
    completion: Option<Arc<EncodedCacheCompletion>>,
    schedule: Option<Schedule>,
}

/// Bounds pending, due-cut and original acknowledgment collection headers.
pub(super) fn storage_bytes() -> usize {
    std::mem::size_of::<Pending>()
        + std::mem::size_of::<Runtime>()
        + std::mem::size_of::<DueRetirements>()
        + 8 * std::mem::size_of::<usize>()
}

/// Retains exact original pending entries due before the accepted queue drains.
pub(in crate::host_cache::owner) struct DueRetirements(Vec<(String, Arc<Mutex<Pending>>)>);

impl DueRetirements {
    /// Reports whether any original encoded retirement was actually due.
    pub(in crate::host_cache::owner) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Recognizes original pending jobs so a census does not reopen missing names.
///
/// # Errors
/// Refuses poisoned retained pending custody rather than guessing absence.
pub(super) fn contains_resource(
    executor: &NativeOwnerExecutor,
    resource: &Arc<Mutex<AdmissionJob>>,
) -> io::Result<bool> {
    for pending in executor.cache.encoded.pending.values() {
        let pending = pending
            .lock()
            .map_err(|_| invalid("encoded pending custody poisoned"))?;
        if pending
            .unit
            .members
            .iter()
            .any(|member| Arc::ptr_eq(member, resource))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Recognizes actual retained pending entries without constructing native custody.
pub(in crate::host_cache::owner) fn contains_key(
    executor: &NativeOwnerExecutor,
    key: &str,
) -> bool {
    executor.cache.encoded.pending.contains_key(key)
}

/// Borrows actual retained retirements for reconstructible queue reconciliation.
pub(in crate::host_cache::owner) fn pending_keys(
    executor: &NativeOwnerExecutor,
) -> impl Iterator<Item = &str> {
    executor.cache.encoded.pending.keys().map(String::as_str)
}

/// Starts retirement only for the original unprotected allocation under exclusion.
///
/// # Errors
/// Refuses protection, changed originals, stale funding and uncertain exchanges.
/// Actual reply resources stay registered through every accepted failure.
pub(in crate::host_cache::owner) fn retire(
    executor: &mut NativeOwnerExecutor,
    unit: EncodedAllocation,
) -> io::Result<()> {
    unit.check_canonical(executor)?;
    unit.check_unprotected(executor)?;
    let running = executor.admission_context()?;
    let interval = executor
        .custody()
        .lock()
        .map_err(|_| invalid("encoded retirement configuration poisoned"))?
        .preparation
        .config
        .retirement_interval;
    let key = unit.key().to_owned();
    if contains_key(executor, &key) {
        return Err(invalid("encoded allocation already pending"));
    }
    let unit = Arc::new(unit);
    let resource = Arc::new(Mutex::new(Pending {
        unit: Arc::clone(&unit),
        reply: None,
        receipt: None,
        completion: None,
        schedule: None,
    }));
    executor
        .cache
        .encoded
        .pending
        .insert(key, Arc::clone(&resource));
    let mut pending = resource
        .lock()
        .map_err(|_| invalid("encoded pending custody poisoned"))?;
    let mut turn = PublisherEncodedCacheTurn::begin(executor, &unit, Transition::Retire)?;
    let observation = running
        .publisher_session()
        .inspect_cached_encoded(&running, &mut turn, &mut pending.reply)
        .map_err(io::Error::other)?;
    let receipt = running
        .publisher_session()
        .retire_cached_encoded(&running, &mut turn, &observation)
        .map_err(io::Error::other)?;
    pending.receipt = Some(Arc::new(receipt));
    pending.schedule = Some(Schedule::after(interval)?);
    drop(turn);
    drop(pending);
    unit.check_held(executor, false)?;
    eviction::reconcile(executor)?;
    Ok(())
}

/// Restores actual pending units before new use of any direct content identity.
///
/// # Errors
/// Refuses uncertain prior transitions, changed original custody and failed IO.
pub(in crate::host_cache::owner) fn restore_for(
    executor: &mut NativeOwnerExecutor,
    hash: &str,
) -> io::Result<()> {
    let keys = executor
        .cache
        .encoded
        .pending
        .iter()
        .map(|(key, pending)| {
            let pending = pending
                .lock()
                .map_err(|_| invalid("encoded pending custody poisoned"))?;
            Ok(pending.unit.hashes().contains(hash).then(|| key.clone()))
        })
        .collect::<io::Result<Vec<_>>>()?;
    for key in keys.into_iter().flatten() {
        restore(executor, &key)?;
    }
    Ok(())
}

fn retained(pending: &Pending) -> io::Result<(Arc<EncodedAllocation>, Arc<EncodedCacheReceipt>)> {
    if pending.completion.is_some() {
        return Err(invalid("uncertain encoded completion requires recovery"));
    }
    Ok((
        Arc::clone(&pending.unit),
        Arc::clone(
            pending
                .receipt
                .as_ref()
                .ok_or_else(|| invalid("encoded retirement lacks actual acknowledgment"))?,
        ),
    ))
}

/// Restores an actual pending pair before duplicate admission can create a copy.
///
/// # Errors
/// Refuses changed original pending custody and failed publisher exchanges.
pub(in crate::host_cache::owner) fn restore_pack(
    executor: &mut NativeOwnerExecutor,
    id: terrane_sdk::pack::PackId,
) -> io::Result<()> {
    let keys = executor
        .cache
        .encoded
        .pending
        .iter()
        .map(|(key, pending)| {
            let pending = pending
                .lock()
                .map_err(|_| invalid("encoded pending custody poisoned"))?;
            Ok((pending.unit.body_key().pack_id.as_slice() == id.as_bytes()).then(|| key.clone()))
        })
        .collect::<io::Result<Vec<_>>>()?;
    for key in keys.into_iter().flatten() {
        restore(executor, &key)?;
    }
    Ok(())
}

fn restore(executor: &mut NativeOwnerExecutor, key: &str) -> io::Result<()> {
    let resource = executor
        .cache
        .encoded
        .pending
        .get(key)
        .cloned()
        .ok_or_else(|| invalid("original encoded pending entry absent"))?;
    let (unit, receipt) = {
        let pending = resource
            .lock()
            .map_err(|_| invalid("encoded pending custody poisoned"))?;
        retained(&pending)?
    };
    let running = executor.admission_context()?;
    let mut turn =
        PublisherEncodedCacheTurn::begin(executor, &unit, Transition::Restore(&receipt))?;
    let completion = Arc::new(
        running
            .publisher_session()
            .transition_cached_encoded(&running, &mut turn, &receipt, Operation::Restore)
            .map_err(io::Error::other)?,
    );
    resource
        .lock()
        .map_err(|_| invalid("encoded pending custody poisoned"))?
        .completion = Some(Arc::clone(&completion));
    drop(turn);
    completion.check_restored(&receipt)?;
    {
        let owner = executor
            .custody()
            .lock()
            .map_err(|_| invalid("encoded restore custody poisoned"))?;
        for member in &unit.members {
            let mut job = backing::lock(member)?;
            let bytes = original_payloads(&job);
            for (index, file) in job.files.iter_mut().enumerate() {
                let payload = bytes
                    .get(index)
                    .ok_or_else(|| invalid("encoded restore member count changed"))?;
                file.restore_after_cache(
                    &owner,
                    unit.inodes[index],
                    payload,
                    &receipt,
                    &completion,
                )?;
            }
        }
    }
    unit.check_canonical(executor)?;
    eviction::reconcile(executor)?;
    eviction::encoded_restored(executor, key)?;
    executor.cache.encoded.pending.remove(key);
    Ok(())
}

/// Captures original entries whose actual local schedule is due now.
///
/// # Errors
/// Refuses incomplete acknowledgments, unavailable clocks or poisoned custody.
pub(in crate::host_cache::owner) fn due_retirements(
    executor: &NativeOwnerExecutor,
) -> io::Result<DueRetirements> {
    let mut due = Vec::new();
    for (key, resource) in &executor.cache.encoded.pending {
        let pending = resource
            .lock()
            .map_err(|_| invalid("encoded pending custody poisoned"))?;
        if pending
            .schedule
            .ok_or_else(|| invalid("encoded retirement has no schedule"))?
            .due()?
        {
            due.push((key.clone(), Arc::clone(resource)));
        }
    }
    Ok(DueRetirements(due))
}

/// Finishes original due entries after the bounded accepted-command batch drains.
///
/// # Errors
/// Refuses changed protection, custody, snapshot or native completion evidence.
pub(in crate::host_cache::owner) async fn finish_due(
    executor: &mut NativeOwnerExecutor,
    due: DueRetirements,
) -> io::Result<usize> {
    let mut finished = 0;
    for (key, original) in due.0 {
        if !executor
            .cache
            .encoded
            .pending
            .get(&key)
            .is_some_and(|current| Arc::ptr_eq(current, &original))
        {
            continue;
        }
        let (unit, receipt) = {
            let pending = original
                .lock()
                .map_err(|_| invalid("encoded pending custody poisoned"))?;
            retained(&pending)?
        };
        let protected = {
            let owner = executor
                .custody()
                .lock()
                .map_err(|_| invalid("encoded completion custody poisoned"))?;
            unit.has_protection(executor, &owner)?
        };
        if protected {
            restore(executor, &key)?;
            continue;
        }
        let running = executor.admission_context()?;
        let mut turn =
            PublisherEncodedCacheTurn::begin(executor, &unit, Transition::Finish(&receipt))?;
        let completion = Arc::new(
            running
                .publisher_session()
                .transition_cached_encoded(
                    &running,
                    &mut turn,
                    &receipt,
                    Operation::FinishRetirement,
                )
                .map_err(io::Error::other)?,
        );
        original
            .lock()
            .map_err(|_| invalid("encoded pending custody poisoned"))?
            .completion = Some(Arc::clone(&completion));
        drop(turn);
        completion.check_removed(&receipt)?;
        unit.check_held(executor, true)?;
        finish_policy(executor, &unit).await?;
        close_removed(executor, &unit, &original, &receipt, &completion)?;
        executor.unregister_retired_admissions(&unit.members, &receipt, &completion)?;
        let inodes = unit
            .inodes
            .iter()
            .map(|&(device, number, _)| (device, number))
            .collect::<Vec<_>>();
        drop(unit);
        executor.cache.encoded.pending.remove(&key);
        drop(original);
        eviction::encoded_finished(executor, &key, &inodes)?;
        // All actual member and inspection descriptions have closed before Q.
        eviction::reconcile(executor)?;
        finished += 1;
    }
    Ok(finished)
}

async fn finish_policy(executor: &NativeOwnerExecutor, unit: &EncodedAllocation) -> io::Result<()> {
    let write = {
        let mut owner = executor
            .custody()
            .lock()
            .map_err(|_| invalid("encoded removal policy poisoned"))?;
        let mut next = owner.state.clone();
        for resource in &unit.members {
            let job = backing::lock(resource)?;
            job.cached
                .as_ref()
                .ok_or_else(|| invalid("encoded cache funding absent"))?
                .remove_transferred(&owner, &job, &mut next)?;
        }
        next.encoded_len(owner.preparation.config.state)
            .map_err(io::Error::other)?;
        owner.begin_mutation()?;
        owner.state = next;
        snapshot::prepare(executor, &mut owner)?
    };
    snapshot::persist(executor, write).await
}

fn close_removed(
    executor: &NativeOwnerExecutor,
    unit: &EncodedAllocation,
    pending: &Arc<Mutex<Pending>>,
    receipt: &Arc<EncodedCacheReceipt>,
    completion: &Arc<EncodedCacheCompletion>,
) -> io::Result<()> {
    completion.check_removed(receipt)?;
    let pending = pending
        .lock()
        .map_err(|_| invalid("encoded pending custody poisoned"))?;
    let reply = pending
        .reply
        .as_ref()
        .ok_or_else(|| invalid("original encoded inspection reply absent"))?;
    let mut released = Vec::new();
    for resource in &unit.members {
        let mut job = backing::lock(resource)?;
        let owner = executor
            .custody()
            .lock()
            .map_err(|_| invalid("encoded closure custody poisoned"))?;
        job.cached
            .as_ref()
            .ok_or_else(|| invalid("removed encoded cache funding absent"))?
            .check_released(&owner, &job)?;
        let payloads = original_payloads(&job);
        for (index, member) in job.files.iter_mut().enumerate() {
            let expected = unit.inodes[index];
            // InspectBody returns only the primary body. Its correlated final
            // acknowledgment covers the complete retained pack/index unit.
            // The index comparison uses the owner's original census descriptor,
            // already checked as unlinked with unchanged bytes by check_held.
            let observed = if index + 1 == unit.inodes.len() {
                original_inspection(&reply.files, expected)?
            } else {
                unit.files
                    .get(index)
                    .ok_or_else(|| invalid("removed encoded unit lost original index custody"))?
            };
            let mut comparison = vec![observed.try_clone()?];
            member.close_finished_source(
                &owner,
                expected,
                payloads
                    .get(index)
                    .ok_or_else(|| invalid("removed encoded member input changed"))?,
                &mut comparison,
            )?;
        }
        released.push((
            std::mem::take(&mut job.files),
            std::mem::take(&mut job.directory_progress),
            std::mem::take(&mut job.dependencies),
            job.cached.take(),
        ));
        job.complete = false;
    }
    drop(pending);
    drop(released);
    Ok(())
}

// An actual metadata error must remain distinguishable from a missing member.
fn original_inspection(files: &[File], expected: (u64, u64, u64)) -> io::Result<&File> {
    for file in files {
        if super::inode(file)? == expected {
            return Ok(file);
        }
    }
    Err(invalid("removed encoded member lost original inspection"))
}

fn original_payloads(job: &AdmissionJob) -> Vec<Arc<Vec<u8>>> {
    match &job.input {
        super::Input::Chunk { encoded, .. } => vec![Arc::clone(encoded)],
        super::Input::Metadata { index, pack, .. } | super::Input::DataPack { index, pack, .. } => {
            vec![Arc::clone(index), Arc::clone(pack)]
        }
    }
}
