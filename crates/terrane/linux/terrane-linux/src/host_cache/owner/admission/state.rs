//! Persists future admission holds before any content allocation effects.

use super::{super::retention::Custody, backing::AdmissionJob};
use crate::host_cache::owner::RETAINED_LEASE_DEADLINE;
use std::{collections::BTreeSet, fs::File, io, io::Read};
use terrane_sdk::host::cache::{LeaseRecord, PinRecord, ReservationRecord};

/// Prepares the complete future hold and pin closure for mandatory synchronization.
///
/// # Errors
/// Refuses unavailable, changed or invalid native inputs and failed completion.
pub(super) fn begin(
    executor: &super::super::retention::NativeOwnerExecutor,
    owner: &mut Custody,
    job: &mut AdmissionJob,
    payload: usize,
    hashes: &[String],
) -> io::Result<super::super::snapshot::PreparedSnapshotWrite> {
    begin_group(executor, owner, &mut [(job, payload, hashes)])
}

/// Funds every member in one state transition before any group member has effects.
///
/// A group keeps an independent reservation and pin owner for each admission.
/// Combined quota and state bounds are checked before changing any job, so a
/// rejected group cannot leave a partially funded prefix. This grants no read
/// authority: original native verification and completion remain separate.
///
/// # Errors
/// Refuses empty or repeated jobs, started admissions, overflowing combined
/// holds, insufficient quota, exhausted state bounds or failed snapshot setup.
pub(super) fn begin_group(
    executor: &super::super::retention::NativeOwnerExecutor,
    owner: &mut Custody,
    members: &mut [(&mut AdmissionJob, usize, &[String])],
) -> io::Result<super::super::snapshot::PreparedSnapshotWrite> {
    if members.is_empty() || members.len() > owner.preparation.config.state.records {
        return Err(io::Error::other(
            "admission funding group exceeds its state bound",
        ));
    }
    owner.preparation.recheck()?;

    let mut orders = BTreeSet::new();
    let mut incoming = 0u64;
    for (job, payload, _) in members.iter() {
        if !std::sync::Arc::ptr_eq(&job.custody, executor.custody())
            || !job.is_effect_free()
            || !orders.insert(job.order)
        {
            return Err(io::Error::other(
                "admission funding group has foreign, repeated or started custody",
            ));
        }
        incoming = incoming
            .checked_add(incoming_hold(owner, *payload)?)
            .ok_or_else(|| io::Error::other("admission group hold overflow"))?;
    }
    check_incoming(owner, incoming)?;

    // Each member funds simultaneous payload and old/new snapshot overlap.
    // Native hard quotas still bound actual growth; a funded promise never
    // substitutes for measuring physical allocations at completion.
    let mut next = owner.state.clone();
    let mut registrations = Vec::new();
    registrations
        .try_reserve_exact(members.len())
        .map_err(io::Error::other)?;
    let mut random_source = File::open("/dev/urandom")?;
    for (_, payload, hashes) in members.iter() {
        let hold = incoming_hold(owner, *payload)?;
        let mut random = [0; 16];
        random_source.read_exact(&mut random)?;
        let token = hex(&random);
        if next.reservations.iter().any(|row| row.id == token) {
            return Err(io::Error::other("admission token collision"));
        }
        let pin_owner = format!("admission:{token}");
        let hashes = hashes
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        next.reservations.push(ReservationRecord {
            id: token.clone(),
            owner: owner.preparation.config.quota_owner.clone(),
            bytes: hold,
        });
        next.leases.push(LeaseRecord {
            owner: pin_owner.clone(),
            expires: RETAINED_LEASE_DEADLINE,
        });
        for hash in &hashes {
            next.pins.push(PinRecord {
                owner: pin_owner.clone(),
                hash: hash.clone(),
                expires: RETAINED_LEASE_DEADLINE,
            });
        }
        registrations.push((token, hold, hashes));
    }
    next.encoded_len(owner.preparation.config.state)
        .map_err(io::Error::other)?;

    owner.begin_mutation()?;
    for ((job, _, _), (token, hold, hashes)) in members.iter_mut().zip(registrations) {
        job.token = token;
        job.hold = hold;
        job.hashes = hashes;
        job.started
            .store(true, std::sync::atomic::Ordering::Release);
    }
    owner.faulted = true;
    owner.state = next;
    super::super::snapshot::prepare(executor, owner)
}

/// Computes the unchanged payload and snapshot-overlap future hold.
///
/// # Errors
/// Refuses an unrepresentable payload or overflowing future hold.
pub(super) fn incoming_hold(owner: &Custody, payload: usize) -> io::Result<u64> {
    u64::try_from(payload)
        .map_err(io::Error::other)?
        .checked_add(owner.preparation.config.metadata_sync_hold_bytes)
        .ok_or_else(|| io::Error::other("admission hold overflow"))
}

/// Checks an incoming hold against all existing holds and fresh kernel usage.
///
/// # Errors
/// Refuses overflowing holds and actual charged usage exceeding capacity.
pub(super) fn check_incoming(owner: &Custody, incoming: u64) -> io::Result<()> {
    let future = owner
        .state
        .reservations
        .iter()
        .try_fold(incoming, |sum, row| {
            sum.checked_add(row.bytes)
                .ok_or_else(|| io::Error::other("admission hold sum overflow"))
        })?;
    check_charge(owner, future)
}

/// Checks fresh full-owner charge separately from every logical future hold.
///
/// # Errors
/// Refuses unavailable, changed or invalid native inputs and failed completion.
pub(super) fn check_charge(owner: &Custody, future: u64) -> io::Result<()> {
    if owner
        .preparation
        .quota()
        .observation()
        .charged_reserved_bytes
        .checked_add(future)
        .is_none_or(|sum| sum > owner.preparation.config.policy.capacity)
    {
        return Err(io::Error::new(
            io::ErrorKind::StorageFull,
            "actual charge and future admission holds exceed capacity",
        ));
    }
    Ok(())
}

/// Encodes the canonical lowercase digest or random operation token.
pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Checks the complete actual operation registration without granting read authority.
///
/// # Errors
/// Refuses missing or altered durable reservation, lease or dependency pins.
pub(super) fn check_registration(owner: &Custody, job: &AdmissionJob) -> io::Result<()> {
    if let Some(cached) = &job.cached {
        return cached.check(owner, job);
    }
    let pin_owner = format!("admission:{}", job.token);
    if !job.started.load(std::sync::atomic::Ordering::Acquire)
        || job.hold == 0
        || !owner.state.reservations.iter().any(|row| {
            row.id == job.token
                && row.owner == owner.preparation.config.quota_owner
                && row.bytes == job.hold
        })
        || !owner
            .state
            .leases
            .iter()
            .any(|row| row.owner == pin_owner && row.expires == RETAINED_LEASE_DEADLINE)
        || job.hashes.iter().any(|hash| {
            !owner.state.pins.iter().any(|row| {
                row.owner == pin_owner
                    && &row.hash == hash
                    && row.expires == RETAINED_LEASE_DEADLINE
            })
        })
    {
        return Err(io::Error::other(
            "actual durable admission registration changed",
        ));
    }
    Ok(())
}
