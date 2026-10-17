//! Persists future admission holds before any content allocation effects.

use super::{super::retention::Custody, backing::AdmissionJob};
use std::{collections::BTreeSet, fs::File, io, io::Read};
use terrane::host::cache::{LeaseRecord, PinRecord, ReservationRecord};

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
    owner.preparation.recheck()?;
    // This funds simultaneous payload and old/new state snapshot overlap. It
    // predicts neither allocation rounding nor directory/allocator metadata.
    // Native hard quotas bound growth; excess actual charge faults completion
    // without releasing the physical resources or this logical hold.
    let hold = u64::try_from(payload)
        .map_err(io::Error::other)?
        .checked_add(owner.preparation.config.metadata_sync_hold_bytes)
        .ok_or_else(|| io::Error::other("admission hold overflow"))?;
    let future = owner.state.reservations.iter().try_fold(hold, |sum, row| {
        sum.checked_add(row.bytes)
            .ok_or_else(|| io::Error::other("admission hold sum overflow"))
    })?;
    check_charge(owner, future)?;
    let mut random = [0; 16];
    File::open("/dev/urandom")?.read_exact(&mut random)?;
    let token = hex(&random);
    if owner.state.reservations.iter().any(|row| row.id == token) {
        return Err(io::Error::other("admission token collision"));
    }
    let pin_owner = format!("admission:{token}");
    let mut next = owner.state.clone();
    next.reservations.push(ReservationRecord {
        id: token.clone(),
        owner: owner.preparation.config.quota_owner.clone(),
        bytes: hold,
    });
    next.leases.push(LeaseRecord {
        owner: pin_owner.clone(),
        expires: u64::MAX,
    });
    for hash in hashes.iter().collect::<BTreeSet<_>>() {
        next.pins.push(PinRecord {
            owner: pin_owner.clone(),
            hash: hash.clone(),
            expires: u64::MAX,
        });
    }
    next.encoded_len(owner.preparation.config.state)
        .map_err(io::Error::other)?;
    job.token = token;
    job.hold = hold;
    job.hashes = hashes
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    owner.begin_mutation()?;
    job.started
        .store(true, std::sync::atomic::Ordering::Release);
    owner.faulted = true;
    owner.state = next;
    super::super::snapshot::prepare(executor, owner)
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
            .any(|row| row.owner == pin_owner && row.expires == u64::MAX)
        || job.hashes.iter().any(|hash| {
            !owner
                .state
                .pins
                .iter()
                .any(|row| row.owner == pin_owner && &row.hash == hash && row.expires == u64::MAX)
        })
    {
        return Err(io::Error::other(
            "actual durable admission registration changed",
        ));
    }
    Ok(())
}
