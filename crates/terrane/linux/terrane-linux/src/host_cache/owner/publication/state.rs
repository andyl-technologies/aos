//! Synchronizes publication funding and exact verified residence policy.
//!
//! Holds describe future allocation, not measured blocks. The original job
//! retains every physical resource while a failed or uncertain command remains
//! faulted. No error removes a pin, lease or reservation.

use super::{PublicationJob, invalid};
use crate::host_cache::owner::{
    RETAINED_LEASE_DEADLINE,
    retention::{Custody, NativeOwnerExecutor},
    snapshot::PreparedSnapshotWrite,
};
use std::{
    fs::File,
    io::{self, Read},
    os::unix::fs::MetadataExt,
    sync::Arc,
};
use terrane_format::codec::Codec;
use terrane_sdk::host::cache::{LeaseRecord, PinRecord, ReservationRecord, ResidenceRecord};

/// Prepares exact durable funding before an anonymous source or publisher copy.
///
/// # Errors
/// Refuses stale custody, changed dictionaries, arithmetic/capacity failures,
/// identifier collisions or unavailable snapshot resources.
pub(super) fn begin(
    executor: &NativeOwnerExecutor,
    owner: &mut Custody,
    job: &mut PublicationJob,
) -> io::Result<PreparedSnapshotWrite> {
    owner.check_current()?;
    if owner.faulted || owner.recovery_required || job.started {
        return Err(invalid(
            "publication requires a fresh running owner command",
        ));
    }
    check_dictionary(executor, owner, job)?;
    if let Some(transfer) = &job.transfer {
        transfer.check_current(owner)?;
        super::io::refuse_other_standalone(
            owner,
            job.claim.descriptor().digest(),
            transfer.key().codec,
        )?;
    }
    owner.preparation.recheck()?;
    // Source plaintext and publisher-private copy overlap. Filesystem rounding,
    // verity and directory metadata remain kernel charges, never guessed blocks.
    let hold = job
        .claim
        .plaintext_size()
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(owner.preparation.config.metadata_sync_hold_bytes))
        .ok_or_else(|| invalid("publication payload overlap overflows accounting"))?;
    check_total(
        owner,
        check_charge(owner)?
            .checked_add(hold)
            .ok_or_else(|| invalid("publication future holds overflow"))?,
    )?;
    let mut random = [0; 16];
    File::open("/dev/urandom")?.read_exact(&mut random)?;
    let token = hex(&random);
    if owner.state.reservations.iter().any(|row| row.id == token) {
        return Err(invalid("publication reservation identifier collision"));
    }
    let pin_owner = format!("publication:{token}");
    let mut next = owner.state.clone();
    next.reservations.push(ReservationRecord {
        id: token.clone(),
        owner: owner.preparation.config.quota_owner.clone(),
        bytes: hold,
    });
    next.leases.push(LeaseRecord {
        owner: pin_owner.clone(),
        expires: RETAINED_LEASE_DEADLINE,
    });
    for hash in backing_hashes(owner, job)? {
        next.pins.push(PinRecord {
            owner: pin_owner.clone(),
            hash,
            expires: RETAINED_LEASE_DEADLINE,
        });
    }
    next.encoded_len(owner.preparation.config.state)
        .map_err(io::Error::other)?;
    owner.begin_mutation()?;
    job.token = token;
    job.hold = hold;
    job.generation = owner.generation;
    job.started = true;
    owner.faulted = true;
    owner.state = next;
    crate::host_cache::owner::snapshot::prepare(executor, owner)
}

/// Adds only independently verified ranges before final synchronization.
///
/// # Errors
/// Refuses absent or mismatched physical results, conflicting residences,
/// changed source custody or exhausted durable-state capacity.
pub(super) fn complete(
    executor: &NativeOwnerExecutor,
    owner: &mut Custody,
    job: &mut PublicationJob,
) -> io::Result<PreparedSnapshotWrite> {
    check_funding(
        owner,
        &job.token,
        &hex(job.claim.descriptor().digest()),
        job.hold,
        job.generation,
    )?;
    check_dictionary(executor, owner, job)?;
    check_producer_pins(owner, job)?;
    super::completion::check(job)?;
    let body = job
        .body
        .as_ref()
        .ok_or_else(|| invalid("publication result absent"))?;
    if body.claim().descriptor() != job.claim.descriptor()
        || body.claim().domain() != job.claim.domain()
        || !Arc::ptr_eq(body.layout(), owner.preparation.layout())
    {
        return Err(invalid("publication result differs from the funded claim"));
    }
    if let Some(transfer) = &job.transfer {
        if !job.transfer_retired || job.transfer_observation.is_none() {
            return Err(invalid(
                "inline residence transfer lacks actual retirement acknowledgment",
            ));
        }
        transfer.check_retired(owner)?;
    }
    let hash = hex(job.claim.descriptor().digest());
    if job.manifest.is_none() {
        super::io::refuse_standalone(owner, job.claim.descriptor().digest())?;
    }
    let mut next = owner.state.clone();
    if let Some(input) = &job.manifest {
        input.check_retired(owner)?;
        let plan = crate::host_cache::NativeResidencePlan::new(
            owner.preparation.layout(),
            &job.claim,
            owner.preparation.config.state.records,
        )?;
        for identity in plan.identities()? {
            let span = plan
                .span(&identity)?
                .ok_or_else(|| invalid("manifest residence span absent"))?;
            let chunk = hex(identity.digest());
            let length = u64::try_from(span.length).map_err(io::Error::other)?;
            if let Some(row) = next.residences.iter().find(|row| row.chunk == chunk) {
                if row.length != length
                    || (!input.retains_residence(row)
                        && (row.object != hash || row.offset != span.offset))
                {
                    return Err(invalid(
                        "manifest publication conflicts with a prior residence",
                    ));
                }
            } else {
                next.residences.push(ResidenceRecord {
                    chunk,
                    object: hash.clone(),
                    offset: span.offset,
                    length,
                });
            }
        }
    } else if let Some(row) = next.residences.iter().find(|row| row.chunk == hash) {
        if row.object != hash || row.offset != 0 || row.length != job.claim.plaintext_size() {
            return Err(invalid(
                "inline publication conflicts with a prior residence",
            ));
        }
    } else {
        next.residences.push(ResidenceRecord {
            chunk: hash.clone(),
            object: hash,
            offset: 0,
            length: job.claim.plaintext_size(),
        });
    }
    // The actual copy and its owned source descriptions have completed. Retain
    // only future metadata capacity; physical inode charges remain in fresh Q,
    // including any independently retained descriptors to transferred sources.
    let metadata_hold = owner.preparation.config.metadata_sync_hold_bytes;
    let retained = next
        .reservations
        .iter_mut()
        .find(|row| {
            row.id == job.token
                && row.owner == owner.preparation.config.quota_owner
                && row.bytes == job.hold
        })
        .ok_or_else(|| invalid("publication original hold absent at settlement"))?;
    if job.hold < metadata_hold {
        return Err(invalid(
            "publication metadata allowance exceeds original hold",
        ));
    }
    retained.bytes = metadata_hold;
    next.encoded_len(owner.preparation.config.state)
        .map_err(io::Error::other)?;
    owner.begin_mutation()?;
    job.hold = metadata_hold;
    job.generation = owner.generation;
    owner.state = next;
    crate::host_cache::owner::snapshot::prepare(executor, owner)
}

/// Requires the actual owner's completed snapshot containing the exact live hold.
///
/// # Errors
/// Refuses fault/generation changes, absent write provenance, altered native
/// snapshot custody, or any changed reservation, pin or lease.
pub(super) fn check_funding(
    owner: &Custody,
    token: &str,
    hash: &str,
    hold: u64,
    generation: u64,
) -> io::Result<()> {
    owner.check_current()?;
    let written = owner
        .synchronized_state
        .as_ref()
        .ok_or_else(|| invalid("publication has no completed snapshot write"))?;
    let (snapshot, _) = owner
        .snapshot
        .as_ref()
        .ok_or_else(|| invalid("publication snapshot absent"))?;
    let metadata = snapshot.metadata()?;
    if !owner.faulted
        || owner.recovery_required
        || owner.generation != generation
        || written.generation != generation
        || (written.device, written.inode) != (metadata.dev(), metadata.ino())
    {
        return Err(invalid("publication snapshot provenance changed"));
    }
    crate::host_cache::owner::recovery_manifest_state::require_same(&owner.state, &written.state)?;
    let pin_owner = format!("publication:{token}");
    if hold == 0
        || !owner.state.reservations.iter().any(|row| {
            row.id == token
                && row.owner == owner.preparation.config.quota_owner
                && row.bytes == hold
        })
        || !owner
            .state
            .leases
            .iter()
            .any(|row| row.owner == pin_owner && row.expires == RETAINED_LEASE_DEADLINE)
        || !owner.state.pins.iter().any(|row| {
            row.owner == pin_owner && row.hash == hash && row.expires == RETAINED_LEASE_DEADLINE
        })
    {
        return Err(invalid("publication durable funding changed"));
    }
    Ok(())
}

/// Checks total logical holds separately from actual full-owner kernel usage.
///
/// # Errors
/// Refuses arithmetic overflow or actual charge plus holds beyond capacity.
pub(super) fn check_charge(owner: &Custody) -> io::Result<u64> {
    let future = owner.state.reservations.iter().try_fold(0u64, |sum, row| {
        sum.checked_add(row.bytes)
            .ok_or_else(|| invalid("publication future holds overflow"))
    })?;
    check_total(owner, future)?;
    Ok(future)
}

/// Checks fresh project charge against distinct total future holds.
///
/// # Errors
/// Refuses overflow or actual charge plus future holds beyond policy capacity.
pub(super) fn check_total(owner: &Custody, future: u64) -> io::Result<()> {
    if owner
        .preparation
        .quota()
        .observation()
        .charged_reserved_bytes
        .checked_add(future)
        .is_none_or(|bytes| bytes > owner.preparation.config.policy.capacity)
    {
        return Err(io::Error::new(
            io::ErrorKind::StorageFull,
            "publication actual charge and future holds exceed capacity",
        ));
    }
    Ok(())
}

fn check_dictionary(
    executor: &NativeOwnerExecutor,
    owner: &Custody,
    job: &PublicationJob,
) -> io::Result<()> {
    if let Some(input) = &job.manifest {
        return input.check(owner);
    }
    let codec = terrane_format::codec::parse_envelope(&job.encoded)
        .map_err(io::Error::other)?
        .codec;
    match (codec, &job.dictionary) {
        (Codec::ZstdDictionary(digest), Some(original)) => {
            if original.identity().digest() != digest {
                return Err(invalid(
                    "publication dictionary differs from its original envelope",
                ));
            }
            original.check_registered(executor, owner)?;
            drop(original.read_verified()?);
            Ok(())
        }
        (Codec::ZstdDictionary(_), None) | (_, Some(_)) => Err(invalid(
            "publication dictionary closure differs from its encoding",
        )),
        (_, None) => Ok(()),
    }
}

/// Collects the exact producer and grace protection for the retained input.
///
/// # Errors
/// Refuses changed manifest backing or exhausted allocation capacity.
pub(super) fn backing_hashes(owner: &Custody, job: &PublicationJob) -> io::Result<Vec<String>> {
    let mut hashes = job
        .manifest
        .as_ref()
        .map(|input| input.backing_hashes(owner))
        .transpose()?
        .unwrap_or_default();
    if let Some(dictionary) = &job.dictionary {
        for digest in dictionary.digests() {
            hashes.try_reserve_exact(1).map_err(io::Error::other)?;
            hashes.push(hex(digest));
        }
    }
    hashes.try_reserve_exact(1).map_err(io::Error::other)?;
    hashes.push(hex(job.claim.descriptor().digest()));
    hashes.sort();
    hashes.dedup();
    Ok(hashes)
}

/// Checks the complete durable closure while original producer custody remains.
///
/// # Errors
/// Refuses absent, duplicate or altered dictionary/container and content pins.
pub(super) fn check_producer_pins(owner: &Custody, job: &PublicationJob) -> io::Result<()> {
    let hashes = backing_hashes(owner, job)?;
    let producer = format!("publication:{}", job.token);
    if owner
        .state
        .pins
        .iter()
        .filter(|pin| pin.owner == producer)
        .count()
        != hashes.len()
        || hashes.iter().any(|hash| {
            !owner.state.pins.iter().any(|pin| {
                pin.owner == producer && &pin.hash == hash && pin.expires == RETAINED_LEASE_DEADLINE
            })
        })
    {
        return Err(invalid("publication original backing pins changed"));
    }
    Ok(())
}

/// Encodes a canonical digest or random physical operation identifier.
pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
