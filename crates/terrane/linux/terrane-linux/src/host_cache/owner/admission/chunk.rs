//! Verifies untrusted chunk envelopes before writing one canonical residence.

use super::{
    super::retention::{Custody, NativeOwnerExecutor},
    Input,
    backing::{self, AdmissionJob},
    io as native, reconcile, state,
};
use crate::host_cache::owner::RETAINED_LEASE_DEADLINE;
use std::{
    io,
    sync::{Arc, Mutex},
};
use terrane_format::{
    codec::Codec,
    identity::{IdentityKind, TERRANE_V1},
};
use terrane_sdk::store::ChunkPosition;

/// Verifies and synchronizes one chunk under registered physical custody.
///
/// # Errors
/// Refuses unavailable, changed or invalid native inputs and failed completion.
pub(super) async fn run(
    executor: &mut NativeOwnerExecutor,
    custody: &Arc<Mutex<Custody>>,
    resource: &Arc<Mutex<AdmissionJob>>,
) -> io::Result<(u64, u64)> {
    let (encoded, hash, hashes) = {
        let mut job = backing::lock(resource)?;
        let (descriptor, position, encoded) = match &job.input {
            Input::Chunk {
                descriptor,
                position,
                encoded,
            } => (descriptor.clone(), *position, Arc::clone(encoded)),
            _ => return Err(io::Error::other("chunk admission received metadata input")),
        };
        let owner = custody
            .lock()
            .map_err(|_| io::Error::other("admission custody poisoned"))?;
        owner.check_current()?;
        let config = &owner.preparation.config;
        super::AdmissionBounds::new(config)?.check(encoded.len(), 0)?;
        super::AdmissionBounds::new(config)?.check(encoded.capacity(), 0)?;
        let profile = config.location.chunk_profile();
        let length = usize::try_from(descriptor.size()).map_err(io::Error::other)?;
        if length > profile.maximum()
            || encoded.len()
                > terrane_sdk::host::cache::maximum_encoded_chunk_bytes(profile)
                    .map_err(io::Error::other)?
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunk admission exceeds the registered profile envelope",
            ));
        }
        if length > config.reads.max_allocation_bytes {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "chunk plaintext exceeds configured read window",
            ));
        }
        let identity = TERRANE_V1
            .from_digest(IdentityKind::Chunk, descriptor.digest())
            .map_err(io::Error::other)?;
        let envelope = terrane_format::codec::parse_envelope(&encoded).map_err(io::Error::other)?;
        let mut hashes = vec![state::hex(identity.digest())];
        let dictionary = if let Codec::ZstdDictionary(digest) = envelope.codec {
            hashes.push(state::hex(&digest));
            let (plaintext, actual) = dictionary(executor, Some(resource), &owner, &digest)?;
            job.dependencies.push(actual);
            Some(plaintext)
        } else {
            None
        };
        let plaintext = terrane_sdk::codec::decode_verified(
            &encoded,
            length,
            profile,
            position == ChunkPosition::Final,
            &identity,
            dictionary.as_deref(),
        )
        .map_err(io::Error::other)?;
        descriptor
            .verify_bytes(&TERRANE_V1, IdentityKind::Chunk, plaintext.plaintext())
            .map_err(io::Error::other)?;
        let hash = state::hex(identity.digest());
        if owner.state.residences.iter().any(|row| row.chunk == hash) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "chunk already resides in a sealed backing",
            ));
        }
        super::refuse_completed(executor, &owner, resource, &job.input)?;
        drop(plaintext);
        drop(dictionary);
        (encoded, hash, hashes)
    };
    super::pressure::prepare(executor, encoded.len()).await?;
    let reservation = {
        let mut job = backing::lock(resource)?;
        let mut owner = custody
            .lock()
            .map_err(|_| io::Error::other("admission custody poisoned"))?;
        owner.check_current()?;
        state::begin(executor, &mut owner, &mut job, encoded.len(), &hashes)?
    };
    super::super::snapshot::persist(executor, reservation).await?;
    let completion = {
        let mut job = backing::lock(resource)?;
        let mut owner = custody
            .lock()
            .map_err(|_| io::Error::other("admission custody poisoned"))?;
        owner.check_current()?;
        state::check_registration(&owner, &job)?;
        let parent = native::parent(&owner, "chunks", &[&hash[..2]], &mut job.directory_progress)?;
        // Different encodings are still the same content residence. Never create
        // another canonical variant beside a current body or guess which to replace.
        for codec in 0..=2 {
            native::refuse_existing(&parent, &format!("{hash}.{codec}"))?;
        }
        let name = format!("{hash}.{}", encoded[0]);
        let pending = native::pending(parent, name)?;
        job.files.push(pending);
        native::write(&owner, &mut job.files[0], &encoded)?;
        native::publish(&owner, &mut job.files[0], &encoded)?;
        // The namespace itself durably records the standalone residence. No sealed
        // ResidenceRecord sentinel is invented for this ordinary encoded body.
        super::super::snapshot::prepare(executor, &mut owner)?
    };
    super::super::snapshot::persist(executor, completion).await?;
    let mut job = backing::lock(resource)?;
    let mut owner = custody
        .lock()
        .map_err(|_| io::Error::other("admission custody poisoned"))?;
    reconcile::finish(&mut owner, &mut job)
}

/// Borrows only a genuinely admitted, durably pinned one-hop dictionary.
///
/// # Errors
/// Refuses absent, changed, unpinned or nested dictionary sources.
pub(in crate::host_cache::owner) fn dictionary(
    executor: &NativeOwnerExecutor,
    current: Option<&Arc<Mutex<AdmissionJob>>>,
    owner: &Custody,
    digest: &[u8],
) -> io::Result<(Vec<u8>, Arc<Mutex<AdmissionJob>>)> {
    for candidate in executor.admission_jobs() {
        if current.is_some_and(|current| Arc::ptr_eq(candidate, current)) {
            continue;
        }
        let job = backing::lock(candidate)?;
        let Input::Chunk {
            descriptor,
            encoded,
            ..
        } = &job.input
        else {
            continue;
        };
        if !job.complete || descriptor.digest() != digest {
            continue;
        }
        state::check_registration(owner, &job)?;
        // A cache-owned dictionary has genuine retained native custody rather
        // than a producer hold. The actual registered dependency protects this
        // source through pressure eviction before state::begin funds its pin.
        let pin_owner = format!("admission:{}", job.token);
        if job.cached.is_none()
            && (!owner.state.pins.iter().any(|pin| {
                pin.owner == pin_owner
                    && pin.hash == state::hex(digest)
                    && pin.expires == RETAINED_LEASE_DEADLINE
            }) || !owner
                .state
                .leases
                .iter()
                .any(|lease| lease.owner == pin_owner && lease.expires == RETAINED_LEASE_DEADLINE))
        {
            return Err(io::Error::other("admitted dictionary lost its durable pin"));
        }
        let member = job
            .files
            .first()
            .ok_or_else(|| io::Error::other("admitted dictionary member absent"))?;
        native::check_current(owner, member, encoded)?;
        // The exact registered bytes were just compared with the positioned
        // canonical FD. Decode that immutable Arc payload rather than making
        // another encoded copy; recheck the same FD again before returning.

        if matches!(
            terrane_format::codec::parse_envelope(encoded)
                .map_err(io::Error::other)?
                .codec,
            Codec::ZstdDictionary(_)
        ) {
            return Err(io::Error::other(
                "dictionary admission cannot depend on another dictionary",
            ));
        }
        let identity = TERRANE_V1
            .from_digest(IdentityKind::Chunk, digest)
            .map_err(io::Error::other)?;
        let length = usize::try_from(descriptor.size()).map_err(io::Error::other)?;
        if length > owner.preparation.config.reads.max_allocation_bytes {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "dictionary exceeds configured plaintext window",
            ));
        }
        let verified = terrane_sdk::codec::decode_verified(
            encoded,
            length,
            owner.preparation.config.location.chunk_profile(),
            true,
            &identity,
            None,
        )
        .map_err(io::Error::other)?;
        descriptor
            .verify_bytes(&TERRANE_V1, IdentityKind::Chunk, verified.plaintext())
            .map_err(io::Error::other)?;
        native::check_current(owner, member, encoded)?;
        return Ok((verified.plaintext().to_vec(), Arc::clone(candidate)));
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "dictionary is not genuinely admitted by this owner",
    ))
}
