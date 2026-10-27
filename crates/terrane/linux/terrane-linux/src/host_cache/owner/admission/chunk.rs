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
    identity::{Identity, IdentityKind, TERRANE_V1},
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

/// Resolves only actual registered dictionary jobs and their original dependency links.
///
/// # Errors
/// Refuses missing or changed custody, lost durable protection, cycles, invalid
/// dependency edges, mismatched canonical bytes or configured resource bounds.
pub(in crate::host_cache::owner) fn dictionary(
    executor: &NativeOwnerExecutor,
    current: Option<&Arc<Mutex<AdmissionJob>>>,
    owner: &Custody,
    digest: &[u8],
) -> io::Result<(Vec<u8>, Arc<Mutex<AdmissionJob>>)> {
    let mut first = None;
    for candidate in executor.admission_jobs() {
        if current.is_some_and(|current| Arc::ptr_eq(candidate, current)) {
            continue;
        }
        let job = backing::lock(candidate)?;
        if let Input::Chunk { descriptor, .. } = &job.input
            && job.complete
            && descriptor.digest() == digest
        {
            first = Some(Arc::clone(candidate));
            break;
        }
    }
    let first = first.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "dictionary is not genuinely admitted by this owner",
        )
    })?;
    let mut expected: [u8; 32] = digest.try_into().map_err(io::Error::other)?;
    let mut next = Some(Arc::clone(&first));
    let mut chain: Vec<Arc<Mutex<AdmissionJob>>> = Vec::new();
    while let Some(resource) = next {
        if chain.len() >= owner.preparation.config.state.records
            || current.is_some_and(|current| Arc::ptr_eq(&resource, current))
            || chain.iter().any(|seen| Arc::ptr_eq(seen, &resource))
            || !executor
                .admission_jobs()
                .iter()
                .any(|registered| Arc::ptr_eq(registered, &resource))
        {
            return Err(io::Error::other(
                "dictionary cycle, registry mismatch or member bound exceeded",
            ));
        }
        let job = backing::lock(&resource)?;
        let (identity, _, codec) = checked_dictionary(owner, &job)?;
        if identity.digest() != expected {
            return Err(io::Error::other(
                "registered dictionary differs from envelope dependency",
            ));
        }
        match (codec, job.dependencies.as_slice()) {
            (Codec::ZstdDictionary(digest), [dependency]) => {
                expected = digest;
                next = Some(Arc::clone(dependency));
            }
            (Codec::ZstdDictionary(_), _) => {
                return Err(io::Error::other("dictionary lacks its original dependency"));
            }
            (_, []) => next = None,
            _ => {
                return Err(io::Error::other(
                    "terminal dictionary retains unexpected dependencies",
                ));
            }
        }
        drop(job);
        chain.try_reserve_exact(1).map_err(io::Error::other)?;
        chain.push(resource);
    }

    // All links retain actual completed jobs. Reverse verification keeps only
    // the nearest plaintext and never recursively locks a dependency job.
    let mut plaintext: Option<Vec<u8>> = None;
    for resource in chain.iter().rev() {
        let job = backing::lock(resource)?;
        let (identity, length, _) = checked_dictionary(owner, &job)?;
        let Input::Chunk {
            descriptor,
            encoded,
            ..
        } = &job.input
        else {
            return Err(io::Error::other("dictionary job changed its input kind"));
        };
        let verified = terrane_sdk::codec::decode_verified(
            encoded,
            length,
            owner.preparation.config.location.chunk_profile(),
            true,
            &identity,
            plaintext.as_deref(),
        )
        .map_err(io::Error::other)?;
        descriptor
            .verify_bytes(&TERRANE_V1, IdentityKind::Chunk, verified.plaintext())
            .map_err(io::Error::other)?;
        native::check_current(owner, &job.files[0], encoded)?;
        plaintext = Some(verified.plaintext().to_vec());
    }
    Ok((
        plaintext.ok_or_else(|| io::Error::other("empty admitted dictionary chain"))?,
        first,
    ))
}

/// Rechecks actual completed custody, original funding and canonical bytes.
///
/// # Errors
/// Refuses incomplete or changed native custody, lost protection, exceeded
/// allocation bounds and malformed original envelopes.
pub(super) fn checked_dictionary(
    owner: &Custody,
    job: &AdmissionJob,
) -> io::Result<(Identity, usize, Codec)> {
    let Input::Chunk {
        descriptor,
        encoded,
        ..
    } = &job.input
    else {
        return Err(io::Error::other("dictionary job is not an encoded chunk"));
    };
    if !job.complete || job.files.len() != 1 {
        return Err(io::Error::other(
            "dictionary lacks completed original native custody",
        ));
    }
    state::check_registration(owner, job)?;
    let pin_owner = format!("admission:{}", job.token);
    if job.cached.is_none()
        && (!owner.state.pins.iter().any(|pin| {
            pin.owner == pin_owner
                && pin.hash == state::hex(descriptor.digest())
                && pin.expires == RETAINED_LEASE_DEADLINE
        }) || !owner
            .state
            .leases
            .iter()
            .any(|lease| lease.owner == pin_owner && lease.expires == RETAINED_LEASE_DEADLINE))
    {
        return Err(io::Error::other("admitted dictionary lost its durable pin"));
    }
    let length = usize::try_from(descriptor.size()).map_err(io::Error::other)?;
    if length > owner.preparation.config.reads.max_allocation_bytes
        || encoded.len() > owner.preparation.config.reads.max_allocation_bytes
    {
        return Err(io::Error::new(
            io::ErrorKind::StorageFull,
            "dictionary exceeds configured allocation window",
        ));
    }
    native::check_current(owner, &job.files[0], encoded)?;
    let identity = TERRANE_V1
        .from_digest(IdentityKind::Chunk, descriptor.digest())
        .map_err(io::Error::other)?;
    let codec = terrane_format::codec::parse_envelope(encoded)
        .map_err(io::Error::other)?
        .codec;
    Ok((identity, length, codec))
}
