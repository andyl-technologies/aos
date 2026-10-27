//! Verifies untrusted chunk envelopes before writing one canonical residence.

use super::{
    super::retention::{Custody, NativeOwnerExecutor},
    Input,
    backing::{self, AdmissionJob},
    io as native, reconcile, state,
};
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
            let (plaintext, actual) =
                super::dictionary_read::verify(executor, Some(resource), &owner, &digest, None)?;
            super::dictionary_read::retain(&mut job, digest, actual, &mut hashes)?;
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
