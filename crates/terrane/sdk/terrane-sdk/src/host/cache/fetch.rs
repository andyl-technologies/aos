//! Bounds lower-tier reads and verifies candidates before returning admission bytes.
//!
//! This layer neither admits bytes nor publishes sealed files. Capacity failure
//! therefore cannot disable fetching directly from a lower tier.

use super::CircuitBreaker;
use crate::{
    bucket::BucketBinding,
    store::{
        Clock, ContentStore, ContentValidator, CorruptSubject, MetaUpload, StoreErrorKind,
        StoreFailure,
    },
};
use std::{
    future::{Future, poll_fn},
    task::Poll,
    time::Duration,
};
use terrane_format::{
    chunking::ChunkProfile,
    identity::{Identity, IdentityKind, TERRANE_V1},
};

/// Supplies independently configured verification context for a requested body.
pub enum FetchRequirement<'a> {
    /// Canonical chunk context supplied by repository metadata validation.
    Chunk {
        /// Expected plaintext identity.
        identity: &'a Identity,
        /// Exact declared plaintext length.
        length: usize,
        /// Immutable store chunk profile.
        profile: &'a ChunkProfile,
        /// Whether this is the object's final chunk.
        final_chunk: bool,
        /// Independently fetched dictionary plaintext, checked against its digest.
        dictionary: Option<&'a [u8]>,
    },
    /// Canonical metadata interpreted by the configured validator.
    Metadata {
        /// Expected canonical encoded identity.
        identity: &'a Identity,
    },
}

impl FetchRequirement<'_> {
    /// Returns the requested immutable identity.
    pub fn identity(&self) -> &Identity {
        match self {
            Self::Chunk { identity, .. } | Self::Metadata { identity } => identity,
        }
    }

    /// Verifies candidate bytes before they can be served or admitted.
    ///
    /// # Errors
    /// Refuses identity, codec, decompression-limit, boundary and schema failures.
    pub fn verify(
        &self,
        bytes: &[u8],
        validator: &impl ContentValidator,
    ) -> Result<(), StoreFailure> {
        match self {
            Self::Chunk {
                identity,
                length,
                profile,
                final_chunk,
                dictionary,
            } => {
                crate::codec::decode_verified(
                    bytes,
                    *length,
                    profile,
                    *final_chunk,
                    identity,
                    *dictionary,
                )
                .map_err(|source| corrupt(identity, source))?;
            }
            Self::Metadata { identity } => {
                if identity.kind() == IdentityKind::Chunk {
                    return Err(StoreFailure::new(StoreErrorKind::Unsupported));
                }
                TERRANE_V1
                    .verify(identity, bytes)
                    .map_err(|source| corrupt(identity, source))?;
                validator.validate_meta(&MetaUpload::new(identity.kind(), bytes)?)?;
            }
        }
        Ok(())
    }
}

/// Attempts lower tiers under one total deadline and their individual circuits.
///
/// Corrupt or unavailable candidates are never returned. Each remaining child
/// gets only the unused part of the same deadline; open circuits are skipped.
/// The caller retains responsibility for reporting failed candidates and for
/// any durable quarantine of resident data. A successful return grants no local
/// admission or publication authority.
///
/// # Errors
/// Returns unavailable when the total deadline expires or every circuit is
/// open, absent when every eligible child lacks content, or the final verified
/// child failure when no fallback succeeds. Circuit/configuration length mismatch
/// is rejected without issuing a request.
pub async fn fetch_verified<S, C, V>(
    stores: &[S],
    circuits: &mut [CircuitBreaker],
    clock: &C,
    budget: Duration,
    requirement: &FetchRequirement<'_>,
    validator: &V,
) -> Result<Vec<u8>, StoreFailure>
where
    S: ContentStore + BucketBinding,
    C: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    if stores.len() != circuits.len() || budget.is_zero() {
        return Err(unavailable());
    }
    let start = clock.monotonic();
    let deadline = start.checked_add(budget).ok_or_else(unavailable)?;
    let mut last_failure = None;
    let mut saw_absent = false;
    let mut skipped_open = false;
    for (store, circuit) in stores.iter().zip(circuits) {
        let now = clock.monotonic();
        if now < start || now >= deadline {
            return Err(unavailable());
        }
        if !circuit.allow(now) {
            skipped_open = true;
            continue;
        }
        let remaining = deadline.checked_sub(now).ok_or_else(unavailable)?;
        let result = bounded(store.get(requirement.identity(), None), clock, remaining)
            .await
            .and_then(|bytes| {
                requirement.verify(&bytes, validator)?;
                Ok(bytes)
            });
        let completed = clock.monotonic();
        if completed < start {
            return Err(unavailable());
        }
        if completed >= deadline {
            circuit.failure(completed);
            return Err(unavailable());
        }
        match result {
            Ok(bytes) => {
                circuit.success();
                return Ok(bytes);
            }
            Err(error) => {
                if matches!(error.kind(), StoreErrorKind::Absent(_)) {
                    saw_absent = true;
                } else {
                    circuit.failure(completed);
                    last_failure = Some(error);
                }
            }
        }
    }
    if let Some(error) = last_failure {
        return Err(error);
    }
    if saw_absent && !skipped_open {
        return Err(StoreFailure::new(StoreErrorKind::Absent(
            requirement.identity().clone(),
        )));
    }
    Err(unavailable())
}

async fn bounded<T>(
    request: impl Future<Output = Result<T, StoreFailure>>,
    clock: &(impl Clock + BucketBinding),
    remaining: Duration,
) -> Result<T, StoreFailure> {
    let mut request = Box::pin(request);
    let mut timeout = Box::pin(clock.sleep(remaining));
    poll_fn(|context| {
        if let Poll::Ready(result) = request.as_mut().poll(context) {
            return Poll::Ready(result);
        }
        if timeout.as_mut().poll(context).is_ready() {
            return Poll::Ready(Err(unavailable()));
        }
        Poll::Pending
    })
    .await
}

fn unavailable() -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Unavailable { retry_after: None })
}
fn corrupt(
    identity: &Identity,
    source: impl std::error::Error + Send + Sync + 'static,
) -> StoreFailure {
    StoreFailure::with_source(
        StoreErrorKind::Corrupt(CorruptSubject::Identity(identity.clone())),
        source,
    )
}
