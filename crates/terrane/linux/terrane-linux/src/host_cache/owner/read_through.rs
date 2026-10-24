//! Reads original resident custody before verified lower-tier fallback.
//!
//! A failed original read retains the physical owner's quarantine reports,
//! aliases and durable funding. Independently verified lower bytes can be used
//! even when that owner's subsequent admission fails.

use super::{
    NativeChunkAdmissionError, NativeChunkAdmissionTicket, NativeChunkFetchRequest,
    NativeFetchedChunk, NativeMetadataOwner,
};
use std::io;
use terrane_sdk::{
    bucket::BucketBinding,
    host::cache::{CircuitBreaker, FetchRequirement},
    store::{Clock, ContentStore, ContentValidator, InvalidReason, StoreErrorKind, StoreFailure},
};

/// Returns verified encoded bytes and an optional real lower-tier submission.
///
/// A resident result has already released its actual consumer grant into grace.
/// A fetched result retains the independently owned admission ticket. Neither
/// result supplies a sealed handle, guest authorization or a producer receipt.
pub struct NativeReadChunk {
    backing: Backing,
}

enum Backing {
    Resident(Vec<u8>),
    Fetched(NativeFetchedChunk),
}

impl NativeReadChunk {
    /// Borrows the completely verified encoded chunk bytes.
    pub fn encoded_bytes(&self) -> &[u8] {
        match &self.backing {
            Backing::Resident(encoded) => encoded,
            Backing::Fetched(fetched) => fetched.encoded_bytes(),
        }
    }

    /// Returns verified bytes and any actual independent lower admission outcome.
    ///
    /// Resident reads return `None`. A fetched result preserves the original
    /// ticket or unsubmitted inputs without manufacturing a producer receipt.
    pub fn into_parts(
        self,
    ) -> (
        Vec<u8>,
        Option<Result<NativeChunkAdmissionTicket, NativeChunkAdmissionError>>,
    ) {
        match self.backing {
            Backing::Resident(encoded) => (encoded, None),
            Backing::Fetched(fetched) => {
                let (encoded, admission) = fetched.into_parts();
                (encoded, Some(admission))
            }
        }
    }
}

impl NativeMetadataOwner {
    /// Reads an original resident grant or fetches verified lower-tier bytes.
    ///
    /// The finite `expires` deadline applies to the actual resident consumer
    /// grant; `request.budget` bounds the separate complete lower-tier attempt.
    /// Every local hit verifies the caller's exact length, boundary and dictionary
    /// context before returning. An invalid context never retries another copy.
    /// Missing, corrupt, unavailable or capacity-limited local reads use the
    /// ordinary circuit-controlled fetch. Rejected native aliases and funding
    /// remain retained, and the returned fetch's admission may independently fail.
    ///
    /// Callers enforce repository authorization before invoking this host-local
    /// operation. A fetched admission ticket must complete and hand off to cache
    /// custody before that new local body becomes an ordinary resident.
    ///
    /// # Errors
    /// Refuses malformed request context, invalid original bytes for the supplied
    /// context, terminal local refusals, and absent, corrupt or unavailable lower
    /// content. Local admission errors remain inside a successful fetched result.
    pub async fn read_or_fetch_chunk<S, C, V>(
        &self,
        stores: &[S],
        circuits: &mut [CircuitBreaker],
        clock: &C,
        expires: u64,
        request: NativeChunkFetchRequest<'_>,
        validator: &V,
    ) -> Result<NativeReadChunk, StoreFailure>
    where
        S: ContentStore + BucketBinding,
        C: Clock + BucketBinding,
        V: ContentValidator + BucketBinding,
    {
        let (identity, length) = self.fetch_context(&request)?;
        if request.budget.is_zero() || stores.len() != circuits.len() {
            return Err(invalid(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid resident/lower chunk context",
            )));
        }
        let resident = match self.pin_resident_chunk(identity.clone(), expires).await {
            Ok(lease) => {
                let result = lease.read_encoded();
                // Release goes through the same physical queue that consumes
                // original failure reports. Failure keeps every uncertain hold.
                let release = self.release_consumer_lease(&lease).await;
                result.and_then(|bytes| release.map(|_| bytes))
            }
            Err(error) => Err(error),
        };
        match resident {
            Ok(encoded) => {
                FetchRequirement::Chunk {
                    identity: &identity,
                    length,
                    profile: &self.chunk_profile,
                    final_chunk: request.position == terrane_sdk::store::ChunkPosition::Final,
                    dictionary: request.dictionary,
                }
                .verify(&encoded, validator)?;
                Ok(NativeReadChunk {
                    backing: Backing::Resident(encoded),
                })
            }
            Err(error) => {
                if error.kind() == io::ErrorKind::InvalidInput {
                    return Err(invalid(error));
                }
                let failure = crate::host_cache::content::native_failure(error, &identity);
                if !matches!(
                    failure.kind(),
                    StoreErrorKind::Absent(_)
                        | StoreErrorKind::Corrupt(_)
                        | StoreErrorKind::Unavailable { .. }
                        | StoreErrorKind::Capacity
                ) {
                    return Err(failure);
                }
                let fetched = self
                    .fetch_chunk(stores, circuits, clock, request, validator)
                    .await?;
                Ok(NativeReadChunk {
                    backing: Backing::Fetched(fetched),
                })
            }
        }
    }
}

fn invalid(source: impl std::error::Error + Send + Sync + 'static) -> StoreFailure {
    StoreFailure::with_source(
        StoreErrorKind::Invalid(InvalidReason::MalformedRequest),
        source,
    )
}
