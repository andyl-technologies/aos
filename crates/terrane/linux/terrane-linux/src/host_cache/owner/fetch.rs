//! Fetches verified lower-tier bytes independently of local admission completion.
//!
//! The physical queue owns accepted admission work. Returning lower-tier bytes
//! requires complete codec, identity and boundary verification but does not wait
//! for cache reservation, eviction or publication and grants no native handle.

use super::{NativeChunkAdmissionError, NativeChunkAdmissionTicket, NativeMetadataOwner};
use std::{io, time::Duration};
use terrane_format::identity::{Descriptor, IdentityKind, TERRANE_V1};
use terrane_sdk::{
    bucket::BucketBinding,
    host::cache::{CircuitBreaker, FetchRequirement, fetch_verified},
    store::{
        ChunkPosition, Clock, ContentStore, ContentValidator, InvalidReason, StoreErrorKind,
        StoreFailure,
    },
};

/// Supplies independently validated repository context for one lower-tier chunk.
pub struct NativeChunkFetchRequest<'a> {
    /// Names the exact plaintext identity and length expected by the repository.
    pub descriptor: &'a Descriptor,
    /// Selects the actual boundary context of this chunk in its object.
    pub position: ChunkPosition,
    /// Supplies independently fetched one-hop dictionary plaintext when required.
    pub dictionary: Option<&'a [u8]>,
    /// Bounds the complete lower-tier attempt, including fallback and verification.
    pub budget: Duration,
}

/// Retains verified lower-tier bytes and their separate local submission outcome.
///
/// The encoded bytes may be consumed immediately. A queued admission ticket
/// must finish before it supplies a producer receipt; neither this value nor
/// its bytes constitute a local consumer lease or native serving readiness.
pub struct NativeFetchedChunk {
    encoded: Vec<u8>,
    admission: Result<NativeChunkAdmissionTicket, NativeChunkAdmissionError>,
}

impl NativeFetchedChunk {
    /// Borrows the completely verified original encoded chunk envelope.
    pub fn encoded_bytes(&self) -> &[u8] {
        &self.encoded
    }

    /// Returns verified bytes and the actual independent local queue outcome.
    ///
    /// A submission failure retains its untouched admission inputs. A successful
    /// submission retains a real reply channel, independent of these bytes.
    pub fn into_parts(
        self,
    ) -> (
        Vec<u8>,
        Result<NativeChunkAdmissionTicket, NativeChunkAdmissionError>,
    ) {
        (self.encoded, self.admission)
    }
}

impl NativeMetadataOwner {
    /// Fetches a verified chunk and submits bounded local admission without waiting.
    ///
    /// Verification uses this owner's immutable configured chunk profile and the
    /// supplied repository descriptor. Lower tiers retain their existing circuit
    /// and total-deadline behavior. Local capacity or queue failure cannot prevent
    /// use of the returned bytes. Accepted native work continues independently
    /// if the caller drops its ticket, including during eviction or failure.
    ///
    /// # Errors
    /// Refuses invalid request context, configured read-window overflow, failed
    /// verification and unavailable or absent lower content. Native admission
    /// errors are returned alongside the verified bytes rather than as fetch
    /// failures; the ticket reports any later physical or capacity failure.
    pub async fn fetch_chunk<S, C, V>(
        &self,
        stores: &[S],
        circuits: &mut [CircuitBreaker],
        clock: &C,
        request: NativeChunkFetchRequest<'_>,
        validator: &V,
    ) -> Result<NativeFetchedChunk, StoreFailure>
    where
        S: ContentStore + BucketBinding,
        C: Clock + BucketBinding,
        V: ContentValidator + BucketBinding,
    {
        let length = usize::try_from(request.descriptor.size()).map_err(invalid)?;
        if length > self.chunk_profile.maximum() {
            return Err(invalid(io::Error::new(
                io::ErrorKind::InvalidInput,
                "lower chunk exceeds the configured profile",
            )));
        }
        self.admission_bounds
            .check(length.max(1), 0)
            .map_err(capacity)?;
        let identity = TERRANE_V1
            .from_digest(IdentityKind::Chunk, request.descriptor.digest())
            .map_err(invalid)?;
        let requirement = FetchRequirement::Chunk {
            identity: &identity,
            length,
            profile: &self.chunk_profile,
            final_chunk: request.position == ChunkPosition::Final,
            dictionary: request.dictionary,
        };

        let encoded = fetch_verified(
            stores,
            circuits,
            clock,
            request.budget,
            &requirement,
            validator,
        )
        .await?;
        self.admission_bounds
            .check(encoded.len(), 0)
            .map_err(capacity)?;
        self.admission_bounds
            .check(encoded.capacity(), 0)
            .map_err(capacity)?;

        // The caller retains the verified body even if local submission or
        // completion fails. Only the worker can fund and create local files.
        let admission = self.submit_chunk(
            request.descriptor.clone(),
            request.position,
            encoded.clone(),
        );
        Ok(NativeFetchedChunk { encoded, admission })
    }
}

fn invalid(source: impl std::error::Error + Send + Sync + 'static) -> StoreFailure {
    StoreFailure::with_source(
        StoreErrorKind::Invalid(InvalidReason::MalformedRequest),
        source,
    )
}

fn capacity(source: io::Error) -> StoreFailure {
    StoreFailure::with_source(StoreErrorKind::Capacity, source)
}
