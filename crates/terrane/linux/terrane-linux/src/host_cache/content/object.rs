//! Streams manifest plaintext from genuine consumer grants without whole-file allocation.
//!
//! Opening verifies the complete ordered object and every declared whole-file
//! hash before exposing a reader. Later readers verify each original chunk again
//! and enforce live grants while copying even already buffered plaintext. This
//! supplies the chunk-serving path; it creates no sealed file or kernel handle.

use super::{NativeConsumerLease, NativeContentStore, native_failure};
use std::io::{self, Cursor, Read};
use terrane_format::identity::{Descriptor, Identity, IdentityKind, TERRANE_V1};
use terrane_sdk::{
    host::publication::{PublicationClaim, PublicationRecipe},
    store::{ChunkPosition, ContentStore, StoreErrorKind, StoreFailure},
};

/// Retains a fully verified manifest object under its original finite native grants.
///
/// This host-local view grants no guest authorization or sealed-file capability.
/// It borrows the running store, preventing its owner from disappearing while the
/// view exists. Call [`Self::close`] to release the grants durably; abandonment
/// leaves them to the physical owner's existing finite expiry and release grace.
pub struct NativeChunkedObject<'store> {
    store: &'store NativeContentStore,
    identity: Identity,
    claim: PublicationClaim,
    leases: Vec<NativeConsumerLease>,
    sequence: Vec<Occurrence>,
}

struct Occurrence {
    lease: usize,
    length: usize,
    position: ChunkPosition,
}

impl NativeContentStore {
    /// Opens verified manifest plaintext without constructing a sealed whole file.
    ///
    /// The original native owner pins each distinct chunk and its real one-hop
    /// dependencies once for this view. Every declared occurrence still checks
    /// its own length and CDC position. Opening streams the complete object
    /// through its canonical manifest's ordered identity and whole-file hash
    /// checks before returning; memory is bounded by individual chunks.
    ///
    /// This is the chunk-serving path for multi-chunk objects under `never`.
    /// Single-chunk sealing and `always` publication are separate operations.
    ///
    /// # Errors
    /// Refuses non-manifest or single-chunk objects, invalid or missing canonical metadata,
    /// expired or unavailable grants, missing/corrupt chunks or whole-file hashes,
    /// configured request/allocation capacity, and native filesystem failures.
    pub async fn open_manifest_chunks(
        &self,
        identity: &Identity,
    ) -> Result<NativeChunkedObject<'_>, StoreFailure> {
        if identity.kind() != IdentityKind::Manifest {
            return Err(StoreFailure::new(StoreErrorKind::Unsupported));
        }
        let canonical = self.get(identity, None).await?;
        let descriptor =
            Descriptor::from_identity(&TERRANE_V1, identity, &canonical).map_err(|error| {
                native_failure(io::Error::new(io::ErrorKind::InvalidData, error), identity)
            })?;
        let claim = PublicationClaim::new(
            self.ready.layout().layout().domain().to_owned(),
            PublicationRecipe::Manifest {
                object: descriptor,
                canonical_manifest: canonical,
            },
            self.ready.layout().layout().chunk_profile(),
        )
        .map_err(|error| native_failure(error, identity))?;
        if claim
            .manifest()
            .is_none_or(|manifest| manifest.chunks.len() < 2)
        {
            // Single-chunk objects require the existing direct sealing path.
            return Err(StoreFailure::new(StoreErrorKind::Unsupported));
        }
        let mut leases = Vec::new();
        let sequence = self.object_sequence(&claim, identity, &mut leases).await;
        let sequence = match sequence {
            Ok(sequence) => sequence,
            Err(error) => return self.finish(Err(error), leases).await,
        };
        let object = NativeChunkedObject {
            store: self,
            identity: identity.clone(),
            claim,
            leases,
            sequence,
        };
        let verified = object.claim.verify_reader(&mut object.reader());
        match verified {
            Ok(()) => Ok(object),
            Err(error) => {
                self.finish(Err(native_failure(error, identity)), object.leases)
                    .await
            }
        }
    }

    async fn object_sequence(
        &self,
        claim: &PublicationClaim,
        object_identity: &Identity,
        leases: &mut Vec<NativeConsumerLease>,
    ) -> Result<Vec<Occurrence>, StoreFailure> {
        let manifest = claim
            .manifest()
            .ok_or_else(|| StoreFailure::new(StoreErrorKind::Unsupported))?;
        if manifest.chunks.len() > self.max_requests
            || manifest.chunks.iter().any(|chunk| {
                usize::try_from(chunk.length)
                    .map_or(true, |length| length > self.max_allocation_bytes)
            })
        {
            return Err(StoreFailure::new(StoreErrorKind::Capacity));
        }
        let mut sequence = Vec::with_capacity(manifest.chunks.len());
        for (index, chunk) in manifest.chunks.iter().enumerate() {
            let identity = TERRANE_V1
                .from_digest(IdentityKind::Chunk, &chunk.digest)
                .map_err(|error| {
                    native_failure(
                        io::Error::new(io::ErrorKind::InvalidData, error),
                        object_identity,
                    )
                })?;
            let lease = match leases
                .iter()
                .position(|lease| lease.identity() == &identity)
            {
                Some(index) => index,
                None => {
                    leases.push(self.pin(&identity).await?);
                    leases.len() - 1
                }
            };
            sequence.push(Occurrence {
                lease,
                length: usize::try_from(chunk.length)
                    .map_err(|error| native_failure(io::Error::other(error), &identity))?,
                position: if index + 1 == manifest.chunks.len() {
                    ChunkPosition::Final
                } else {
                    ChunkPosition::NonFinal
                },
            });
        }
        Ok(sequence)
    }
}

impl<'store> NativeChunkedObject<'store> {
    /// Borrows the independently verified canonical manifest identity.
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Returns the complete verified plaintext length from the canonical manifest.
    pub fn plaintext_size(&self) -> u64 {
        self.claim.plaintext_size()
    }

    /// Starts a new bounded reader at the beginning of the verified object.
    ///
    /// Reads enforce the original live grants and reverify each actual chunk.
    /// They take no embedded-store lock and perform no publisher or quota RPC.
    pub fn reader(&self) -> NativeChunkedReader<'_, 'store> {
        NativeChunkedReader {
            object: self,
            next: 0,
            current: None,
        }
    }

    /// Returns the earliest acknowledged live Unix-second expiry among the grants.
    ///
    /// # Errors
    /// Refuses a revoked, expired or concurrently changing original grant.
    pub fn expires_at(&self) -> Result<u64, StoreFailure> {
        let first = self
            .leases
            .first()
            .ok_or_else(|| StoreFailure::new(StoreErrorKind::Unavailable { retry_after: None }))?;
        let initial = first
            .expires_at()
            .map_err(|error| native_failure(error, first.identity()))?;
        self.leases
            .iter()
            .skip(1)
            .try_fold(initial, |earliest, lease| {
                lease
                    .expires_at()
                    .map(|expires| earliest.min(expires))
                    .map_err(|error| native_failure(error, lease.identity()))
            })
    }

    /// Renews original grants using the store's configured finite lease duration.
    ///
    /// A renewal failure or cancellation can leave some grants extended. The
    /// physical owner retains every accepted effect, and readers continue to
    /// check each actual grant. A retry skips grants already extended to the
    /// requested deadline; it never replaces a grant or re-pins another source.
    ///
    /// # Errors
    /// Refuses expired or revoked grants, clock or deadline failures, unavailable
    /// physical custody, queue capacity and native policy synchronization errors.
    pub async fn renew(&self) -> Result<(), StoreFailure> {
        let expires = self.store.consumer_deadline()?;
        for lease in &self.leases {
            let current = lease
                .expires_at()
                .map_err(|error| native_failure(error, lease.identity()))?;
            if current < expires {
                self.store
                    .ready
                    .owner()
                    .renew_consumer_lease(lease, expires)
                    .await
                    .map_err(|error| native_failure(error, lease.identity()))?;
            }
        }
        Ok(())
    }

    /// Revokes and durably releases every original distinct consumer grant.
    ///
    /// # Errors
    /// Reports native release failures after attempting all original releases.
    /// Failed or cancelled effects remain with the physical owner for expiry
    /// and reconciliation; a successful release retains normal durable grace.
    pub async fn close(self) -> Result<(), StoreFailure> {
        self.store.finish(Ok(()), self.leases).await
    }
}

/// Reads verified manifest plaintext while borrowing its original native grants.
///
/// Each reader buffers at most one plaintext chunk. The grants remain owned by
/// the object, and every read checks liveness before and after copying bytes.
pub struct NativeChunkedReader<'object, 'store> {
    object: &'object NativeChunkedObject<'store>,
    next: usize,
    current: Option<(usize, Cursor<Vec<u8>>)>,
}

impl Read for NativeChunkedReader<'_, '_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        loop {
            if let Some((index, cursor)) = &mut self.current {
                let lease = &self.object.leases[*index];
                lease.expires_at()?;
                let count = cursor.read(output)?;
                lease.expires_at()?;
                if count != 0 {
                    return Ok(count);
                }
                self.current = None;
            }
            let Some(occurrence) = self.object.sequence.get(self.next) else {
                return Ok(0);
            };
            let lease = &self.object.leases[occurrence.lease];
            let bytes = lease.read_verified()?;
            let profile = self.object.store.ready.layout().layout().chunk_profile();
            let boundary_valid = match occurrence.position {
                ChunkPosition::Final => profile.first_boundary(&bytes) == bytes.len(),
                ChunkPosition::NonFinal => profile.valid_nonfinal_chunk(&bytes),
            };
            if bytes.len() != occurrence.length || !boundary_valid {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "native object chunk differs from manifest context",
                ));
            }
            self.current = Some((occurrence.lease, Cursor::new(bytes)));
            self.next += 1;
        }
    }
}
