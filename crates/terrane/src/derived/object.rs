//! Reassembles bounded plaintext ranges from verified manifest-ordered chunks.

use super::Error;
use crate::{codec::decode_verified, store::ContentStore};
use terrane_core::{
    chunking::ChunkProfile,
    codec::{Codec, parse_envelope},
    derived::MAGIC_PREFIX_LIMIT,
    identity::{Digest, IdentityKind, TERRANE_V1},
    manifest::{ChunkRef, Manifest},
    tree_format::ContentRef,
};

/// A portable object reader whose bounded ranges address plaintext bytes.
#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
pub trait PlaintextObject {
    /// Returns the object's manifest or inline-chunk digest.
    fn digest(&self) -> Digest;
    /// Returns the complete plaintext length without fetching object bytes.
    fn size(&self) -> u64;
    /// Reads an exact bounded plaintext range.
    ///
    /// # Errors
    /// Returns an error for an invalid range or unavailable/unverified content.
    async fn read_range(&self, offset: u64, length: usize) -> Result<Vec<u8>, Error>;
}

/// Resolves already verified dictionary plaintext through an injected host.
#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
pub trait DictionaryResolver {
    /// Returns the plaintext for the exact named dictionary chunk.
    ///
    /// # Errors
    /// Returns an error when the dictionary is absent or cannot be verified.
    async fn resolve(&self, digest: Digest) -> Result<Vec<u8>, Error>;
}

/// A resolver for stores that admit no dictionary-coded chunks.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoDictionaries;

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl DictionaryResolver for NoDictionaries {
    async fn resolve(&self, _digest: Digest) -> Result<Vec<u8>, Error> {
        Err(crate::codec::FrameError::MissingDictionary.into())
    }
}

/// An opened object backed by a configured immutable content store.
pub struct StoreObject<'a, S, D> {
    store: &'a S,
    dictionaries: &'a D,
    profile: &'a ChunkProfile,
    digest: Digest,
    size: u64,
    chunks: Vec<ChunkRef>,
    chunk_ends: Vec<u64>,
}

impl<'a, S: ContentStore, D: DictionaryResolver> StoreObject<'a, S, D> {
    /// Opens a regular-file reference and verifies its manifest when present.
    ///
    /// # Errors
    /// Returns a retrieval, manifest, identity, or declared-size mismatch error.
    pub async fn open(
        store: &'a S,
        dictionaries: &'a D,
        profile: &'a ChunkProfile,
        content: ContentRef,
        size: u64,
    ) -> Result<Self, Error> {
        let (digest, chunks) = match content {
            ContentRef::Inline(digest) => {
                if size > profile.minimum() as u64 {
                    return Err(terrane_core::derived::Error::LengthMismatch.into());
                }

                // Empty streams perform no range reads, so their inline identity
                // must be checked against the one possible plaintext here.
                if size == 0 {
                    let identity = TERRANE_V1.from_digest(IdentityKind::Chunk, &digest)?;
                    TERRANE_V1.verify(&identity, b"")?;
                }

                (
                    digest,
                    vec![ChunkRef {
                        digest,
                        length: size,
                    }],
                )
            }
            ContentRef::Manifest(digest) => {
                if size <= profile.minimum() as u64 {
                    return Err(terrane_core::derived::Error::LengthMismatch.into());
                }

                let identity = TERRANE_V1.from_digest(IdentityKind::Manifest, &digest)?;
                let bytes = store.get(&identity, None).await?;
                let manifest = Manifest::decode_verified(&bytes, profile, &identity)?;
                if manifest.size != size {
                    return Err(terrane_core::derived::Error::LengthMismatch.into());
                }
                (digest, manifest.chunks)
            }
        };
        let mut end = 0u64;
        let mut chunk_ends = Vec::with_capacity(chunks.len());
        for chunk in &chunks {
            end = end.checked_add(chunk.length).ok_or(Error::InvalidRead)?;
            chunk_ends.push(end);
        }
        if end != size {
            return Err(Error::InvalidRead);
        }

        Ok(Self {
            store,
            dictionaries,
            profile,
            digest,
            size,
            chunks,
            chunk_ends,
        })
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl<S: ContentStore + Sync, D: DictionaryResolver + Sync> PlaintextObject
    for StoreObject<'_, S, D>
{
    fn digest(&self) -> Digest {
        self.digest
    }
    fn size(&self) -> u64 {
        self.size
    }

    async fn read_range(&self, offset: u64, length: usize) -> Result<Vec<u8>, Error> {
        let end = offset
            .checked_add(length as u64)
            .filter(|&end| end <= self.size)
            .ok_or(Error::InvalidRead)?;
        if length > MAGIC_PREFIX_LIMIT {
            return Err(terrane_core::derived::Error::Limit.into());
        }
        let mut result = Vec::with_capacity(length);
        let first_chunk = self.chunk_ends.partition_point(|&end| end <= offset);
        let mut start = if first_chunk == 0 {
            0
        } else {
            self.chunk_ends[first_chunk - 1]
        };
        for (index, chunk) in self.chunks.iter().enumerate().skip(first_chunk) {
            let chunk_end = start.checked_add(chunk.length).ok_or(Error::InvalidRead)?;
            if start < end && chunk_end > offset {
                let identity = TERRANE_V1.from_digest(IdentityKind::Chunk, &chunk.digest)?;
                let encoded = self.store.get(&identity, None).await?;
                let dictionary = match parse_envelope(&encoded)
                    .map_err(crate::codec::FrameError::from)?
                    .codec
                {
                    Codec::ZstdDictionary(digest) => Some(self.dictionaries.resolve(digest).await?),
                    _ => None,
                };
                let chunk_length = usize::try_from(chunk.length).map_err(|_| Error::InvalidRead)?;
                let verified = decode_verified(
                    &encoded,
                    chunk_length,
                    self.profile,
                    index + 1 == self.chunks.len(),
                    &identity,
                    dictionary.as_deref(),
                )?;
                let first = usize::try_from(offset.saturating_sub(start))
                    .map_err(|_| Error::InvalidRead)?;
                let last =
                    usize::try_from(end.min(chunk_end) - start).map_err(|_| Error::InvalidRead)?;
                result.extend_from_slice(
                    verified
                        .plaintext()
                        .get(first..last)
                        .ok_or(Error::InvalidRead)?,
                );
            }
            start = chunk_end;
            if start >= end {
                break;
            }
        }
        if result.len() != length {
            return Err(Error::InvalidRead);
        }
        Ok(result)
    }
}
