//! Resolves stored dictionary dependency chains before any plaintext leaves the guard.
//!
//! Each dependency is an ordinary final chunk under the source profile. Stored
//! envelopes and their verified lengths remain data, never operation authority.

use std::collections::BTreeSet;

use terrane_format::codec::{Codec, parse_envelope};
use terrane_format::identity::{Identity, IdentityKind, TERRANE_V1};

use super::{AuthorizedSnapshot, Guard, HistoryObservation, invalid};
use crate::store::{Clock, Store, StoreFailure};

/// Retains a dictionary's verified plaintext and, with `std`, its stored envelope.
pub(super) struct ReadDictionary {
    /// Identifies the exact dictionary plaintext in the registered chunk domain.
    pub(super) identity: Identity,
    /// Preserves the fetched encoding, including its named dependency when present.
    #[cfg(feature = "std")]
    pub(super) encoded: Vec<u8>,
    /// Contains bytes released only after final-chunk size and identity validation.
    pub(super) plaintext: Vec<u8>,
}

/// Keeps a file's checked bytes and complete dependency evidence together.
pub(super) struct ReadContent {
    /// Contains the exact authenticated file plaintext after all chunk checks.
    pub(super) plaintext: Vec<u8>,
    /// Includes the content, manifest when present, and every traversed dictionary.
    pub(super) identities: Vec<Identity>,
    /// Orders each chunk's dictionary chain with dependencies before dependents.
    pub(super) dictionaries: Vec<ReadDictionary>,
}

impl<S: Store, C: Clock> Guard<S, C> {
    /// Resolves a chain iteratively, then verifies it from its terminal dependency.
    ///
    /// # Errors
    /// Rejects malformed, unavailable, cyclic, oversized or inconsistent dictionary
    /// evidence and preserves failures from fresh source-path authorization.
    pub(super) async fn read_chunk_dictionaries(
        &self,
        snapshot: &AuthorizedSnapshot,
        path: &[u8],
        content_identity: &Identity,
        content_encoded: &[u8],
        observation: HistoryObservation<'_>,
    ) -> Result<Vec<ReadDictionary>, StoreFailure> {
        let mut codec = parse_envelope(content_encoded)
            .map_err(|_| invalid())?
            .codec;
        let mut seen = BTreeSet::from([content_identity
            .terrane_v1_digest()
            .map_err(|_| invalid())?]);
        let mut pending = Vec::new();
        let maximum = self.config().chunk_profile.maximum();

        while let Codec::ZstdDictionary(digest) = codec {
            let identity = TERRANE_V1
                .from_digest(IdentityKind::Chunk, &digest)
                .map_err(|_| invalid())?;
            if !seen.insert(digest) {
                return Err(invalid());
            }

            // The snapshot's live policy is checked for every dependency fetch.
            self.authorize_snapshot_path_observed(snapshot, path, observation)
                .await?;
            let encoded = self.store().get(&identity, None).await?;
            let envelope = parse_envelope(&encoded).map_err(|_| invalid())?;
            let length = match envelope.codec {
                Codec::Raw => envelope.body.len(),
                Codec::Zstd | Codec::ZstdDictionary(_) => {
                    let declared = zstd::zstd_safe::get_frame_content_size(envelope.body)
                        .map_err(|_| invalid())?
                        .ok_or_else(invalid)?;
                    usize::try_from(declared).map_err(|_| invalid())?
                }
            };
            // Inspection enforces profile bounds and the single sized ordinary
            // frame requirement before any native decompression allocation.
            crate::codec::inspect_chunk(&encoded, length, maximum).map_err(|_| invalid())?;
            codec = envelope.codec;
            pending.push((identity, encoded, length));
        }

        let mut dictionaries: Vec<ReadDictionary> = Vec::with_capacity(pending.len());
        for (identity, encoded, length) in pending.into_iter().rev() {
            let dependency = dictionaries
                .last()
                .map(|record| record.plaintext.as_slice());
            let verified = crate::codec::decode_verified(
                &encoded,
                length,
                &self.config().chunk_profile,
                true,
                &identity,
                dependency,
            )
            .map_err(|_| invalid())?;
            let plaintext = verified.plaintext().to_vec();
            dictionaries.push(ReadDictionary {
                identity,
                #[cfg(feature = "std")]
                encoded,
                plaintext,
            });
        }
        Ok(dictionaries)
    }
}
