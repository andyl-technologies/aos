//! Answers bounded index membership for an authenticated file's direct objects.

use std::collections::BTreeSet;

use terrane_format::{
    identity::{Digest, IdentityKind, TERRANE_V1},
    manifest::Manifest,
    tree_format::ContentRef,
};

use super::{Error, PreparedFileRead};
use crate::store::{
    Clock, IndexedContent, InvalidReason, MAX_INDEXED_HASHES, Store, StoreErrorKind, StoreFailure,
};

impl<S: Store + IndexedContent, C: Clock> PreparedFileRead<'_, S, C> {
    /// Returns committed-index membership for this file's directly named objects.
    ///
    /// Only the selected inline chunk, or its canonical manifest and listed
    /// chunks, can return true. Other digests return false without an index
    /// lookup. Dictionary dependencies and ancestor metadata require separate
    /// reachability evidence and are excluded from this operation.
    ///
    /// At most 4,096 digests are accepted; order and duplicates are preserved.
    /// A manifest is read and verified once to establish its chunk references.
    /// Chunk bodies are never read. Permitted hashes use one committed-index
    /// observation, followed by fresh scoped authorization against the complete
    /// policy reference captured during preparation. No reusable content-read
    /// permit is issued, and a positive bit does not verify plaintext.
    ///
    /// # Errors
    /// Refuses excessive requests, invalid or unavailable manifests, failed or
    /// malformed index observations, and changed, expired or denied authority.
    /// Errors disclose no partial result.
    pub async fn indexed_presence(self, hashes: &[Digest]) -> Result<Vec<bool>, Error> {
        if hashes.len() > MAX_INDEXED_HASHES {
            return Err(
                StoreFailure::new(StoreErrorKind::Invalid(InvalidReason::Upload {
                    rule_id: "PROTO-10",
                }))
                .into(),
            );
        }
        self.head
            .authorize_path(self.guard, &self.snapshot, &self.absolute)
            .await?;

        let mut result = vec![false; hashes.len()];
        if hashes.is_empty() {
            self.finish().await?;
            return Ok(result);
        }

        let mut reachable = BTreeSet::new();
        match self.content {
            ContentRef::Inline(digest) => {
                reachable.insert(digest);
            }
            ContentRef::Manifest(digest) => {
                let identity = TERRANE_V1
                    .from_digest(IdentityKind::Manifest, &digest)
                    .map_err(|_| crate::guard::invalid())?;
                let bytes = self.guard.store().get(&identity, None).await?;
                let manifest = Manifest::decode_verified(
                    &bytes,
                    &self.guard.config().chunk_profile,
                    &identity,
                )
                .map_err(|_| crate::guard::invalid())?;
                if manifest.size != self.size {
                    return Err(crate::guard::invalid().into());
                }
                reachable.insert(digest);
                reachable.extend(manifest.chunks.iter().map(|chunk| chunk.digest));
                self.head
                    .authorize_path(self.guard, &self.snapshot, &self.absolute)
                    .await?;
            }
        }

        let positions: Vec<_> = hashes
            .iter()
            .enumerate()
            .filter_map(|(position, digest)| reachable.contains(digest).then_some(position))
            .collect();
        if !positions.is_empty() {
            let permitted: Vec<_> = positions.iter().map(|position| hashes[*position]).collect();
            let present = self.guard.store().indexed_presence(&permitted).await?;
            if present.len() != positions.len() {
                return Err(
                    StoreFailure::new(StoreErrorKind::Unavailable { retry_after: None }).into(),
                );
            }
            for (position, present) in positions.into_iter().zip(present) {
                result[position] = present;
            }
        }

        self.finish().await?;
        Ok(result)
    }
}
