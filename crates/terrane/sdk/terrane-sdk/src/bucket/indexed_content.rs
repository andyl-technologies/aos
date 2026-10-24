//! Answers bounded negotiation batches from one complete selected catalog.
//!
//! Only committed Live merged-index entries count as present. Body verification
//! remains the ordinary content read path's responsibility; neither standalone
//! container inventory nor the virtual empty chunk supplies an index entry.

use std::collections::BTreeSet;

use terrane_format::identity::Digest;

use super::{BucketBinding, FileBucket, catalog::registered};
use crate::{
    pack::RecordState,
    store::{
        Clock, ContentValidator, IndexedContent, InvalidReason, LocalFs, MAX_INDEXED_HASHES,
        StoreErrorKind, StoreFailure,
    },
};

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl<F, C, V> IndexedContent for FileBucket<F, C, V>
where
    F: LocalFs + BucketBinding,
    C: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    async fn indexed_presence(&self, hashes: &[Digest]) -> Result<Vec<bool>, StoreFailure> {
        if hashes.len() > MAX_INDEXED_HASHES {
            return Err(StoreFailure::new(StoreErrorKind::Invalid(
                InvalidReason::Upload {
                    rule_id: "PROTO-10",
                },
            )));
        }
        if hashes.is_empty() {
            return Ok(Vec::new());
        }

        let _exclusion = self.read_exclusion().await?;
        let catalog = self.catalog().await?;
        // Legacy tombstones also exclude their physical pack. Build the complete
        // set once so a batch does not rescan all catalog entries for each hash.
        let excluded: BTreeSet<_> = catalog
            .exclusions
            .iter()
            .flatten()
            .map(|entry| entry.pack_id)
            .chain(catalog.burns.iter().flatten().copied())
            .chain(
                catalog
                    .shards
                    .iter()
                    .flat_map(|shard| shard.entries())
                    .filter(|entry| entry.state() == RecordState::Tombstone)
                    .map(|entry| *entry.pack().as_bytes()),
            )
            .collect();
        let values = hashes
            .iter()
            .map(|hash| {
                catalog
                    .shards
                    .iter()
                    .find(|shard| shard.shard() == hash[0])
                    .and_then(|shard| {
                        shard
                            .entries()
                            .binary_search_by_key(hash, |entry| *entry.entry().hash())
                            .ok()
                            .map(|position| &shard.entries()[position])
                    })
                    .is_some_and(|entry| {
                        entry.state() == RecordState::Live
                            && !excluded.contains(entry.pack().as_bytes())
                    })
            })
            .collect();

        // The writable native path retains exclusion throughout this operation.
        // A read-only binding must also refuse a changed selected generation.
        let current = self.logical_optional(&registered("CAPABILITIES")?).await?;
        if current.as_deref() != Some(catalog.capability_bytes.as_slice()) {
            return Err(StoreFailure::new(StoreErrorKind::Unavailable {
                retry_after: None,
            }));
        }
        Ok(values)
    }
}
