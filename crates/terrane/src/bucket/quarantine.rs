//! Durably excludes individual identities without deleting retained pack bytes.

use super::catalog::Catalog;
use super::{BucketBinding, FileBucket, files};
use crate::pack::{MergedShard, RecordState};
use crate::store::{Clock, ContentValidator, LocalFs, StoreErrorKind, StoreFailure};
use terrane_core::identity::{Identity, TERRANE_V1};

impl<F: LocalFs + BucketBinding, C: Clock + BucketBinding, V: ContentValidator + BucketBinding>
    FileBucket<F, C, V>
{
    /// Returns an exact identity's selected state independently of container inventory.
    ///
    /// # Errors
    /// Rejects identities outside the configured initial identity profile.
    fn selected_state(
        &self,
        catalog: &Catalog,
        identity: &Identity,
    ) -> Result<Option<RecordState>, StoreFailure> {
        if identity.profile() != TERRANE_V1.name() {
            return Err(files::malformed());
        }
        let hash = identity
            .terrane_v1_digest()
            .map_err(|_| files::malformed())?;
        let record = catalog
            .shards
            .iter()
            .find(|shard| shard.shard() == hash[0])
            .and_then(|shard| {
                shard
                    .entries()
                    .binary_search_by_key(&hash, |entry| *entry.entry().hash())
                    .ok()
                    .map(|position| &shard.entries()[position])
            });
        Ok(record
            .filter(|record| record.entry().kind().identity_kind() == identity.kind())
            .map(|record| record.state()))
    }

    /// Tests selected GC retirement or identity quarantine before serving content.
    ///
    /// # Errors
    /// Rejects identities outside the configured initial identity profile.
    pub(super) fn is_excluded(
        &self,
        catalog: &Catalog,
        identity: &Identity,
    ) -> Result<bool, StoreFailure> {
        Ok(matches!(
            self.selected_state(catalog, identity)?,
            Some(RecordState::Tombstone | RecordState::Quarantine)
        ))
    }

    /// Tests the sticky identity quarantine that ordinary admission cannot clear.
    ///
    /// # Errors
    /// Rejects identities outside the configured initial identity profile.
    pub(super) fn is_quarantined(
        &self,
        catalog: &Catalog,
        identity: &Identity,
    ) -> Result<bool, StoreFailure> {
        Ok(self.selected_state(catalog, identity)? == Some(RecordState::Quarantine))
    }

    /// Excludes an individual published body through durable identity quarantine.
    ///
    /// Other bodies in the same retained pack and its container inventory remain
    /// unchanged. Repeated exclusion succeeds. Ordinary `put` never restores an
    /// excluded identity; restoration requires a separate explicit procedure.
    ///
    /// # Errors
    /// Returns `Absent` for an identity without a published body record, `Invalid`
    /// for another profile, or a specified failure if durable publication fails.
    pub async fn exclude(&self, identity: &Identity) -> Result<(), StoreFailure> {
        let _guard = self.exclusive().await?;
        let catalog = self.catalog().await?;
        if self.is_quarantined(&catalog, identity)? {
            return Ok(());
        }
        let hash = identity
            .terrane_v1_digest()
            .map_err(|_| files::malformed())?;
        let generation = self.next_generation(&catalog).await?;
        let mut shards = Vec::new();
        let mut found = false;
        for previous in &catalog.shards {
            let mut records =
                terrane_core::pack_format::decode_shard(&previous.encode(), previous.shard())
                    .map_err(|_| files::layout_corrupt())?;
            for record in &mut records {
                if record.record.hash == hash
                    && previous.entries().iter().any(|entry| {
                        entry.entry().hash() == &hash
                            && entry.entry().kind().identity_kind() == identity.kind()
                    })
                {
                    record.state = RecordState::Quarantine as u8;
                    found = true;
                }
            }
            let bytes = terrane_core::pack_format::encode_shard(&records);
            shards.push(
                MergedShard::decode(&bytes, generation, previous.shard())
                    .map_err(|_| files::layout_corrupt())?,
            );
        }
        if !found {
            return Err(StoreFailure::new(StoreErrorKind::Absent(identity.clone())));
        }
        self.publish_shards(catalog, generation, &shards).await
    }
}
