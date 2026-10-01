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

    /// Recognizes active retirement, permanent burns and legacy exact evidence.
    pub(super) fn physically_excluded(&self, catalog: &Catalog, pack: &[u8; 16]) -> bool {
        catalog.exclusions.as_ref().is_some_and(|entries| {
            entries
                .binary_search_by_key(pack, |entry| entry.pack_id)
                .is_ok()
        }) || catalog
            .burns
            .as_ref()
            .is_some_and(|burns| burns.binary_search(pack).is_ok())
            || catalog
                .shards
                .iter()
                .flat_map(|shard| shard.entries())
                .any(|entry| {
                    entry.state() == RecordState::Tombstone && entry.pack().as_bytes() == pack
                })
    }

    /// Tests whether an exact active incarnation preserves physical retirement evidence.
    pub(super) fn has_active_exclusion(&self, catalog: &Catalog, pack: &[u8; 16]) -> bool {
        catalog.exclusions.as_ref().is_some_and(|entries| {
            entries
                .binary_search_by_key(pack, |entry| entry.pack_id)
                .is_ok()
        })
    }

    /// Requires represented complete exclusion and permanent-burn sets.
    ///
    /// Missing old inventory or artifacts does not make a represented set
    /// unknown. Detached-index aliases independently name their physical pack.
    pub(super) fn index_retirement_known(&self, catalog: &Catalog) -> bool {
        catalog.exclusions.is_some() && catalog.burns.is_some()
    }

    /// Tests a canonical detached index's embedded physical pack association.
    ///
    /// Generic Index payloads retain their separate validation rules. A TRPK
    /// alias cannot escape an exclusion or burn by using another live carrier
    /// or by dropping the old container inventory and artifacts.
    ///
    /// # Errors
    /// Rejects malformed detached-index headers, ordering, coverage or records.
    pub(super) fn detached_index_excluded(
        &self,
        catalog: &Catalog,
        bytes: &[u8],
    ) -> Result<bool, crate::pack::PackError> {
        if !bytes.starts_with(b"TRPK") {
            return Ok(false);
        }
        let (header, _) = terrane_core::pack_format::decode_detached_index(bytes)?;
        Ok(self.physically_excluded(catalog, header.id()))
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
        let retired_container = catalog.inventory.as_ref().is_some_and(|entries| {
            entries.iter().any(|entry| {
                let matches_identity = match identity.kind() {
                    terrane_core::identity::IdentityKind::Pack => {
                        entry.pack_hash == identity.digest()
                    }
                    terrane_core::identity::IdentityKind::Index => {
                        entry.index_hash == identity.digest()
                    }
                    _ => false,
                };
                matches_identity && self.physically_excluded(catalog, &entry.pack_id)
            })
        });
        Ok(retired_container
            || matches!(
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
        let holder = super::held::SingleHeld::acquire(self).await?;
        let held = holder.destination();
        let observed = held.observe_publication().await?;
        self.write_layout_locked().await?;
        let catalog = self.catalog().await?;
        if self.is_quarantined(&catalog, identity)? {
            return Ok(());
        }
        let hash = identity
            .terrane_v1_digest()
            .map_err(|_| files::malformed())?;
        if catalog
            .shards
            .iter()
            .flat_map(|shard| shard.entries())
            .any(|entry| {
                entry.entry().hash() == &hash
                    && entry.entry().kind().identity_kind() == identity.kind()
                    && entry.state() == RecordState::Tombstone
                    && !self.has_active_exclusion(&catalog, entry.pack().as_bytes())
            })
        {
            // Quarantine cannot erase a legacy pack's final exact physical
            // retirement evidence, even when key6 claims an empty set.
            return Err(StoreFailure::new(StoreErrorKind::Unsupported));
        }
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
        self.publish_shards_held(&held, &observed, catalog, generation, &shards)
            .await
    }
}
