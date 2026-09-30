//! Publishes exact physical exclusion and restoration generations under root exclusion.
//!
//! These internal effects do not authorize collection. The collector must hold
//! the bucket's stable guard and qualify its lease, roots, marks, and age before
//! calling them; durable trash creation and deletion are separate effects.

use super::catalog::Catalog;
use super::{BucketBinding, FileBucket, files};
use crate::pack::{MergedShard, RecordState};
use crate::store::{Clock, ContentValidator, LocalFs, StoreErrorKind, StoreFailure};
use std::collections::BTreeSet;
use terrane_core::bucket::PackExclusion;

impl<F: LocalFs + BucketBinding, C: Clock + BucketBinding, V: ContentValidator + BucketBinding>
    FileBucket<F, C, V>
{
    /// Applies an already-qualified retirement without dropping earlier incarnations.
    ///
    /// The caller retains the canonical root guard and must supply independently
    /// qualified lease, snapshot, and age evidence. This helper verifies exact
    /// selected container/index binding and all-member mark exclusion again.
    ///
    /// # Errors
    /// Rejects unknown completeness, active conflicting incarnations, changed
    /// index bindings, marked members, corrupt artifacts, or failed durable I/O.
    #[allow(
        dead_code,
        reason = "The reviewed collector adapter supplies the authorization boundary."
    )]
    pub(super) async fn retire_pack_locked(
        &self,
        mut catalog: Catalog,
        exclusion: PackExclusion,
        expected_index: [u8; 32],
        marked: &BTreeSet<[u8; 32]>,
    ) -> Result<(), StoreFailure> {
        self.write_layout_locked().await?;
        let exclusions = catalog.exclusions.as_mut().ok_or_else(unsupported)?;
        match exclusions.binary_search_by_key(&exclusion.pack_id, |entry| entry.pack_id) {
            Ok(position) if exclusions[position] == exclusion => return Ok(()),
            // Recovery must separately qualify a fresh cycle; silently replacing
            // an active incarnation would let stale trash authorize deletion.
            Ok(_) => return Err(unsupported()),
            Err(position) => exclusions.insert(position, exclusion.clone()),
        }
        let inventory = catalog
            .inventory
            .as_ref()
            .and_then(|entries| {
                entries
                    .iter()
                    .find(|entry| entry.pack_id == exclusion.pack_id)
            })
            .ok_or_else(unsupported)?;
        if inventory.index_hash != expected_index {
            return Err(files::layout_corrupt());
        }
        let (_, index) = self.verified_container(inventory).await?;
        let (_, entries) = terrane_core::pack_format::decode_detached_index(&index)
            .map_err(|_| files::layout_corrupt())?;
        if entries.iter().any(|entry| marked.contains(&entry.hash)) {
            return Err(unsupported());
        }
        self.publish_retirement(catalog, &exclusion, false).await
    }

    /// Clears only the exact active incarnation while preserving newer placements.
    ///
    /// # Errors
    /// Rejects unknown completeness, unavailable inventory or retained bytes,
    /// corrupt artifacts, and failed generation publication.
    #[allow(
        dead_code,
        reason = "The reviewed collector adapter supplies the authorization boundary."
    )]
    pub(super) async fn restore_pack_locked(
        &self,
        mut catalog: Catalog,
        exclusion: &PackExclusion,
    ) -> Result<bool, StoreFailure> {
        self.write_layout_locked().await?;
        let exclusions = catalog.exclusions.as_mut().ok_or_else(unsupported)?;
        let Ok(position) =
            exclusions.binary_search_by_key(&exclusion.pack_id, |entry| entry.pack_id)
        else {
            return Ok(false);
        };
        if &exclusions[position] != exclusion {
            return Ok(false);
        }
        let inventory = catalog
            .inventory
            .as_ref()
            .and_then(|entries| {
                entries
                    .iter()
                    .find(|entry| entry.pack_id == exclusion.pack_id)
            })
            .ok_or_else(unsupported)?;
        // Restore never promises retained bytes without verifying their exact
        // immutable pair. It does not create membership for imported-only bodies.
        self.verified_container(inventory).await?;
        exclusions.remove(position);
        self.publish_retirement(catalog, exclusion, true).await?;
        Ok(true)
    }

    async fn publish_retirement(
        &self,
        catalog: Catalog,
        exclusion: &PackExclusion,
        restore: bool,
    ) -> Result<(), StoreFailure> {
        self.write_layout_locked().await?;
        let generation = self.next_generation(&catalog).await?;
        let mut shards = Vec::new();
        for previous in &catalog.shards {
            let mut records =
                terrane_core::pack_format::decode_shard(&previous.encode(), previous.shard())
                    .map_err(|_| files::layout_corrupt())?;
            for record in &mut records {
                if record.pack != exclusion.pack_id {
                    continue;
                }
                if restore && record.state == RecordState::Tombstone as u8 {
                    record.state = RecordState::Live as u8;
                } else if !restore && record.state == RecordState::Live as u8 {
                    record.state = RecordState::Tombstone as u8;
                }
            }
            shards.push(
                MergedShard::decode(
                    &terrane_core::pack_format::encode_shard(&records),
                    generation,
                    previous.shard(),
                )
                .map_err(|_| files::layout_corrupt())?,
            );
        }
        self.publish_shards(catalog, generation, &shards).await
    }
}

fn unsupported() -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Unsupported)
}
