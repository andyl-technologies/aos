//! Inventory mutations in the caches capability.

use super::*;

impl Database {
    /// Computes a canonical digest of one placement's complete observed inventory.
    ///
    /// The digest includes every active logical object on the placement's
    /// surface and the corresponding presence state, hash, and size. A missing
    /// presence row is represented explicitly, so two placements compare equal
    /// only when their complete keysets and byte evidence agree.
    ///
    /// # Errors
    ///
    /// Returns an error when the placement is missing, persisted evidence is
    /// malformed, JSON serialization fails, or the database query fails.
    pub async fn placement_inventory_digest(&self, placement_id: i64) -> Result<String> {
        use sha2::Digest as _;

        if self.surface_placement(placement_id).await?.is_none() {
            bail!("placement does not exist");
        }
        let rows = self
            .backend
            .query(
                "SELECT object.object_key, object.content_hash, object.size,
                        presence.state, presence.observed_hash, presence.observed_size
                   FROM surface_placements placement
                   JOIN surface_objects object
                     ON object.registry_id = placement.registry_id
                     OR object.cache_id = placement.cache_id
                   LEFT JOIN object_placements presence
                     ON presence.surface_object_id = object.id
                    AND presence.placement_id = placement.id
                  WHERE placement.id = ?1 AND object.lifecycle_state = 'active'
                  ORDER BY object.object_key, object.id",
                &vals![placement_id],
            )
            .await?;
        let mut evidence = Vec::with_capacity(rows.len());
        for row in rows {
            evidence.push((
                row.get::<String>(0)?,
                row.get::<Option<String>>(1)?,
                row.get::<Option<i64>>(2)?,
                row.get::<Option<String>>(3)?,
                row.get::<Option<String>>(4)?,
                row.get::<Option<i64>>(5)?,
            ));
        }
        Ok(hex::encode(sha2::Sha256::digest(serde_json::to_vec(
            &evidence,
        )?)))
    }
}
