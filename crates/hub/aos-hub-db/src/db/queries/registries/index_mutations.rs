//! Index mutations in the registries capability.

use super::*;

impl Database {
    /// Removes expired in-flight snapshot leases.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn prune_expired_image_snapshot_leases(&self) -> Result<u64> {
        Ok(self
            .backend
            .execute(
                "DELETE FROM image_snapshot_leases WHERE expires_at <= ?1",
                &vals![unix_now()],
            )
            .await?)
    }

    // -- index writes -------------------------------------------------------

    /// Replace a registry's entire index with a fresh snapshot, atomically.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure; the transaction rolls back.
    pub async fn apply_snapshot(&self, registry_id: i64, snapshot: &IndexSnapshot) -> Result<()> {
        self.apply_snapshot_from_placement(registry_id, snapshot, None)
            .await
    }

    /// Atomically applies an index and its exact signed-image placement evidence.
    ///
    /// Release, channel, index-state, and webhook visibility commit in the same
    /// transaction as the image objects proven present on `placement_id`.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid source, malformed snapshot or presence
    /// evidence, or database failure.
    pub async fn apply_snapshot_with_image_presence(
        &self,
        registry_id: i64,
        snapshot: &IndexSnapshot,
        placement_id: i64,
        objects: &[VerifiedRegistryImageObject],
        observed_at: i64,
    ) -> Result<()> {
        let mut expected = std::collections::BTreeMap::new();
        for release in &snapshot.release_images {
            for image in &release.images {
                if image.delivery.is_store_backed() {
                    continue;
                }
                for (key, digest, size) in [
                    (
                        image.delivery.object_key.as_str(),
                        image.delivery.sha256.as_str(),
                        image.delivery.byte_size,
                    ),
                    (
                        image
                            .delivery
                            .artifact_contract
                            .document
                            .object_key
                            .as_str(),
                        image.delivery.artifact_contract.document.sha256.as_str(),
                        image.delivery.artifact_contract.document.byte_size,
                    ),
                ] {
                    let size = i64::try_from(size)
                        .context("signed image object size exceeds database range")?;
                    if let Some((prior_digest, prior_size)) =
                        expected.insert(key.to_string(), (digest.to_string(), size))
                    {
                        anyhow::ensure!(
                            prior_digest == digest && prior_size == size,
                            "signed image snapshot assigns conflicting identities to object key '{key}'"
                        );
                    }
                }
            }
        }
        anyhow::ensure!(
            objects.len() == expected.len(),
            "signed image presence is not a complete snapshot"
        );
        let mut observed_keys = std::collections::BTreeSet::new();
        for object in objects {
            anyhow::ensure!(
                observed_keys.insert(object.object_key.as_str()),
                "signed image presence repeats object key '{}'",
                object.object_key
            );
            let Some((digest, size)) = expected.get(object.object_key.as_str()) else {
                bail!(
                    "signed image presence contains unknown object key '{}'",
                    object.object_key
                );
            };
            anyhow::ensure!(
                object.sha256 == *digest && object.byte_size == *size,
                "signed image presence does not match snapshot object '{}'",
                object.object_key
            );
            if let Some(row) = self
                .backend
                .query_opt(
                    "SELECT byte_size FROM image_snapshots WHERE digest = ?1",
                    &vals![object.sha256],
                )
                .await?
            {
                let existing_size: i64 = row.get(0)?;
                anyhow::ensure!(
                    existing_size == object.byte_size,
                    "image snapshot digest was already recorded with a different size"
                );
            }
        }
        self.apply_snapshot_transaction(
            registry_id,
            snapshot,
            Some(placement_id),
            Some((objects, observed_at)),
        )
        .await
    }

    /// Record an indexing failure without touching the last good index.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn mark_index_failed(&self, registry_id: i64, error: &str) -> Result<()> {
        self.backend
            .checked_batch(&[
                Self::registry_index_publication_guard(registry_id),
                Statement::new(
                    "INSERT INTO registry_index (registry_id, state, error)
             VALUES (?1, 'failed', ?2)
             ON CONFLICT(registry_id) DO UPDATE SET state = 'failed', error = excluded.error",
                    vals![registry_id, error],
                )
                .unchecked(),
            ])
            .await?;
        Ok(())
    }

    /// Records an indexing failure only if no newer index generation committed.
    ///
    /// A slow verification pass can overlap a later pass that successfully
    /// publishes a fresh snapshot. Its terminal error must not replace that
    /// newer success. The generation predicate makes that ordering check part
    /// of the same database statement as the state transition.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or while a registry publication is
    /// active.
    pub async fn mark_index_failed_if_generation(
        &self,
        registry_id: i64,
        expected_generation: i64,
        error: &str,
    ) -> Result<()> {
        if expected_generation < 0 {
            bail!("expected registry index generation cannot be negative");
        }
        self.backend
            .checked_batch(&[
                Self::registry_index_publication_guard(registry_id),
                Statement::new(
                    "INSERT INTO registry_index (registry_id, state, error)
             VALUES (?1, 'failed', ?3)
             ON CONFLICT(registry_id) DO UPDATE SET
               state = 'failed', error = excluded.error
             WHERE registry_index.generation = ?2",
                    vals![registry_id, expected_generation, error],
                )
                .unchecked(),
            ])
            .await?;
        Ok(())
    }

    /// Mark a registry's index `pending`: it has no published surface yet (a
    /// freshly-created registry whose `info/refs` does not exist).
    ///
    /// This is a benign, non-error state — distinct from `failed` (a real,
    /// surfaced indexing error) — so a newly created registry reads as "nothing
    /// published yet" rather than broken. The `error` column is cleared.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn mark_index_pending(&self, registry_id: i64) -> Result<()> {
        self.backend
            .checked_batch(&[
                Self::registry_index_publication_guard(registry_id),
                Statement::new(
                    "INSERT INTO registry_index (registry_id, state, error)
             VALUES (?1, 'pending', NULL)
             ON CONFLICT(registry_id) DO UPDATE SET state = 'pending', error = NULL",
                    vals![registry_id],
                )
                .unchecked(),
            ])
            .await?;
        Ok(())
    }

    /// Mark a registry's index stale (surface unreachable), keeping the
    /// last good index.
    ///
    /// Like [`Database::mark_index_failed`] but for transient transport
    /// failures: the surface could not be *read*, as opposed to being
    /// read and found invalid.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn mark_index_stale(&self, registry_id: i64, error: &str) -> Result<()> {
        self.backend
            .checked_batch(&[
                Self::registry_index_publication_guard(registry_id),
                Statement::new(
                    "INSERT INTO registry_index (registry_id, state, error)
             VALUES (?1, 'stale', ?2)
             ON CONFLICT(registry_id) DO UPDATE SET state = 'stale', error = excluded.error",
                    vals![registry_id, error],
                )
                .unchecked(),
            ])
            .await?;
        Ok(())
    }

    // -- index reads --------------------------------------------------------

    /// The index status for a registry.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn index_status(&self, registry_id: i64) -> Result<Option<IndexStatus>> {
        self.backend
            .query_opt(
                "SELECT state, error, last_indexed_commit, name, description, readme, indexed_at,
                        generation, content_digest, support_json
                 FROM registry_index WHERE registry_id = ?1",
                &vals![registry_id],
            )
            .await
            .context("loading index status")?
            .map(|row| {
                // A policy that no longer parses is treated as absent rather
                // than failing every page; the indexer validated it when it
                // was written, so this only guards against a schema change.
                let support = row
                    .get::<Option<String>>(9)?
                    .and_then(|json| serde_json::from_str(&json).ok());
                Ok(IndexStatus {
                    state: row.get(0)?,
                    error: row.get(1)?,
                    last_indexed_commit: row.get(2)?,
                    name: row.get(3)?,
                    description: row.get(4)?,
                    readme: row.get(5)?,
                    support,
                    indexed_at: row.get(6)?,
                    generation: row.get(7)?,
                    content_digest: row.get(8)?,
                })
            })
            .transpose()
    }

    /// Returns every snapshot digest tracked by durable GC state.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn known_image_snapshot_digests(&self) -> Result<std::collections::HashSet<String>> {
        Ok(self
            .backend
            .query("SELECT digest FROM image_snapshots", &[])
            .await?
            .iter()
            .map(|row| row.get(0))
            .collect::<Result<_>>()?)
    }

    /// Reports whether a snapshot already has durable registry-placement roots.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn image_snapshot_has_references(&self, digest: &str) -> Result<bool> {
        Ok(self
            .backend
            .query_opt(
                "SELECT 1 FROM image_snapshot_references WHERE digest = ?1 LIMIT 1",
                &vals![digest],
            )
            .await?
            .is_some())
    }

    /// Forgets a physically deleted snapshot only while it remains unreferenced.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn forget_collectible_image_snapshot(&self, digest: &str) -> Result<bool> {
        let now = unix_now();
        Ok(self
            .backend
            .execute(
                "DELETE FROM image_snapshots
                 WHERE digest = ?1 AND NOT EXISTS (
                   SELECT 1 FROM image_snapshot_references reference
                   WHERE reference.digest = image_snapshots.digest)
                   AND NOT EXISTS (
                     SELECT 1 FROM staged_release_objects staged_object
                     JOIN staged_release_revisions staged_revision
                       ON staged_revision.registry_id = staged_object.registry_id
                      AND staged_revision.stage_id = staged_object.stage_id
                      AND staged_revision.revision = staged_object.revision
                     WHERE staged_object.sha256 = image_snapshots.digest
                       AND (staged_revision.retire_after IS NULL
                         OR staged_revision.retire_after > ?2))
                   AND NOT EXISTS (
                     SELECT 1 FROM image_snapshot_leases lease
                     WHERE lease.digest = image_snapshots.digest AND lease.expires_at > ?2)",
                &vals![digest, now],
            )
            .await?
            == 1)
    }
}
