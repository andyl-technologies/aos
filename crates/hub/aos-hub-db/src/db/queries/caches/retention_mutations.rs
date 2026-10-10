//! Retention mutations in the caches capability.

use super::*;

impl Database {
    /// Protects a verified snapshot while indexing or a response is in flight.
    ///
    /// A successful registry-presence transaction replaces this transient
    /// protection with durable registry/placement references. Expiration makes
    /// an interrupted request or crashed process self-cleaning.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid snapshot metadata or a database failure.
    pub async fn lease_image_snapshot(
        &self,
        lease_id: &str,
        digest: &str,
        byte_size: i64,
        expires_at: i64,
    ) -> Result<()> {
        if lease_id.is_empty()
            || lease_id.len() > 64
            || digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || byte_size <= 0
            || expires_at <= unix_now()
        {
            bail!("invalid image snapshot lease identity, digest, size, or expiry");
        }
        self.backend
            .batch(&[
                Statement::new(
                    "INSERT INTO image_snapshots(digest, byte_size, state, created_at)
                     VALUES (?1, ?2, 'live', ?3)
                     ON CONFLICT(digest) DO UPDATE SET
                       state = 'live'
                     WHERE image_snapshots.byte_size = excluded.byte_size",
                    vals![digest, byte_size, unix_now()].to_vec(),
                ),
                Statement::new(
                    "INSERT INTO image_snapshot_leases(lease_id, digest, expires_at)
                     SELECT ?1, digest, ?3 FROM image_snapshots
                     WHERE digest = ?2 AND byte_size = ?4
                       AND NOT EXISTS (SELECT 1
                         FROM image_snapshot_references reference
                         JOIN oci_gc_candidates candidate
                           ON candidate.registry_id = reference.registry_id
                          AND candidate.object_key = reference.object_key
                         JOIN oci_gc_runs run ON run.id = candidate.run_id
                         WHERE reference.digest = image_snapshots.digest
                           AND run.state = 'applying'
                           AND candidate.state IN('deleting', 'physically_absent'))",
                    vals![lease_id, digest, expires_at, byte_size].to_vec(),
                ),
            ])
            .await?;
        let leased = self
            .backend
            .query_opt(
                "SELECT 1 FROM image_snapshot_leases
                 WHERE lease_id = ?1 AND digest = ?2",
                &vals![lease_id, digest],
            )
            .await?
            .is_some();
        if !leased {
            bail!("image snapshot digest was already recorded with a different size");
        }
        Ok(())
    }
}
