//! Durable expiry and physical-cleanup reconciliation for OCI sessions.
//!
//! Terminal database state is authoritative. Physical staging deletion is
//! exact-placement, idempotent work which remains pending across crashes.

use super::*;

impl Database {
    /// Expires one overdue nonterminal upload and releases reserved quota.
    ///
    /// # Errors
    ///
    /// Returns an error when the upload is not overdue/nonterminal or on
    /// database failure.
    pub async fn expire_oci_upload(&self, upload_id: &str, now: i64) -> Result<()> {
        self.backend
            .checked_batch(&release_upload_statements(
                upload_id, None, None, None, now, "failed", true, true,
            ))
            .await
            .context("expiring OCI upload")
    }

    /// Expires a bounded page of overdue upload sessions.
    ///
    /// Terminalization releases quota and records pending physical cleanup in
    /// one transaction. A concurrent completion may win its version fence; in
    /// that case the now-terminal record is left for the same cleanup pass.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid bounds or a database failure that cannot
    /// be explained by a concurrent terminal transition.
    pub async fn expire_due_oci_uploads(&self, now: i64, limit: u32) -> Result<u32> {
        if now <= 0 || limit == 0 || limit > 1_000 {
            bail!("OCI upload expiry bounds are invalid");
        }
        let rows = self
            .backend
            .query(
                "SELECT id FROM oci_upload_sessions
                 WHERE state IN('active', 'completing') AND expires_at <= ?1
                 ORDER BY expires_at, id LIMIT ?2",
                &vals![now, i64::from(limit)],
            )
            .await?;
        let mut expired = 0_u32;
        for row in rows {
            let upload_id = row.get::<String>(0)?;
            if let Err(error) = self.expire_oci_upload(&upload_id, now).await {
                let still_due = self
                    .backend
                    .query_opt(
                        "SELECT 1 FROM oci_upload_sessions
                         WHERE id = ?1 AND state IN('active', 'completing')
                           AND expires_at <= ?2",
                        &vals![upload_id, now],
                    )
                    .await?
                    .is_some();
                if still_due {
                    return Err(error).context("expiring overdue OCI upload page");
                }
                continue;
            }
            expired = expired.saturating_add(1);
        }
        Ok(expired)
    }

    /// Fails a bounded page of overdue publication sessions and releases all
    /// owned upload reservations atomically.
    ///
    /// A publication with a live child completion lease is deferred until that
    /// lease expires. This prevents the publication sweep from invalidating a
    /// finalizer which still owns durable materialization work.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid bounds or an unrecoverable database
    /// failure. Concurrent publication completion is treated as progress.
    pub async fn expire_due_oci_publications(&self, now: i64, limit: u32) -> Result<u32> {
        if now <= 0 || limit == 0 || limit > 1_000 {
            bail!("OCI publication expiry bounds are invalid");
        }
        let rows = self
            .backend
            .query(
                "SELECT publication.id, publication.resource_version
                 FROM oci_publication_sessions publication
                 WHERE publication.state IN('preparing', 'committing')
                   AND publication.expires_at <= ?1
                   AND NOT EXISTS (SELECT 1 FROM oci_upload_sessions upload
                     WHERE upload.publication_id = publication.id
                       AND upload.state IN('active', 'completing')
                       AND upload.expires_at > ?1)
                 ORDER BY publication.expires_at, publication.id LIMIT ?2",
                &vals![now, i64::from(limit)],
            )
            .await?;
        let mut expired = 0_u32;
        for row in rows {
            let publication_id = row.get::<String>(0)?;
            let resource_version = row.get::<i64>(1)?;
            let statements = vec![
                Statement::new(
                    "UPDATE org_usage SET
                       used_bytes = CASE WHEN used_bytes - COALESCE((SELECT SUM(reserved_bytes)
                         FROM oci_quota_reservations reservation
                         JOIN oci_upload_sessions upload
                           ON upload.quota_reservation_id = reservation.id
                         WHERE upload.publication_id = ?1
                           AND reservation.state = 'reserved'), 0) < 0
                         THEN 0 ELSE used_bytes - COALESCE((SELECT SUM(reserved_bytes)
                         FROM oci_quota_reservations reservation
                         JOIN oci_upload_sessions upload
                           ON upload.quota_reservation_id = reservation.id
                         WHERE upload.publication_id = ?1
                           AND reservation.state = 'reserved'), 0) END,
                       object_count = CASE WHEN object_count - COALESCE((SELECT SUM(reserved_objects)
                         FROM oci_quota_reservations reservation
                         JOIN oci_upload_sessions upload
                           ON upload.quota_reservation_id = reservation.id
                         WHERE upload.publication_id = ?1
                           AND reservation.state = 'reserved'), 0) < 0
                         THEN 0 ELSE object_count - COALESCE((SELECT SUM(reserved_objects)
                         FROM oci_quota_reservations reservation
                         JOIN oci_upload_sessions upload
                           ON upload.quota_reservation_id = reservation.id
                         WHERE upload.publication_id = ?1
                           AND reservation.state = 'reserved'), 0) END,
                       updated_at = ?2
                     WHERE org_id = (SELECT registry.org_id
                       FROM oci_publication_sessions publication
                       JOIN registries registry ON registry.id = publication.registry_id
                       WHERE publication.id = ?1
                         AND publication.resource_version = ?3
                         AND publication.state IN('preparing', 'committing')
                         AND publication.expires_at <= ?2)",
                    vals![publication_id, now, resource_version],
                )
                .expecting(1),
                Statement::new(
                    "UPDATE oci_quota_reservations SET state = 'released', updated_at = ?2
                     WHERE state = 'reserved' AND id IN
                       (SELECT upload.quota_reservation_id FROM oci_upload_sessions upload
                        WHERE upload.publication_id = ?1
                          AND upload.state IN('active', 'completing'))",
                    vals![publication_id, now],
                )
                .unchecked(),
                Statement::new(
                    "DELETE FROM oci_blob_claims WHERE upload_id IN
                       (SELECT id FROM oci_upload_sessions WHERE publication_id = ?1)",
                    vals![publication_id],
                )
                .unchecked(),
                Statement::new(
                    "UPDATE oci_upload_sessions SET state = 'failed', finished_at = ?2,
                       cleanup_state = CASE WHEN EXISTS
                         (SELECT 1 FROM oci_upload_chunks chunk
                          WHERE chunk.upload_id = oci_upload_sessions.id)
                         THEN 'pending' ELSE 'complete' END,
                       cleanup_finished_at = CASE WHEN EXISTS
                         (SELECT 1 FROM oci_upload_chunks chunk
                          WHERE chunk.upload_id = oci_upload_sessions.id)
                         THEN NULL ELSE ?2 END,
                       resource_version = resource_version + 1
                     WHERE publication_id = ?1 AND state IN('active', 'completing')
                       AND expires_at <= ?2",
                    vals![publication_id, now],
                )
                .unchecked(),
                Statement::new(
                    "UPDATE oci_publication_sessions SET state = 'failed',
                       resource_version = resource_version + 1
                     WHERE id = ?1 AND resource_version = ?3
                       AND state IN('preparing', 'committing') AND expires_at <= ?2
                       AND NOT EXISTS (SELECT 1 FROM oci_upload_sessions upload
                         WHERE upload.publication_id = oci_publication_sessions.id
                           AND upload.state IN('active', 'completing'))",
                    vals![publication_id, now, resource_version],
                )
                .expecting(1),
            ];
            if let Err(error) = self.backend.checked_batch(&statements).await {
                let still_due = self
                    .backend
                    .query_opt(
                        "SELECT 1 FROM oci_publication_sessions
                         WHERE id = ?1 AND resource_version = ?2
                           AND state IN('preparing', 'committing') AND expires_at <= ?3",
                        &vals![publication_id, resource_version, now],
                    )
                    .await?
                    .is_some();
                if still_due {
                    return Err(error).context("expiring overdue OCI publication page");
                }
                continue;
            }
            expired = expired.saturating_add(1);
        }
        Ok(expired)
    }

    /// Lists a bounded page of terminal uploads with pending staging cleanup.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid bounds, malformed durable upload state,
    /// non-contiguous chunks, or database failure.
    pub async fn oci_upload_cleanup_candidates(
        &self,
        limit: u32,
    ) -> Result<Vec<OciUploadCleanupRecord>> {
        if limit == 0 || limit > 1_000 {
            bail!("OCI upload cleanup bound is invalid");
        }
        let rows = self
            .backend
            .query(
                &format!(
                    "SELECT {OCI_UPLOAD_COLUMNS} FROM oci_upload_sessions
                     WHERE state IN('complete', 'cancelled', 'failed')
                       AND cleanup_state = 'pending'
                     ORDER BY finished_at, id LIMIT ?1"
                ),
                &vals![i64::from(limit)],
            )
            .await?;
        let mut candidates = Vec::with_capacity(rows.len());
        for row in rows {
            let upload = row_to_oci_upload(&row)?;
            let chunks = self.oci_upload_chunks(&upload.id).await?;
            candidates.push(OciUploadCleanupRecord { upload, chunks });
        }
        Ok(candidates)
    }

    /// Marks one terminal upload's staging cleanup durably complete.
    ///
    /// The caller must first confirm that every recorded key is absent from
    /// the upload's frozen placement revision. Exact retries return the current
    /// terminal record. Completion clears the physical locator fields so the
    /// immutable binding revision may be retired after no recovery work pins it.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid metadata, stale state/version, or database
    /// failure.
    pub async fn complete_oci_upload_cleanup(
        &self,
        upload_id: &str,
        expected_resource_version: i64,
        now: i64,
    ) -> Result<OciUploadRecord> {
        if upload_id.is_empty() || expected_resource_version < 1 || now <= 0 {
            bail!("OCI upload cleanup completion metadata is invalid");
        }
        let changed = self
            .backend
            .execute(
                "UPDATE oci_upload_sessions SET cleanup_state = 'complete',
                    cleanup_finished_at = COALESCE(cleanup_finished_at, ?3),
                    staging_placement_id = NULL,
                    staging_placement_resource_version = NULL,
                    staging_binding_id = NULL,
                    staging_binding_write_revision = NULL,
                    materialization_placement_id = NULL,
                    materialization_placement_resource_version = NULL,
                    materialization_binding_id = NULL,
                    materialization_binding_write_revision = NULL,
                    resource_version = resource_version + 1
                 WHERE id = ?1 AND resource_version = ?2
                   AND state IN('complete', 'cancelled', 'failed')
                   AND (cleanup_state = 'pending'
                     OR (cleanup_state = 'complete' AND
                       (staging_placement_id IS NOT NULL
                        OR materialization_placement_id IS NOT NULL)))",
                &vals![upload_id, expected_resource_version, now],
            )
            .await?;
        if changed == 0 {
            let existing = self
                .backend
                .query_opt(
                    &format!(
                        "SELECT {OCI_UPLOAD_COLUMNS} FROM oci_upload_sessions
                         WHERE id = ?1 AND state IN('complete', 'cancelled', 'failed')"
                    ),
                    &vals![upload_id],
                )
                .await?
                .as_ref()
                .map(row_to_oci_upload)
                .transpose()?;
            if existing
                .as_ref()
                .is_some_and(|upload| upload.cleanup_state == "complete")
            {
                return existing.context("completed OCI upload cleanup disappeared");
            }
            bail!("OCI upload cleanup state or version changed");
        }
        self.backend
            .query_opt(
                &format!("SELECT {OCI_UPLOAD_COLUMNS} FROM oci_upload_sessions WHERE id = ?1"),
                &vals![upload_id],
            )
            .await?
            .as_ref()
            .map(row_to_oci_upload)
            .transpose()?
            .context("cleaned OCI upload disappeared")
    }

    /// Reports whether an upload chunk row references one staging key.
    ///
    /// Ambiguous append failures call this before deleting an attempt-unique
    /// object, so a committed row can never lose its only physical bytes.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn oci_upload_references_staging_key(
        &self,
        upload_id: &str,
        staging_object_key: &str,
    ) -> Result<bool> {
        Ok(self
            .backend
            .query_opt(
                "SELECT 1 FROM oci_upload_chunks
                 WHERE upload_id = ?1 AND staging_object_key = ?2",
                &vals![upload_id, staging_object_key],
            )
            .await?
            .is_some())
    }
}
