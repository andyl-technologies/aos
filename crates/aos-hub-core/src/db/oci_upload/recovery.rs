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

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use tokio::sync::Barrier;

    use super::*;
    use crate::db::{SurfacePlacementRecord, SurfaceTarget};
    use crate::oci::recover_expired_oci_work;
    use crate::surface_write::{SurfaceWrite, SurfaceWriteProvider};

    const NOW: i64 = 1_900_000_000;

    struct RecordingWriter {
        deleted: Arc<Mutex<Vec<String>>>,
        fail_deletes: Arc<AtomicBool>,
    }

    #[async_trait::async_trait]
    impl SurfaceWrite for RecordingWriter {
        async fn write(&self, _path: &str, _bytes: &[u8]) -> Result<()> {
            Ok(())
        }

        async fn delete(&self, path: &str) -> Result<()> {
            if self.fail_deletes.load(Ordering::SeqCst) {
                bail!("injected staging delete failure");
            }
            self.deleted.lock().unwrap().push(path.to_string());
            Ok(())
        }
    }

    struct RecordingWriters {
        placements: Arc<Mutex<Vec<i64>>>,
        deleted: Arc<Mutex<Vec<String>>>,
        fail_deletes: Arc<AtomicBool>,
    }

    #[async_trait::async_trait]
    impl SurfaceWriteProvider for RecordingWriters {
        async fn placement_writer(
            &self,
            placement: &SurfacePlacementRecord,
        ) -> Result<Box<dyn SurfaceWrite>> {
            self.placements.lock().unwrap().push(placement.id);
            Ok(Box::new(RecordingWriter {
                deleted: Arc::clone(&self.deleted),
                fail_deletes: Arc::clone(&self.fail_deletes),
            }))
        }

        async fn placement_writer_at_revision(
            &self,
            placement: &SurfacePlacementRecord,
            revision: &crate::db::BindingWriteRevisionRecord,
        ) -> Result<Box<dyn SurfaceWrite>> {
            assert_eq!(placement.binding_id, revision.binding_id);
            self.placement_writer(placement).await
        }

        async fn placement_deleter(
            &self,
            placement: &SurfacePlacementRecord,
            _expected_binding_resource_version: i64,
            _delete_credential_generation: i64,
        ) -> Result<Box<dyn SurfaceWrite>> {
            self.placement_writer(placement).await
        }
    }

    async fn upload_fixture(path: &Path) -> (Database, i64, i64, i64, i64) {
        let db = Database::open(path).await.unwrap();
        let org_id = db
            .create_org("oci-upload-recovery", "OCI Upload Recovery")
            .await
            .unwrap();
        let registry_id = db
            .create_managed_registry(org_id, "", "containers", "private", &[], false)
            .await
            .unwrap();
        let repository = db
            .ensure_oci_repository(registry_id, &RepositoryName::parse("aos").unwrap(), NOW)
            .await
            .unwrap();
        let owner = db.org_by_id(org_id).await.unwrap().unwrap();
        let binding_id = db
            .create_topology_binding(
                Some(org_id),
                "oci-upload-recovery-binding",
                &owner.stable_id,
                "oci-upload-recovery",
                "r2",
                None,
                Some("fixture-bucket"),
                Some("oci"),
                Some("https"),
                Some("dns"),
                Some(b"storage.example.invalid"),
                Some(443),
                Some("auto"),
                Some("private"),
            )
            .await
            .unwrap();
        let placement = db
            .create_surface_placement(&crate::db::NewSurfacePlacementSpec {
                surface: SurfaceTarget::Registry(registry_id),
                name: "primary".to_string(),
                binding_id,
                prefix: "oci".to_string(),
                kind: "complete".to_string(),
                desired_state: "active".to_string(),
                hash_range: None,
                desired_read_enabled: true,
                read_order: 0,
                requires_conditional_writes: false,
            })
            .await
            .unwrap();
        db.observe_surface_placement(placement.id, "ready", "complete", 1)
            .await
            .unwrap();
        let credential = db
            .set_binding_credential_revision(
                binding_id,
                "write",
                "secret://test/oci-upload-recovery-write/v1",
                0,
                &"0".repeat(64),
                "test",
            )
            .await
            .unwrap();
        db.validate_binding_credential_revision(
            binding_id,
            "write",
            credential.generation,
            "valid",
            None,
            credential.head_resource_version,
        )
        .await
        .unwrap();
        let revision = db
            .create_binding_write_revision(&crate::db::NewBindingWriteRevision {
                binding_id,
                write_credential_generation: credential.generation,
                writes_supported: true,
                conditional_writes_supported: true,
                revision_fingerprint: "oci-upload-recovery-revision".to_string(),
                capability_fingerprint: "oci-upload-recovery-capability".to_string(),
            })
            .await
            .unwrap();
        db.observe_binding_write_revision(binding_id, revision.revision, "valid", None, None)
            .await
            .unwrap();
        db.bind_surface_placement_write_capability(placement.id, revision.revision)
            .await
            .unwrap();
        (db, registry_id, repository.id, placement.id, binding_id)
    }

    fn begin_upload(registry_id: i64, repository_id: i64, idempotency_key: &str) -> BeginOciUpload {
        BeginOciUpload {
            registry_id,
            repository_id,
            publication_id: None,
            writer_id: "writer:recovery".to_string(),
            token_id: "token:recovery".to_string(),
            idempotency_key: idempotency_key.to_string(),
            expected_digest: None,
            expected_size: None,
            maximum_size: 1024,
            now: NOW,
            expires_at: NOW + 60,
        }
    }

    fn append_chunk(
        upload: &OciUploadRecord,
        placement_id: i64,
        binding_id: i64,
        ordinal: u32,
        bytes: &[u8],
        prior: &OciSha256State,
    ) -> AppendOciUploadChunk {
        let mut next_sha256 = prior.clone();
        next_sha256.update(bytes).unwrap();
        AppendOciUploadChunk {
            upload_id: upload.id.clone(),
            writer_id: upload.writer_id.clone(),
            token_id: upload.token_id.clone(),
            expected_resource_version: upload.resource_version,
            staging_placement_id: placement_id,
            staging_placement_resource_version: 1,
            staging_binding_id: binding_id,
            staging_binding_write_revision: 1,
            chunk: OciUploadChunkRecord {
                ordinal,
                byte_offset: upload.uploaded_size,
                byte_size: bytes.len() as u64,
                digest: Sha256Digest::digest(bytes),
                staging_object_key: format!("oci/uploads/{}/attempt-{ordinal}", upload.id),
                created_at: NOW + i64::from(ordinal) + 1,
            },
            next_sha256,
            now: NOW + i64::from(ordinal) + 1,
        }
    }

    #[tokio::test]
    async fn terminal_digest_and_staging_cleanup_survive_restart() {
        let temporary = tempfile::tempdir().unwrap();
        let database_path = temporary.path().join("hub.sqlite");
        let (db, registry_id, repository_id, placement_id, binding_id) =
            upload_fixture(&database_path).await;
        let upload = db
            .begin_oci_upload(&begin_upload(registry_id, repository_id, "restart"))
            .await
            .unwrap();
        let append = append_chunk(
            &upload,
            placement_id,
            binding_id,
            0,
            b"durable bytes",
            &upload.sha256,
        );
        let advanced = db.append_oci_upload_chunk(&append).await.unwrap();
        let digest = advanced.sha256.final_digest().unwrap();
        assert_eq!(advanced.staging_placement_id, Some(placement_id));
        assert_eq!(advanced.staging_placement_resource_version, Some(1));

        let claim = db
            .claim_oci_upload(&ClaimOciUpload {
                upload_id: advanced.id.clone(),
                writer_id: advanced.writer_id.clone(),
                token_id: advanced.token_id.clone(),
                expected_resource_version: advanced.resource_version,
                materialization_placement_id: placement_id,
                materialization_placement_resource_version: 1,
                materialization_binding_id: binding_id,
                materialization_binding_write_revision: 1,
                digest,
                now: NOW + 2,
                lease_expires_at: NOW + 32,
            })
            .await
            .unwrap();
        assert_eq!(claim, OciBlobClaimOutcome::Claimed);
        let claimed = db
            .oci_upload(
                &advanced.id,
                &advanced.writer_id,
                &advanced.token_id,
                NOW + 2,
            )
            .await
            .unwrap()
            .unwrap();
        assert!(db
            .cancel_oci_upload(
                &claimed.id,
                &claimed.writer_id,
                &claimed.token_id,
                claimed.resource_version,
                NOW + 3,
            )
            .await
            .is_err());
        drop(db);
        let restarted_after_claim = Database::open(&database_path).await.unwrap();
        let claimed_after_restart = restarted_after_claim
            .oci_upload(&claimed.id, &claimed.writer_id, &claimed.token_id, NOW + 3)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(claimed_after_restart.state, "completing");
        assert_eq!(claimed_after_restart.final_digest, Some(digest));
        let evidence = restarted_after_claim
            .record_oci_uploaded_object(
                registry_id,
                placement_id,
                digest,
                advanced.uploaded_size,
                "restart-etag",
                NOW + 3,
            )
            .await
            .unwrap();
        drop(restarted_after_claim);
        let restarted_after_evidence = Database::open(&database_path).await.unwrap();
        assert_eq!(
            restarted_after_evidence
                .oci_pending_uploaded_object_evidence(
                    registry_id,
                    placement_id,
                    digest,
                    advanced.uploaded_size,
                )
                .await
                .unwrap(),
            Some(evidence.clone())
        );
        let evidenced_upload = restarted_after_evidence
            .oci_upload(&claimed.id, &claimed.writer_id, &claimed.token_id, NOW + 3)
            .await
            .unwrap()
            .unwrap();
        assert!(restarted_after_evidence
            .cancel_oci_upload(
                &evidenced_upload.id,
                &evidenced_upload.writer_id,
                &evidenced_upload.token_id,
                evidenced_upload.resource_version,
                NOW + 3,
            )
            .await
            .is_err());
        let complete = CompleteOciUpload {
            upload_id: claimed.id.clone(),
            writer_id: claimed.writer_id.clone(),
            token_id: claimed.token_id.clone(),
            expected_resource_version: claimed.resource_version,
            digest,
            byte_size: claimed.uploaded_size,
            surface_object_id: evidence.surface_object_id,
            placement_id: evidence.placement_id,
            now: NOW + 4,
        };
        let completed = restarted_after_evidence
            .complete_oci_upload(&complete)
            .await
            .unwrap();
        assert_eq!(completed.final_digest, Some(digest));
        assert_eq!(completed.cleanup_state, "pending");
        let mut wrong = complete;
        wrong.expected_resource_version = completed.resource_version;
        wrong.digest = Sha256Digest::digest(b"wrong terminal replay");
        assert!(restarted_after_evidence
            .complete_oci_upload(&wrong)
            .await
            .is_err());

        drop(restarted_after_evidence);
        let restarted = Database::open(&database_path).await.unwrap();
        let candidates = restarted.oci_upload_cleanup_candidates(10).await.unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].upload.staging_placement_id,
            Some(placement_id)
        );
        assert_eq!(candidates[0].chunks, vec![append.chunk]);

        let current_placement = restarted
            .surface_placement(placement_id)
            .await
            .unwrap()
            .unwrap();
        let drained = restarted
            .update_surface_placement(
                placement_id,
                &crate::db::UpdateSurfacePlacementSpec {
                    expected_version: current_placement.resource_version,
                    desired_state: "draining".to_string(),
                    desired_read_enabled: false,
                    read_order: current_placement.read_order + 1,
                },
            )
            .await
            .unwrap();
        assert_ne!(
            drained.resource_version,
            completed.staging_placement_resource_version.unwrap()
        );
        assert!(restarted
            .placement_publication_write_revision(placement_id)
            .await
            .unwrap()
            .is_none());

        let placements = Arc::new(Mutex::new(Vec::new()));
        let deleted = Arc::new(Mutex::new(Vec::new()));
        let fail_deletes = Arc::new(AtomicBool::new(true));
        let writers = RecordingWriters {
            placements: Arc::clone(&placements),
            deleted: Arc::clone(&deleted),
            fail_deletes: Arc::clone(&fail_deletes),
        };
        assert!(recover_expired_oci_work(&restarted, &writers, NOW + 5, 10)
            .await
            .is_err());
        assert_eq!(
            restarted
                .oci_upload_cleanup_candidates(10)
                .await
                .unwrap()
                .len(),
            1
        );
        fail_deletes.store(false, Ordering::SeqCst);
        let summary = recover_expired_oci_work(&restarted, &writers, NOW + 6, 10)
            .await
            .unwrap();
        assert_eq!(summary.cleaned_uploads, 1);
        assert_eq!(
            *placements.lock().unwrap(),
            vec![placement_id, placement_id]
        );
        assert_eq!(
            *deleted.lock().unwrap(),
            vec![candidates[0].chunks[0].staging_object_key.clone()]
        );
        assert!(restarted
            .oci_upload_cleanup_candidates(10)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn cancel_and_claim_barrier_has_one_durable_owner() {
        let temporary = tempfile::tempdir().unwrap();
        let (db, registry_id, repository_id, placement_id, binding_id) =
            upload_fixture(&temporary.path().join("barrier.sqlite")).await;
        let db = Arc::new(db);
        let upload = db
            .begin_oci_upload(&begin_upload(registry_id, repository_id, "barrier"))
            .await
            .unwrap();
        let barrier = Arc::new(Barrier::new(3));
        let cancel_db = Arc::clone(&db);
        let cancel_barrier = Arc::clone(&barrier);
        let cancel_upload = upload.clone();
        let cancel = tokio::spawn(async move {
            cancel_barrier.wait().await;
            cancel_db
                .cancel_oci_upload(
                    &cancel_upload.id,
                    &cancel_upload.writer_id,
                    &cancel_upload.token_id,
                    cancel_upload.resource_version,
                    NOW + 1,
                )
                .await
        });
        let claim_db = Arc::clone(&db);
        let claim_barrier = Arc::clone(&barrier);
        let claim_upload = upload.clone();
        let claim = tokio::spawn(async move {
            claim_barrier.wait().await;
            claim_db
                .claim_oci_upload(&ClaimOciUpload {
                    upload_id: claim_upload.id.clone(),
                    writer_id: claim_upload.writer_id.clone(),
                    token_id: claim_upload.token_id.clone(),
                    expected_resource_version: claim_upload.resource_version,
                    materialization_placement_id: placement_id,
                    materialization_placement_resource_version: 1,
                    materialization_binding_id: binding_id,
                    materialization_binding_write_revision: 1,
                    digest: Sha256Digest::digest(b""),
                    now: NOW + 1,
                    lease_expires_at: NOW + 31,
                })
                .await
        });
        barrier.wait().await;
        let (cancel, claim) = tokio::join!(cancel, claim);
        let cancel = cancel.unwrap();
        let claim = claim.unwrap();
        assert_ne!(cancel.is_ok(), claim.is_ok());
        let current = db
            .oci_upload(&upload.id, &upload.writer_id, &upload.token_id, NOW + 2)
            .await
            .unwrap()
            .unwrap();
        match current.state.as_str() {
            "cancelled" => assert!(claim.is_err()),
            "completing" => assert!(cancel.is_err()),
            state => panic!("unexpected barrier terminal state {state}"),
        }
    }

    #[tokio::test]
    async fn writer_change_after_patch_preserves_status_cancel_and_cleanup() {
        let temporary = tempfile::tempdir().unwrap();
        let (db, registry_id, repository_id, placement_id, binding_id) =
            upload_fixture(&temporary.path().join("writer-change.sqlite")).await;
        let upload = db
            .begin_oci_upload(&begin_upload(registry_id, repository_id, "writer-change"))
            .await
            .unwrap();
        let append = append_chunk(
            &upload,
            placement_id,
            binding_id,
            0,
            b"frozen staging bytes",
            &upload.sha256,
        );
        let advanced = db.append_oci_upload_chunk(&append).await.unwrap();

        let placement = db.surface_placement(placement_id).await.unwrap().unwrap();
        db.update_surface_placement(
            placement_id,
            &crate::db::UpdateSurfacePlacementSpec {
                expected_version: placement.resource_version,
                desired_state: "draining".to_string(),
                desired_read_enabled: false,
                read_order: placement.read_order + 1,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            db.oci_upload(
                &advanced.id,
                &advanced.writer_id,
                &advanced.token_id,
                NOW + 2,
            )
            .await
            .unwrap()
            .unwrap()
            .state,
            "active"
        );

        let cancelled = db
            .cancel_oci_upload(
                &advanced.id,
                &advanced.writer_id,
                &advanced.token_id,
                advanced.resource_version,
                NOW + 2,
            )
            .await
            .unwrap();
        assert_eq!(cancelled.cleanup_state, "pending");
        let placements = Arc::new(Mutex::new(Vec::new()));
        let deleted = Arc::new(Mutex::new(Vec::new()));
        let writers = RecordingWriters {
            placements: Arc::clone(&placements),
            deleted: Arc::clone(&deleted),
            fail_deletes: Arc::new(AtomicBool::new(false)),
        };
        let summary = recover_expired_oci_work(&db, &writers, NOW + 3, 10)
            .await
            .unwrap();
        assert_eq!(summary.cleaned_uploads, 1);
        assert_eq!(*placements.lock().unwrap(), vec![placement_id]);
        assert_eq!(
            *deleted.lock().unwrap(),
            vec![append.chunk.staging_object_key]
        );
    }

    #[tokio::test]
    async fn claimed_upload_expiry_releases_before_retryable_physical_cleanup() {
        let temporary = tempfile::tempdir().unwrap();
        let database_path = temporary.path().join("claimed-expiry.sqlite");
        let (db, registry_id, repository_id, placement_id, binding_id) =
            upload_fixture(&database_path).await;
        let upload = db
            .begin_oci_upload(&begin_upload(registry_id, repository_id, "claimed-expiry"))
            .await
            .unwrap();
        let append = append_chunk(
            &upload,
            placement_id,
            binding_id,
            0,
            b"expire claimed bytes",
            &upload.sha256,
        );
        let advanced = db.append_oci_upload_chunk(&append).await.unwrap();
        let digest = advanced.sha256.final_digest().unwrap();
        db.claim_oci_upload(&ClaimOciUpload {
            upload_id: advanced.id.clone(),
            writer_id: advanced.writer_id.clone(),
            token_id: advanced.token_id.clone(),
            expected_resource_version: advanced.resource_version,
            materialization_placement_id: placement_id,
            materialization_placement_resource_version: 1,
            materialization_binding_id: binding_id,
            materialization_binding_write_revision: 1,
            digest,
            now: NOW + 2,
            lease_expires_at: NOW + 3,
        })
        .await
        .unwrap();
        drop(db);

        let restarted = Database::open(&database_path).await.unwrap();
        let placements = Arc::new(Mutex::new(Vec::new()));
        let deleted = Arc::new(Mutex::new(Vec::new()));
        let fail_deletes = Arc::new(AtomicBool::new(true));
        let writers = RecordingWriters {
            placements: Arc::clone(&placements),
            deleted: Arc::clone(&deleted),
            fail_deletes: Arc::clone(&fail_deletes),
        };
        assert!(recover_expired_oci_work(&restarted, &writers, NOW + 4, 10)
            .await
            .is_err());
        let failed = restarted
            .oci_upload(
                &advanced.id,
                &advanced.writer_id,
                &advanced.token_id,
                NOW + 4,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(failed.state, "failed");
        assert_eq!(failed.cleanup_state, "pending");
        let claim_count: i64 = restarted
            .backend
            .query_opt(
                "SELECT COUNT(*) FROM oci_blob_claims WHERE upload_id = ?1",
                &vals![advanced.id],
            )
            .await
            .unwrap()
            .unwrap()
            .get(0)
            .unwrap();
        assert_eq!(claim_count, 0);
        let reservation_state: String = restarted
            .backend
            .query_opt(
                "SELECT state FROM oci_quota_reservations WHERE id = ?1",
                &vals![failed.quota_reservation_id],
            )
            .await
            .unwrap()
            .unwrap()
            .get(0)
            .unwrap();
        assert_eq!(reservation_state, "released");

        fail_deletes.store(false, Ordering::SeqCst);
        let summary = recover_expired_oci_work(&restarted, &writers, NOW + 5, 10)
            .await
            .unwrap();
        assert_eq!(summary.cleaned_uploads, 1);
        assert_eq!(
            *placements.lock().unwrap(),
            vec![placement_id, placement_id]
        );
        assert_eq!(
            *deleted.lock().unwrap(),
            vec![append.chunk.staging_object_key]
        );
    }

    #[tokio::test]
    async fn losing_patch_probe_cannot_delete_winner_or_later_chunk() {
        let temporary = tempfile::tempdir().unwrap();
        let (db, registry_id, repository_id, placement_id, binding_id) =
            upload_fixture(&temporary.path().join("patch-race.sqlite")).await;
        let db = Arc::new(db);
        let upload = db
            .begin_oci_upload(&begin_upload(registry_id, repository_id, "patch-race"))
            .await
            .unwrap();
        let first = append_chunk(
            &upload,
            placement_id,
            binding_id,
            0,
            b"same",
            &upload.sha256,
        );
        let mut second = first.clone();
        second.chunk.staging_object_key = format!("oci/uploads/{}/attempt-0-second", upload.id);
        let barrier = Arc::new(Barrier::new(3));
        let left_db = Arc::clone(&db);
        let left_barrier = Arc::clone(&barrier);
        let left_input = first.clone();
        let left = tokio::spawn(async move {
            left_barrier.wait().await;
            left_db.append_oci_upload_chunk(&left_input).await
        });
        let right_db = Arc::clone(&db);
        let right_barrier = Arc::clone(&barrier);
        let right_input = second.clone();
        let right = tokio::spawn(async move {
            right_barrier.wait().await;
            right_db.append_oci_upload_chunk(&right_input).await
        });
        barrier.wait().await;
        let (left, right) = tokio::join!(left, right);
        let left = left.unwrap();
        let right = right.unwrap();
        assert_ne!(left.is_ok(), right.is_ok());
        let (winner, loser) = if left.is_ok() {
            (&first, &second)
        } else {
            (&second, &first)
        };
        let advanced = left.or(right).unwrap();
        let later = append_chunk(
            &advanced,
            placement_id,
            binding_id,
            1,
            b"later",
            &advanced.sha256,
        );
        db.append_oci_upload_chunk(&later).await.unwrap();

        assert!(db
            .oci_upload_references_staging_key(&upload.id, &winner.chunk.staging_object_key)
            .await
            .unwrap());
        assert!(db
            .oci_upload_references_staging_key(&upload.id, &later.chunk.staging_object_key)
            .await
            .unwrap());
        assert!(!db
            .oci_upload_references_staging_key(&upload.id, &loser.chunk.staging_object_key)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn publication_expiry_releases_children_and_schedules_cleanup() {
        let temporary = tempfile::tempdir().unwrap();
        let (db, registry_id, repository_id, placement_id, binding_id) =
            upload_fixture(&temporary.path().join("publication.sqlite")).await;
        let digest = Sha256Digest::digest(b"publication-expiry").to_string();
        db.backend
            .execute(
                "INSERT INTO oci_publication_sessions
                   (id, registry_id, repository_id, writer_id, token_id,
                    root_digest, catalog_digest, confirmation_hash,
                    topology_digest, required_placement_count, source_kind,
                    state, idempotency_key, expires_at, created_at, resource_version)
                 VALUES ('publication-expiry', ?1, ?2, 'writer:recovery',
                    'token:recovery', ?3, ?3, ?3, ?3, 1, 'manual',
                    'preparing', 'publication-expiry', ?4, ?5, 1)",
                &vals![registry_id, repository_id, digest, NOW + 10, NOW],
            )
            .await
            .unwrap();
        let mut begin = begin_upload(registry_id, repository_id, "publication-child");
        begin.publication_id = Some("publication-expiry".to_string());
        begin.expires_at = NOW + 5;
        let upload = db.begin_oci_upload(&begin).await.unwrap();
        let append = append_chunk(
            &upload,
            placement_id,
            binding_id,
            0,
            b"child",
            &upload.sha256,
        );
        db.append_oci_upload_chunk(&append).await.unwrap();

        assert_eq!(
            db.expire_due_oci_publications(NOW + 10, 10).await.unwrap(),
            1
        );
        let publication_state: String = db
            .backend
            .query_opt(
                "SELECT state FROM oci_publication_sessions WHERE id = 'publication-expiry'",
                &[],
            )
            .await
            .unwrap()
            .unwrap()
            .get(0)
            .unwrap();
        assert_eq!(publication_state, "failed");
        let candidates = db.oci_upload_cleanup_candidates(10).await.unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].upload.state, "failed");
        assert_eq!(candidates[0].chunks, vec![append.chunk]);
    }
}
