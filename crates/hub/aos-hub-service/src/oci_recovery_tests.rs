//! OCI recovery integration fixtures across persistence and storage ports.

#[cfg(test)]
mod tests {
    macro_rules! vals {
        ($($v:expr),* $(,)?) => { vec![$( aos_hub_db::value::ToValue::to_value(&$v) ),*] };
    }
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use tokio::sync::Barrier;

    use crate::oci::recover_expired_oci_work;
    use crate::surface_write::{SurfaceWrite, SurfaceWriteProvider};
    use anyhow::{bail, Result};
    use aos_hub_db::db::*;
    use aos_hub_db::db::{SurfacePlacementRecord, SurfaceTarget};
    use aos_oci_types::{RepositoryName, Sha256Digest};

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
            revision: &aos_hub_db::db::BindingWriteRevisionRecord,
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
            .create_surface_placement(&aos_hub_db::db::NewSurfacePlacementSpec {
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
            .create_binding_write_revision(&aos_hub_db::db::NewBindingWriteRevision {
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
                &aos_hub_db::db::UpdateSurfacePlacementSpec {
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
            &aos_hub_db::db::UpdateSurfacePlacementSpec {
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
            .fixture_backend()
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
            .fixture_backend()
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
        db.fixture_backend()
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
            .fixture_backend()
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
