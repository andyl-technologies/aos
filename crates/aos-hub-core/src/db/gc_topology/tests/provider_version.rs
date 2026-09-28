//! SQLite regressions for cache inventory and immutable R2 deletion versions.

use super::*;
use std::sync::{Arc, Mutex};

use crate::db::{BindingWriteRevisionRecord, SurfacePlacementRecord};
use crate::surface_write::{
    SurfaceDeleteOutcome, SurfaceDeletePrecondition, SurfaceWrite, SurfaceWriteProvider,
};

const R2_BINDING_SQL: &str = "UPDATE bindings SET kind = 'deployment_r2',
    local_root_path = NULL, object_bucket = 'cache-test-bucket', object_prefix = ''
    WHERE id = 1";

struct RecordingDeleter(Arc<Mutex<Option<SurfaceDeletePrecondition>>>);

#[async_trait::async_trait]
impl SurfaceWrite for RecordingDeleter {
    async fn write(&self, _path: &str, _bytes: &[u8]) -> Result<()> {
        bail!("test deleter cannot write")
    }

    async fn delete(&self, _path: &str) -> Result<()> {
        bail!("test requires an identity-checked delete")
    }

    async fn delete_if_matches(
        &self,
        _path: &str,
        expected: &SurfaceDeletePrecondition,
    ) -> Result<SurfaceDeleteOutcome> {
        *self.0.lock().unwrap() = Some(expected.clone());
        Ok(SurfaceDeleteOutcome::PreconditionFailed {
            detail: "replacement has a different upload incarnation".into(),
        })
    }
}

struct RecordingStorage(Arc<Mutex<Option<SurfaceDeletePrecondition>>>);

#[async_trait::async_trait]
impl SurfaceWriteProvider for RecordingStorage {
    async fn placement_writer(
        &self,
        _placement: &SurfacePlacementRecord,
    ) -> Result<Box<dyn SurfaceWrite>> {
        bail!("test storage cannot write")
    }

    async fn placement_writer_at_revision(
        &self,
        _placement: &SurfacePlacementRecord,
        _revision: &BindingWriteRevisionRecord,
    ) -> Result<Box<dyn SurfaceWrite>> {
        bail!("test storage cannot write")
    }

    async fn placement_deleter(
        &self,
        _placement: &SurfacePlacementRecord,
        expected_binding_resource_version: i64,
        delete_credential_generation: i64,
    ) -> Result<Box<dyn SurfaceWrite>> {
        assert_eq!(
            (
                expected_binding_resource_version,
                delete_credential_generation
            ),
            (1, 1)
        );
        Ok(Box::new(RecordingDeleter(Arc::clone(&self.0))))
    }
}

async fn enable_r2(db: &Database) {
    let statements = [
        R2_BINDING_SQL,
        "INSERT INTO binding_credential_revisions
         (binding_id, purpose, generation, secret_version_ref, validation_state,
          validated_at, credential_fingerprint, created_by, created_at)
         VALUES (1, 'write', 1, 'test-write-marker', 'valid', 1, 'test-write', 'test', 1)",
        "INSERT INTO binding_write_revisions
         (binding_id, revision, write_credential_version_ref, writes_supported,
          conditional_writes_supported, revision_fingerprint, capability_fingerprint,
          created_at, write_credential_generation)
         VALUES (1, 1, 'test-write-marker', 1, 1, 'test-write', 'test-capability', 1, 1)",
        "INSERT INTO binding_write_state (binding_id, current_write_revision, updated_at)
         VALUES (1, 1, 1)",
        "INSERT INTO oci_conditional_delete_capabilities
         (binding_id, binding_write_revision, binding_resource_version,
          capability_fingerprint, state, observed_at)
         VALUES (1, 1, 1, 'test-delete-capability', 'valid', 100)",
        "INSERT INTO surface_placement_observations
         (placement_id, state, completeness, observed_at, observation_version)
         VALUES (1, 'ready', 'complete', 20, 1)",
        "UPDATE cache_gc_state SET destructive_enabled = 1 WHERE cache_id = 1",
        "UPDATE cache_gc_policies SET unreferenced_grace_secs = 0 WHERE cache_id = 1",
    ];
    for sql in statements {
        db.backend.execute(sql, &[]).await.unwrap();
    }
}

async fn inventory_fixture(version: Option<&str>) -> Database {
    let db = gc_fixture().await;
    install_inventory_placement(&db).await;
    enable_r2(&db).await;
    db.begin_cache_inventory_topology(1, 2, 0, "inventory-owner", 10, 100)
        .await
        .unwrap();
    let listed = CacheInventoryListedObject {
        object_key: "nar/listed-version.nar".into(),
        observed_sha256: hex::encode(Sha256::digest(b"listed physical bytes")),
        observed_size: 21,
        etag: Some("listed-etag".into()),
        provider_version: version.map(str::to_string),
    };
    db.stage_cache_inventory_listed_objects(1, 2, 1, "inventory-owner", &[listed])
        .await
        .unwrap();
    let evidence = db
        .cache_inventory_listed_object_evidence(
            1,
            2,
            1,
            "inventory-owner",
            "nar/listed-version.nar",
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(evidence.3.as_deref(), version);
    stage_test_inventory_candidate_with_version(&db, 2, 1, "narinfo-hash", version).await;
    db.publish_cache_inventory_topology(
        1,
        2,
        "inventory-owner",
        "inventory-versioned",
        0,
        "publish-versioned",
        20,
    )
    .await
    .unwrap();
    db
}

#[tokio::test]
async fn cache_provider_version_flows_from_inventory_through_review_and_receipt() {
    let db = inventory_fixture(Some("upload-one")).await;
    let presence = db.reusable_placement_scan_evidence(1).await.unwrap();
    assert_eq!(presence.len(), 2);
    assert!(presence
        .iter()
        .all(|row| row.provider_version.as_deref() == Some("upload-one")));

    let plan = db
        .build_cache_gc_plan_topology(
            1,
            "actor-scope",
            "user:1",
            "plan-request",
            "request-digest",
            100,
            200,
        )
        .await
        .unwrap();
    assert_eq!(plan.actions.len(), 2);
    assert!(plan
        .actions
        .iter()
        .all(|action| action.expected_provider_version.as_deref() == Some("upload-one")));

    // A replacement with identical hash, size, and ETag still invalidates review.
    db.backend
        .execute(
            "UPDATE object_placements SET provider_version = 'upload-two' WHERE cache_id = 1",
            &[],
        )
        .await
        .unwrap();
    let apply = ApplyCacheGcPlan {
        plan_id: plan.plan_id.clone(),
        claim_id: "apply-versioned".into(),
        operation_id: "operation-versioned".into(),
        actor_scope_digest: "actor-scope".into(),
        confirmation_hash: plan.confirmation_hash.clone(),
        now: 101,
    };
    assert!(db.apply_cache_gc_plan_topology(&apply).await.is_err());
    db.backend.execute("UPDATE cache_gc_plan_actions SET expected_provider_version = 'upload-two' WHERE cache_id = 1", &[]).await.unwrap();
    let tampered = db.apply_cache_gc_plan_topology(&apply).await.unwrap_err();
    assert!(format!("{tampered:#}").contains("digests"));
    db.backend.execute("UPDATE cache_gc_plan_actions SET expected_provider_version = 'upload-one' WHERE cache_id = 1", &[]).await.unwrap();
    db.backend
        .execute(
            "UPDATE object_placements SET provider_version = 'upload-one' WHERE cache_id = 1",
            &[],
        )
        .await
        .unwrap();
    db.apply_cache_gc_plan_topology(&apply).await.unwrap();

    let jobs = db
        .list_cache_gc_deletion_jobs_topology(1, Some("operation-versioned"))
        .await
        .unwrap();
    assert_eq!(jobs.len(), 2);
    let narinfo = jobs.iter().find(|job| job.phase == "narinfo").unwrap();
    assert_eq!(
        narinfo.expected_provider_version.as_deref(),
        Some("upload-one")
    );
    db.claim_cache_gc_deletion_job(
        1,
        &narinfo.job_id,
        narinfo.resource_version,
        "delete-versioned",
        102,
    )
    .await
    .unwrap();
    let receipt = db
        .object_deletion_attempt_receipt("delete-versioned")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        receipt.expected_provider_version.as_deref(),
        Some("upload-one")
    );

    // Later observations cannot rewrite the durable backend request.
    db.backend
        .execute(
            "UPDATE object_placements SET provider_version = 'upload-three' WHERE cache_id = 1",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(
        db.current_object_deletion_attempt_receipt(1, &narinfo.job_id)
            .await
            .unwrap()
            .unwrap()
            .expected_provider_version,
        receipt.expected_provider_version
    );

    let recorded = Arc::new(Mutex::new(None));
    let controller = crate::gc_controller::CacheGcDeletionController::new(
        Arc::new(db),
        Arc::new(RecordingStorage(Arc::clone(&recorded))),
    );
    let stats = controller.run_due(103, 10).await.unwrap();
    assert_eq!(stats.failed, 1);
    assert_eq!(
        recorded
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .expected_provider_version
            .as_deref(),
        Some("upload-one")
    );
}

#[tokio::test]
async fn legacy_r2_inventory_requires_rescan_before_creating_actions() {
    let db = inventory_fixture(None).await;

    let error = db
        .build_cache_gc_plan_topology(
            1,
            "actor-scope",
            "user:1",
            "legacy-request",
            "request-digest",
            100,
            200,
        )
        .await
        .unwrap_err();

    assert!(format!("{error:#}").contains("rescan complete inventory"));
    let count: i64 = db
        .backend
        .query_opt("SELECT COUNT(*) FROM cache_gc_plans", &[])
        .await
        .unwrap()
        .unwrap()
        .get(0)
        .unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn legacy_r2_job_cannot_claim_or_invent_a_provider_version() {
    let db = deletion_fixture().await;
    db.backend.execute(R2_BINDING_SQL, &[]).await.unwrap();

    assert!(db
        .claim_cache_gc_deletion_job(1, "delete-job", 1, "legacy-attempt", 20)
        .await
        .is_err());
    assert!(db
        .object_deletion_attempt_receipt("legacy-attempt")
        .await
        .unwrap()
        .is_none());
    assert!(db
        .list_runnable_object_deletion_jobs(20, 10)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        db.object_deletion_job(1, "delete-job")
            .await
            .unwrap()
            .unwrap()
            .state,
        "pending"
    );
}

#[tokio::test]
async fn legacy_r2_response_finalization_and_terminal_replay_remain_safe() {
    let db = deletion_fixture().await;
    let claimed = db
        .claim_cache_gc_deletion_job(1, "delete-job", 1, "legacy-response", 20)
        .await
        .unwrap();
    db.record_object_deletion_attempt_response(&RecordObjectDeletionAttemptResponse {
        request_id: "legacy-response".into(),
        cache_id: 1,
        job_id: "delete-job".into(),
        outcome: "not_found".into(),
        response_etag: None,
        response_hash: None,
        response_size: None,
        error_class: None,
        response_detail: None,
        responded_at: 21,
    })
    .await
    .unwrap();
    db.backend.execute(R2_BINDING_SQL, &[]).await.unwrap();

    let completed = db
        .succeed_cache_gc_deletion_job(
            1,
            "delete-job",
            claimed.resource_version,
            "legacy-response",
            22,
        )
        .await
        .unwrap();
    let replay = db
        .succeed_cache_gc_deletion_job(
            1,
            "delete-job",
            claimed.resource_version,
            "legacy-response",
            22,
        )
        .await
        .unwrap();

    assert_eq!(completed, replay);
    assert_eq!(completed.state, "succeeded");
    assert_eq!(completed.expected_provider_version, None);
    assert_eq!(
        db.object_deletion_attempt_receipt("legacy-response")
            .await
            .unwrap()
            .unwrap()
            .expected_provider_version,
        None
    );
}
