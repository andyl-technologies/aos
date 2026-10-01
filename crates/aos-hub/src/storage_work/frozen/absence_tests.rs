//! Reviewed R2 absence reconciliation through the actual Native controller.

use super::super::{HybridSurfaceProvider, HybridSurfaceWrites};
use super::*;
use aos_hub_core::backend::SqlxBackend;
use aos_hub_core::db::{
    AppendOciProviderInventoryPage, ApplyOciGc, BeginOciProviderInventory,
    CompleteOciProviderInventory, GrantResource, NewSurfacePlacementSpec, PlanOciGc,
    RecordOciConditionalDeleteCapability, SurfaceTarget,
};
use aos_hub_core::oci_gc_controller::OciGcDeletionController;
use aos_hub_core::storage_work::{
    StorageWorkKey, StorageWorkResult, STORAGE_WORK_SIGNATURE_HEADER,
};
use aos_oci_types::Sha256Digest;
use axum::{
    body::Bytes,
    http::{HeaderMap, StatusCode},
};
use std::sync::atomic::{AtomicUsize, Ordering};

const WORK_KEY: &[u8] = b"frozen-absence-test-key-with-thirty-two-bytes";

async fn reviewed_absent_action() -> (Arc<Database>, sqlx::SqlitePool, String, String) {
    let backend = SqlxBackend::connect_sqlite(":memory:").await.unwrap();
    let pool = match &backend {
        SqlxBackend::Sqlite(pool) => pool.clone(),
        #[cfg(feature = "postgres")]
        SqlxBackend::Postgres(_) => panic!("SQLite fixture required"),
        #[cfg(feature = "mysql")]
        SqlxBackend::Mysql(_) => panic!("SQLite fixture required"),
    };
    let db = Arc::new(Database::with_backend(Box::new(backend)).await.unwrap());
    let org_id = db.create_org("absent-r2", "Absent R2").await.unwrap();
    db.add_org_usage(org_id, 10, 1).await.unwrap();
    let registry_id = db
        .create_managed_registry(org_id, "", "absent", "private", &[], false)
        .await
        .unwrap();
    let binding = db
        .ensure_instance_default_binding("deployment_r2", None, Some("absence-fixture"))
        .await
        .unwrap();
    let consumer_scope = db
        .registry_by_id(registry_id)
        .await
        .unwrap()
        .unwrap()
        .owner_scope_key;
    db.grant_consumer_scope(
        GrantResource::Binding {
            id: binding.id,
            stable_id: &binding.stable_id,
        },
        &consumer_scope,
        "explicit",
        "test",
        "absence-binding-grant",
    )
    .await
    .unwrap();
    let placement = db
        .create_surface_placement(&NewSurfacePlacementSpec {
            surface: SurfaceTarget::Registry(registry_id),
            name: "primary".into(),
            binding_id: binding.id,
            prefix: "reviewed-prefix".into(),
            kind: "complete".into(),
            desired_state: "active".into(),
            hash_range: None,
            desired_read_enabled: true,
            read_order: 0,
            requires_conditional_writes: false,
        })
        .await
        .unwrap();
    let placement = db
        .observe_surface_placement(placement.id, "ready", "complete", 1)
        .await
        .unwrap();
    let revision = db
        .binding_write_state(binding.id)
        .await
        .unwrap()
        .unwrap()
        .current_write_revision
        .unwrap();
    db.bind_surface_placement_write_capability(placement.id, revision)
        .await
        .unwrap();
    let now = aos_hub_core::clock::now_unix_secs();
    db.record_oci_conditional_delete_capability(&RecordOciConditionalDeleteCapability {
        binding_id: binding.id,
        binding_write_revision: revision,
        binding_resource_version: binding.resource_version,
        delete_credential_purpose: None,
        delete_credential_generation: None,
        capability_fingerprint: "hybrid-r2-object-guard-v1".into(),
        state: "valid".into(),
        expected_resource_version: None,
        observed_at: now,
    })
    .await
    .unwrap();

    // Catalog identity predates collection, while the sealed provider listing
    // contains no key. Review and execution still use their transaction APIs.
    let digest = Sha256Digest::digest(b"collect-me");
    let object_key = aos_hub_core::db::oci_blob_object_key(digest);
    sqlx::query(
        "INSERT INTO surface_objects
        (id, registry_id, object_key, object_kind, partition_key, content_hash,
         size, lifecycle_state, created_at, updated_at, resource_version)
        VALUES(301, ?1, ?2, 'immutable', zeroblob(32), ?3, 10, 'active', 1, 1, 1)",
    )
    .bind(registry_id)
    .bind(&object_key)
    .bind(digest.encoded())
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO oci_blobs
        (registry_id, digest, byte_size, media_type, surface_object_id, quota_bytes,
         lifecycle_state, created_at, updated_at, unreferenced_since)
        VALUES(?1, ?2, 10, 'application/octet-stream', 301, 10, 'active', 1, 1, 1)",
    )
    .bind(registry_id)
    .bind(digest.to_string())
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO oci_registry_state
        (registry_id, mutation_epoch, charged_bytes, charged_objects, updated_at)
        VALUES(?1, 0, 10, 1, 1)
        ON CONFLICT(registry_id) DO UPDATE SET charged_bytes = 10, charged_objects = 1",
    )
    .bind(registry_id)
    .execute(&pool)
    .await
    .unwrap();
    let inventory = db
        .begin_oci_provider_inventory(&BeginOciProviderInventory {
            registry_id,
            placement_id: placement.id,
            expected_placement_resource_version: placement.resource_version,
            expected_placement_observation_version: placement.observation_version.unwrap(),
            collector_id: "absence-collector".into(),
            collector_claim_token: "absence-inventory".into(),
            collector_lease_seconds: 100,
            idempotency_key: "empty-inventory".into(),
            now,
        })
        .await
        .unwrap();
    db.append_oci_provider_inventory_page(&AppendOciProviderInventoryPage {
        generation_id: inventory.id.clone(),
        collector_id: "absence-collector".into(),
        collector_claim_token: "absence-inventory".into(),
        expected_checkpoint_ordinal: 0,
        expected_provider_cursor: None,
        next_provider_cursor: None,
        last_listed_key: None,
        entries: Vec::new(),
        now,
        lease_seconds: 100,
    })
    .await
    .unwrap();
    db.complete_oci_provider_inventory(&CompleteOciProviderInventory {
        generation_id: inventory.id,
        collector_id: "absence-collector".into(),
        collector_claim_token: "absence-inventory".into(),
        expected_checkpoint_ordinal: 1,
        observed_at: now,
        now,
    })
    .await
    .unwrap();
    let plan = db
        .plan_oci_gc(&PlanOciGc {
            registry_id,
            actor_id: "absence-operator".into(),
            idempotency_key: "absence-plan".into(),
            expected_resource_version: 0,
            now,
        })
        .await
        .unwrap();
    let actions = db
        .list_oci_gc_placement_actions(&plan.id, None, 10, None)
        .await
        .unwrap();
    assert_eq!(actions.items.len(), 1);
    assert!(!actions.items[0].inventory_entry_present);
    assert_eq!(actions.items[0].expected_provider_version, None);
    db.apply_oci_gc(&ApplyOciGc {
        generation_id: plan.id.clone(),
        actor_id: "absence-operator".into(),
        idempotency_key: "absence-apply".into(),
        confirmation_hash: plan.confirmation_hash,
        now,
    })
    .await
    .unwrap();
    (db, pool, plan.id, object_key)
}

#[tokio::test]
async fn reviewed_absent_r2_action_uses_only_head_and_fenced_reads_cannot_finalize() {
    for pending_provider_effect in [false, true] {
        let (db, pool, run_id, object_key) = reviewed_absent_action().await;
        let requests = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&requests);
        let app = axum::Router::new().route(
            "/",
            axum::routing::post(move |headers: HeaderMap, body: Bytes| {
                let count = Arc::clone(&count);
                let object_key = object_key.clone();
                async move {
                    let key = StorageWorkKey::new(WORK_KEY).unwrap();
                    let plan = key
                        .verify_plan(
                            headers
                                .get(STORAGE_WORK_SIGNATURE_HEADER)
                                .unwrap()
                                .to_str()
                                .unwrap(),
                            &body,
                            "deployment-1",
                            aos_hub_core::clock::now_unix_secs(),
                        )
                        .unwrap();
                    assert_eq!(plan.placement_prefix, "reviewed-prefix");
                    assert_eq!(
                        plan.operation,
                        StorageWorkOperation::Head { path: object_key }
                    );
                    count.fetch_add(1, Ordering::SeqCst);
                    if pending_provider_effect {
                        return Err(StatusCode::CONFLICT);
                    }
                    Ok(axum::Json(StorageWorkResult {
                        plan_id: plan.plan_id,
                        placement_id: plan.placement_id,
                        placement_resource_version: plan.placement_resource_version,
                        binding_id: plan.binding_id,
                        binding_resource_version: plan.binding_resource_version,
                        source_bytes: 0,
                        outcome: StorageWorkOutcome::NotFound,
                    }))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await });
        let mut work =
            RemoteStorageWorkClient::new("https://worker.example", "deployment-1".into(), WORK_KEY)
                .unwrap();
        work.endpoint = format!("http://{address}/");
        let work = Arc::new(work);
        let surfaces = Arc::new(HybridSurfaceProvider::new(
            Arc::clone(&db),
            Arc::clone(&work),
        ));
        let writes = Arc::new(HybridSurfaceWrites::new(Arc::clone(&db), work));
        let controller = OciGcDeletionController::new(Arc::clone(&db), surfaces, writes);

        let result = controller
            .run_due("absence-worker", aos_hub_core::clock::now_unix_secs(), 1)
            .await
            .unwrap();
        assert_eq!(requests.load(Ordering::SeqCst), 1);
        assert_eq!(result.claimed, 1);
        assert_eq!(result.confirmed_absent, u64::from(!pending_provider_effect));
        assert_eq!(result.failed, u64::from(pending_provider_effect));
        let actions = db
            .list_oci_gc_placement_actions(&run_id, None, 10, None)
            .await
            .unwrap();
        assert_eq!(
            actions.items[0].state == "confirmed_absent",
            !pending_provider_effect
        );
        let evidence_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM oci_gc_deletion_evidence")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(evidence_count, i64::from(!pending_provider_effect));
        assert_eq!(
            result.finalized_candidates,
            u64::from(!pending_provider_effect)
        );
        // One candidate consumes this pass's maintenance bound. The following
        // pass releases the completed run without another provider request.
        if !pending_provider_effect {
            let finalized = controller
                .run_due("absence-worker", aos_hub_core::clock::now_unix_secs(), 1)
                .await
                .unwrap();
            assert_eq!(finalized.claimed, 0);
            assert_eq!(finalized.finalized_runs, 1);
            assert_eq!(requests.load(Ordering::SeqCst), 1);
        }
        server.abort();
    }
}
