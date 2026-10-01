//! Regressions for frozen cleanup addresses and SQL fences before remote IO.

use super::super::{HybridSurfaceProvider, HybridSurfaceWrites};
use super::*;
use aos_hub_core::db::{
    NewSurfacePlacementSpec, RecordOciConditionalDeleteCapability, SurfaceTarget,
    UpdateSurfacePlacementSpec,
};
use aos_hub_core::fetch::SurfaceProvider as _;
use aos_hub_core::storage_work::{
    StorageObjectIdentity, StorageWorkKey, StorageWorkResult, STORAGE_WORK_SIGNATURE_HEADER,
};
use aos_hub_core::surface_write::SurfaceWriteProvider as _;
use axum::body::Bytes;
use axum::http::HeaderMap;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Mutex;

const WORK_KEY: &[u8] = b"frozen-storage-test-key-with-thirty-two-bytes";

async fn fixture() -> (Arc<Database>, FrozenSurfaceAccess) {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let registry_id = db
        .register_registry("frozen-hybrid", &[], false)
        .await
        .unwrap();
    let binding = db
        .ensure_instance_default_binding("deployment_r2", None, Some("fleet-frozen"))
        .await
        .unwrap();
    let placement = db
        .create_surface_placement(&NewSurfacePlacementSpec {
            surface: SurfaceTarget::Registry(registry_id),
            name: "current".into(),
            binding_id: binding.id,
            prefix: "current".into(),
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
    let mut observation = RecordOciConditionalDeleteCapability {
        binding_id: binding.id,
        binding_write_revision: revision,
        binding_resource_version: binding.resource_version,
        delete_credential_purpose: None,
        delete_credential_generation: None,
        capability_fingerprint: "hybrid-r2-object-guard-v1".into(),
        state: "valid".into(),
        expected_resource_version: None,
        observed_at: 10,
    };
    let capability = db
        .record_oci_conditional_delete_capability(&observation)
        .await
        .unwrap();
    let access = FrozenSurfaceAccess {
        registry_id,
        placement_id: placement.id,
        placement_name: placement.name.clone(),
        // A durable claim can retain a different address than today's row.
        placement_prefix: "frozen".into(),
        placement_resource_version: placement.resource_version,
        placement_write_spec_version: placement.write_spec_version,
        placement_observation_version: placement.observation_version.unwrap(),
        binding_id: binding.id,
        binding_resource_version: binding.resource_version,
        binding_write_revision: revision,
        delete_credential_purpose: None,
        delete_credential_generation: None,
        delete_capability_fingerprint: capability.capability_fingerprint,
        delete_capability_resource_version: capability.resource_version,
    };

    db.update_surface_placement(
        placement.id,
        &UpdateSurfacePlacementSpec {
            expected_version: placement.resource_version,
            desired_state: "offline".into(),
            desired_read_enabled: false,
            read_order: 0,
        },
    )
    .await
    .unwrap();
    observation.state = "invalid".into();
    observation.expected_resource_version = Some(capability.resource_version);
    observation.observed_at = 11;
    db.record_oci_conditional_delete_capability(&observation)
        .await
        .unwrap();

    (db, access)
}

fn client() -> RemoteStorageWorkClient {
    RemoteStorageWorkClient::new("https://worker.example", "deployment-1".into(), WORK_KEY).unwrap()
}

#[tokio::test]
async fn frozen_hybrid_cleanup_keeps_old_address_after_placement_and_capability_advance() {
    let (db, access) = fixture().await;
    let path = format!("oci/blobs/sha256/{}", "a".repeat(64));
    let objects = Arc::new(Mutex::new(BTreeMap::from([
        (format!("frozen/{path}"), 4_u64),
        (format!("current/{path}"), 7_u64),
    ])));
    let requests = Arc::new(AtomicUsize::new(0));
    let server_objects = Arc::clone(&objects);
    let server_requests = Arc::clone(&requests);
    let app = axum::Router::new().route(
        "/",
        axum::routing::post(move |headers: HeaderMap, body: Bytes| {
            let objects = Arc::clone(&server_objects);
            let requests = Arc::clone(&server_requests);
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
                requests.fetch_add(1, Ordering::SeqCst);
                assert_eq!(plan.placement_prefix, "frozen");
                let mut objects = objects.lock().await;
                let outcome = match &plan.operation {
                    StorageWorkOperation::Head { path } => {
                        let object_key = plan.object_key(path).unwrap();
                        match objects.get(&object_key) {
                            Some(size) => StorageWorkOutcome::Head {
                                object: StorageObjectIdentity {
                                    provider_version: Some("current-upload-v2".into()),
                                    key: object_key,
                                    etag: "\"frozen-etag\"".into(),
                                    size: *size,
                                },
                            },
                            None => StorageWorkOutcome::NotFound,
                        }
                    }
                    StorageWorkOperation::DeleteIfMatches {
                        path,
                        claim_id,
                        expected_etag,
                        expected_size,
                        expected_provider_version,
                        ..
                    } => {
                        assert_eq!(claim_id, &"b".repeat(32));
                        assert_eq!(
                            expected_provider_version.as_deref(),
                            Some("frozen-upload-v1")
                        );
                        assert_eq!(expected_etag, "\"frozen-etag\"");
                        let object_key = plan.object_key(path).unwrap();
                        assert_eq!(objects.remove(&object_key), Some(*expected_size));
                        StorageWorkOutcome::ObjectDeleted {
                            etag: expected_etag.clone(),
                        }
                    }
                    _ => panic!("cleanup must not send object bodies"),
                };
                axum::Json(StorageWorkResult {
                    plan_id: plan.plan_id,
                    placement_id: plan.placement_id,
                    placement_resource_version: plan.placement_resource_version,
                    binding_id: plan.binding_id,
                    binding_resource_version: plan.binding_resource_version,
                    source_bytes: 0,
                    outcome,
                })
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await });
    let mut work = client();
    work.endpoint = format!("http://{address}/");
    let work = Arc::new(work);

    let reads = HybridSurfaceProvider::new(Arc::clone(&db), Arc::clone(&work));
    let fetch = reads.frozen_placement_fetcher(&access).await.unwrap();
    assert_eq!(fetch.size(&path).await.unwrap(), Some(4));
    assert!(fetch.fetch(&path).await.is_err());

    let writes = HybridSurfaceWrites::new(db, work);
    let deleter = writes.frozen_placement_deleter(&access).await.unwrap();
    let expected = SurfaceDeletePrecondition {
        expected_provider_version: Some("frozen-upload-v1".into()),
        etag: Some("\"frozen-etag\"".into()),
        content_hash: Some(format!("sha256:{}", "a".repeat(64))),
        size: Some(4),
    };
    assert!(deleter.delete(&path).await.is_err());
    assert!(deleter.delete_if_matches(&path, &expected).await.is_err());
    assert!(deleter.write(&path, b"no writes").await.is_err());
    assert!(matches!(
        deleter
            .delete_if_matches_claimed(&path, &expected, &"b".repeat(32))
            .await
            .unwrap(),
        SurfaceDeleteOutcome::ConditionalDeleteAcknowledged { .. }
    ));
    assert_eq!(fetch.size(&path).await.unwrap(), None);
    assert_eq!(requests.load(Ordering::SeqCst), 3);
    assert_eq!(
        *objects.lock().await,
        BTreeMap::from([(format!("current/{path}"), 7)])
    );
    server.abort();
}

#[tokio::test]
async fn frozen_hybrid_cleanup_rejects_binding_drift_and_external_credentials_before_io() {
    let (db, access) = fixture().await;
    let work = Arc::new(client());
    let reads = HybridSurfaceProvider::new(Arc::clone(&db), Arc::clone(&work));
    let writes = HybridSurfaceWrites::new(Arc::clone(&db), Arc::clone(&work));
    let mut stale = access.clone();
    stale.binding_resource_version += 1;

    assert!(reads.frozen_placement_fetcher(&stale).await.is_err());
    assert!(writes.frozen_placement_deleter(&stale).await.is_err());
    stale = access.clone();
    stale.binding_write_revision += 100;
    assert!(writes.frozen_placement_deleter(&stale).await.is_err());
    stale = access;
    stale.delete_credential_purpose = Some("delete".into());
    stale.delete_credential_generation = Some(1);
    assert!(reads.frozen_placement_fetcher(&stale).await.is_err());
    assert!(writes.frozen_placement_deleter(&stale).await.is_err());
}
