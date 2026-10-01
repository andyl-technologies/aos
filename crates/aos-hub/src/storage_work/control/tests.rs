//! Bounded OCI control reads without enabling public body delivery on Native.

use std::sync::Arc;

use aos_hub_core::db::{Database, NewSurfacePlacementSpec, SurfaceTarget};
use aos_hub_core::fetch::SurfaceFetch as _;
use aos_hub_core::storage_work::{
    StorageBindingSnapshot, StorageObjectIdentity, StorageWorkKey, StorageWorkOperation,
    StorageWorkOutcome, StorageWorkResult, STORAGE_WORK_SIGNATURE_HEADER,
};
use axum::body::Bytes;
use axum::http::HeaderMap;
use base64::Engine as _;
use tokio::sync::Mutex;

use super::super::{HybridSurfaceFetch, RemoteStorageWorkClient};
use super::{MAX_CONTROL_BYTES, MAX_OCI_RANGE_BYTES};

const WORK_KEY: &[u8] = b"control-storage-test-key-with-thirty-two-bytes";

async fn surface(
    size: usize,
    changed_range_etag: bool,
) -> (
    HybridSurfaceFetch,
    Arc<Mutex<Vec<StorageWorkOperation>>>,
    tokio::task::JoinHandle<()>,
) {
    surface_with_binding(size, changed_range_etag, "deployment_r2", None).await
}

async fn surface_with_binding(
    size: usize,
    changed_range_etag: bool,
    binding_kind: &str,
    provider_version: Option<String>,
) -> (
    HybridSurfaceFetch,
    Arc<Mutex<Vec<StorageWorkOperation>>>,
    tokio::task::JoinHandle<()>,
) {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org_id = db
        .create_org("control-owner", "Control owner")
        .await
        .unwrap();
    let registry_id = if binding_kind == "deployment_r2" {
        db.register_registry("hybrid-control", &[], false)
            .await
            .unwrap()
    } else {
        db.create_managed_registry(org_id, "", "hybrid-control", "public", &[], false)
            .await
            .unwrap()
    };
    let binding = if binding_kind == "deployment_r2" {
        db.ensure_instance_default_binding("deployment_r2", None, Some("fleet-control"))
            .await
            .unwrap()
    } else {
        let owner = db.org_by_id(org_id).await.unwrap().unwrap();
        let binding_id = db
            .create_topology_binding(
                Some(org_id),
                "control-binding",
                &owner.stable_id,
                "primary",
                binding_kind,
                None,
                Some("fixture-bucket"),
                Some("binding-prefix"),
                Some("https"),
                Some("dns"),
                Some(b"storage.example.invalid"),
                Some(443),
                Some("fixture-region"),
                Some("public"),
            )
            .await
            .unwrap();
        db.binding(binding_id).await.unwrap().unwrap()
    };
    let placement = db
        .create_surface_placement(&NewSurfacePlacementSpec {
            surface: SurfaceTarget::Registry(registry_id),
            name: "primary".into(),
            binding_id: binding.id,
            prefix: "primary".into(),
            kind: "complete".into(),
            desired_state: "active".into(),
            hash_range: None,
            desired_read_enabled: true,
            read_order: 0,
            requires_conditional_writes: false,
        })
        .await
        .unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let server_requests = Arc::clone(&requests);
    let app = axum::Router::new().route(
        "/",
        axum::routing::post(move |headers: HeaderMap, body: Bytes| {
            let requests = Arc::clone(&server_requests);
            let provider_version = provider_version.clone();
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
                requests.lock().await.push(plan.operation.clone());
                let (source_bytes, outcome) = match &plan.operation {
                    StorageWorkOperation::Head { path } => (
                        0,
                        StorageWorkOutcome::Head {
                            object: StorageObjectIdentity {
                                provider_version,
                                key: plan.object_key(path).unwrap(),
                                size: size as u64,
                                etag: "\"initial-version\"".into(),
                            },
                        },
                    ),
                    StorageWorkOperation::InspectOciRange { path, start, end } => {
                        let bytes = vec![42; (end - start + 1) as usize];
                        (
                            bytes.len() as u64,
                            StorageWorkOutcome::OciRange {
                                source: StorageObjectIdentity {
                                    provider_version: None,
                                    key: plan.object_key(path).unwrap(),
                                    size: size as u64,
                                    etag: if changed_range_etag {
                                        "\"changed-version\""
                                    } else {
                                        "\"initial-version\""
                                    }
                                    .into(),
                                },
                                start: *start,
                                end: *end,
                                content_base64: base64::engine::general_purpose::STANDARD
                                    .encode(bytes),
                            },
                        )
                    }
                    StorageWorkOperation::HashOciRange {
                        path,
                        start,
                        end,
                        sha256_state,
                        ..
                    } => {
                        let bytes = vec![42; (end - start + 1) as usize];
                        let mut sha256_state = sha256_state.clone();
                        sha256_state.update(&bytes).unwrap();
                        (
                            bytes.len() as u64,
                            StorageWorkOutcome::OciRangeHashed {
                                source: StorageObjectIdentity {
                                    provider_version,
                                    key: plan.object_key(path).unwrap(),
                                    size: size as u64,
                                    etag: "\"initial-version\"".into(),
                                },
                                start: *start,
                                end: *end,
                                sha256_state,
                            },
                        )
                    }
                    _ => panic!("OCI control reads must use head and bounded ranges"),
                };
                axum::Json(StorageWorkResult {
                    plan_id: plan.plan_id,
                    placement_id: plan.placement_id,
                    placement_resource_version: plan.placement_resource_version,
                    binding_id: plan.binding_id,
                    binding_resource_version: plan.binding_resource_version,
                    source_bytes,
                    outcome,
                })
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let mut work =
        RemoteStorageWorkClient::new("https://worker.example", "deployment-1".into(), WORK_KEY)
            .unwrap();
    work.endpoint = format!("http://{address}/");
    if binding_kind != "deployment_r2" {
        let now = aos_hub_core::clock::now_unix_secs();
        let snapshot = StorageBindingSnapshot::from_binding(
            "deployment-1".into(),
            &binding,
            &[],
            now,
            now + 120,
        )
        .unwrap();
        work.published_bindings
            .write()
            .unwrap()
            .insert(binding.id, snapshot);
    }
    (
        HybridSurfaceFetch {
            db,
            placement,
            binding,
            work: Arc::new(work),
        },
        requests,
        server,
    )
}

fn path() -> String {
    format!("oci/blobs/sha256/{}", "a".repeat(64))
}

#[tokio::test]
async fn signed_inventory_head_requires_upload_versions_only_for_deployment_r2() {
    for binding_kind in ["s3", "r2", "deployment_r2"] {
        let (surface, requests, server) = surface_with_binding(10, false, binding_kind, None).await;

        let result = surface.inventory_head(&path()).await;
        if binding_kind == "deployment_r2" {
            assert!(result.unwrap_err().to_string().contains("upload version"));
        } else {
            let head = result.unwrap().unwrap();
            assert_eq!(head.size, 10);
            assert_eq!(head.strong_etag.as_deref(), Some("\"initial-version\""));
            assert_eq!(head.provider_version, None);
        }
        assert!(matches!(
            requests.lock().await.as_slice(),
            [StorageWorkOperation::Head { .. }]
        ));
        server.abort();
    }

    let (surface, requests, server) =
        surface_with_binding(10, false, "deployment_r2", Some("upload-v1".into())).await;

    let head = surface.inventory_head(&path()).await.unwrap().unwrap();
    assert_eq!(head.provider_version.as_deref(), Some("upload-v1"));
    assert_eq!(requests.lock().await.len(), 1);
    server.abort();
}

#[tokio::test]
async fn signed_external_inventory_hash_accepts_versionless_replies_and_fences_versions() {
    for binding_kind in ["s3", "r2"] {
        let (surface, requests, server) = surface_with_binding(10, false, binding_kind, None).await;

        let chunk = surface
            .inventory_hash_chunk_bounded(
                &path(),
                0,
                10,
                10,
                "\"initial-version\"",
                None,
                aos_hub_core::db::OciSha256State::initial(),
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(chunk.provider_version, None);
        assert_eq!(chunk.range, (0, 9));
        assert_eq!(chunk.sha256_state.total_bytes, 10);

        let error = surface
            .inventory_hash_chunk_bounded(
                &path(),
                0,
                10,
                10,
                "\"initial-version\"",
                Some("another-upload"),
                aos_hub_core::db::OciSha256State::initial(),
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("signed range or object"));
        let requests = requests.lock().await;
        assert_eq!(requests.len(), 2);
        assert!(matches!(
            &requests[0],
            StorageWorkOperation::HashOciRange {
                expected_provider_version: None,
                ..
            }
        ));
        server.abort();
    }
}

#[tokio::test]
async fn bounded_oci_control_queries_use_exact_ranges_and_keep_public_streams_disabled() {
    let size = MAX_OCI_RANGE_BYTES + 3;
    let (surface, requests, server) = surface(size, false).await;

    assert_eq!(
        surface.fetch_bounded(&path(), size).await.unwrap(),
        Some(vec![42; size])
    );
    assert!(surface.fetch_stream(&path(), None).await.is_err());
    let requests = requests.lock().await;
    assert_eq!(requests.len(), 3);
    assert!(
        matches!(&requests[1], StorageWorkOperation::InspectOciRange { start: 0, end, .. } if *end == MAX_OCI_RANGE_BYTES as u64 - 1)
    );
    assert!(
        matches!(&requests[2], StorageWorkOperation::InspectOciRange { start, end, .. } if *start == MAX_OCI_RANGE_BYTES as u64 && *end == size as u64 - 1)
    );
    server.abort();
}

#[tokio::test]
async fn bounded_oci_control_queries_reject_semantic_and_hard_limits_before_reading_bodies() {
    for (size, limit) in [(10, 9), (MAX_CONTROL_BYTES + 1, usize::MAX)] {
        let (surface, requests, server) = surface(size, false).await;

        assert!(surface.fetch_bounded(&path(), limit).await.is_err());
        assert!(matches!(
            requests.lock().await.as_slice(),
            [StorageWorkOperation::Head { .. }]
        ));
        server.abort();
    }
}

#[tokio::test]
async fn bounded_oci_control_queries_reject_changed_object_versions() {
    let (surface, requests, server) = surface(10, true).await;

    let error = surface.fetch_bounded(&path(), 10).await.unwrap_err();
    assert!(error.to_string().contains("changed during inspection"));
    assert_eq!(requests.lock().await.len(), 2);
    server.abort();
}
