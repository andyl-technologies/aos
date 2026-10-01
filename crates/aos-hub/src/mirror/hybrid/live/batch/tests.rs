//! Actual signed TLS controls through the production Native batch exchange.
//!
//! This peer supplies typed observations, not provider or runtime qualification.

use super::*;
use aos_hub_core::{db::*, storage_work::*};
use axum::{
    body::Body,
    extract::{Request, State},
    response::Response,
    routing::post,
    Router,
};
use live_metadata_batch::LiveMetadataObservation;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

const DEPLOYMENT: &str = "live-batch-fixture";
const KEY: &[u8] = b"live-batch-fixture-storage-work-key";

#[derive(Default)]
struct Peer {
    requests: Mutex<Vec<StorageWorkPlan>>,
    request_bytes: Mutex<Vec<usize>>,
    responses: Mutex<Vec<usize>>,
    active: AtomicUsize,
    peak: AtomicUsize,
    rewrite: bool,
    refuse: bool,
    budget: bool,
    oversized: bool,
    singleton_only: bool,
}

async fn capabilities(State(peer): State<Arc<Peer>>, request: Request) -> Response {
    let signature = request.headers()[STORAGE_WORK_SIGNATURE_HEADER]
        .to_str()
        .unwrap()
        .to_owned();
    let bytes = axum::body::to_bytes(request.into_body(), 4096)
        .await
        .unwrap();
    StorageWorkKey::new(KEY)
        .unwrap()
        .verify_body(&signature, &bytes)
        .unwrap();
    assert_eq!(bytes.as_ref(), STORAGE_CAPABILITIES_CHALLENGE);
    let mut operations: Vec<String> = [
        "head",
        "list_page",
        "inspect_sha256",
        "inspect_git_object",
        "inspect_git_objects",
        "filter_git_tree_entries_v1",
        "inspect_metadata",
        "inspect_metadata_objects",
        "inspect_documentation",
        "inspect_documentation_content",
        "inspect_oci_range",
        "hash_oci_range",
        "copy_object",
        "compose_oci_blob",
        "stage_oci_manifest",
        "delete_oci_staging",
        "delete_if_matches",
        "put_metadata",
        "put_probe",
        "delete_probe",
        "create_multipart",
        "complete_multipart",
        "abort_multipart",
        "credential_probe",
        "inspect_mirror_live_metadata_v1",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if !peer.singleton_only {
        operations.push(live_metadata_batch::OPERATION.into());
    }
    let body = serde_json::to_vec(&StorageCapabilities {
        version: 1,
        deployment_id: DEPLOYMENT.into(),
        binding_kind: "deployment_r2".into(),
        console_asset_version: Some(aos_hub_core::web::assets::asset_version().into()),
        r2_gc_incarnation_v1: true,
        operations,
        max_result_bytes: MAX_RESULT_BYTES,
        max_verify_source_bytes: MAX_VERIFY_SOURCE_BYTES,
    })
    .unwrap();
    Response::builder().body(Body::from(body)).unwrap()
}

async fn execute(State(peer): State<Arc<Peer>>, request: Request) -> Response {
    let signature = request.headers()[STORAGE_WORK_SIGNATURE_HEADER]
        .to_str()
        .unwrap()
        .to_owned();
    let body = axum::body::to_bytes(request.into_body(), MAX_PLAN_BYTES)
        .await
        .unwrap();
    let plan = StorageWorkKey::new(KEY)
        .unwrap()
        .verify_plan(
            &signature,
            &body,
            DEPLOYMENT,
            aos_hub_core::clock::now_unix_secs(),
        )
        .unwrap();
    peer.requests.lock().unwrap().push(plan.clone());
    peer.request_bytes.lock().unwrap().push(body.len());
    let active = peer.active.fetch_add(1, Ordering::SeqCst) + 1;
    peer.peak.fetch_max(active, Ordering::SeqCst);
    tokio::time::sleep(std::time::Duration::from_millis(15)).await;
    let outcome = match &plan.operation {
        StorageWorkOperation::InspectMirrorLiveMetadataBatch { targets } => {
            let mut items: Vec<_> = targets
                .iter()
                .enumerate()
                .map(|(index, target)| LiveMetadataObservation {
                    target_digest: live_metadata_batch::target_digest(target).unwrap(),
                    source_bytes: if peer.refuse && index == 1 {
                        None
                    } else if peer.budget && index == 1 {
                        Some(128 * 1024)
                    } else {
                        Some(if index % 2 == 0 { 2 } else { 0 })
                    },
                    outcome: if peer.refuse && index == 1 {
                        LiveMetadataOutcome::Refused {
                            reason: live_metadata_batch::LiveMetadataRefusal::SourceReadFailed,
                        }
                    } else if peer.budget && index == 1 {
                        LiveMetadataOutcome::Refused {
                            reason: live_metadata_batch::LiveMetadataRefusal::ResultBudget,
                        }
                    } else if index % 2 == 0 {
                        LiveMetadataOutcome::Found {
                            sha256: aos_hub_core::hybrid_ingress::body_sha256(b"{}"),
                            size: 2,
                            content_base64: "e30=".into(),
                        }
                    } else {
                        LiveMetadataOutcome::NotFound
                    },
                })
                .collect();
            if peer.rewrite {
                items[0].target_digest = "0".repeat(64);
            }
            StorageWorkOutcome::MirrorLiveMetadataBatch { items }
        }
        StorageWorkOperation::InspectMirrorLiveMetadata { .. } => {
            StorageWorkOutcome::MirrorLiveMetadata {
                sha256: aos_hub_core::hybrid_ingress::body_sha256(b"{}"),
                size: 2,
                content_base64: "e30=".into(),
            }
        }
        _ => panic!("unexpected Native operation"),
    };
    let mut outcome = outcome;
    if peer.oversized {
        if let StorageWorkOutcome::MirrorLiveMetadataBatch { items } = &mut outcome {
            let bytes = vec![0; 128 * 1024];
            for item in items.iter_mut() {
                item.source_bytes = Some(bytes.len() as u64);
                item.outcome = LiveMetadataOutcome::Found {
                    sha256: aos_hub_core::hybrid_ingress::body_sha256(&bytes),
                    size: bytes.len() as u64,
                    content_base64: base64::engine::general_purpose::STANDARD.encode(&bytes),
                };
            }
        }
    }
    let source_bytes = match &outcome {
        StorageWorkOutcome::MirrorLiveMetadataBatch { items } => {
            items.iter().filter_map(|item| item.source_bytes).sum()
        }
        _ => 2,
    };
    let result = StorageWorkResult {
        plan_id: plan.plan_id,
        placement_id: plan.placement_id,
        placement_resource_version: plan.placement_resource_version,
        binding_id: plan.binding_id,
        binding_resource_version: plan.binding_resource_version,
        source_bytes,
        outcome,
    };
    let body = serde_json::to_vec(&result).unwrap();
    peer.responses.lock().unwrap().push(body.len());
    peer.active.fetch_sub(1, Ordering::SeqCst);
    Response::builder().body(Body::from(body)).unwrap()
}

async fn fixture(
    peer: Peer,
) -> (
    tempfile::TempDir,
    Database,
    SurfacePlacementRecord,
    BindingRecord,
    RemoteStorageWorkClient,
    Arc<Peer>,
    tokio::task::JoinHandle<()>,
) {
    let directory = tempfile::tempdir().unwrap();
    let db = Database::open(&directory.path().join("batch.db"))
        .await
        .unwrap();
    let registry_id = db
        .register_registry("live-batch", &[], false)
        .await
        .unwrap();
    let binding = db
        .ensure_instance_default_binding(
            "deployment_r2",
            None,
            Some(aos_hub_core::binding::DEPLOYMENT_R2_ATTACHMENT),
        )
        .await
        .unwrap();
    let placement = db
        .create_surface_placement(&NewSurfacePlacementSpec {
            surface: SurfaceTarget::Registry(registry_id),
            name: "live".into(),
            binding_id: binding.id,
            prefix: "registry".into(),
            kind: "complete".into(),
            desired_state: "active".into(),
            hash_range: None,
            desired_read_enabled: true,
            read_order: 0,
            requires_conditional_writes: false,
        })
        .await
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    let tls = crate::native_tls::NativeTlsListener::new(
        listener,
        &fixtures.join("hub-hybrid-fleet-server.crt"),
        &fixtures.join("hub-hybrid-fleet-server.key"),
        "localhost".into(),
    )
    .unwrap();
    let peer = Arc::new(peer);
    let app = Router::new()
        .route(STORAGE_WORK_PATH, post(execute))
        .route(STORAGE_CAPABILITIES_PATH, post(capabilities))
        .with_state(peer.clone());
    let task = tokio::spawn(async move {
        axum::serve(tls, app).await.unwrap();
    });
    let work =
        RemoteStorageWorkClient::new(&format!("https://localhost:{port}"), DEPLOYMENT.into(), KEY)
            .unwrap()
            .with_live_metadata_fixture_ca(
                &std::fs::read(fixtures.join("hub-hybrid-fleet-ca.crt")).unwrap(),
            )
            .unwrap();
    (directory, db, placement, binding, work, peer, task)
}

fn targets(
    placement: &SurfacePlacementRecord,
    binding: &BindingRecord,
) -> Vec<HybridLiveDeliveryTarget> {
    (0..32)
        .map(|index| HybridLiveDeliveryTarget {
            registry_id: placement.registry_id.unwrap(),
            registry_resource_version: 1,
            mirror_resource_version: 1,
            placement_id: placement.id,
            placement_resource_version: placement.resource_version,
            write_spec_version: placement.write_spec_version,
            placement_prefix: placement.prefix.clone(),
            binding_id: binding.id,
            binding_resource_version: binding.resource_version,
            protected_profile_digest: "a".repeat(64),
            upstream_base: "https://example.org/registry/".into(),
            path: format!("channels/stable/{index:02x}"),
            class: aos_hub_core::hybrid_ingress::live::HybridLiveDeliveryClass::Metadata,
            maximum_bytes: 128 * 1024,
        })
        .collect()
}

#[tokio::test]
async fn thirty_two_cold_paths_use_one_actual_signed_tls_batch_with_ordered_missing_results() {
    let (_directory, _db, placement, binding, work, peer, task) = fixture(Peer::default()).await;
    assert!(work.supports_live_metadata_batch().await.unwrap());
    let returned = exchange_targets(
        &work,
        &placement,
        &binding,
        &targets(&placement, &binding),
        true,
        || async { Ok(()) },
    )
    .await
    .unwrap();
    assert_eq!(returned.len(), 32);
    assert_eq!(returned[0].as_deref(), Some(&b"{}"[..]));
    assert!(returned[1].is_none());
    assert_eq!(peer.requests.lock().unwrap().len(), 1);
    assert!(peer.responses.lock().unwrap()[0] < MAX_RESULT_BYTES);
    assert!(peer.request_bytes.lock().unwrap()[0] < MAX_PLAN_BYTES);
    println!(
        "live_batch_tls originals=32 calls=1 request_bytes={} response_bytes={}",
        peer.request_bytes.lock().unwrap()[0],
        peer.responses.lock().unwrap()[0]
    );
    task.abort();
}

#[tokio::test]
async fn older_advertised_singleton_uses_four_bounded_tls_calls_without_unknown_batch_wire() {
    let (_directory, _db, placement, binding, work, peer, task) = fixture(Peer {
        singleton_only: true,
        ..Peer::default()
    })
    .await;
    assert!(!work.supports_live_metadata_batch().await.unwrap());
    let returned = exchange_targets(
        &work,
        &placement,
        &binding,
        &targets(&placement, &binding),
        false,
        || async { Ok(()) },
    )
    .await
    .unwrap();
    assert!(returned
        .iter()
        .all(|item| item.as_deref() == Some(&b"{}"[..])));
    let requests = peer.requests.lock().unwrap();
    assert_eq!(requests.len(), 32);
    assert!(requests.iter().all(|plan| matches!(
        plan.operation,
        StorageWorkOperation::InspectMirrorLiveMetadata { .. }
    )));
    assert!(peer.peak.load(Ordering::SeqCst) > 1);
    assert!(peer.peak.load(Ordering::SeqCst) <= 4);
    task.abort();
}

#[tokio::test]
async fn rewritten_or_refused_items_never_return_partial_success() {
    for peer in [
        Peer {
            rewrite: true,
            ..Peer::default()
        },
        Peer {
            refuse: true,
            ..Peer::default()
        },
    ] {
        let (_directory, _db, placement, binding, work, peer, task) = fixture(peer).await;
        assert!(exchange_targets(
            &work,
            &placement,
            &binding,
            &targets(&placement, &binding),
            true,
            || async { Ok(()) }
        )
        .await
        .is_err());
        assert_eq!(peer.requests.lock().unwrap().len(), 1);
        task.abort();
    }
}

#[tokio::test]
async fn changed_original_sql_selection_after_reply_refuses_all_observations() {
    use aos_hub_core::direct_upload::*;

    let (_directory, db, placement, binding, work, peer, task) = fixture(Peer::default()).await;
    let registry_id = placement.registry_id.unwrap();
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
    db.create_surface_write_authority(
        SurfaceTarget::Registry(registry_id),
        "live-batch-authority",
        placement.id,
        placement.resource_version,
        placement.write_spec_version,
        revision,
    )
    .await
    .unwrap();
    db.set_registry_mirror(
        registry_id,
        "https://example.org/registry/",
        "refs/*",
        "",
        "pull_through",
        "allow_unsigned",
        3600,
        None,
    )
    .await
    .unwrap();
    let registry = db.registry_by_id(registry_id).await.unwrap().unwrap();
    let source = db.registry_mirror(registry_id).await.unwrap().unwrap();
    // Raw candidate facts provide only a test selection commitment. The TLS
    // transport remains ordinary signed storage-work; no runtime is qualified.
    let profile = DirectManagedR2Profile {
        deployment_id: DEPLOYMENT.into(),
        account_id: "0".repeat(32),
        bucket_name: "controlled-test-bucket".into(),
        bucket_namespace: "controlled-test-namespace".into(),
        credential_id: "controlled-test-material".into(),
        credential_generation: WireInteger::new(1),
        secret_version_ref: "controlled-test-material/v1".into(),
        credential_fingerprint: "1".repeat(64),
        checksum_algorithm: DirectChecksumAlgorithm::Md5,
        clock_qualification: "2".repeat(64),
        clock_uncertainty_seconds: WireInteger::new(1),
    };
    let policy = DirectPrivateStagePolicyRef {
        policy_id: "controlled-test-policy".into(),
        policy_digest: "3".repeat(64),
        namespace: profile.bucket_namespace.clone(),
    };
    let selection_work =
        RemoteStorageWorkClient::new(&work.executor_origin().unwrap(), DEPLOYMENT.into(), KEY)
            .unwrap()
            .with_controlled_mirror(
                &profile,
                &policy,
                aos_hub_core::mirror_guard::MirrorGuardIssuer {
                    source_digest: "4".repeat(64),
                    script_version: format!("emulated-{}", "4".repeat(64)),
                },
                b"live-batch-fixture-independent-candidate-key",
            )
            .unwrap();
    let selection = Selection::capture(&db, &selection_work, &registry, source.clone())
        .await
        .unwrap();
    let originals: Vec<_> = (0..32)
        .map(|index| {
            super::super::target_for(
                &selection,
                &registry,
                &format!("channels/stable/{index:02x}"),
            )
        })
        .collect();
    let calls = AtomicUsize::new(0);

    let result = exchange_targets(
        &work,
        &selection.placement,
        &selection.binding,
        &originals,
        true,
        || async {
            if calls.fetch_add(1, Ordering::SeqCst) == 1 {
                // The actual configuration API changes trust policy while preserving
                // URL. Existing replies cannot acquire this newly selected version.
                db.set_registry_mirror(
                    registry_id,
                    &source.source_url,
                    "refs/*",
                    "",
                    "pull_through",
                    "required",
                    3600,
                    Some(source.resource_version),
                )
                .await?;
            }
            selection
                .validate_current(&db, &selection_work, &registry)
                .await
        },
    )
    .await;

    assert!(result.is_err());
    assert_eq!(peer.requests.lock().unwrap().len(), 1);
    assert!(
        db.registry_mirror(registry_id)
            .await
            .unwrap()
            .unwrap()
            .resource_version
            > source.resource_version
    );
    assert_eq!(
        originals[0].mirror_resource_version,
        source.resource_version
    );
    task.abort();
}

#[tokio::test]
async fn only_explicit_response_capacity_refusals_use_bounded_singleton_retry() {
    let (_directory, _db, placement, binding, work, peer, task) = fixture(Peer {
        budget: true,
        ..Peer::default()
    })
    .await;
    let returned = exchange_targets(
        &work,
        &placement,
        &binding,
        &targets(&placement, &binding),
        true,
        || async { Ok(()) },
    )
    .await
    .unwrap();
    assert_eq!(returned[0].as_deref(), Some(&b"{}"[..]));
    assert_eq!(returned[1].as_deref(), Some(&b"{}"[..]));
    assert!(returned[3].is_none());
    let requests = peer.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(matches!(
        requests[0].operation,
        StorageWorkOperation::InspectMirrorLiveMetadataBatch { .. }
    ));
    let StorageWorkOperation::InspectMirrorLiveMetadata { target } = &requests[1].operation else {
        unreachable!()
    };
    assert_eq!(target.path, "channels/stable/01");
    task.abort();
}

#[tokio::test]
async fn oversized_remote_batch_is_refused_without_singleton_compatibility_retry() {
    let (_directory, _db, placement, binding, work, peer, task) = fixture(Peer {
        oversized: true,
        ..Peer::default()
    })
    .await;
    assert!(exchange_targets(
        &work,
        &placement,
        &binding,
        &targets(&placement, &binding),
        true,
        || async { Ok(()) }
    )
    .await
    .is_err());
    assert_eq!(peer.requests.lock().unwrap().len(), 1);
    assert!(peer.responses.lock().unwrap()[0] > MAX_RESULT_BYTES);
    task.abort();
}
