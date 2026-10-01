//! Real TLS control counts through the production phased Native controller.
//!
//! This peer supplies controlled metadata replies; it does not exercise or
//! qualify a provider. Actual SDK streams and permanent effect fences have a
//! separate Worker runtime gate. Encoded requests/replies are retained here.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use aos_hub_core::{direct_upload::*, mirror_work::*, storage_work::*};
use axum::{
    body::Body,
    extract::{Request, State},
    response::Response,
    routing::post,
    Router,
};

use super::*;

const DEPLOYMENT: &str = "mirror-phase-transport-fixture";
const PRODUCER_KEY: &[u8] = b"mirror-production-control-fixture-key";
const CANDIDATE_KEY: &[u8] = b"mirror-candidate-control-fixture-key";
const GUARD_KEY: &[u8] = b"mirror-independent-guard-fixture-key";

mod guard_batch;
mod runtime;
#[cfg(feature = "test-support")]
mod runtime_gc;
mod runtime_membership;
mod runtime_purposes;

use guard_batch::execute as guard_execute;

#[derive(Default)]
struct Peer {
    originals: BTreeMap<String, MirrorOriginal>,
    progress: BTreeMap<String, MirrorProgress>,
    requests: Vec<StorageWorkPlan>,
    request_bytes: Vec<usize>,
    response_bytes: Vec<usize>,
    refuse_path: Option<String>,
    lose_upload_reply: bool,
    guard_requests: Vec<aos_hub_core::mirror_guard::batch::MirrorGuardBatchLookup>,
    guard_request_bytes: Vec<usize>,
    guard_reply_bytes: Vec<usize>,
    refuse_guard_path: Option<String>,
    lose_guard_reply: bool,
}

async fn execute(State(state): State<Arc<Mutex<Peer>>>, request: Request) -> Response {
    let signature = request.headers()[STORAGE_WORK_SIGNATURE_HEADER]
        .to_str()
        .unwrap()
        .to_owned();
    let body = axum::body::to_bytes(request.into_body(), MAX_PLAN_BYTES)
        .await
        .unwrap();
    let plan = aos_hub_core::mirror_candidate::verify_mirror_candidate_plan(
        &StorageWorkKey::new(CANDIDATE_KEY).unwrap(),
        &signature,
        &body,
        DEPLOYMENT,
        aos_hub_core::clock::now_unix_secs(),
    )
    .unwrap();
    let StorageWorkOperation::MirrorTransferBatch { items } = &plan.operation else {
        panic!("production controller sent an individual control");
    };
    let mut peer = state.lock().unwrap();
    peer.request_bytes.push(body.len());
    peer.requests.push(plan.clone());
    let mut results = Vec::new();
    let mut source_bytes = 0;
    let mut lose = false;
    for item in items {
        if let Some(prior) = peer
            .originals
            .insert(item.original.job_id.clone(), item.original.clone())
        {
            assert_eq!(prior, item.original);
        }
        if peer.refuse_path.as_deref() == Some(&item.original.path)
            && matches!(item.step, MirrorStep::Begin)
        {
            results.push(aos_hub_core::mirror_batch::MirrorBatchResult {
                job_id: item.original.job_id.clone(),
                original_digest: digest(&item.original).unwrap(),
                outcome: MirrorBatchOutcome::Refused,
            });
            continue;
        }
        let mut progress =
            peer.progress
                .get(&item.original.job_id)
                .cloned()
                .unwrap_or(MirrorProgress {
                    original_digest: digest(&item.original).unwrap(),
                    ..Default::default()
                });
        let size = item.original.verification.size();
        let mut consumed = 0;
        match &item.step {
            MirrorStep::Status { destination: false } => {}
            MirrorStep::Begin => {
                progress.stage_upload_id = Some(format!("upload-{}", item.original.job_id))
            }
            MirrorStep::UploadParts { first_part, .. } => {
                assert_eq!(*first_part, 1);
                if progress.stage_parts.is_empty() {
                    progress.stage_parts.push(MirrorPart {
                        part_number: 1,
                        size,
                        sha256: "1".repeat(64),
                        etag: "\"part\"".into(),
                    });
                    consumed = size;
                }
                lose |= peer.lose_upload_reply;
            }
            MirrorStep::CloseStage => {
                progress.stage_object = Some(StorageObjectIdentity {
                    key: item.original.stage_key(),
                    size,
                    etag: "\"stage\"".into(),
                    provider_version: Some("controlled-stage-version".into()),
                })
            }
            MirrorStep::VerifyStage => {
                progress.verified = Some(MirrorVerifiedObject {
                    object: progress.stage_object.clone().unwrap(),
                    sha256: "1".repeat(64),
                    nar_sha256: None,
                    nar_size: None,
                });
                consumed = size;
            }
            _ => panic!("unexpected preparation phase"),
        }
        progress.validate(&item.original).unwrap();
        peer.progress
            .insert(item.original.job_id.clone(), progress.clone());
        source_bytes += consumed;
        results.push(aos_hub_core::mirror_batch::MirrorBatchResult {
            job_id: item.original.job_id.clone(),
            original_digest: digest(&item.original).unwrap(),
            outcome: MirrorBatchOutcome::Progress {
                progress,
                source_bytes: consumed,
            },
        });
    }
    if lose {
        peer.lose_upload_reply = false;
        return Response::builder().status(502).body(Body::empty()).unwrap();
    }
    let result = StorageWorkResult {
        plan_id: plan.plan_id,
        placement_id: plan.placement_id,
        placement_resource_version: plan.placement_resource_version,
        binding_id: plan.binding_id,
        binding_resource_version: plan.binding_resource_version,
        source_bytes,
        outcome: StorageWorkOutcome::MirrorBatch { items: results },
    };
    let bytes = serde_json::to_vec(&result).unwrap();
    assert!(bytes.len() <= MAX_RESULT_BYTES);
    peer.response_bytes.push(bytes.len());
    Response::builder()
        .header("content-type", "application/json")
        .body(Body::from(bytes))
        .unwrap()
}

async fn fixture() -> (
    tempfile::TempDir,
    Database,
    aos_hub_core::db::RegistryRecord,
    RemoteStorageWorkClient,
    Arc<Mutex<Peer>>,
    tokio::task::JoinHandle<()>,
) {
    let directory = tempfile::tempdir().unwrap();
    let db = Database::open(&directory.path().join("controller.db"))
        .await
        .unwrap();
    let registry_id = db
        .register_registry("mirror-phase-tests", &[], false)
        .await
        .unwrap();
    // Positive controller fixtures use the same explicit default ref selection
    // as public mirror configuration, rather than the legacy SQL empty default.
    db.set_registry_mirror(
        registry_id,
        "https://upstream.example.invalid/registry/",
        "refs/*",
        "",
        "full",
        "allow_unsigned",
        3600,
        None,
    )
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
        .create_surface_placement(&aos_hub_core::db::NewSurfacePlacementSpec {
            surface: aos_hub_core::db::SurfaceTarget::Registry(registry_id),
            name: "mirror".into(),
            binding_id: binding.id,
            prefix: format!(".aos-mirror-qualification/{}/final", "a".repeat(32)),
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
    db.create_surface_write_authority(
        aos_hub_core::db::SurfaceTarget::Registry(registry_id),
        "mirror-test-authority",
        placement.id,
        placement.resource_version,
        placement.write_spec_version,
        revision,
    )
    .await
    .unwrap();
    let registry = db.registry_by_id(registry_id).await.unwrap().unwrap();
    let profile = DirectManagedR2Profile {
        deployment_id: DEPLOYMENT.into(),
        account_id: "0123456789abcdef0123456789abcdef".into(),
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
    let state = Arc::new(Mutex::new(Peer::default()));
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
    let app = Router::new()
        .route(
            aos_hub_core::mirror_candidate::MIRROR_CANDIDATE_PATH,
            post(execute),
        )
        .route(
            aos_hub_core::mirror_guard::batch::MIRROR_CANDIDATE_GUARD_BATCH_LOOKUP_PATH,
            post(guard_execute),
        )
        .with_state(state.clone())
        .layer(axum::extract::DefaultBodyLimit::max(MAX_PLAN_BYTES));
    let task = tokio::spawn(async move {
        axum::serve(tls, app).await.unwrap();
    });
    let client = RemoteStorageWorkClient::new(
        &format!("https://localhost:{port}"),
        DEPLOYMENT.into(),
        PRODUCER_KEY,
    )
    .unwrap()
    .with_mirror_guard_key(GUARD_KEY)
    .unwrap()
    .with_controlled_mirror(
        &profile,
        &policy,
        aos_hub_core::mirror_guard::MirrorGuardIssuer {
            source_digest: "4".repeat(64),
            script_version: format!("emulated-{}", "4".repeat(64)),
        },
        CANDIDATE_KEY,
    )
    .unwrap()
    .with_controlled_ca(&std::fs::read(fixtures.join("hub-hybrid-fleet-ca.crt")).unwrap())
    .unwrap();
    (directory, db, registry, client, state, task)
}

fn selected() -> Vec<(String, MirrorVerification)> {
    (0..64)
        .map(|index| {
            (
                format!("web/object-{index:03}.json"),
                MirrorVerification::Sha256 {
                    sha256: "1".repeat(64),
                    size: 11,
                },
            )
        })
        .collect()
}

#[tokio::test]
async fn discovery_configuration_changes_refuse_before_admission_or_provider_control() {
    let (_directory, db, registry, client, peer, task) = fixture().await;
    let source = db.registry_mirror(registry.id).await.unwrap().unwrap();
    let selection =
        super::super::selection::Selection::capture(&db, &client, &registry, source.clone())
            .await
            .unwrap();

    // An actual configuration API changes signature policy while preserving
    // the upstream URL. Previously verified unsigned bytes cannot acquire the
    // new signed-policy resource version during admission.
    db.create_mirror_source(registry.id, &source.source_url, "full", true, 3600)
        .await
        .unwrap();
    assert!(
        prepare_selected(&db, &client, &registry, selected(), Some(&selection))
            .await
            .is_err()
    );
    assert!(peer.lock().unwrap().requests.is_empty());
    assert!(db
        .mirror_import_for_path(registry.id, "web/object-000.json")
        .await
        .unwrap()
        .is_none());

    let source = db.registry_mirror(registry.id).await.unwrap().unwrap();
    let selection =
        super::super::selection::Selection::capture(&db, &client, &registry, source.clone())
            .await
            .unwrap();
    db.set_registry_mirror(
        registry.id,
        &source.source_url,
        "refs/heads/selected",
        "secret:mirror-upstream",
        "full",
        "required",
        3600,
        Some(source.resource_version),
    )
    .await
    .unwrap();
    assert!(
        prepare_selected(&db, &client, &registry, selected(), Some(&selection))
            .await
            .is_err()
    );
    assert!(peer.lock().unwrap().requests.is_empty());
    assert!(db
        .mirror_import_for_path(registry.id, "web/object-000.json")
        .await
        .unwrap()
        .is_none());
    task.abort();
}

#[test]
fn pullthrough_encoded_metadata_limit_does_not_hide_excessive_inflation() {
    use aos_registry_surface::object::{self, ObjectKind};

    let content = vec![0; 4 * 1024 * 1024 + 1];
    let oid = object::hash_object(ObjectKind::Blob, &content);
    let encoded = object::encode_loose(ObjectKind::Blob, &content).unwrap();
    assert!(encoded.len() < 256 * 1024);
    assert!(super::super::validate_pullthrough_loose(&encoded, oid).is_err());

    let content = &content[..4 * 1024 * 1024];
    let oid = object::hash_object(ObjectKind::Blob, content);
    let encoded = object::encode_loose(ObjectKind::Blob, content).unwrap();
    assert!(super::super::validate_pullthrough_loose(&encoded, oid).is_ok());
}

#[tokio::test]
async fn sixty_four_small_objects_use_five_actual_bounded_tls_phase_requests() {
    let (_directory, db, registry, client, peer, task) = fixture().await;
    let prepared = prepare(&db, &client, &registry, selected()).await.unwrap();
    assert_eq!(prepared.len(), 64);
    let peer = peer.lock().unwrap();
    assert_eq!(peer.requests.len(), 5);
    for plan in &peer.requests {
        let StorageWorkOperation::MirrorTransferBatch { items } = &plan.operation else {
            panic!()
        };
        assert_eq!(items.len(), 64);
    }
    assert!(peer
        .request_bytes
        .iter()
        .all(|bytes| *bytes <= MAX_PLAN_BYTES));
    assert!(peer
        .response_bytes
        .iter()
        .all(|bytes| *bytes <= MAX_RESULT_BYTES));
    eprintln!(
        "controlled mirror TLS preparation requests={} max_request_bytes={} max_reply_bytes={}",
        peer.requests.len(),
        peer.request_bytes.iter().max().unwrap(),
        peer.response_bytes.iter().max().unwrap()
    );
    task.abort();
}

#[tokio::test]
async fn partial_refusal_and_lost_phase_reply_keep_exact_originals_for_recovery() {
    let (directory, db, registry, client, peer, task) = fixture().await;
    peer.lock().unwrap().refuse_path = Some("web/object-000.json".into());
    assert!(prepare(&db, &client, &registry, selected()).await.is_err());
    for index in 1..64 {
        assert!(db
            .mirror_import_for_path(registry.id, &format!("web/object-{index:03}.json"))
            .await
            .unwrap()
            .unwrap()
            .progress
            .unwrap()
            .verified
            .is_some());
    }
    peer.lock().unwrap().refuse_path = None;
    peer.lock().unwrap().lose_upload_reply = true;
    assert!(prepare(&db, &client, &registry, selected()).await.is_err());
    let originals = peer.lock().unwrap().originals.clone();
    drop(db);
    let db = Database::open(&directory.path().join("controller.db"))
        .await
        .unwrap();
    let prepared = prepare(&db, &client, &registry, selected()).await.unwrap();
    assert_eq!(prepared.len(), 64);
    assert_eq!(peer.lock().unwrap().originals, originals);
    task.abort();
}
