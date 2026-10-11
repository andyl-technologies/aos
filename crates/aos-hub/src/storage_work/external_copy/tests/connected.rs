//! Controlled actual Native SQL, issuer, Worker guard and versioned provider.
//!
//! This explicit process gate requires source-built tools and an exact Worker
//! artifact. It establishes no hosted provider or filesystem qualification.

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use aos_hub_core::{
    backend::{Backend as _, SqlxBackend, Statement},
    fetch::SurfaceProvider,
    placement_scan::PlacementScanController,
    secret_version::{ResolvedSecretVersion, SecretVersionResolver},
    value::Value as SqlValue,
};
use serde_json::{json, Value};

use super::*;

#[path = "configuration.rs"]
mod configuration;

#[path = "connected/scheduling.rs"]
mod scheduling;

struct FixtureProcess(Child);

impl Drop for FixtureProcess {
    fn drop(&mut self) {
        // Closing the fixture's private control pipe asks Node to stop its
        // retained Worker child before the bounded last-resort termination.
        self.0.stdin.take();
        for _ in 0..100 {
            if self.0.try_wait().ok().flatten().is_some() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct IssuerTask(tokio::task::JoinHandle<()>);

impl Drop for IssuerTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct Resolver;

#[async_trait::async_trait]
impl SecretVersionResolver for Resolver {
    async fn resolve(&self, reference: &str) -> anyhow::Result<ResolvedSecretVersion> {
        anyhow::ensure!(
            matches!(
                reference,
                "secret://connected-copy/read/v1"
                    | "secret://connected-copy/write/v1"
                    | "secret://connected-copy/list/v1"
            ),
            "fixture reference changed"
        );
        Ok(ResolvedSecretVersion::from_bytes(MATERIAL.to_vec()))
    }
}

fn private_file(path: &Path, bytes: &[u8]) {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

async fn admin(origin: &str, action: &str) -> Value {
    reqwest::Client::new()
        .post(format!("{origin}/fixture/{action}"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap()
}

async fn new_claim(
    db: &Database,
    source: &SurfacePlacementRecord,
    destination: &SurfacePlacementRecord,
    id: &str,
) -> (TopologyOperationRecord, String) {
    let target = |role: &str, row: &SurfacePlacementRecord| NewTopologyOperationTarget {
        role: role.into(),
        target: NewTopologyOperationTargetRef::Placement(row.id),
        generation_key: row.resource_version,
        configuration_digest: String::new(),
    };
    let operation = db
        .create_topology_operation(&NewTopologyOperation {
            operation_id: id.into(),
            operation_kind: "replicate_placement".into(),
            control_permission: Permission::StorageManage,
            targets: vec![target("source", source), target("primary", destination)],
            detail_json: "{\"phase\":\"pending\"}".into(),
            progress_total: None,
        })
        .await
        .unwrap();
    let token = uuid::Uuid::new_v4().simple().to_string();
    let running = db
        .claim_surface_placement_scan_operation(
            &operation.operation_id,
            operation.resource_version,
            &token,
            600,
        )
        .await
        .unwrap()
        .unwrap();
    (running, token)
}

async fn set_catalogue(
    db: &Database,
    backend: &SqlxBackend,
    surface: SurfaceTarget,
    path: &str,
    hash: &str,
    bytes: i64,
) {
    if let Some(original) = db.surface_object_named(surface, path).await.unwrap() {
        // Deliberate metadata tamper/race uses the exact existing row and RV.
        // It cannot create observation, credential or provider authority.
        backend
            .checked_batch(&[Statement::new(
                "UPDATE surface_objects SET content_hash = ?1, size = ?2,
                   resource_version = resource_version + 1
                 WHERE id = ?3 AND resource_version = ?4 AND object_key = ?5
                   AND lifecycle_state = 'active'",
                vec![
                    SqlValue::Text(format!("sha256:{hash}")),
                    SqlValue::Int(bytes),
                    SqlValue::Int(original.id),
                    SqlValue::Int(original.resource_version),
                    SqlValue::Text(path.to_owned()),
                ],
            )
            .expecting(1)])
            .await
            .unwrap();
        return;
    }

    db.create_surface_object(&aos_hub_core::db::SetSurfaceObject {
        surface,
        object_key: path.into(),
        object_kind: "immutable".into(),
        content_hash: Some(format!("sha256:{hash}")),
        size: Some(bytes),
        mutable_publication_id: None,
    })
    .await
    .unwrap();
}

async fn close_legacy_original(
    writer: &HybridSurfaceWrites,
    work: &RemoteStorageWorkClient,
    operation: &TopologyOperationRecord,
    token: &str,
    source: &SurfacePlacementRecord,
    destination: &SurfacePlacementRecord,
    base: &ExternalCopyOriginal,
) {
    // This models a genuinely signed pre-fix None original, not a fabricated
    // terminal receipt. The real guard/provider positively completes it.
    let current = writer
        .current_copy(operation, source, destination, true)
        .await
        .unwrap();
    let mut original = base.clone();
    original.topology = current.topology;
    original.path = "nar/legacy.nar".into();
    original.expected_sha256 = None;
    let head_plan = work
        .plan_for_placement(
            source,
            &current.binding,
            StorageWorkOperation::Head {
                path: original.path.clone(),
            },
            aos_hub_core::clock::now_unix_secs(),
        )
        .unwrap();
    let observed = work.execute(&head_plan).await.unwrap();
    let StorageWorkOutcome::Head { object, .. } = observed.outcome else {
        panic!("actual legacy source HEAD absent")
    };
    original.source_object = CopySourceObject {
        provider_version: Some(object.provider_version.unwrap()),
        etag: object.etag,
        bytes: LeaseInteger::new(i64::try_from(object.size).unwrap()).unwrap(),
        guard_stamp: None,
    };
    for _ in 0..original.part_count().unwrap() + 2 {
        let now = aos_hub_core::clock::now_unix_secs();
        let claim = writer
            .db
            .placement_copy_claim(operation, token, now)
            .await
            .unwrap();
        let plan = work
            .plan_for_placement(
                destination,
                &current.binding,
                StorageWorkOperation::CopyObject {
                    source_binding_id: None,
                    source_placement_id: source.id,
                    source_placement_resource_version: source.resource_version,
                    source_prefix: source.prefix.clone(),
                    path: original.path.clone(),
                    expected_size: object.size,
                    expected_etag: original.source_object.etag.clone(),
                },
                now,
            )
            .unwrap();
        let request =
            ExternalCopyRequest::new(original.clone(), claim, plan, CopyControl::Advance, now)
                .unwrap();
        let progress = work.external_copy_control(&request).await.unwrap();
        if progress.phase == CopyPhase::Closed {
            return;
        }
    }
    panic!("legacy copy did not positively close");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires explicitly pinned AOS Node/workerd/Worker artifact and retained evidence directory"]
async fn actual_native_copy_guard_issuer_and_cold_terminal_replay() {
    run_connected(false).await;
}

#[tokio::test]
#[ignore = "requires exact same-source AOS Node/workerd/Worker and a fresh retained evidence directory"]
async fn actual_cross_binding_copy_and_cold_terminal_replay() {
    run_connected(true).await;
}

async fn run_connected(cross_binding: bool) {
    let root = PathBuf::from(std::env::var("AOS_COPY_CONNECTED_ROOT").unwrap());
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let root = root.canonicalize().unwrap();
    std::fs::create_dir(root.join("issuer")).unwrap();
    std::fs::set_permissions(root.join("issuer"), std::fs::Permissions::from_mode(0o700)).unwrap();
    let db_file = root.join("hub.db");
    let db = Arc::new(Database::open(&db_file).await.unwrap());
    std::fs::set_permissions(&db_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let catalogue_backend = Arc::new(
        SqlxBackend::connect_sqlite(db_file.to_str().unwrap())
            .await
            .unwrap(),
    );
    let (old_writer, operation, source, destination, token) = if cross_binding {
        super::paired::fixture_with_database(db.clone()).await
    } else {
        fixture_with_database(db.clone()).await
    };
    let binding_ids = if cross_binding {
        vec![destination.binding_id, source.binding_id]
    } else {
        vec![source.binding_id]
    };
    let (configuration, object, copy, rpc, auth) =
        configuration::configure_bindings(db.clone(), &binding_ids, &root).await;
    private_file(
        &configuration.publisher_key_file,
        b"fixture-copy-publisher-independent-role-key",
    );
    private_file(
        &configuration.renewal_key_file,
        configuration::RENEWAL.as_bytes(),
    );
    private_file(
        &configuration.signing_seed_file,
        &hex::encode([17; 32]).into_bytes(),
    );
    let publication: aos_hub_core::storage_authority::control::StorageAuthorityPublication =
        serde_json::from_value(object["publications"][0].clone()).unwrap();
    private_file(
        &root.join("publication.json"),
        &serde_json::to_vec(&publication).unwrap(),
    );
    configuration
        .initialize(&root.join("publication.json"))
        .unwrap();
    let issuer = crate::authority_server::AuthorityServer::open(&configuration).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer_address = listener.local_addr().unwrap();
    let _issuer_task = IssuerTask(tokio::spawn(async move {
        axum::serve(listener, issuer.router()).await.unwrap();
    }));
    let catalogue_db = db.clone();
    let mutation_backend = catalogue_backend.clone();
    let catalogue_surface = SurfaceTarget::Registry(source.registry_id.unwrap());
    let callback_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let callback_address = callback_listener.local_addr().unwrap();
    let callback = axum::Router::new().route(
        "/fixture/catalogue-race",
        axum::routing::post(move || {
            let catalogue_db = catalogue_db.clone();
            let mutation_backend = mutation_backend.clone();
            async move {
                set_catalogue(
                    &catalogue_db,
                    &mutation_backend,
                    catalogue_surface,
                    "nar/race.nar",
                    &"0".repeat(64),
                    8 * 1024 * 1024,
                )
                .await;
                axum::http::StatusCode::NO_CONTENT
            }
        }),
    );
    let _callback_task = IssuerTask(tokio::spawn(async move {
        axum::serve(callback_listener, callback).await.unwrap();
    }));
    let source_digest = if cross_binding {
        let path = std::env::var("AOS_COPY_WORKER_SOURCE_PATH").unwrap();
        assert!(path.starts_with("/nix/store/") && Path::new(&path).is_dir());
        Some(hex::encode(sha2::Sha256::digest(path.as_bytes())))
    } else {
        None
    };
    private_file(
        &root.join("setup.json"),
        &serde_json::to_vec(&json!({
            "issuer": issuer_address.to_string(),
            "catalogueMutation": format!("http://{callback_address}/fixture/catalogue-race"),
            "object": object,
            "copy": copy,
            "application": configuration::APPLICATION,
            "guard": configuration::GUARD,
            "renewal": configuration::RENEWAL,
            "sourceDigest": source_digest,
            "sourceKey": if cross_binding {"managed/source-binding/objects/source/nar/source.nar"}
                else {"managed/binding/objects/source/nar/source.nar"},
            "destinationKey": "managed/binding/objects/destination/nar/source.nar"
        }))
        .unwrap(),
    );
    let node = std::env::var("AOS_COPY_NODE").unwrap();
    let workerd = std::env::var("AOS_COPY_WORKERD").unwrap();
    assert!(node.starts_with("/nix/store/") && workerd.starts_with("/nix/store/"));
    let fixture_script = std::env::var_os("AOS_COPY_FIXTURE_SCRIPT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../pkgs/tools/aos-hub-external-copy-connected-e2e.mjs")
        });
    let log = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(root.join("fixture.log"))
        .unwrap();
    let mut _process = FixtureProcess(
        Command::new(node)
            .arg(fixture_script)
            .arg(&root)
            .arg(std::env::var("AOS_COPY_DIST").unwrap())
            .arg(workerd)
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures"))
            .stdout(log.try_clone().unwrap())
            .stdin(Stdio::piped())
            .stderr(log)
            .spawn()
            .unwrap(),
    );
    tokio::time::timeout(Duration::from_secs(30), async {
        while !root.join("ready.json").exists() {
            assert!(
                _process.0.try_wait().unwrap().is_none(),
                "controlled fixture exited before readiness; retained fixture.log"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    let ready: Value =
        serde_json::from_slice(&std::fs::read(root.join("ready.json")).unwrap()).unwrap();
    let origin = ready["workerOrigin"].as_str().unwrap();
    let administrative = ready["administrativeOrigin"].as_str().unwrap();
    db.create_surface_object(&aos_hub_core::db::SetSurfaceObject {
        surface: SurfaceTarget::Registry(source.registry_id.unwrap()),
        object_key: "nar/source.nar".into(),
        object_kind: "immutable".into(),
        content_hash: Some(format!(
            "sha256:{}",
            ready["sourceSha256"].as_str().unwrap()
        )),
        size: Some(8 * 1024 * 1024),
        mutable_publication_id: None,
    })
    .await
    .unwrap();
    let mut client = RemoteStorageWorkClient::new(
        origin,
        "fixture-deployment".into(),
        configuration::APPLICATION.as_bytes(),
    )
    .unwrap();
    // The real HTTPS scheme remains enforced. Only this controlled fixture
    // pins the tracked CA and resolves that certificate host to its listener.
    let ca = std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/hub-hybrid-fleet-s3-ca.crt"),
    )
    .unwrap();
    let relay = ready["relayAddress"].as_str().unwrap().parse().unwrap();
    let controlled_http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .timeout(Duration::from_secs(60))
        .add_root_certificate(reqwest::Certificate::from_pem(&ca).unwrap())
        .resolve("s3.fleet.test", relay)
        .build()
        .unwrap();
    client.http = controlled_http.clone();
    client.semantic_observation_http = controlled_http;
    let work = Arc::new(client);
    // Each binding independently stages and probes its actual credential originals.
    for &binding_id in &binding_ids {
        let binding = db.binding(binding_id).await.unwrap().unwrap();
        // Operator staging and the real Worker probe retain genuine queued SQL
        // originals. This does not grant provider capability or settle those tasks.
        for purpose in ["list", "read", "write"] {
            let credential = db
                .current_binding_credential(binding.id, purpose)
                .await
                .unwrap()
                .unwrap();
            let plan = rpc
                .plan_validate_binding_credential(
                    Some(&auth),
                    aos_proto_types::hub_v1::PlanValidateBindingCredentialRequest {
                        binding_id: binding.stable_id.clone(),
                        purpose: purpose.into(),
                        generation: credential.generation,
                        expected_resource_version: credential.head_resource_version.to_string(),
                        idempotency_key: format!("copy-custody-{}-{purpose}-plan", binding.id),
                    },
                )
                .await
                .unwrap()
                .plan
                .unwrap();
            let operation = rpc
                .validate_binding_credential(
                    Some(&auth),
                    aos_proto_types::hub_v1::ApplyTopologyPlanRequest {
                        plan_id: plan.plan_id,
                        confirmation_hash: plan.confirmation_hash,
                        idempotency_key: format!("copy-custody-{}-{purpose}-apply", binding.id),
                    },
                )
                .await
                .unwrap()
                .operation
                .unwrap();
            let queued = db
                .topology_operation(&operation.operation_id)
                .await
                .unwrap()
                .unwrap();
            let detail: Value = serde_json::from_str(&queued.detail_json).unwrap();
            let write_state = db.binding_write_state(binding.id).await.unwrap().unwrap();
            assert_eq!(detail["credentialGeneration"], credential.generation);
            assert_eq!(
                detail["credentialHeadResourceVersion"],
                credential.head_resource_version
            );
            assert_eq!(
                detail["bindingWriteStateResourceVersion"],
                write_state.resource_version
            );
            assert_eq!(
                detail["bindingWriteRevision"],
                write_state.current_write_revision.unwrap_or(0)
            );
            assert_eq!(queued.primary_target_stable_id, binding.stable_id);
            assert_eq!(
                queued.primary_target_generation_key,
                binding.resource_version
            );
            let now = aos_hub_core::clock::now_unix_secs();
            let request =
                aos_hub_core::storage_work::binding_custody::StorageCredentialCustodyProbe {
                    version: 1,
                    nonce: hex::encode(rand::random::<[u8; 32]>()),
                    issued_at: now,
                    expires_at: now + 30,
                    operation_id: queued.operation_id.clone(),
                    probe_token: detail["probeToken"].as_str().unwrap().into(),
                    head_resource_version: credential.head_resource_version,
                    snapshot:
                        aos_hub_core::storage_work::StorageBindingSnapshot::for_credential_probe(
                            work.deployment_id().into(),
                            &binding,
                            &credential,
                            now,
                        )
                        .unwrap(),
                };
            work.stage_credential_custody(request, &Resolver, now + 3600)
                .await
                .unwrap();
            assert_eq!(
                db.topology_operation(&operation.operation_id)
                    .await
                    .unwrap()
                    .unwrap(),
                queued
            );
            let queued = db
                .topology_operation(&operation.operation_id)
                .await
                .unwrap()
                .unwrap();
            let detail: Value = serde_json::from_str(&queued.detail_json).unwrap();
            let proof = work
                .probe_retained_credential(
                    &binding,
                    &credential,
                    &operation.operation_id,
                    detail["probeToken"].as_str().unwrap(),
                )
                .await
                .unwrap();
            assert!(proof.valid);
            assert_eq!(
                db.topology_operation(&operation.operation_id)
                    .await
                    .unwrap()
                    .unwrap()
                    .state,
                "pending"
            );
        }
        work.ensure_binding_snapshot(&db, &binding, &Resolver)
            .await
            .unwrap();
    }
    let (operation, token, destination) = if cross_binding {
        scheduling::replicate_claim(&db, &rpc, &auth, &source, &destination).await
    } else {
        (operation, token, destination)
    };
    let writer = Arc::new(HybridSurfaceWrites::new(db.clone(), work.clone()));
    let provider = Arc::new(super::super::super::HybridSurfaceProvider::new(
        db.clone(),
        work.clone(),
    ));
    let fetch = provider.placement_fetcher(&source).await.unwrap();
    assert!(
        fetch.fetch("nar/source.nar").await.is_err(),
        "Native generic bulk fallback must remain refused"
    );
    let listed = fetch.list_page("", None, 128).await.unwrap();
    assert_eq!(listed.paths, ["nar/source.nar"]);
    let evidence = listed.evidence.get("nar/source.nar").unwrap();
    let mut changed_incarnation = evidence.clone();
    changed_incarnation.provider_version = Some("different-listed-version".into());
    let before_incarnation = admin(administrative, "inspect").await;
    let refused_incarnation = writer
        .copy_external_claimed(
            &operation,
            &token,
            &source,
            &destination,
            "nar/source.nar",
            Some(&changed_incarnation),
        )
        .await
        .unwrap_err();
    assert!(refused_incarnation
        .to_string()
        .contains("source changed after inventory"));
    for effect in [
        "creates",
        "parts",
        "completeRequests",
        "completes",
        "aborts",
    ] {
        assert_eq!(
            admin(administrative, "inspect").await[effect],
            before_incarnation[effect]
        );
    }
    assert_eq!(
        writer
            .copy_external_claimed(
                &operation,
                &token,
                &source,
                &destination,
                "nar/source.nar",
                Some(evidence)
            )
            .await
            .unwrap(),
        Some(8 * 1024 * 1024)
    );
    let positive = admin(administrative, "inspect").await;
    assert_eq!(positive["creates"], 1);
    assert_eq!(positive["parts"], 2);
    assert_eq!(positive["completes"], 1);
    assert_eq!(positive["unconditionalReads"], 0);
    admin(administrative, "restart-replace-source").await;
    let retained = writer
        .retained_external_copy_original(&operation, &source, &destination, "nar/source.nar")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        retained.original.source_object.provider_version,
        Some("source-version-1".to_owned())
    );
    assert_eq!(
        writer
            .copy_external_claimed(
                &operation,
                &token,
                &source,
                &destination,
                "nar/source.nar",
                Some(evidence)
            )
            .await
            .unwrap(),
        Some(8 * 1024 * 1024)
    );
    if cross_binding {
        assert_eq!(retained.original.version, 3);
        let pins = retained.original.transfer.as_ref().unwrap();
        assert_eq!(pins.source_binding.binding_id.get(), source.binding_id);
        assert_eq!(retained.original.binding_id.get(), destination.binding_id);
        assert_ne!(
            pins.source_binding.profile_digest,
            retained.original.profile_digest
        );
        assert_ne!(
            pins.source_binding.snapshot_revision,
            retained.original.snapshot_revision
        );
        assert_eq!(pins.maximum_source_range_bytes.get(), 5 * 1024 * 1024);
    }
    let cold_replay = admin(administrative, "inspect").await;
    for effect in [
        "creates",
        "parts",
        "completeRequests",
        "completes",
        "aborts",
    ] {
        assert_eq!(
            cold_replay[effect], positive[effect],
            "Cold replay changed {effect}"
        );
    }
    let surface = SurfaceTarget::Registry(source.registry_id.unwrap());
    let expected_hash = ready["sourceSha256"].as_str().unwrap();
    set_catalogue(
        &db,
        &catalogue_backend,
        surface,
        "nar/source.nar",
        &"0".repeat(64),
        8 * 1024 * 1024,
    )
    .await;
    assert!(writer
        .copy_external_claimed(
            &operation,
            &token,
            &source,
            &destination,
            "nar/source.nar",
            Some(evidence)
        )
        .await
        .is_err());
    set_catalogue(
        &db,
        &catalogue_backend,
        surface,
        "nar/source.nar",
        expected_hash,
        8 * 1024 * 1024 - 1,
    )
    .await;
    assert!(writer
        .copy_external_claimed(
            &operation,
            &token,
            &source,
            &destination,
            "nar/source.nar",
            Some(evidence)
        )
        .await
        .is_err());
    set_catalogue(
        &db,
        &catalogue_backend,
        surface,
        "nar/source.nar",
        expected_hash,
        8 * 1024 * 1024,
    )
    .await;
    let mut wrong_surface = source.clone();
    wrong_surface.registry_id = Some(source.registry_id.unwrap() + 10000);
    assert!(writer
        .copy_external_claimed(
            &operation,
            &token,
            &wrong_surface,
            &destination,
            "nar/source.nar",
            Some(evidence)
        )
        .await
        .is_err());
    assert!(writer
        .copy_external_claimed(
            &operation,
            &token,
            &source,
            &destination,
            "../nar/source.nar",
            Some(evidence)
        )
        .await
        .is_err());
    assert_eq!(admin(administrative, "inspect").await["creates"], 1);
    admin(administrative, "populate-scan-tail").await;
    let destination_fetch = provider.placement_fetcher(&destination).await.unwrap();
    let first = destination_fetch.list_page("", None, 1000).await.unwrap();
    assert_eq!(first.paths.len(), 128);
    let cursor = first.next_cursor.as_deref().unwrap();
    let second = destination_fetch
        .list_page("", Some(cursor), 1000)
        .await
        .unwrap();
    assert_eq!(second.paths.len(), 2);
    assert!(second.next_cursor.is_none());
    let paths = first
        .paths
        .iter()
        .chain(second.paths.iter())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(paths.len(), 130);
    let before = admin(administrative, "inspect").await["listRequests"].clone();
    let changed = format!("{cursor}x");
    assert!(destination_fetch
        .list_page("", Some(&changed), 1000)
        .await
        .is_err());
    assert_eq!(
        admin(administrative, "inspect").await["listRequests"],
        before
    );
    // A real failed operation is retried through the current authorized API;
    // the normal controller then scans and commits the recovered destination.
    assert!(db
        .finish_claimed_surface_placement_scan_operation(
            &operation.operation_id,
            operation.resource_version,
            &token,
            "failed",
            0,
            None,
            "{\"phase\":\"lost-logical-reply\"}",
            Some("controlled lost logical reply"),
            aos_hub_core::clock::now_unix_secs()
        )
        .await
        .unwrap());
    let failed = db
        .topology_operation(&operation.operation_id)
        .await
        .unwrap()
        .unwrap();
    rpc.retry_operation(
        Some(&auth),
        aos_proto_types::hub_v1::MutateOperationRequest {
            operation_id: failed.operation_id.clone(),
            expected_resource_version: failed.resource_version.to_string(),
            idempotency_key: "copy-cold-retry".into(),
        },
    )
    .await
    .unwrap();
    let controller =
        PlacementScanController::new(db.clone(), provider.clone()).with_writes(writer.clone());
    assert_eq!(controller.run_due(1).await.unwrap(), 1);
    let settled = db
        .topology_operation(&operation.operation_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        settled.state,
        "succeeded",
        "{}",
        settled.error.unwrap_or_default()
    );
    let presence = db
        .list_object_presence(
            SurfaceTarget::Registry(source.registry_id.unwrap()),
            "nar/source.nar",
        )
        .await
        .unwrap();
    assert!(presence
        .iter()
        .any(|copy| copy.placement_name == "destination" && copy.state == "present"));
    let detail: Value = serde_json::from_str(&settled.detail_json).unwrap();
    assert_eq!(detail["listedObjects"], 130);
    assert_eq!(detail["unknownObjects"], 129);
    assert_eq!(
        admin(administrative, "inspect").await["maximumListLimit"],
        128
    );
    assert_eq!(admin(administrative, "inspect").await["creates"], 1);
    admin(administrative, "restore-source-version-1").await;
    let repair_operation = if cross_binding {
        Some(
            scheduling::repair_incomplete_target(
                &db,
                &rpc,
                &auth,
                &source,
                &destination,
                &controller,
            )
            .await,
        )
    } else {
        None
    };
    let before_unknown = admin(administrative, "inspect").await;
    let (unresolved, unknown_token) =
        new_claim(&db, &source, &destination, "connected-copy-unknown-create").await;
    let current_source = fetch.list_page("", None, 128).await.unwrap();
    let current_evidence = current_source.evidence.get("nar/source.nar").unwrap();
    admin(administrative, "lose-create-reply").await;
    assert!(writer
        .copy_external_claimed(
            &unresolved,
            &unknown_token,
            &source,
            &destination,
            "nar/source.nar",
            Some(current_evidence)
        )
        .await
        .is_err());
    let before_restart = admin(administrative, "inspect").await;
    assert_eq!(
        before_restart["creates"],
        before_unknown["creates"].as_u64().unwrap() + 1
    );
    assert!(db
        .finish_claimed_surface_placement_scan_operation(
            &unresolved.operation_id,
            unresolved.resource_version,
            &unknown_token,
            "failed",
            0,
            None,
            "{\"phase\":\"unknown-create\"}",
            Some("controlled provider reply loss"),
            aos_hub_core::clock::now_unix_secs()
        )
        .await
        .unwrap());
    admin(administrative, "restart-replace-source").await;
    let failed = db
        .topology_operation(&unresolved.operation_id)
        .await
        .unwrap()
        .unwrap();
    let original = writer
        .retained_external_copy_original(&failed, &source, &destination, "nar/source.nar")
        .await
        .unwrap()
        .unwrap();
    assert!(original.progress.pending);
    assert_eq!(
        original.original.source_object.provider_version,
        Some("source-version-1".to_owned())
    );
    rpc.retry_operation(
        Some(&auth),
        aos_proto_types::hub_v1::MutateOperationRequest {
            operation_id: failed.operation_id.clone(),
            expected_resource_version: failed.resource_version.to_string(),
            idempotency_key: "copy-unknown-retry".into(),
        },
    )
    .await
    .unwrap();
    assert_eq!(controller.run_due(1).await.unwrap(), 1);
    let refused = db
        .topology_operation(&unresolved.operation_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(refused.state, "failed");
    assert_eq!(
        admin(administrative, "inspect").await["creates"],
        before_restart["creates"]
    );
    assert_eq!(
        admin(administrative, "inspect").await["parts"],
        before_restart["parts"]
    );
    set_catalogue(
        &db,
        &catalogue_backend,
        surface,
        "nar/race.nar",
        expected_hash,
        8 * 1024 * 1024,
    )
    .await;
    admin(administrative, "enable-race-source").await;
    let (race, race_token) =
        new_claim(&db, &source, &destination, "connected-copy-catalogue-race").await;
    let listed_race = fetch.list_page("", None, 128).await.unwrap();
    let before_race = admin(administrative, "inspect").await;
    assert!(writer
        .copy_external_claimed(
            &race,
            &race_token,
            &source,
            &destination,
            "nar/race.nar",
            listed_race.evidence.get("nar/race.nar")
        )
        .await
        .is_err());
    assert_eq!(
        db.surface_object_named(surface, "nar/race.nar")
            .await
            .unwrap()
            .unwrap()
            .content_hash,
        Some(format!("sha256:{}", "0".repeat(64)))
    );
    assert_eq!(
        admin(administrative, "inspect").await["creates"],
        before_race["creates"]
    );
    admin(administrative, "restore-source-version-1").await;
    if !cross_binding {
        set_catalogue(
            &db,
            &catalogue_backend,
            surface,
            "nar/legacy.nar",
            expected_hash,
            8 * 1024 * 1024,
        )
        .await;
        admin(administrative, "enable-legacy-source").await;
        let (legacy, legacy_token) =
            new_claim(&db, &source, &destination, "connected-copy-legacy-unpinned").await;
        close_legacy_original(
            &writer,
            &work,
            &legacy,
            &legacy_token,
            &source,
            &destination,
            &retained.original,
        )
        .await;
        let old_positive = writer
            .retained_external_copy_original(&legacy, &source, &destination, "nar/legacy.nar")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(old_positive.progress.phase, CopyPhase::Closed);
        assert!(old_positive.original.expected_sha256.is_none());
        let before_legacy = admin(administrative, "inspect").await;
        assert!(writer
            .copy_external_claimed(
                &legacy,
                &legacy_token,
                &source,
                &destination,
                "nar/legacy.nar",
                None
            )
            .await
            .is_err());
        assert_eq!(
            admin(administrative, "inspect").await["creates"],
            before_legacy["creates"]
        );
    }
    admin(administrative, "select-source-version-2").await;
    db.create_surface_object(&aos_hub_core::db::SetSurfaceObject {
        surface: SurfaceTarget::Registry(source.registry_id.unwrap()),
        object_key: "nar/mismatch.nar".into(),
        object_kind: "immutable".into(),
        content_hash: Some(format!(
            "sha256:{}",
            ready["sourceSha256"].as_str().unwrap()
        )),
        size: Some(8 * 1024 * 1024),
        mutable_publication_id: None,
    })
    .await
    .unwrap();
    admin(administrative, "enable-mismatch-source").await;
    let before_presence = db
        .list_object_presence(
            SurfaceTarget::Registry(source.registry_id.unwrap()),
            "nar/mismatch.nar",
        )
        .await
        .unwrap();
    let (mismatch, mismatch_token) =
        new_claim(&db, &source, &destination, "connected-copy-sha-mismatch").await;
    let changed_source = fetch.list_page("", None, 128).await.unwrap();
    let changed_evidence = changed_source.evidence.get("nar/mismatch.nar").unwrap();
    let before_mismatch = admin(administrative, "inspect").await;
    assert!(writer
        .copy_external_claimed(
            &mismatch,
            &mismatch_token,
            &source,
            &destination,
            "nar/mismatch.nar",
            Some(changed_evidence)
        )
        .await
        .is_err());
    let mismatch_original = writer
        .retained_external_copy_original(&mismatch, &source, &destination, "nar/mismatch.nar")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        mismatch_original.original.expected_sha256.as_deref(),
        ready["sourceSha256"].as_str()
    );
    assert_ne!(
        mismatch_original.progress.phase,
        aos_hub_core::storage_authority::external_object::copy::session::CopyPhase::Closed
    );
    assert_eq!(
        admin(administrative, "inspect").await["completes"],
        before_mismatch["completes"]
    );
    assert_eq!(
        admin(administrative, "inspect").await["completeRequests"],
        before_mismatch["completeRequests"]
    );
    let after_mismatch = db
        .list_object_presence(
            SurfaceTarget::Registry(source.registry_id.unwrap()),
            "nar/mismatch.nar",
        )
        .await
        .unwrap();
    assert_eq!(after_mismatch, before_presence);
    let before_unsupported = admin(administrative, "inspect").await;
    admin(administrative, "null-source-version").await;
    let (unsupported, unsupported_token) =
        new_claim(&db, &source, &destination, "connected-copy-null-version").await;
    assert!(writer
        .copy_external_claimed(
            &unsupported,
            &unsupported_token,
            &source,
            &destination,
            "nar/source.nar",
            Some(current_evidence)
        )
        .await
        .is_err());
    assert_eq!(
        admin(administrative, "inspect").await["creates"],
        before_unsupported["creates"]
    );
    // Diagnosing the genuine unknown remains read-only even when a fresh
    // provider observation cannot qualify another copy incarnation.
    assert!(
        writer
            .retained_external_copy_original(&refused, &source, &destination, "nar/source.nar")
            .await
            .unwrap()
            .unwrap()
            .progress
            .pending
    );
    let observed = admin(administrative, "inspect").await;
    assert!(observed["nativeBoundary"]["calls"].as_u64().unwrap() > 0);
    assert_eq!(observed["nativeBoundary"]["bodyForwardingCalls"], 0);
    assert!(observed["nativeBoundary"]["requestBytes"].as_u64().unwrap() < 2 * 1024 * 1024);
    assert!(observed["nativeBoundary"]["replyBytes"].as_u64().unwrap() < 2 * 1024 * 1024);
    private_file(&root.join("receipt.json"), &serde_json::to_vec_pretty(&json!({
        "version":1,"crossBinding":cross_binding,"sourceBinding":source.binding_id,
        "destinationBinding":destination.binding_id,"actualRepairOperation":repair_operation,
        "actualSqlOperation":settled.operation_id,"state":settled.state,"provider":admin(administrative,"inspect").await,
        "scope":"Controlled actual SQL, Native issuer, persistent Worker guard and TLS fixture; no hosted provider qualification"
    })).unwrap());
}
