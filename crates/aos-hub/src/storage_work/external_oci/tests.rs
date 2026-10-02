//! Genuine SQL, Native issuer, permanent Worker guard and TLS OCI business flow.
//!
//! This explicit gate requires independently selected source-built artifacts.
//! Its reserved fixture authorization is never a Hosted qualification artifact.

use super::{ExternalOciRuntime, RemoteStorageWorkClient};
use aos_hub_core::{
    auth::jwt::{OciRepositoryGrant, OciTokenGrant},
    db::{Database, NewBindingWriteRevision, NewSurfacePlacementSpec, SurfaceTarget},
    domain::{Permission, Principal},
    secret_version::{ResolvedSecretVersion, SecretVersionResolver},
    storage_authority::{
        external_object::oci::{
            candidate::ExternalOciCandidate, qualification::ExternalOciProfile,
        },
        lease::LeaseCohort,
    },
    storage_work::{STORAGE_WORK_PATH, StorageBindingSnapshot},
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::{
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Arc,
    time::Duration,
};

#[path = "tests/allocation.rs"]
mod allocation;
#[path = "tests/configuration.rs"]
mod configuration;
#[path = "tests/delete.rs"]
mod delete;
#[path = "tests/route.rs"]
mod route;

const MATERIAL: &[u8] = b"fixture-access:fixture-secret:fixture-region";
const CANDIDATE: &str = "fixture-oci-candidate-independent-role-key";
const INGRESS: &str = "fixture-oci-ingress-independent-role-key";
const PREFIX: &str = ".aos-direct-qualification/oci-business/registry";

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
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

struct Task(tokio::task::JoinHandle<()>);
impl Drop for Task {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct Resolver;
#[async_trait::async_trait]
impl SecretVersionResolver for Resolver {
    async fn resolve(&self, reference: &str) -> anyhow::Result<ResolvedSecretVersion> {
        anyhow::ensure!(
            [
                "secret://connected-copy/read/v1",
                "secret://connected-copy/write/v1",
                "secret://connected-copy/list/v1",
                "secret://connected-copy/delete/v1"
            ]
            .contains(&reference),
            "fixture credential reference changed"
        );
        Ok(ResolvedSecretVersion::from_bytes(MATERIAL.to_vec()))
    }
}

fn private(path: &Path, bytes: &[u8]) {
    use std::{io::Write as _, os::unix::fs::OpenOptionsExt as _};
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

async fn fixture() -> (Arc<Database>, aos_hub_core::db::SurfacePlacementRecord) {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org = db
        .create_org("connected-copy", "Connected copy")
        .await
        .unwrap();
    let owner = db.org_by_id(org).await.unwrap().unwrap();
    let registry = db
        .create_managed_registry(org, "", "system", "public", &[], false)
        .await
        .unwrap();
    let binding = db
        .create_topology_binding(
            Some(org),
            "connected-copy-binding",
            &owner.stable_id,
            "Copy fixture",
            "s3",
            None,
            Some("fixture-bucket"),
            Some("managed/binding"),
            Some("https"),
            Some("dns"),
            Some(b"s3.fleet.test"),
            Some(443),
            Some("fixture-region"),
            Some("private"),
        )
        .await
        .unwrap();
    for purpose in ["read", "write", "list", "delete"] {
        let revision = db
            .set_binding_credential_revision(
                binding,
                purpose,
                &format!("secret://connected-copy/{purpose}/v1"),
                0,
                &hex::encode(Sha256::digest(MATERIAL)),
                "fixture",
            )
            .await
            .unwrap();
        if purpose == "delete" {
            assert_eq!(revision.validation_state, "unknown");
            continue;
        }
        db.validate_binding_credential_revision(
            binding,
            purpose,
            revision.generation,
            "valid",
            None,
            revision.head_resource_version,
        )
        .await
        .unwrap();
    }
    let revision = db
        .create_binding_write_revision(&NewBindingWriteRevision {
            binding_id: binding,
            write_credential_generation: 1,
            writes_supported: true,
            conditional_writes_supported: true,
            revision_fingerprint: "fixture-writer".into(),
            capability_fingerprint: "fixture-copy".into(),
        })
        .await
        .unwrap();
    db.observe_binding_write_revision(binding, revision.revision, "valid", None, None)
        .await
        .unwrap();

    let write_state = db.binding_write_state(binding).await.unwrap().unwrap();
    db.set_current_binding_write_revision(binding, revision.revision, write_state.resource_version)
        .await
        .unwrap();

    let placement = db
        .create_surface_placement(&NewSurfacePlacementSpec {
            surface: SurfaceTarget::Registry(registry),
            name: "oci-primary".into(),
            binding_id: binding,
            prefix: PREFIX.into(),
            kind: "complete".into(),
            desired_state: "active".into(),
            hash_range: None,
            desired_read_enabled: true,
            read_order: 0,
            requires_conditional_writes: true,
        })
        .await
        .unwrap();
    let placement = db
        .observe_surface_placement(
            placement.id,
            "ready",
            "complete",
            placement.observation_version.unwrap(),
        )
        .await
        .unwrap();
    db.bind_surface_placement_write_capability(placement.id, revision.revision)
        .await
        .unwrap();
    let placement = db.surface_placement(placement.id).await.unwrap().unwrap();
    db.create_surface_write_authority(
        SurfaceTarget::Registry(registry),
        "oci-actual-authority",
        placement.id,
        placement.resource_version,
        placement.write_spec_version,
        revision.revision,
    )
    .await
    .unwrap();
    let placement = db.surface_placement(placement.id).await.unwrap().unwrap();
    (db, placement)
}

async fn inspect(http: &reqwest::Client, origin: &str) -> Value {
    http.post(format!("{origin}/fixture/inspect"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires pinned AOS Node/workerd/Worker source artifact and a fresh private evidence directory"]
async fn actual_external_oci_blob_config_manifest_index_tag_and_cold_replay() {
    use std::os::unix::fs::PermissionsExt as _;
    let root = PathBuf::from(std::env::var("AOS_OCI_CONNECTED_ROOT").unwrap());
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let root = root.canonicalize().unwrap();
    std::fs::create_dir(root.join("issuer")).unwrap();
    std::fs::set_permissions(root.join("issuer"), std::fs::Permissions::from_mode(0o700)).unwrap();
    let (db, placement) = fixture().await;
    delete::validate_credential(db.clone(), placement.binding_id, &root).await;
    let (authority, object, _copy, delete, rpc, operator) =
        configuration::configure(db.clone(), placement.binding_id, &root).await;
    private(
        &authority.publisher_key_file,
        b"fixture-copy-publisher-independent-role-key",
    );
    private(
        &authority.renewal_key_file,
        configuration::RENEWAL.as_bytes(),
    );
    private(
        &authority.signing_seed_file,
        hex::encode([17; 32]).as_bytes(),
    );
    let publication: aos_hub_core::storage_authority::control::StorageAuthorityPublication =
        serde_json::from_value(object["publications"][0].clone()).unwrap();
    private(
        &root.join("publication.json"),
        &serde_json::to_vec(&publication).unwrap(),
    );
    authority
        .initialize(&root.join("publication.json"))
        .unwrap();
    let issuer = crate::authority_server::AuthorityServer::open(&authority).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer_address = listener.local_addr().unwrap();
    let _issuer = Task(tokio::spawn(async move {
        axum::serve(listener, issuer.router()).await.unwrap();
    }));
    let native_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let native_address = native_listener.local_addr().unwrap();
    let binding = db.binding(placement.binding_id).await.unwrap().unwrap();
    let mut credentials = Vec::new();
    for purpose in ["delete", "list", "read", "write"] {
        credentials.push(
            db.current_binding_credential(binding.id, purpose)
                .await
                .unwrap()
                .unwrap(),
        );
    }
    let now = aos_hub_core::clock::now_unix_secs();
    let snapshot = StorageBindingSnapshot::from_binding(
        "fixture-deployment".into(),
        &binding,
        &credentials,
        now,
        now + 3600,
    )
    .unwrap();
    let cohorts: Vec<LeaseCohort> = serde_json::from_value(object["cohorts"].clone()).unwrap();
    let profile = ExternalOciProfile {
        issuer_installation: authority.installation.clone(),
        read_cohort: cohorts
            .iter()
            .find(|c| {
                c.credential.purpose == aos_hub_core::storage_authority::lease::LeasePurpose::Read
            })
            .unwrap()
            .clone(),
        write_cohort: cohorts
            .iter()
            .find(|c| {
                c.credential.purpose == aos_hub_core::storage_authority::lease::LeasePurpose::Write
            })
            .unwrap()
            .clone(),
        binding_spec_revision: snapshot.binding_spec_revision().unwrap(),
        private_policy: aos_hub_core::direct_upload::DirectPrivateStagePolicyRef {
            policy_id: "controlled-oci-private-writer".into(),
            policy_digest: "8".repeat(64),
            namespace: authority.installation.authority.guard_namespace_id.clone(),
        },
        maximum_blob_bytes: 16 * 1024 * 1024 * 1024,
        maximum_chunk_bytes: 20 * 1024 * 1024,
        part_bytes: 8 * 1024 * 1024,
        versionless_conditional_reads: false,
    };
    profile.validate().unwrap();
    let source = std::env::var("AOS_OCI_WORKER_SOURCE_DIGEST").unwrap();
    let candidate = ExternalOciCandidate {
        version: 1,
        deployment_id: "fixture-deployment".into(),
        source_digest: source.clone(),
        script_version: aos_hub_core::direct_upload::direct_worker_emulated_script_id(&source)
            .unwrap(),
        profile_digest: profile.digest().unwrap(),
        placement_prefix: PREFIX.into(),
        issued_at: now,
        expires_at: now + 900,
    };
    let (candidate_bytes, candidate_signature) = candidate
        .sign(&aos_hub_core::storage_work::StorageWorkKey::new(CANDIDATE).unwrap())
        .unwrap();
    let clock_policy = aos_hub_core::direct_upload::DirectClockPolicy {
        version: 1,
        mode: aos_hub_core::direct_upload::DirectClockPolicyMode::BoundedUtc,
        uncertainty_seconds: aos_hub_core::direct_upload::WireInteger::new(2),
    };
    assert_eq!(object["clock_uncertainty"], 2);
    let clock_qualification = clock_policy.commitment().unwrap();

    private(&root.join("setup.json"),&serde_json::to_vec(&json!({
        "issuer":issuer_address.to_string(),"native":native_address.to_string(),"object":object,"delete":delete,
        "guardClockPolicy":clock_policy,"guardClockQualification":clock_qualification,
        "oci":{"version":1,"profiles":[profile]},"application":configuration::APPLICATION,
        "guard":configuration::GUARD,"renewal":configuration::RENEWAL,"ingress":INGRESS,
        "candidateKey":CANDIDATE,"candidate":String::from_utf8(candidate_bytes).unwrap(),"candidateSignature":candidate_signature,
        "physicalPrefix":format!("managed/binding/{PREFIX}"),"sourceKey":format!("managed/binding/{PREFIX}/fixture-unused-source")
    })).unwrap());
    let node = std::env::var("AOS_OCI_NODE").unwrap();
    let workerd = std::env::var("AOS_OCI_WORKERD").unwrap();
    assert!(node.starts_with("/nix/store/") && workerd.starts_with("/nix/store/"));
    let log = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(root.join("fixture.log"))
        .unwrap();
    let script = std::env::var_os("AOS_OCI_FIXTURE_SCRIPT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../pkgs/tools/aos-hub-external-oci-connected-e2e.mjs")
        });
    let mut process = Process(
        Command::new(node)
            .arg(script)
            .arg(&root)
            .arg(std::env::var("AOS_OCI_DIST").unwrap())
            .arg(workerd)
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures"))
            .stdin(Stdio::piped())
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap(),
    );
    tokio::time::timeout(Duration::from_secs(30), async {
        while !root.join("ready.json").exists() {
            assert!(
                process.0.try_wait().unwrap().is_none(),
                "fixture exited before readiness; inspect retained fixture.log"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    let ready: Value =
        serde_json::from_slice(&std::fs::read(root.join("ready.json")).unwrap()).unwrap();
    let origin = ready["workerOrigin"].as_str().unwrap();
    let relay = ready["relayAddress"].as_str().unwrap().parse().unwrap();
    let ca = std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/hub-hybrid-fleet-s3-ca.crt"),
    )
    .unwrap();
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .timeout(Duration::from_secs(60))
        .add_root_certificate(reqwest::Certificate::from_pem(&ca).unwrap())
        .resolve("s3.fleet.test", relay)
        .build()
        .unwrap();
    let mut client = RemoteStorageWorkClient::new(
        origin,
        "fixture-deployment".into(),
        configuration::APPLICATION.as_bytes(),
    )
    .unwrap();
    client.http = http.clone();
    client.semantic_observation_http = http.clone();
    client = client
        .with_external_oci_runtime(
            ExternalOciRuntime::controlled(
                candidate,
                profile,
                2,
                configuration::GUARD.as_bytes(),
                now,
            )
            .unwrap(),
        )
        .unwrap();
    let work = Arc::new(client);
    for credential in &credentials {
        let purpose = &credential.purpose;
        let plan = rpc
            .plan_validate_binding_credential(
                Some(&operator),
                aos_proto_types::hub_v1::PlanValidateBindingCredentialRequest {
                    binding_id: binding.stable_id.clone(),
                    purpose: purpose.clone(),
                    generation: credential.generation,
                    expected_resource_version: credential.head_resource_version.to_string(),
                    idempotency_key: format!("oci-custody-{purpose}-plan"),
                },
            )
            .await
            .unwrap()
            .plan
            .unwrap();
        let operation = rpc
            .validate_binding_credential(
                Some(&operator),
                aos_proto_types::hub_v1::ApplyTopologyPlanRequest {
                    plan_id: plan.plan_id,
                    confirmation_hash: plan.confirmation_hash,
                    idempotency_key: format!("oci-custody-{purpose}-apply"),
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
        let stage_now = aos_hub_core::clock::now_unix_secs();
        db.validate_binding_identity_reservations().await.unwrap();
        let stage = aos_hub_core::storage_work::binding_custody::StorageCredentialCustodyProbe {
            version: 1,
            nonce: uuid::Uuid::new_v4().simple().to_string().repeat(2),
            issued_at: stage_now,
            expires_at: stage_now + 30,
            operation_id: queued.operation_id.clone(),
            probe_token: detail["probeToken"].as_str().unwrap().into(),
            head_resource_version: credential.head_resource_version,
            snapshot: StorageBindingSnapshot::for_credential_probe(
                "fixture-deployment".into(),
                &binding,
                credential,
                stage_now,
            )
            .unwrap(),
        };
        work.stage_credential_custody(stage, &Resolver, stage_now + 3600)
            .await
            .unwrap();
        db.validate_binding_identity_reservations().await.unwrap();
        assert_eq!(
            db.topology_operation(&queued.operation_id)
                .await
                .unwrap()
                .unwrap(),
            queued
        );
        assert_eq!(
            &db.current_binding_credential(binding.id, purpose)
                .await
                .unwrap()
                .unwrap(),
            credential
        );
        assert!(
            work.probe_retained_credential(
                &binding,
                credential,
                &operation.operation_id,
                detail["probeToken"].as_str().unwrap()
            )
            .await
            .unwrap()
            .valid
        );
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
    delete::qualify_capability(db.clone(), work.clone(), &placement, &root).await;
    let port = url::Url::parse(origin).unwrap().port().unwrap();
    route::install(&db, &placement, port).await;
    let mut state =
        crate::server::AppState::new(db.clone(), "https://control.fixture.test".into()).await;
    state.deployment_id = Some("fixture-deployment".into());
    let user = db
        .create_user("external-oci-writer@example.test", None)
        .await
        .unwrap();
    db.grant_membership("user", user, "instance", "owner")
        .await
        .unwrap();
    let (token, _) = db
        .create_token(
            Principal::user(user),
            "instance",
            &[Permission::Publish],
            None,
            None,
        )
        .await
        .unwrap();
    let auth = db.current_token_authority(&token).await.unwrap().unwrap();
    let registry = db
        .registry_by_id(placement.registry_id.unwrap())
        .await
        .unwrap()
        .unwrap();
    let authorization = state
        .auth
        .jwt_keys
        .mint_oci(
            &OciTokenGrant {
                subject: format!("token:{token}"),
                owner_kind: Some("user".into()),
                owner_incarnation: auth.owner_incarnation,
                authority: format!("s3.fleet.test:{port}"),
                registry_stable_id: registry.stable_id,
                grants: vec![OciRepositoryGrant {
                    repository: aos_oci_types::RepositoryName::parse("aos").unwrap(),
                    actions: vec!["pull".into(), "push".into()],
                }],
            },
            900,
        )
        .unwrap();
    let router = crate::server::router_with_hybrid_ingress(
        Arc::new(state),
        Arc::new(aos_hub_core::hybrid_ingress::HybridIngressKey::new(INGRESS).unwrap()),
        "fixture-deployment".into(),
        work.clone(),
    )
    .await;
    let _native = Task(tokio::spawn(async move {
        axum::serve(
            native_listener,
            router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    }));
    http.post(format!(
        "{}/fixture/lose-cleanup-reply",
        ready["administrativeOrigin"].as_str().unwrap()
    ))
    .send()
    .await
    .unwrap()
    .error_for_status()
    .unwrap();
    let completed_url = business(
        &http,
        origin,
        &format!("Bearer {authorization}"),
        &db,
        placement.registry_id.unwrap(),
        &format!("token:{token}"),
        ready["administrativeOrigin"].as_str().unwrap(),
        &root,
    )
    .await;

    delete::settle_terminal_chunks(
        &db,
        work.clone(),
        &http,
        ready["administrativeOrigin"].as_str().unwrap(),
        &root,
    )
    .await;

    delete::unknown_acknowledgement(
        &db,
        work.clone(),
        &http,
        origin,
        &format!("Bearer {authorization}"),
        ready["administrativeOrigin"].as_str().unwrap(),
        &root,
    )
    .await;

    let before_revocation = inspect(&http, ready["administrativeOrigin"].as_str().unwrap()).await;
    db.revoke_token(&token).await.unwrap();
    let revoked = http
        .put(&completed_url)
        .header("authorization", format!("Bearer {authorization}"))
        .send()
        .await
        .unwrap();
    assert!(matches!(
        revoked.status(),
        reqwest::StatusCode::UNAUTHORIZED
            | reqwest::StatusCode::FORBIDDEN
            | reqwest::StatusCode::BAD_GATEWAY
    ));
    let after_revocation = inspect(&http, ready["administrativeOrigin"].as_str().unwrap()).await;
    for field in [
        "creates",
        "parts",
        "completes",
        "completeRequests",
        "aborts",
        "signatures",
        "conditionalReads",
        "unconditionalReads",
        "providerReceivedBytes",
        "providerOfferedReadBytes",
    ] {
        assert_eq!(
            after_revocation[field], before_revocation[field],
            "revoked completion replay dispatched a provider operation: {field}"
        );
    }
    private(&root.join("current-actor-refusal.json"), &serde_json::to_vec_pretty(&json!({
        "status":revoked.status().as_u16(), "provider_dispatch_delta":0,
        "scope":"Actual revoked IAM token on exact already-completed OCI upload; no provider operation observed."
    })).unwrap());
}

async fn upload(
    http: &reqwest::Client,
    origin: &str,
    auth: &str,
    bytes: &[u8],
    patch: bool,
    administrative: &str,
) -> (aos_oci_types::Sha256Digest, String) {
    let digest = aos_oci_types::Sha256Digest::digest(bytes);
    let start = http
        .post(format!(
            "{origin}/v2/aos/blobs/uploads/?size={}",
            bytes.len()
        ))
        .header("authorization", auth)
        .send()
        .await
        .unwrap();
    assert_eq!(
        start.status(),
        reqwest::StatusCode::ACCEPTED,
        "actual upload allocation: {}",
        start.status()
    );
    let location = start
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let url = url::Url::parse(origin)
        .unwrap()
        .join(&location)
        .unwrap()
        .to_string();
    if patch && !bytes.is_empty() {
        let response = http
            .patch(&url)
            .header("authorization", auth)
            .header("content-type", "application/octet-stream")
            .header("content-range", format!("0-{}", bytes.len() - 1))
            .body(bytes.to_vec())
            .send()
            .await
            .unwrap();
        let status = response.status();
        let response_body = response.bytes().await.unwrap();
        assert_eq!(
            status,
            reqwest::StatusCode::ACCEPTED,
            "actual PATCH: {}",
            String::from_utf8_lossy(&response_body)
        );
    }
    let final_url = format!("{url}?digest={digest}");
    let response = http
        .put(&final_url)
        .header("authorization", auth)
        .header("content-type", "application/octet-stream")
        .body(if patch { Vec::new() } else { bytes.to_vec() })
        .send()
        .await
        .unwrap();
    let status = response.status();
    let body = response.bytes().await.unwrap();
    assert_eq!(
        status,
        reqwest::StatusCode::CREATED,
        "actual final PUT: {}",
        String::from_utf8_lossy(&body)
    );
    // Exact already-complete requests must return metadata without creating
    // another stage or canonical provider effect. The empty replay does not
    // offer a second public object body.
    let replay = http
        .put(&final_url)
        .header("authorization", auth)
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), reqwest::StatusCode::CREATED);

    let before_refusals = inspect(http, administrative).await;
    let wrong_digest = aos_oci_types::Sha256Digest::digest(b"different completed selection");
    for target in [&url, &format!("{url}?digest={wrong_digest}")] {
        let refused = http
            .put(target)
            .header("authorization", auth)
            .send()
            .await
            .unwrap();
        assert!(
            matches!(
                refused.status(),
                reqwest::StatusCode::BAD_REQUEST | reqwest::StatusCode::BAD_GATEWAY
            ),
            "invalid final selection was not refused before its body"
        );
    }
    let nonempty = http
        .put(&final_url)
        .header("authorization", auth)
        .body(b"new bytes".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(nonempty.status(), reqwest::StatusCode::CONFLICT);
    let after_refusals = inspect(http, administrative).await;
    let prior_native_records = before_refusals["nativeBusiness"].as_array().unwrap().len();
    assert!(
        after_refusals["nativeBusiness"].as_array().unwrap()[prior_native_records..]
            .iter()
            .all(|record| record["requestBytes"] == 0),
        "completed refusal forwarded a new Native object body"
    );
    assert_eq!(
        after_refusals["nativeBoundary"]["bodyForwardingCalls"],
        before_refusals["nativeBoundary"]["bodyForwardingCalls"]
    );
    for field in [
        "creates",
        "parts",
        "completes",
        "completeRequests",
        "aborts",
        "conditionalReads",
        "unconditionalReads",
        "providerReceivedBytes",
        "providerOfferedReadBytes",
    ] {
        assert_eq!(
            after_refusals[field], before_refusals[field],
            "completed body/digest refusal dispatched a provider operation: {field}"
        );
    }
    (digest, final_url)
}

async fn put_document(
    http: &reqwest::Client,
    origin: &str,
    auth: &str,
    tag: &str,
    media: &str,
    bytes: &[u8],
) -> aos_oci_types::Sha256Digest {
    let response = http
        .put(format!("{origin}/v2/aos/manifests/{tag}"))
        .header("authorization", auth)
        .header("content-type", media)
        .body(bytes.to_vec())
        .send()
        .await
        .unwrap();
    let status = response.status();
    let body = response.bytes().await.unwrap();
    assert_eq!(
        status,
        reqwest::StatusCode::CREATED,
        "actual OCI document: {}",
        String::from_utf8_lossy(&body)
    );
    aos_oci_types::Sha256Digest::digest(bytes)
}

async fn business(
    http: &reqwest::Client,
    origin: &str,
    auth: &str,
    db: &Database,
    registry: i64,
    owner: &str,
    administrative: &str,
    root: &Path,
) -> String {
    let mut layer = vec![0_u8; 8 * 1024 * 1024 + 31];
    for (index, byte) in layer.iter_mut().enumerate() {
        *byte = (index % 251) as u8;
    }
    let (layer_digest, layer_final_url) =
        upload(http, origin, auth, &layer, true, administrative).await;
    let (empty, empty_final_url) = upload(http, origin, auth, b"", false, administrative).await;
    let empty_upload_id = empty_final_url
        .rsplit_once("/blobs/uploads/")
        .unwrap()
        .1
        .split('?')
        .next()
        .unwrap();
    let empty_upload = db
        .oci_upload(
            empty_upload_id,
            owner,
            owner,
            aos_hub_core::clock::now_unix_secs(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(empty_upload.state, "complete");
    assert_eq!(empty_upload.cleanup_state, "complete");
    assert_eq!(empty_upload.materialization_placement_id, None);
    assert_eq!(empty_upload.materialization_binding_id, None);
    let config = serde_json::to_vec(&json!({
        "architecture": "amd64", "os": "linux",
        "rootfs": {"type": "layers", "diff_ids": [layer_digest.to_string()]},
    }))
    .unwrap();
    let (config_digest, _) = upload(http, origin, auth, &config, false, administrative).await;
    let manifest=serde_json::to_vec(&json!({
        "schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",
        "config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":config_digest.to_string(),"size":config.len()},
        "layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":layer_digest.to_string(),"size":layer.len()}]
    })).unwrap();
    let manifest_digest = put_document(
        http,
        origin,
        auth,
        "candidate",
        "application/vnd.oci.image.manifest.v1+json",
        &manifest,
    )
    .await;
    let index=serde_json::to_vec(&json!({
        "schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json",
        "manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":manifest_digest.to_string(),"size":manifest.len(),"platform":{"architecture":"amd64","os":"linux"}}]
    })).unwrap();
    let index_digest = put_document(
        http,
        origin,
        auth,
        "latest",
        "application/vnd.oci.image.index.v1+json",
        &index,
    )
    .await;
    let observed = inspect(http, administrative).await;
    assert!(observed["creates"].as_u64().unwrap() >= 8);
    assert_eq!(observed["emptyPuts"], 1);
    assert!(observed["conditionalReads"].as_u64().unwrap() > 0);
    assert_eq!(observed["unconditionalReads"], 0);
    assert!(observed["providerReceivedBytes"].as_u64().unwrap() >= layer.len() as u64 * 2);
    assert!(observed["providerOfferedReadBytes"].as_u64().unwrap() >= layer.len() as u64);
    assert!(observed["maximumPartBytes"].as_u64().unwrap() <= 8 * 1024 * 1024);
    assert_eq!(observed["nativeBoundary"]["bodyForwardingCalls"], 0);
    assert!(
        observed["nativeBusiness"]
            .as_array()
            .unwrap()
            .iter()
            .all(|record| record["requestBytes"].as_u64().unwrap() <= 256 * 1024)
    );
    for (digest, size) in [
        (layer_digest, layer.len()),
        (empty, 0),
        (config_digest, config.len()),
        (manifest_digest, manifest.len()),
        (index_digest, index.len()),
    ] {
        let row = db
            .surface_object_named(
                SurfaceTarget::Registry(registry),
                &aos_hub_core::db::oci_blob_object_key(digest),
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.size, Some(size as i64));
    }
    let before = observed["creates"].clone();
    http.post(format!("{administrative}/fixture/restart-replace-source"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let replay = http
        .put(&layer_final_url)
        .header("authorization", auth)
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), reqwest::StatusCode::CREATED);
    let tags = http
        .get(format!("{origin}/v2/aos/tags/list"))
        .header("authorization", auth)
        .send()
        .await
        .unwrap();
    assert_eq!(tags.status(), reqwest::StatusCode::OK);
    let tags: Value = tags.json().await.unwrap();
    assert!(
        tags["tags"]
            .as_array()
            .unwrap()
            .iter()
            .any(|tag| tag == "latest")
    );
    assert_eq!(inspect(http, administrative).await["creates"], before);
    private(&root.join("receipt.json"),&serde_json::to_vec_pretty(&json!({
        "version":1,"provider":inspect(http,administrative).await,"registry":registry,
        "layer":layer_digest.to_string(),"config":config_digest.to_string(),"manifest":manifest_digest.to_string(),"index":index_digest.to_string(),
        "scope":"Controlled actual SQL/current IAM/issuer/persistent Worker guard/versioned TLS provider. Provider read bytes are offered, not client-consumption measurements. Terminal private cleanup is exercised by a separately retained Delete-capability/guard receipt gate. No hosted acceptance or whole-isolate budget claim."
    })).unwrap());
    layer_final_url
}
