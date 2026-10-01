//! Actual root Plan/Apply derivation, private file custody and protected hydration races.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use aos_hub::auth::jwt::JwtKeys;
use aos_hub::domain::{Permission, Principal, Scope};
use aos_hub_core::db::{NewBindingWriteRevision, TokenAuth};
use aos_hub_core::secret_version::{ResolvedSecretVersion, SecretVersionResolver};
use aos_hub_core::service::RpcService;
use aos_hub_core::storage_authority::lease::{BoundedLeaseRevocationPolicy, LeaseInteger};
use aos_hub_core::storage_work::{
    StorageBindingAcknowledgement, StorageBindingControl, StorageWorkKey,
    STORAGE_BINDING_CONTROL_PATH, STORAGE_WORK_SIGNATURE_HEADER,
};
use aos_proto_types::hub_v1 as pb;
use axum::{body::Bytes, http::HeaderMap, routing::post, Router};

use super::*;

#[path = "custody_tests.rs"]
mod credential_custody;

#[path = "registration_tests.rs"]
mod credential_registration;

#[path = "binding_lifetime_tests.rs"]
mod binding_lifetime;

#[path = "publication_tests.rs"]
mod publication_export;

const AUTHORITY: &str = "00000000-0000-4000-8000-000000000041";
const EXECUTOR: &str = "qualification-executor";
const NAMESPACE: &str = "qualification-guard-namespace";
const PREFIX: &str = "managed/binding/.aos-direct-qualification/probe";
const MATERIAL: &[u8] = b"operator-material-canary-never-exported";
const KEY: &[u8] = b"operator-control-key-thirty-two-bytes";
static TLS_TEST_GATE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Fixture {
    db: Arc<Database>,
    rpc: Arc<RpcService>,
    auth: String,
    binding_id: i64,
    configuration: AuthorityConfiguration,
    public_key: String,
    directory: tempfile::TempDir,
}

fn relative_private_directory(directory: &tempfile::TempDir) -> std::path::PathBuf {
    directory
        .path()
        .strip_prefix(std::env::current_dir().unwrap())
        .unwrap()
        .to_owned()
}

fn private_directory() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt as _;
    let directory = tempfile::Builder::new()
        .prefix(".authority-bootstrap-")
        .tempdir_in(".")
        .unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

async fn decision(
    rpc: &RpcService,
    auth: &str,
    input: pb::storage_authority_decision::Input,
    version: &str,
    key: &str,
) {
    let reviewed = rpc
        .plan_storage_authority_decision(
            Some(auth),
            pb::PlanStorageAuthorityDecisionRequest {
                decision: Some(pb::StorageAuthorityDecision { input: Some(input) }),
                expected_resource_version: version.into(),
                idempotency_key: format!("{key}-plan"),
            },
        )
        .await
        .unwrap();
    let plan = reviewed.plan.unwrap();
    rpc.apply_storage_authority_decision(
        Some(auth),
        pb::ApplyStorageAuthorityDecisionRequest {
            plan_id: plan.plan_id,
            confirmation_hash: plan.confirmation_hash,
            idempotency_key: format!("{key}-apply"),
        },
    )
    .await
    .unwrap();
}

async fn fixture_with_database(db: Database) -> Fixture {
    let directory = private_directory();
    let db = Arc::new(db);
    let user = db
        .create_user("bootstrap-owner@example.test", None)
        .await
        .unwrap();
    db.grant_membership("user", user, "instance", "owner")
        .await
        .unwrap();
    let jwt = JwtKeys::random();
    let session = db.create_session(user, 3600, 1).await.unwrap();
    let session = db.validate_session(&session).await.unwrap().unwrap();
    let bearer = jwt
        .mint(
            &TokenAuth {
                token_id: format!("browser-session-{user}"),
                owner: Principal::user(user),
                owner_incarnation: Some(session.owner_incarnation),
                browser_session_id_hash: Some(session.session_id_hash),
                scope: Scope::root(),
                permissions: vec![
                    Permission::StorageManage,
                    Permission::BindingManage,
                    Permission::BindingRead,
                ],
            },
            3600,
        )
        .unwrap();
    let auth = format!("Bearer {bearer}");
    let http = reqwest::Client::new();
    let rpc = Arc::new(RpcService::new(
        db.clone(),
        jwt,
        "https://localhost".into(),
        Arc::new(aos_hub::ratelimit::RateLimiter::new()),
        Arc::new(aos_hub::coreports::HubSurfaceProvider::new(
            db.clone(),
            http.clone(),
            None,
        )),
        Arc::new(aos_hub::coreports::HubSurfaceWriteProvider::new(
            db.clone(),
            http,
        )),
        Arc::new(aos_hub_core::lease::InMemoryLease::new()),
        Arc::new(aos_hub::coreports::HubReindexer::new(db.clone(), None)),
        Arc::new(aos_hub_core::topology_probe::DatabaseTopologyProbeScheduler::new(db.clone())),
        None,
    ));
    let org_id = db.create_org("bootstrap", "Bootstrap").await.unwrap();
    let owner = db.org_by_id(org_id).await.unwrap().unwrap();
    let binding_id = db
        .create_topology_binding(
            Some(org_id),
            "bootstrap-binding",
            &owner.stable_id,
            "Qualification",
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
    let mut credentials = Vec::new();
    for purpose in ["presign", "read", "write"] {
        let credential = db
            .set_binding_credential_revision(
                binding_id,
                purpose,
                &format!("secret://bootstrap/{purpose}/v1"),
                0,
                &hex::encode(Sha256::digest(MATERIAL)),
                "operator",
            )
            .await
            .unwrap();
        let credential = db
            .validate_binding_credential_revision(
                binding_id,
                purpose,
                credential.generation,
                "valid",
                None,
                credential.head_resource_version,
            )
            .await
            .unwrap();
        credentials.push(pb::StorageAuthorityCredentialMember {
            association_id: "bootstrap-association".into(),
            purpose: purpose.into(),
            generation: credential.generation.to_string(),
            secret_version_ref: credential.secret_version_ref,
            credential_fingerprint: credential.credential_fingerprint,
        });
    }
    let writer = db
        .create_binding_write_revision(&NewBindingWriteRevision {
            binding_id,
            write_credential_generation: 1,
            writes_supported: true,
            conditional_writes_supported: true,
            revision_fingerprint: "bootstrap-writer".into(),
            capability_fingerprint: "conditional".into(),
        })
        .await
        .unwrap();
    use pb::storage_authority_decision::Input;
    decision(
        &rpc,
        &auth,
        Input::Create(pb::CreatePhysicalStorageAuthorityDecision {
            authority_id: AUTHORITY.into(),
            guard_namespace_id: NAMESPACE.into(),
            physical_resource_evidence_digest: "1".repeat(64),
            qualification_digest: "2".repeat(64),
            qualified_managed_prefix: Some("managed".into()),
        }),
        "",
        "create",
    )
    .await;
    let authority = rpc
        .get_storage_authority(
            Some(&auth),
            pb::GetStorageAuthorityRequest {
                authority_id: AUTHORITY.into(),
            },
        )
        .await
        .unwrap();
    decision(
        &rpc,
        &auth,
        Input::ApproveAlias(pb::ApproveStorageAuthorityAliasDecision {
            alias_id: "bootstrap-alias".into(),
            authority_id: AUTHORITY.into(),
            address: Some(pb::StorageAuthorityAddress {
                host: Some(pb::storage_authority_address::Host::DnsName(
                    "s3.fleet.test".into(),
                )),
                port: 443,
                bucket: "fixture-bucket".into(),
            }),
            equivalence_evidence_digest: "3".repeat(64),
        }),
        &authority.resource_version,
        "alias",
    )
    .await;
    let binding = db.binding(binding_id).await.unwrap().unwrap();
    decision(
        &rpc,
        &auth,
        Input::AssociateBinding(pb::AssociateStorageAuthorityBindingDecision {
            association_id: "bootstrap-association".into(),
            authority_id: AUTHORITY.into(),
            alias_id: "bootstrap-alias".into(),
            binding_id: binding_id.to_string(),
            binding_stable_id: binding.stable_id,
            binding_resource_version: binding.resource_version.to_string(),
            binding_write_revision: writer.revision.to_string(),
            binding_prefix: "managed/binding".into(),
        }),
        &binding.resource_version.to_string(),
        "association",
    )
    .await;
    decision(
        &rpc,
        &auth,
        Input::Attest(pb::AttestStorageAuthorityExclusivityDecision {
            attestation_id: "bootstrap-attestation".into(),
            authority_id: AUTHORITY.into(),
            managed_prefix: "managed".into(),
            qualification_digest: "2".repeat(64),
            provider_policy_evidence_digest: "4".repeat(64),
            executor_identity: EXECUTOR.into(),
            credentials,
            valid_until: aos_hub_core::clock::now_unix_secs() + 600,
        }),
        &authority.resource_version,
        "attest",
    )
    .await;
    decision(
        &rpc,
        &auth,
        Input::SetAdmission(pb::SetStorageAuthorityAdmissionDecision {
            authority_id: AUTHORITY.into(),
            expected_generation: "0".into(),
            expected_digest: None,
            guard_namespace_id: NAMESPACE.into(),
            state: pb::StorageAuthorityDesiredState::Admitted as i32,
            attestation_id: Some("bootstrap-attestation".into()),
            association_ids: vec!["bootstrap-association".into()],
        }),
        "0",
        "admit",
    )
    .await;
    let creation = db
        .physical_storage_authority(&PhysicalStorageAuthorityId::parse(AUTHORITY).unwrap())
        .await
        .unwrap()
        .unwrap();
    let issuer_root = directory.path().canonicalize().unwrap();
    let configuration = AuthorityConfiguration {
        format_version: 1,
        listen: "127.0.0.1:8765".parse().unwrap(),
        journal_file: issuer_root.join("issuer/state.db"),
        installation: IssuerInstallation {
            format_version: 1,
            authority: creation,
            issuer_resource_id: "independent-retained-resource".into(),
            runtime_identity: "dedicated-issuer".into(),
            executor_identity: EXECUTOR.into(),
        },
        hub_root: issuer_root.join("hub"),
        hub_sqlite_file: None,
        policy: BoundedLeaseRevocationPolicy {
            timing_profile: LeaseTimingProfile {
                profile_id: "explicit-test-policy".into(),
                review_digest: "5".repeat(64),
                maximum_lifetime: LeaseInteger::new(30).unwrap(),
                maximum_clock_uncertainty: LeaseInteger::new(4).unwrap(),
            },
        },
        clock_uncertainty: LeaseInteger::new(2).unwrap(),
        clock_commit_latency: LeaseInteger::new(1).unwrap(),
        clock_recovery: None,
        issuance_enabled: false,
        publisher_key_file: issuer_root.join("publisher.key"),
        renewal_key_file: issuer_root.join("renewal.key"),
        signing_seed_file: issuer_root.join("issuer-only-seed.key"),
        signing_key_id: "actual-issuer-key".into(),
        tls: None,
    };
    let public_key = hex::encode(
        ed25519_dalek::SigningKey::from_bytes(&[7; 32])
            .verifying_key()
            .to_bytes(),
    );
    Fixture {
        db,
        rpc,
        auth,
        binding_id,
        configuration,
        public_key,
        directory,
    }
}

async fn fixture() -> Fixture {
    fixture_with_database(Database::open_in_memory().await.unwrap()).await
}

async fn exported(fixture: &Fixture) -> Bootstrap {
    derive(
        &fixture.db,
        "qualification-deployment",
        &PhysicalStorageAuthorityId::parse(AUTHORITY).unwrap(),
        "bootstrap-association",
        &fixture.configuration,
        &fixture.public_key,
        PREFIX,
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn actual_root_decisions_export_exact_cohorts_and_private_canonical_publication() {
    let fixture = fixture().await;
    let value = exported(&fixture).await;
    assert_eq!(
        value.write_cohort.publication_digest,
        value.read_cohort.publication_digest
    );
    assert_eq!(
        value.selector.association.binding_id.get(),
        fixture.binding_id
    );
    assert_eq!(value.selector.association.binding_write_revision.get(), 1);
    assert_eq!(value.staging_prefix, format!("{PREFIX}/.aos-direct-upload"));
    assert!(!fixture.configuration.signing_seed_file.exists());

    let output = relative_private_directory(&fixture.directory).join("export");
    write_export(&output, &value).unwrap();
    assert_eq!(
        read_bootstrap(&output.join("bootstrap.json")).unwrap(),
        value
    );
    let raw = std::fs::read(output.join("publication.json")).unwrap();
    assert_eq!(raw, serde_json::to_vec(&value.publication).unwrap());
    let document =
        String::from_utf8(std::fs::read(output.join("bootstrap.json")).unwrap()).unwrap();
    assert!(!document.contains(std::str::from_utf8(MATERIAL).unwrap()));
    assert!(!document.contains("provider_contract") && !document.contains("runtime_qualification"));
    assert!(write_export(&output, &value).is_err());
    use std::os::unix::fs::PermissionsExt as _;
    assert_eq!(
        std::fs::metadata(&output).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::metadata(output.join("bootstrap.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    let authority = PhysicalStorageAuthorityId::parse(AUTHORITY).unwrap();
    assert!(derive(
        &fixture.db,
        "qualification-deployment",
        &authority,
        "bootstrap-association",
        &fixture.configuration,
        &fixture.public_key,
        "managed/binding/production"
    )
    .await
    .is_err());
    assert!(derive(
        &fixture.db,
        "qualification-deployment",
        &authority,
        "bootstrap-association",
        &fixture.configuration,
        &fixture.public_key,
        "other/.aos-direct-qualification"
    )
    .await
    .is_err());
    let mut changed = value.clone();
    changed.write_cohort.association.binding_stable_id = "other-binding".into();
    assert!(changed.validate().is_err());

    let mut changed = value.clone();
    changed.write_cohort.allowed_effects.pop();
    assert!(changed.validate().is_err());

    let mut changed = value.clone();
    changed.selector.presign_credential.credential_id = "a".repeat(64);
    assert!(changed.validate().is_err());

    std::fs::set_permissions(
        output.join("bootstrap.json"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(read_bootstrap(&output.join("bootstrap.json")).is_err());
}

#[tokio::test]
async fn existing_sqlite_attachment_rejects_missing_foreign_schema_and_all_mutations() {
    let directory = private_directory();
    let path = directory.path().join("existing.db");
    assert!(open_existing(path.to_str().unwrap()).await.is_err());
    assert!(!path.exists());
    let _writer = Database::open(&path).await.unwrap();
    let before = std::fs::read(&path).unwrap();
    let reader = open_existing(path.to_str().unwrap()).await.unwrap();
    assert!(reader
        .create_user("forbidden@example.test", None)
        .await
        .is_err());
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute("UPDATE hub_schema_identity SET identity = 'foreign'", [])
        .unwrap();
    assert!(open_existing(path.to_str().unwrap()).await.is_err());
    let symlink = directory.path().join("linked");
    std::os::unix::fs::symlink(directory.path(), &symlink).unwrap();
    let relative = relative_private_directory(&directory);
    assert!(custody::publish_directory(
        &relative.join("linked/export"),
        &[("metadata.json", b"{}".to_vec())]
    )
    .is_err());
    assert!(custody::publish_directory(
        &relative.join("oversized"),
        &[("metadata.json", vec![0; MAX_DOCUMENT_BYTES + 1])]
    )
    .is_err());
    assert!(!directory.path().join("oversized").exists());
}

struct MaterialResolver;

#[async_trait::async_trait]
impl SecretVersionResolver for MaterialResolver {
    async fn resolve(&self, _: &str) -> Result<ResolvedSecretVersion> {
        Ok(ResolvedSecretVersion::from_bytes(MATERIAL.to_vec()))
    }
}

#[derive(Clone, Copy)]
enum Fault {
    None,
    RotateCredential,
    DenyAuthority,
}

async fn protected_client(
    fixture: &Fixture,
    fault: Fault,
) -> (
    RemoteStorageWorkClient,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!(
        "https://localhost:{}",
        listener.local_addr().unwrap().port()
    );
    let publishes = Arc::new(AtomicUsize::new(0));
    let revokes = Arc::new(AtomicUsize::new(0));
    let (published, revoked) = (publishes.clone(), revokes.clone());
    let (db, rpc, auth, binding) = (
        fixture.db.clone(),
        fixture.rpc.clone(),
        fixture.auth.clone(),
        fixture.binding_id,
    );
    let app = Router::new().route(
        STORAGE_BINDING_CONTROL_PATH,
        post(move |headers: HeaderMap, body: Bytes| {
            let (published, revoked, db, rpc, auth) = (
                published.clone(),
                revoked.clone(),
                db.clone(),
                rpc.clone(),
                auth.clone(),
            );
            async move {
                let key = StorageWorkKey::new(KEY).unwrap();
                key.verify_body(
                    headers
                        .get(STORAGE_WORK_SIGNATURE_HEADER)
                        .unwrap()
                        .to_str()
                        .unwrap(),
                    &body,
                )
                .unwrap();
                let control: StorageBindingControl = serde_json::from_slice(&body).unwrap();
                control
                    .validate(
                        "qualification-deployment",
                        aos_hub_core::clock::now_unix_secs(),
                    )
                    .unwrap();
                let revision = match control {
                    StorageBindingControl::Publish { publication } => {
                        assert_eq!(publication.materials.len(), 3);
                        published.fetch_add(1, Ordering::SeqCst);
                        match fault {
                            Fault::None => {}
                            Fault::RotateCredential => {
                                db.set_binding_credential_revision(
                                    binding,
                                    "read",
                                    "secret://bootstrap/read/v2",
                                    1,
                                    &hex::encode(Sha256::digest(b"changed")),
                                    "operator",
                                )
                                .await
                                .unwrap();
                            }
                            Fault::DenyAuthority => {
                                decision(
                                    &rpc,
                                    &auth,
                                    pb::storage_authority_decision::Input::SetAdmission(
                                        pb::SetStorageAuthorityAdmissionDecision {
                                            authority_id: AUTHORITY.into(),
                                            expected_generation: "1".into(),
                                            expected_digest: Some(
                                                db.desired_storage_authority_admission(
                                                    &PhysicalStorageAuthorityId::parse(AUTHORITY)
                                                        .unwrap(),
                                                )
                                                .await
                                                .unwrap()
                                                .unwrap()
                                                .digest,
                                            ),
                                            guard_namespace_id: NAMESPACE.into(),
                                            state: pb::StorageAuthorityDesiredState::Blocked as i32,
                                            attestation_id: None,
                                            association_ids: vec![],
                                        },
                                    ),
                                    "1",
                                    "deny-during-hydration",
                                )
                                .await;
                            }
                        }
                        publication.snapshot.revision().unwrap()
                    }
                    StorageBindingControl::Revoke { revision, .. } => {
                        revoked.fetch_add(1, Ordering::SeqCst);
                        revision
                    }
                };
                axum::Json(StorageBindingAcknowledgement { revision })
            }
        }),
    );
    let files = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    let tls = aos_hub::native_tls::NativeTlsListener::new(
        listener,
        &files.join("hub-hybrid-fleet-server.crt"),
        &files.join("hub-hybrid-fleet-server.key"),
        "localhost".into(),
    )
    .unwrap();
    let server = tokio::spawn(async move {
        axum::serve(tls, app).await.unwrap();
    });
    // This bin's test process owns only these fixture HTTP clients; no production
    // trust store or unrelated test runner receives the disposable CA.
    std::env::set_var("SSL_CERT_FILE", files.join("hub-hybrid-fleet-ca.crt"));
    let client =
        RemoteStorageWorkClient::new(&origin, "qualification-deployment".into(), KEY).unwrap();
    (client, publishes, revokes, server)
}

#[tokio::test]
async fn actual_protected_hydration_acknowledges_pins_and_revokes_both_sql_races() {
    let _gate = TLS_TEST_GATE.lock().await;
    for fault in [Fault::None, Fault::RotateCredential, Fault::DenyAuthority] {
        let fixture = fixture().await;
        let value = exported(&fixture).await;
        let (client, published, revoked, server) = protected_client(&fixture, fault).await;
        let result = hydrate(&fixture.db, &value, &client, &MaterialResolver).await;
        assert_eq!(published.load(Ordering::SeqCst), 1);
        match fault {
            Fault::None => {
                let receipt = result.unwrap();
                assert!(receipt.binding_hydrated && !receipt.provider_readiness_evaluated);
                assert_eq!(
                    receipt.snapshot_revision,
                    client
                        .acknowledged_binding_snapshot(fixture.binding_id)
                        .unwrap()
                        .revision()
                        .unwrap()
                );
                assert_eq!(
                    receipt.snapshot.credentials,
                    value.binding_snapshot.credentials
                );
                let output = relative_private_directory(&fixture.directory).join("receipt");
                write_receipt(&output, &receipt).unwrap();
                let body = std::fs::read_to_string(output.join("hydration.json")).unwrap();
                assert!(!body.contains(std::str::from_utf8(MATERIAL).unwrap()));
                assert_eq!(revoked.load(Ordering::SeqCst), 0);
            }
            _ => {
                assert!(result.is_err());
                assert_eq!(revoked.load(Ordering::SeqCst), 1);
                assert!(client
                    .acknowledged_binding_snapshot(fixture.binding_id)
                    .is_err());
            }
        }
        server.abort();
    }
    std::env::remove_var("SSL_CERT_FILE");
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn postgres_operator_role_derives_and_hydrates_with_only_selected_table_reads() {
    let Ok(url) = std::env::var("AOS_HUB_BOOTSTRAP_TEST_PG_URL") else {
        return;
    };
    let _gate = TLS_TEST_GATE.lock().await;
    let fixture = fixture_with_database(Database::connect(&url).await.unwrap()).await;
    let value = exported(&fixture).await;
    let owner = sqlx::PgPool::connect(&url).await.unwrap();
    let role = format!("bootstrap_reader_{}", uuid::Uuid::new_v4().simple());
    let password = uuid::Uuid::new_v4().simple().to_string();
    sqlx::query(&format!(
        "CREATE ROLE {role} LOGIN PASSWORD '{password}' NOSUPERUSER NOCREATEDB NOCREATEROLE"
    ))
    .execute(&owner)
    .await
    .unwrap();
    sqlx::query(&format!("GRANT USAGE ON SCHEMA public TO {role}"))
        .execute(&owner)
        .await
        .unwrap();
    sqlx::query(&format!(
        "GRANT SELECT ON schema_version, hub_schema_identity,
        physical_storage_authorities, physical_storage_aliases,
        binding_storage_authority_revisions, storage_authority_attestations,
        storage_authority_admission_heads, storage_authority_admission_revisions,
        bindings, binding_credential_heads, binding_credential_revisions,
        binding_write_revisions, topology_operations, binding_write_state,
        binding_identity_reservations, topology_plans TO {role}"
    ))
    .execute(&owner)
    .await
    .unwrap();
    let mut address = url::Url::parse(&url).unwrap();
    address.set_username(&role).unwrap();
    address.set_password(Some(&password)).unwrap();
    let reader = open_existing(address.as_str()).await.unwrap();
    let derived = derive(
        &reader,
        &value.deployment_id,
        &PhysicalStorageAuthorityId::parse(AUTHORITY).unwrap(),
        "bootstrap-association",
        &fixture.configuration,
        &fixture.public_key,
        PREFIX,
    )
    .await
    .unwrap();
    assert_eq!(derived.publication, value.publication);
    assert_eq!(derived.selector, value.selector);
    assert!(reader
        .create_user("forbidden-pg@example.test", None)
        .await
        .is_err());
    let (client, published, revoked, server) = protected_client(&fixture, Fault::None).await;
    let receipt = hydrate(&reader, &value, &client, &MaterialResolver)
        .await
        .unwrap();
    assert_eq!(published.load(Ordering::SeqCst), 1);
    assert_eq!(revoked.load(Ordering::SeqCst), 0);
    assert!(receipt.binding_hydrated && !receipt.provider_readiness_evaluated);
    server.abort();
    credential_custody::stage_as_reader(&fixture, &reader).await;
    drop(reader);
    sqlx::query(&format!("DROP OWNED BY {role}"))
        .execute(&owner)
        .await
        .unwrap();
    sqlx::query(&format!("DROP ROLE {role}"))
        .execute(&owner)
        .await
        .unwrap();
    std::env::remove_var("SSL_CERT_FILE");
}

#[tokio::test]
async fn stale_export_refuses_hydration_before_any_protected_publication() {
    let fixture = fixture().await;
    let value = exported(&fixture).await;
    fixture
        .db
        .set_binding_credential_revision(
            fixture.binding_id,
            "presign",
            "secret://bootstrap/presign/v2",
            1,
            &hex::encode(Sha256::digest(b"rotated")),
            "operator",
        )
        .await
        .unwrap();
    let client = RemoteStorageWorkClient::new(
        "https://unreachable.invalid",
        "qualification-deployment".into(),
        KEY,
    )
    .unwrap();
    let result = hydrate(&fixture.db, &value, &client, &MaterialResolver).await;
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("no longer current and validated"));
}
