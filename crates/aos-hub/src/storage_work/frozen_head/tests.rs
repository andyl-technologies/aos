//! Native claim issuance and response admission over a real reviewed GC run.

use super::*;
use aos_hub_core::backend::SqlxBackend;
use aos_hub_core::db::{
    AppendOciProviderInventoryPage, ApplyOciGc, BeginOciProviderInventory,
    CompleteOciProviderInventory, NewBindingWriteRevision, NewSurfacePlacementSpec, PlanOciGc,
    RecordOciConditionalDeleteCapability, SurfaceTarget,
};
use aos_hub_core::secret_version::{ResolvedSecretVersion, SecretVersionResolver};
use aos_hub_core::storage_work::StorageFrozenCleanupHeadResult;
use aos_hub_core::storage_work::StorageWorkKey;
use aos_oci_types::Sha256Digest;
use axum::{
    body::Bytes,
    http::{HeaderMap, Uri},
};
use sha2::{Digest as _, Sha256};
use std::sync::atomic::{AtomicUsize, Ordering};

const WORK_KEY: &[u8] = b"claimed-head-test-key-with-thirty-two-bytes";
const SECRET: &[u8] = b"fixture-access:fixture-delete:fixture-region";

struct Fixture {
    db: Arc<Database>,
    pool: sqlx::SqlitePool,
    claim: OciGcPlacementActionClaim,
}

struct RetainedSecrets(AtomicUsize);

#[async_trait]
impl SecretVersionResolver for RetainedSecrets {
    async fn resolve(&self, version_ref: &str) -> Result<ResolvedSecretVersion> {
        // A rotated current generation must never be selected here.
        anyhow::ensure!(
            version_ref == "secret://claim/delete/v1",
            "wrong retained version"
        );
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(ResolvedSecretVersion::from_bytes(SECRET.to_vec()))
    }
}

async fn fixture() -> Fixture {
    fixture_with_inventory(false).await
}

async fn fixture_with_inventory(versioned: bool) -> Fixture {
    let backend = SqlxBackend::connect_sqlite(":memory:").await.unwrap();
    let pool = match &backend {
        SqlxBackend::Sqlite(pool) => pool.clone(),
        #[cfg(feature = "postgres")]
        SqlxBackend::Postgres(_) => panic!("SQLite fixture required"),
        #[cfg(feature = "mysql")]
        SqlxBackend::Mysql(_) => panic!("SQLite fixture required"),
    };
    let db = Arc::new(Database::with_backend(Box::new(backend)).await.unwrap());
    let now = aos_hub_core::clock::now_unix_secs();
    let org_id = db.create_org("claimed-head", "Claimed HEAD").await.unwrap();
    let owner = db.org_by_id(org_id).await.unwrap().unwrap();
    let binding_id = db
        .create_topology_binding(
            Some(org_id),
            "claimed-binding",
            &owner.stable_id,
            "primary",
            "s3",
            None,
            Some("fixture-bucket"),
            Some("binding-prefix"),
            Some("https"),
            Some("dns"),
            Some(b"storage.example.invalid"),
            Some(443),
            Some("fixture-region"),
            Some("private"),
        )
        .await
        .unwrap();
    let fingerprint = hex::encode(Sha256::digest(SECRET));
    let write = db
        .set_binding_credential_revision(
            binding_id,
            "write",
            "secret://claim/write/v1",
            0,
            &fingerprint,
            "test",
        )
        .await
        .unwrap();
    let write = db
        .validate_binding_credential_revision(
            binding_id,
            "write",
            write.generation,
            "valid",
            None,
            write.head_resource_version,
        )
        .await
        .unwrap();
    let revision = db
        .create_binding_write_revision(&NewBindingWriteRevision {
            binding_id,
            write_credential_generation: write.generation,
            writes_supported: true,
            conditional_writes_supported: true,
            revision_fingerprint: "claimed-write-revision".into(),
            capability_fingerprint: "conditional-write-v1".into(),
        })
        .await
        .unwrap();
    db.observe_binding_write_revision(binding_id, revision.revision, "valid", None, None)
        .await
        .unwrap();
    let state = db.binding_write_state(binding_id).await.unwrap().unwrap();
    db.set_current_binding_write_revision(binding_id, revision.revision, state.resource_version)
        .await
        .unwrap();
    let delete = db
        .set_binding_credential_revision(
            binding_id,
            "delete",
            "secret://claim/delete/v1",
            0,
            &fingerprint,
            "test",
        )
        .await
        .unwrap();
    let delete = db
        .validate_binding_credential_revision(
            binding_id,
            "delete",
            delete.generation,
            "valid",
            None,
            delete.head_resource_version,
        )
        .await
        .unwrap();
    let binding = db.binding(binding_id).await.unwrap().unwrap();
    db.record_oci_conditional_delete_capability(&RecordOciConditionalDeleteCapability {
        binding_id,
        binding_write_revision: revision.revision,
        binding_resource_version: binding.resource_version,
        delete_credential_purpose: Some("delete".into()),
        delete_credential_generation: Some(delete.generation),
        capability_fingerprint: "conditional-delete-v1".into(),
        state: "valid".into(),
        expected_resource_version: None,
        observed_at: now - 5,
    })
    .await
    .unwrap();

    let registry_id = db
        .create_managed_registry(org_id, "", "claimed", "public", &[], false)
        .await
        .unwrap();
    let placement = db
        .create_surface_placement(&NewSurfacePlacementSpec {
            surface: SurfaceTarget::Registry(registry_id),
            name: "frozen".into(),
            binding_id,
            prefix: "old-placement".into(),
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
        .observe_surface_placement(placement.id, "ready", "complete", 1)
        .await
        .unwrap();
    db.bind_surface_placement_write_capability(placement.id, revision.revision)
        .await
        .unwrap();

    // Seed catalog state; plan, apply, holds and claim acquisition use their
    // real transaction APIs. The reviewed inventory reports this object absent.
    let digest = Sha256Digest::digest(b"collect-me");
    sqlx::query(
        "INSERT INTO surface_objects
        (id, registry_id, object_key, object_kind, partition_key, content_hash,
         size, lifecycle_state, created_at, updated_at, resource_version)
        VALUES(301, ?1, ?2, 'immutable', zeroblob(32), ?3, 10, 'active', 1, 1, 1)",
    )
    .bind(registry_id)
    .bind(aos_hub_core::db::oci_blob_object_key(digest))
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
            collector_id: "collector".into(),
            collector_claim_token: "inventory-claim".into(),
            collector_lease_seconds: 100,
            idempotency_key: "empty-inventory".into(),
            now: now - 4,
        })
        .await
        .unwrap();
    db.append_oci_provider_inventory_page(&AppendOciProviderInventoryPage {
        generation_id: inventory.id.clone(),
        collector_id: "collector".into(),
        collector_claim_token: "inventory-claim".into(),
        expected_checkpoint_ordinal: 0,
        expected_provider_cursor: None,
        next_provider_cursor: None,
        last_listed_key: versioned.then(|| aos_hub_core::db::oci_blob_object_key(digest)),
        entries: if versioned {
            vec![aos_hub_core::db::OciProviderInventoryEntryInput {
                object_key: aos_hub_core::db::oci_blob_object_key(digest),
                object_digest: digest,
                observed_hash: digest,
                byte_size: 10,
                strong_etag: "\"original\"".into(),
                provider_version: Some("original-version".into()),
            }]
        } else {
            Vec::new()
        },
        now: now - 3,
        lease_seconds: 100,
    })
    .await
    .unwrap();
    db.complete_oci_provider_inventory(&CompleteOciProviderInventory {
        generation_id: inventory.id,
        collector_id: "collector".into(),
        collector_claim_token: "inventory-claim".into(),
        expected_checkpoint_ordinal: 1,
        observed_at: now - 3,
        now: now - 2,
    })
    .await
    .unwrap();
    let plan = db
        .plan_oci_gc(&PlanOciGc {
            registry_id,
            actor_id: "operator".into(),
            idempotency_key: "reviewed-plan".into(),
            expected_resource_version: 0,
            now: now - 1,
        })
        .await
        .unwrap();
    assert!(db.list_oci_gc_blockers(&plan.id).await.unwrap().is_empty());
    assert_eq!(plan.placement_action_count, 1);
    db.apply_oci_gc(&ApplyOciGc {
        generation_id: plan.id,
        actor_id: "operator".into(),
        idempotency_key: "apply".into(),
        confirmation_hash: plan.confirmation_hash,
        now,
    })
    .await
    .unwrap();
    let claim = db
        .claim_oci_gc_placement_action("worker", "live-claim", now, 100)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(claim.inventory_entry_present, versioned);

    // Current credentials can advance without publishing this retained one.
    let rotated = db
        .set_binding_credential_revision(
            binding_id,
            "delete",
            "secret://claim/delete/v2",
            delete.generation,
            &fingerprint,
            "test",
        )
        .await
        .unwrap();
    db.validate_binding_credential_revision(
        binding_id,
        "delete",
        rotated.generation,
        "valid",
        None,
        rotated.head_resource_version,
    )
    .await
    .unwrap();
    Fixture { db, pool, claim }
}

#[derive(Clone, Copy)]
enum Reply {
    DeleteAcknowledged,
    DeleteWrongVersion,
    DeleteRevokeCredential,
    DeleteLostReply,
    Absent,
    WrongFingerprint,
    RevokeCredential,
    RemoveHold,
    ChangeEpoch,
    ExpireClaim,
    StopRun,
    WrongSignature,
}

async fn worker(
    fixture: &Fixture,
    reply: Reply,
) -> (
    RemoteStorageWorkClient,
    Arc<AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
    let requests = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&requests);
    let pool = fixture.pool.clone();
    let expected = fixture.claim.clone();
    let app = axum::Router::new().fallback(
        axum::routing::post(move |uri: Uri, headers: HeaderMap, body: Bytes| {
            let (count, pool, expected) = (Arc::clone(&count), pool.clone(), expected.clone());
            async move {
                let key = StorageWorkKey::new(WORK_KEY).unwrap();
                let signature = headers.get(STORAGE_WORK_SIGNATURE_HEADER).unwrap().to_str().unwrap();
                if uri.path() == STORAGE_FROZEN_CLEANUP_CREDENTIAL_STAGE_PATH {
                    let stage = verify_storage_frozen_cleanup_credential_stage(&key, signature, &body,
                        "deployment-1", aos_hub_core::clock::now_unix_secs()).unwrap();
                    assert_eq!(stage.request.snapshot.credentials[0].generation, 1);
                    assert_eq!(stage.request.snapshot.credentials[0].secret_version_ref, "secret://claim/delete/v1");
                    count.fetch_add(1, Ordering::SeqCst);
                    if matches!(reply, Reply::RemoveHold) {
                        sqlx::query("DELETE FROM oci_gc_credential_holds WHERE run_id = ?1")
                            .bind(&expected.generation_id).execute(&pool).await.unwrap();
                    }
                    let signed = sign_storage_frozen_cleanup_credential_stage_reply(&key,
                        &StorageFrozenCleanupCredentialStageReply {
                            request: stage.request, material_not_after: stage.material_not_after,
                            stage_body_sha256: hex::encode(Sha256::digest(&body)),
                        }).unwrap();
                    assert!(!std::str::from_utf8(&signed.body).unwrap().contains("value_base64"));
                    return ([(STORAGE_WORK_SIGNATURE_HEADER, signed.signature)], signed.body);
                }
                if uri.path() == STORAGE_FROZEN_DELETE_CUSTODY_PATH {
                    let request = verify_storage_frozen_delete_custody(&key, signature, &body,
                        "deployment-1", aos_hub_core::clock::now_unix_secs()).unwrap();
                    assert!(!std::str::from_utf8(&body).unwrap().contains("value_base64"));
                    assert_eq!(request.claim.action_id, expected.action_id);
                    assert_eq!(request.claim.claim_token, expected.claim_token);
                    assert_eq!(request.claim.snapshot.credentials[0].generation, 1);
                    assert_eq!(request.expected_provider_version, "original-version");
                    assert_eq!(request.claim.operation, StorageFrozenCleanupOperation::DeleteIfMatches);
                    count.fetch_add(1, Ordering::SeqCst);
                    if matches!(reply, Reply::DeleteRevokeCredential) {
                        sqlx::query("UPDATE binding_credential_revisions SET validation_state='invalid' WHERE binding_id=?1 AND purpose='delete' AND generation=1")
                            .bind(expected.binding_id).execute(&pool).await.unwrap();
                    }
                    let provider_version = if matches!(reply, Reply::DeleteWrongVersion) { "replacement" } else { "original-version" };
                    let response = StorageFrozenDeleteCustodyReply { request,
                        outcome: aos_hub_core::storage_authority::external_object::ExternalObjectOutcome::DeleteAcknowledged {
                            provider_version: provider_version.into(), etag: "\"original\"".into(),
                        }, observed_at: aos_hub_core::clock::now_unix_secs() };
                    let signed = sign_storage_frozen_delete_custody_reply(&key, &response).unwrap();
                    let signature = if matches!(reply, Reply::DeleteLostReply) { "0".repeat(64) } else { signed.signature };
                    return ([(STORAGE_WORK_SIGNATURE_HEADER, signature)], signed.body);
                }
                assert_eq!(uri.path(), STORAGE_FROZEN_CLEANUP_CUSTODY_PATH);
                let request = verify_storage_frozen_cleanup_custody(
                        &key,
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
                assert!(!std::str::from_utf8(&body).unwrap().contains("value_base64"));
                count.fetch_add(1, Ordering::SeqCst);
                assert_eq!(request.action_id, expected.action_id);
                assert_eq!(request.claim_token, expected.claim_token);
                assert_eq!(request.operation, StorageFrozenCleanupOperation::Head);
                assert_eq!(request.path, expected.object_key);
                assert_eq!(request.snapshot.credentials[0].generation, 1);
                assert_eq!(
                    aos_hub_core::keymap::r2_key(&request.snapshot.object_prefix, &aos_hub_core::keymap::r2_key(&request.access.placement_prefix, &request.path)),
                    format!("binding-prefix/old-placement/{}", expected.object_key)
                );
                match reply {
                    Reply::RevokeCredential => {
                        sqlx::query(
                            "UPDATE binding_credential_revisions SET validation_state = 'invalid'
                            WHERE binding_id = ?1 AND purpose = 'delete' AND generation = 1",
                        )
                        .bind(expected.binding_id)
                        .execute(&pool)
                        .await
                        .unwrap();
                    }
                    Reply::RemoveHold => {
                        sqlx::query("DELETE FROM oci_gc_credential_holds WHERE run_id = ?1")
                            .bind(&expected.generation_id)
                            .execute(&pool)
                            .await
                            .unwrap();
                    }
                    Reply::ChangeEpoch => {
                        sqlx::query(
                            "UPDATE oci_registry_state SET mutation_epoch = mutation_epoch + 1
                            WHERE registry_id = ?1",
                        )
                        .bind(expected.registry_id)
                        .execute(&pool)
                        .await
                        .unwrap();
                    }
                    Reply::ExpireClaim => {
                        sqlx::query(
                            "UPDATE oci_gc_placement_actions SET lease_expires_at = ?2
                            WHERE id = ?1",
                        )
                        .bind(&expected.action_id)
                        .bind(aos_hub_core::clock::now_unix_secs() - 1)
                        .execute(&pool)
                        .await
                        .unwrap();
                    }
                    Reply::StopRun => {
                        sqlx::query("UPDATE oci_gc_runs SET state = 'failed', finished_at = ?2 WHERE id = ?1")
                            .bind(&expected.generation_id)
                            .bind(aos_hub_core::clock::now_unix_secs())
                            .execute(&pool)
                            .await
                            .unwrap();
                    }
                    _ => {}
                }
                let fingerprint = if matches!(reply, Reply::WrongFingerprint) {
                    "0".repeat(64)
                } else {
                    request.claim_fingerprint().unwrap()
                };
                let reply_mode = reply;
                let reply = StorageFrozenCleanupCustodyReply {
                    result: StorageFrozenCleanupHeadResult {
                        version: 1, request_id: request.request_id.clone(),
                        action_id: request.action_id.clone(), claim_token: request.claim_token.clone(),
                        claim_fingerprint: fingerprint, object: None,
                    },
                    request, observed_at: aos_hub_core::clock::now_unix_secs(),
                };
                let signed = sign_storage_frozen_cleanup_custody_reply(&key, &reply).unwrap();
                let signature = if matches!(reply_mode, Reply::WrongSignature) { "0".repeat(64) } else { signed.signature };
                ([(STORAGE_WORK_SIGNATURE_HEADER, signature)], signed.body)
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let files = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    let tls = crate::native_tls::NativeTlsListener::new(
        listener,
        &files.join("hub-hybrid-fleet-server.crt"),
        &files.join("hub-hybrid-fleet-server.key"),
        "localhost".into(),
    )
    .unwrap();
    let task = tokio::spawn(async move {
        axum::serve(tls, app).await.unwrap();
    });
    let mut client = RemoteStorageWorkClient::new(
        &format!("https://localhost:{}", address.port()),
        "deployment-1".into(),
        WORK_KEY,
    )
    .unwrap();
    client.http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(30))
        .add_root_certificate(
            reqwest::Certificate::from_pem(
                &std::fs::read(files.join("hub-hybrid-fleet-ca.crt")).unwrap(),
            )
            .unwrap(),
        )
        .build()
        .unwrap();
    client.semantic_observation_http = client.http.clone();
    (client, requests, task)
}

#[tokio::test]
async fn retained_generation_head_succeeds_and_altered_claim_never_reaches_worker() {
    let fixture = fixture().await;
    let (client, requests, task) = worker(&fixture, Reply::Absent).await;
    let secrets = RetainedSecrets(AtomicUsize::new(0));

    assert_eq!(
        client
            .frozen_cleanup_head(&fixture.db, &fixture.claim)
            .await
            .unwrap(),
        None
    );
    assert_eq!(requests.load(Ordering::SeqCst), 1);
    let mut altered = fixture.claim.clone();
    altered.object_key = format!("oci/blobs/sha256/{}", "b".repeat(64));
    assert!(client
        .frozen_cleanup_head(&fixture.db, &altered)
        .await
        .is_err());
    assert_eq!(requests.load(Ordering::SeqCst), 1);
    assert_eq!(secrets.0.load(Ordering::SeqCst), 0);

    let mut swapped = fixture.claim.clone();
    swapped.delete_credential_generation = Some(2);
    assert!(client
        .frozen_cleanup_head(&fixture.db, &swapped)
        .await
        .is_err());
    assert_eq!(requests.load(Ordering::SeqCst), 1);
    assert_eq!(secrets.0.load(Ordering::SeqCst), 0);
    task.abort();
}

#[tokio::test]
async fn operator_recovers_only_exact_held_generation_and_refuses_a_hold_removed_during_stage() {
    for reply in [Reply::Absent, Reply::RemoveHold] {
        let fixture = fixture().await;
        let (client, requests, task) = worker(&fixture, reply).await;
        let secrets = RetainedSecrets(AtomicUsize::new(0));
        let result = client
            .stage_frozen_cleanup_credential(&fixture.db, &fixture.claim, &secrets, 86400)
            .await;
        assert_eq!(secrets.0.load(Ordering::SeqCst), 1);
        assert_eq!(requests.load(Ordering::SeqCst), 1);
        if matches!(reply, Reply::Absent) {
            let receipt = result.unwrap();
            assert_eq!(receipt.request.snapshot.credentials[0].generation, 1);
            assert!(!String::from_utf8(serde_json::to_vec(&receipt).unwrap())
                .unwrap()
                .contains("value_base64"));
            assert_eq!(
                client
                    .frozen_cleanup_head(&fixture.db, &fixture.claim)
                    .await
                    .unwrap(),
                None
            );
            assert_eq!(secrets.0.load(Ordering::SeqCst), 1);
            assert_eq!(requests.load(Ordering::SeqCst), 2);
        } else {
            assert!(result.is_err());
        }
        task.abort();
    }
}

#[tokio::test]
async fn known_head_result_requires_current_sql_authorization_when_receipt_is_committed() {
    use aos_hub_core::db::{
        oci_gc_deletion_evidence_digest, OciGcDeleteOutcome, RecordOciGcDeletionSuccess,
    };

    for race in ["none", "hold", "epoch", "binding", "lease"] {
        let fixture = fixture().await;
        let (client, requests, server) = worker(&fixture, Reply::Absent).await;
        assert_eq!(
            client
                .frozen_cleanup_head(&fixture.db, &fixture.claim)
                .await
                .unwrap(),
            None
        );
        let now = aos_hub_core::clock::now_unix_secs();
        match race {
            "hold" => {
                sqlx::query("DELETE FROM oci_gc_credential_holds WHERE run_id = ?1")
                    .bind(&fixture.claim.generation_id)
                    .execute(&fixture.pool)
                    .await
                    .unwrap();
            }
            "epoch" => {
                sqlx::query("UPDATE oci_registry_state SET mutation_epoch = mutation_epoch + 1 WHERE registry_id = ?1")
                    .bind(fixture.claim.registry_id).execute(&fixture.pool).await.unwrap();
            }
            "binding" => {
                sqlx::query(
                    "UPDATE bindings SET resource_version = resource_version + 1 WHERE id = ?1",
                )
                .bind(fixture.claim.binding_id)
                .execute(&fixture.pool)
                .await
                .unwrap();
            }
            "lease" => {
                sqlx::query(
                    "UPDATE oci_gc_placement_actions SET lease_expires_at = ?2 WHERE id = ?1",
                )
                .bind(&fixture.claim.action_id)
                .bind(now)
                .execute(&fixture.pool)
                .await
                .unwrap();
            }
            _ => {}
        }
        let outcome = OciGcDeleteOutcome::AlreadyAbsent;
        let receipt = RecordOciGcDeletionSuccess {
            action_id: fixture.claim.action_id.clone(),
            claim_token: fixture.claim.claim_token.clone(),
            response_idempotency_key: "authenticated-head-receipt".into(),
            outcome,
            conditional_etag: None,
            provider_request_id: None,
            confirmed_at: now,
            evidence_digest: oci_gc_deletion_evidence_digest(
                &fixture.claim.action_id,
                "authenticated-head-receipt",
                outcome,
                None,
                None,
                now,
            )
            .unwrap(),
        };
        let result = fixture
            .db
            .record_oci_gc_placement_action_success(&receipt)
            .await;
        let action = fixture
            .db
            .oci_gc_placement_action(&fixture.claim.action_id)
            .await
            .unwrap()
            .unwrap();
        if race == "none" {
            assert!(result.is_ok(), "{result:?}");
            assert_eq!(action.state, "confirmed_absent");
        } else {
            assert!(result.is_err(), "late receipt race {race} admitted");
            assert_eq!(action.state, "claimed");
            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM oci_gc_deletion_evidence WHERE action_id = ?1",
            )
            .bind(&fixture.claim.action_id)
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
            assert_eq!(count, 0);
        }
        // A refused SQL settlement never retries a provider effect here.
        assert_eq!(requests.load(Ordering::SeqCst), 1);
        server.abort();
    }
}

#[tokio::test]
async fn late_reply_cannot_outlive_credential_hold_epoch_or_stable_scope() {
    for reply in [
        Reply::WrongFingerprint,
        Reply::WrongSignature,
        Reply::RevokeCredential,
        Reply::RemoveHold,
        Reply::ChangeEpoch,
        Reply::ExpireClaim,
        Reply::StopRun,
    ] {
        let fixture = fixture().await;
        let (client, requests, task) = worker(&fixture, reply).await;
        let error = client
            .frozen_cleanup_head(&fixture.db, &fixture.claim)
            .await
            .unwrap_err();
        match reply {
            Reply::WrongFingerprint | Reply::WrongSignature => {
                assert!(
                    error
                        .downcast_ref::<aos_hub_core::storage_work::StorageWorkError>()
                        .is_some(),
                    "{error:#}"
                );
            }
            _ => assert!(
                error.to_string().contains("claim is no longer authorized"),
                "{error:#}"
            ),
        }
        assert_eq!(requests.load(Ordering::SeqCst), 1);
        task.abort();
    }
}

#[tokio::test]
async fn revoked_retained_credential_fails_before_resolution_and_worker_io() {
    let fixture = fixture().await;
    let (client, requests, task) = worker(&fixture, Reply::Absent).await;
    let secrets = RetainedSecrets(AtomicUsize::new(0));
    sqlx::query(
        "UPDATE binding_credential_revisions SET validation_state = 'invalid'
        WHERE binding_id = ?1 AND purpose = 'delete' AND generation = 1",
    )
    .bind(fixture.claim.binding_id)
    .execute(&fixture.pool)
    .await
    .unwrap();

    assert!(client
        .frozen_cleanup_head(&fixture.db, &fixture.claim)
        .await
        .is_err());
    assert_eq!(requests.load(Ordering::SeqCst), 0);
    assert_eq!(secrets.0.load(Ordering::SeqCst), 0);
    task.abort();
}

#[tokio::test]
async fn claimed_opener_authorizes_only_its_real_claim_key() {
    use crate::storage_work::HybridSurfaceProvider;
    use aos_hub_core::fetch::SurfaceProvider as _;

    let fixture = fixture().await;
    let (client, requests, task) = worker(&fixture, Reply::Absent).await;
    let provider = HybridSurfaceProvider::new(Arc::clone(&fixture.db), Arc::new(client));
    let access = fixture.claim.frozen_access();
    let surface = provider
        .claimed_placement_fetcher(&access, &fixture.claim)
        .await
        .unwrap();

    assert!(surface.size("oci/blobs/sha256/another-key").await.is_err());
    assert!(surface.fetch(&fixture.claim.object_key).await.is_err());
    assert_eq!(requests.load(Ordering::SeqCst), 0);
    assert_eq!(surface.size(&fixture.claim.object_key).await.unwrap(), None);
    assert_eq!(requests.load(Ordering::SeqCst), 1);

    let mut changed = access;
    changed.placement_prefix = "different-placement".into();
    assert!(provider
        .claimed_placement_fetcher(&changed, &fixture.claim)
        .await
        .is_err());
    assert_eq!(requests.load(Ordering::SeqCst), 1);
    task.abort();
}

#[tokio::test]
async fn versioned_delete_uses_the_reviewed_frozen_claim_and_rejects_changed_receipts() {
    use crate::storage_work::HybridSurfaceWrites;
    use aos_hub_core::surface_write::SurfaceWriteProvider as _;
    use aos_hub_core::surface_write::{SurfaceDeleteOutcome, SurfaceDeletePrecondition};

    for reply in [
        Reply::DeleteAcknowledged,
        Reply::DeleteWrongVersion,
        Reply::DeleteRevokeCredential,
        Reply::DeleteLostReply,
    ] {
        let fixture = fixture_with_inventory(true).await;
        let (client, requests, task) = worker(&fixture, reply).await;
        let client = Arc::new(client);
        let writes = HybridSurfaceWrites::new(Arc::clone(&fixture.db), Arc::clone(&client));
        let deleter = writes
            .claimed_placement_deleter(&fixture.claim.frozen_access(), &fixture.claim)
            .await
            .unwrap();
        let expected = SurfaceDeletePrecondition {
            etag: fixture.claim.expected_strong_etag.clone(),
            content_hash: Some(fixture.claim.expected_hash.to_string()),
            size: Some(i64::try_from(fixture.claim.expected_size).unwrap()),
            expected_provider_version: fixture.claim.expected_provider_version.clone(),
        };
        let result = deleter
            .delete_if_matches_claimed(
                &fixture.claim.object_key,
                &expected,
                &fixture.claim.action_id,
            )
            .await;
        if matches!(reply, Reply::DeleteAcknowledged) {
            assert!(matches!(
                result.unwrap(),
                SurfaceDeleteOutcome::ConditionalDeleteAcknowledged { .. }
            ));
        } else {
            assert!(result.is_err());
        }
        // The only external call is signed metadata. There is no Native object
        // body read, credential resolution, or retry after ambiguous admission.
        assert_eq!(requests.load(Ordering::SeqCst), 1);
        assert!(deleter.delete(&fixture.claim.object_key).await.is_err());
        let mut changed = expected;
        changed.expected_provider_version = Some("replacement".into());
        assert!(deleter
            .delete_if_matches_claimed(
                &fixture.claim.object_key,
                &changed,
                &fixture.claim.action_id
            )
            .await
            .is_err());
        assert_eq!(requests.load(Ordering::SeqCst), 1);
        task.abort();
    }
}
