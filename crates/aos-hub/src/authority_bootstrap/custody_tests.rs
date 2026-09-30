//! Actual queued controller persistence and cold-client custody challenges over TLS.

use aos_hub::storage_work::HybridStorageCredentialProbeProvider;
use aos_hub_core::storage_work::binding_custody::*;
use aos_hub_core::topology_probe::{DomainProbeController, DomainTlsProbeVerifier};
use axum::http::{StatusCode, Uri};
use tokio::sync::Mutex;

#[path = "custody_cohort_tests.rs"]
mod cohorts;

use super::*;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum CustodyFault {
    None,
    ProbeRotation,
    AdoptionRotation,
    ReplySignature,
    ReplyNonce,
}

#[derive(Default)]
pub(super) struct Controls {
    staged: Mutex<Option<StorageCredentialCustodyProbe>>,
    adopted: Mutex<std::collections::BTreeMap<i64, StorageBindingSnapshot>>,
    revoked: Mutex<std::collections::BTreeSet<String>>,
    active_adoptions: AtomicUsize,
    peak_adoptions: AtomicUsize,
    refuse_adoption: std::sync::atomic::AtomicBool,
    short_lifetime: std::sync::atomic::AtomicBool,
    pause_adoption: std::sync::atomic::AtomicBool,
    adoption_entered: tokio::sync::Notify,
    pending_snapshot: Mutex<Option<StorageBindingSnapshot>>,
    release_adoption: tokio::sync::Notify,
    probes: AtomicUsize,
    adoptions: AtomicUsize,
    revokes: AtomicUsize,
}

pub(super) async fn custody_client(
    fixture: &Fixture,
    fault: CustodyFault,
) -> (
    Arc<RemoteStorageWorkClient>,
    String,
    Arc<Controls>,
    tokio::task::JoinHandle<()>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!(
        "https://localhost:{}",
        listener.local_addr().unwrap().port()
    );
    let controls = Arc::new(Controls::default());
    let state = controls.clone();
    let db = fixture.db.clone();
    let binding = fixture.binding_id;
    let app = Router::new().fallback(post(move |uri: Uri, headers: HeaderMap, body: Bytes| {
        let (state, db) = (state.clone(), db.clone());
        async move {
            let key = StorageWorkKey::new(KEY).unwrap();
            let signature = headers.get(STORAGE_WORK_SIGNATURE_HEADER).unwrap().to_str().unwrap();
            let now = aos_hub_core::clock::now_unix_secs();
            let reply = match uri.path() {
                STORAGE_CREDENTIAL_CUSTODY_PATH => {
                    let stage = verify_storage_credential_custody_stage(
                        &key, signature, &body, "qualification-deployment", now,
                    ).unwrap();
                    assert!(["read", "presign", "write", "list", "delete"].contains(&stage.material.selector.purpose.as_str()));
                    *state.staged.lock().await = Some(stage.request.clone());
                    sign_storage_credential_custody_stage_reply(&key, &StorageCredentialCustodyStageReply {
                        request: stage.request,
                        material_not_after: stage.material_not_after,
                        stage_body_sha256: hex::encode(Sha256::digest(&body)),
                    }).unwrap()
                }
                STORAGE_CREDENTIAL_CUSTODY_PROBE_PATH => {
                    assert!(!std::str::from_utf8(&body).unwrap().contains("value_base64"));
                    let mut request = verify_storage_credential_custody_probe(
                        &key, signature, &body, "qualification-deployment", now,
                    ).unwrap();
                    let original = state.staged.lock().await.clone();
                    let Some(original) = original else {
                        return (StatusCode::SERVICE_UNAVAILABLE,
                            [(STORAGE_WORK_SIGNATURE_HEADER, String::new())], b"{}".to_vec());
                    };
                    request.matches_original(&original).unwrap();
                    state.probes.fetch_add(1, Ordering::SeqCst);
                    if fault == CustodyFault::ProbeRotation {
                        db.set_binding_credential_revision(binding, "read", "secret://bootstrap/read/v3",
                            request.snapshot.credentials[0].generation, &hex::encode(Sha256::digest(b"rotated")), "operator").await.unwrap();
                    }
                    if fault == CustodyFault::ReplyNonce {
                        request.nonce = "e".repeat(64);
                    }
                    // This TLS fixture tests Native authentication and real SQL
                    // persistence; physical SDK probe qualification is separate.
                    sign_storage_credential_custody_probe_reply(&key, &StorageCredentialCustodyProbeReply {
                        request,
                        evidence: aos_hub_core::topology_probe::StorageCredentialProbeEvidence {
                            valid: true, conditional_writes_supported: false, error: None,
                            evidence: serde_json::json!({"fixture": "authenticated-controller-result"}),
                        },
                        observed_at: now,
                    }).unwrap()
                }
                STORAGE_BINDING_ADOPTION_PATH => {
                    assert!(!std::str::from_utf8(&body).unwrap().contains("value_base64"));
                    let request = verify_storage_binding_adoption(
                        &key, signature, &body, "qualification-deployment", now,
                    ).unwrap();
                    state.adoptions.fetch_add(1, Ordering::SeqCst);
                    let active = state.active_adoptions.fetch_add(1, Ordering::SeqCst) + 1;
                    state.peak_adoptions.fetch_max(active, Ordering::SeqCst);
                    *state.pending_snapshot.lock().await = Some(request.expected.clone());
                    state.adoption_entered.notify_one();
                    if state.pause_adoption.load(Ordering::SeqCst) {
                        state.release_adoption.notified().await;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    state.active_adoptions.fetch_sub(1, Ordering::SeqCst);
                    if state.refuse_adoption.load(Ordering::SeqCst)
                        || state.revoked.lock().await.contains(&request.expected.revision().unwrap()) {
                        return (StatusCode::SERVICE_UNAVAILABLE,
                            [(STORAGE_WORK_SIGNATURE_HEADER, String::new())], b"{}".to_vec());
                    }
                    let mut adopted = state.adopted.lock().await;
                    let acknowledged = adopted.entry(request.expected.binding_id)
                        .or_insert_with(|| {
                            let mut snapshot = request.expected.clone();
                            if state.short_lifetime.load(Ordering::SeqCst) {
                                snapshot.expires_at = now + 59;
                            }
                            snapshot
                        }).clone();
                    if state.revoked.lock().await.contains(&acknowledged.revision().unwrap()) {
                        return (StatusCode::SERVICE_UNAVAILABLE,
                            [(STORAGE_WORK_SIGNATURE_HEADER, String::new())], b"{}".to_vec());
                    }
                    if fault == CustodyFault::AdoptionRotation {
                        let head = db.current_binding_credential(binding, "read").await.unwrap().unwrap();
                        db.set_binding_credential_revision(binding, "read", "secret://bootstrap/read/v2",
                            head.generation, &hex::encode(Sha256::digest(b"rotated")), "operator").await.unwrap();
                    }
                    sign_storage_binding_adoption_reply(&key, &StorageBindingAdoptionReply { request, acknowledged }).unwrap()
                }
                STORAGE_BINDING_CONTROL_PATH => {
                    key.verify_body(signature, &body).unwrap();
                    let control: StorageBindingControl = serde_json::from_slice(&body).unwrap();
                    let StorageBindingControl::Revoke { revision, .. } = control else { panic!("unexpected publish") };
                    state.revokes.fetch_add(1, Ordering::SeqCst);
                    state.revoked.lock().await.insert(revision.clone());
                    return (StatusCode::OK, [(STORAGE_WORK_SIGNATURE_HEADER, String::new())], serde_json::to_vec(&StorageBindingAcknowledgement { revision }).unwrap());
                }
                _ => panic!("unexpected custody path"),
            };
            let signature = if fault == CustodyFault::ReplySignature && uri.path() != STORAGE_CREDENTIAL_CUSTODY_PATH {
                "0".repeat(64)
            } else { reply.signature };
            (StatusCode::OK, [(STORAGE_WORK_SIGNATURE_HEADER, signature)], reply.body)
        }
    }));
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
    std::env::set_var("SSL_CERT_FILE", files.join("hub-hybrid-fleet-ca.crt"));
    let client = Arc::new(
        RemoteStorageWorkClient::new(&origin, "qualification-deployment".into(), KEY).unwrap(),
    );
    (client, origin, controls, server)
}

async fn queue_read(
    fixture: &Fixture,
) -> (String, aos_hub_core::db::BindingCredentialRevisionRecord) {
    let head = fixture
        .db
        .current_binding_credential(fixture.binding_id, "read")
        .await
        .unwrap()
        .unwrap();
    let credential = fixture
        .db
        .set_binding_credential_revision(
            fixture.binding_id,
            "read",
            "secret://bootstrap/read/v2",
            head.generation,
            &hex::encode(Sha256::digest(MATERIAL)),
            "operator",
        )
        .await
        .unwrap();
    let binding = fixture
        .db
        .binding(fixture.binding_id)
        .await
        .unwrap()
        .unwrap();
    let plan = fixture
        .rpc
        .plan_validate_binding_credential(
            Some(&fixture.auth),
            pb::PlanValidateBindingCredentialRequest {
                binding_id: binding.stable_id,
                purpose: "read".into(),
                generation: credential.generation,
                expected_resource_version: credential.head_resource_version.to_string(),
                idempotency_key: "custody-plan".into(),
            },
        )
        .await
        .unwrap()
        .plan
        .unwrap();
    let operation = fixture
        .rpc
        .validate_binding_credential(
            Some(&fixture.auth),
            pb::ApplyTopologyPlanRequest {
                plan_id: plan.plan_id,
                confirmation_hash: plan.confirmation_hash,
                idempotency_key: "custody-apply".into(),
            },
        )
        .await
        .unwrap()
        .operation
        .unwrap();
    (operation.operation_id, credential)
}

#[cfg(feature = "postgres")]
pub(super) async fn stage_as_reader(fixture: &Fixture, reader: &Database) {
    let (operation, credential) = queue_read(fixture).await;
    let (client, _, controls, server) = custody_client(fixture, CustodyFault::None).await;
    let reply = stage_queued_credential(reader, &client, &operation, &MaterialResolver, 86400)
        .await
        .unwrap();
    assert_eq!(reply.request.operation_id, operation);
    assert!(controls.staged.lock().await.is_some());
    let current = reader
        .current_binding_credential(fixture.binding_id, "read")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(current, credential);
    assert_eq!(current.validation_state, "unknown");
    assert!(reader
        .validate_binding_credential_revision(
            fixture.binding_id,
            "read",
            credential.generation,
            "valid",
            None,
            credential.head_resource_version
        )
        .await
        .is_err());
    server.abort();
}

#[tokio::test]
async fn actual_plan_apply_queue_staged_operator_material_authenticates_native_controller_result() {
    let _gate = TLS_TEST_GATE.lock().await;
    for fault in [
        CustodyFault::None,
        CustodyFault::ProbeRotation,
        CustodyFault::ReplySignature,
        CustodyFault::ReplyNonce,
    ] {
        let fixture = fixture().await;
        let (operation, credential) = queue_read(&fixture).await;
        let (client, _, controls, server) = custody_client(&fixture, fault).await;
        let receipt =
            stage_queued_credential(&fixture.db, &client, &operation, &MaterialResolver, 86400)
                .await
                .unwrap();
        assert!(!String::from_utf8(serde_json::to_vec(&receipt).unwrap())
            .unwrap()
            .contains("value_base64"));
        assert_eq!(
            fixture
                .db
                .current_binding_credential(fixture.binding_id, "read")
                .await
                .unwrap()
                .unwrap()
                .validation_state,
            "unknown"
        );
        let controller = DomainProbeController::new(
            fixture.db.clone(),
            Arc::new(aos_hub::coreports::HubHttpClient::new(
                reqwest::Client::new(),
            )),
            DomainTlsProbeVerifier::new(),
            "https://dns.example.test/resolve",
            "custody-fixture",
        )
        .unwrap()
        .with_storage_credential_probe(Arc::new(
            HybridStorageCredentialProbeProvider::new(client, fixture.db.clone()),
        ));
        assert_eq!(controller.run_due(1).await.unwrap(), 1);
        let retained = fixture
            .db
            .binding_credential_revision(fixture.binding_id, "read", credential.generation)
            .await
            .unwrap()
            .unwrap();
        let task = fixture
            .db
            .topology_operation(&operation)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(controls.probes.load(Ordering::SeqCst), 1);
        if fault == CustodyFault::None {
            assert_eq!(task.state, "succeeded");
            assert_eq!(retained.validation_state, "valid");
            assert_eq!(
                retained.head_resource_version,
                credential.head_resource_version + 1
            );
        } else {
            assert_eq!(task.state, "failed");
            assert_eq!(retained.validation_state, "unknown");
            assert!(retained.validated_at.is_none());
        }
        server.abort();
    }
    std::env::remove_var("SSL_CERT_FILE");
}

#[tokio::test]
async fn cold_native_adopts_signed_current_snapshot_and_preserves_live_hash_across_restart() {
    let _gate = TLS_TEST_GATE.lock().await;
    let fixture = fixture().await;
    let binding = fixture
        .db
        .binding(fixture.binding_id)
        .await
        .unwrap()
        .unwrap();
    let (client, origin, controls, server) = custody_client(&fixture, CustodyFault::None).await;
    client
        .ensure_remote_binding_snapshot(&fixture.db, &binding)
        .await
        .unwrap();
    let original = client.acknowledged_binding_snapshot(binding.id).unwrap();
    drop(client);
    let cold =
        RemoteStorageWorkClient::new(&origin, "qualification-deployment".into(), KEY).unwrap();
    assert!(cold.acknowledged_binding_snapshot(binding.id).is_err());
    cold.ensure_remote_binding_snapshot(&fixture.db, &binding)
        .await
        .unwrap();
    assert_eq!(
        cold.acknowledged_binding_snapshot(binding.id).unwrap(),
        original
    );
    assert_eq!(controls.adoptions.load(Ordering::SeqCst), 2);
    assert_eq!(controls.revokes.load(Ordering::SeqCst), 0);
    server.abort();
    std::env::remove_var("SSL_CERT_FILE");
}

#[tokio::test]
async fn unstaged_task_remains_unknown_and_actual_authenticated_retry_reuses_original() {
    let _gate = TLS_TEST_GATE.lock().await;
    let fixture = fixture().await;
    let (operation, credential) = queue_read(&fixture).await;
    let original = fixture
        .db
        .topology_operation(&operation)
        .await
        .unwrap()
        .unwrap();
    let (client, _, controls, server) = custody_client(&fixture, CustodyFault::None).await;
    let controller = DomainProbeController::new(
        fixture.db.clone(),
        Arc::new(aos_hub::coreports::HubHttpClient::new(
            reqwest::Client::new(),
        )),
        DomainTlsProbeVerifier::new(),
        "https://dns.example.test/resolve",
        "custody-fixture",
    )
    .unwrap()
    .with_storage_credential_probe(Arc::new(HybridStorageCredentialProbeProvider::new(
        client.clone(),
        fixture.db.clone(),
    )));
    assert_eq!(controller.run_due(1).await.unwrap(), 1);
    let failed = fixture
        .db
        .topology_operation(&operation)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(failed.state, "failed");
    assert_eq!(failed.detail_json, original.detail_json);
    assert_eq!(
        fixture
            .db
            .current_binding_credential(fixture.binding_id, "read")
            .await
            .unwrap()
            .unwrap(),
        credential
    );
    stage_queued_credential(&fixture.db, &client, &operation, &MaterialResolver, 86400)
        .await
        .unwrap();
    fixture
        .rpc
        .retry_operation(
            Some(&fixture.auth),
            pb::MutateOperationRequest {
                operation_id: operation.clone(),
                expected_resource_version: failed.resource_version.to_string(),
                idempotency_key: "retry-staged-original".into(),
            },
        )
        .await
        .unwrap();
    assert_eq!(controller.run_due(1).await.unwrap(), 1);
    assert_eq!(
        fixture
            .db
            .topology_operation(&operation)
            .await
            .unwrap()
            .unwrap()
            .state,
        "succeeded"
    );
    assert_eq!(controls.probes.load(Ordering::SeqCst), 1);
    server.abort();
    std::env::remove_var("SSL_CERT_FILE");
}

#[tokio::test]
async fn cold_native_rejects_rotated_sql_or_forged_adoption_and_revokes_raced_snapshot() {
    let _gate = TLS_TEST_GATE.lock().await;
    for fault in [CustodyFault::AdoptionRotation, CustodyFault::ReplySignature] {
        let fixture = fixture().await;
        let binding = fixture
            .db
            .binding(fixture.binding_id)
            .await
            .unwrap()
            .unwrap();
        let (client, _, controls, server) = custody_client(&fixture, fault).await;
        assert!(client
            .ensure_remote_binding_snapshot(&fixture.db, &binding)
            .await
            .is_err());
        assert!(client.acknowledged_binding_snapshot(binding.id).is_err());
        assert_eq!(controls.adoptions.load(Ordering::SeqCst), 1);
        assert_eq!(
            controls.revokes.load(Ordering::SeqCst),
            usize::from(fault == CustodyFault::AdoptionRotation)
        );
        server.abort();
    }
    std::env::remove_var("SSL_CERT_FILE");
}
