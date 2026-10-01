//! Signed loopback control transport against real reviewed SQLite decisions.

mod denial;

// The signed transport regression uses the production pure ledger handler,
// independently of the transport fault fixture below.
#[path = "../../../../../aos-hub-worker/src/hybrid_authority_state.rs"]
mod actual_ledger;

use std::collections::BTreeMap;
use std::sync::Arc;

use aos_hub_core::db::{NewTopologyPlan, ReviewedStorageAuthorityDecision};
use aos_hub_core::storage_authority::control::{
    sign_authority_message, verify_authority_message, StorageAuthorityControlReceipt,
    StorageAuthorityOperation, StorageAuthorityPublication, StorageAuthorityRequest,
    StorageAuthorityResponse, STORAGE_AUTHORITY_CONTROL_PATH,
};
use aos_hub_core::storage_authority::{
    CreatePhysicalStorageAuthority, SetStorageAuthorityAdmission, StorageAuthorityAdmissionState,
    StorageAuthorityDecisionInput,
};
use aos_hub_core::storage_work::{StorageWorkKey, STORAGE_WORK_SIGNATURE_HEADER};
use axum::{
    body::Bytes, extract::State, http::HeaderMap, response::IntoResponse, routing::post, Router,
};
use tokio::sync::Mutex;

use super::*;

const NAMESPACE: &str = "account/namespace";
const EXECUTOR: &str = "configured-executor";
const KEY: &[u8] = b"authority-control-test-key-32bytes";

fn canonical_digest<T: serde::Serialize>(value: &T) -> Result<String> {
    use sha2::Digest as _;

    Ok(hex::encode(sha2::Sha256::digest(serde_json::to_vec(
        value,
    )?)))
}

fn authority_id() -> PhysicalStorageAuthorityId {
    PhysicalStorageAuthorityId::parse("00000000-0000-4000-8000-000000000021").unwrap()
}

async fn apply(db: &Database, input: StorageAuthorityDecisionInput) {
    let id = uuid::Uuid::new_v4().to_string();
    let confirmation = canonical_digest(&input).unwrap();
    db.create_topology_plan(&NewTopologyPlan {
        plan_id: id.clone(),
        plan_kind: input.plan_kind().into(),
        actor_kind: "user".into(),
        actor_id: Some(7),
        // This fixture exercises trusted DB primitives, not public actor authorization.
        actor_incarnation: None,
        actor_label: "reviewed root".into(),
        scope: "instance".into(),
        input_versions_json: serde_json::to_string(&input).unwrap(),
        effects_json: "[]".into(),
        warnings_json: "[]".into(),
        confirmation_hash: Some(confirmation.clone()),
        request_idempotency_key: Some(id.clone()),
        expires_at: aos_hub_core::clock::now_unix_secs() + 300,
    })
    .await
    .unwrap();
    db.begin_topology_plan_apply(&id, "exact-apply")
        .await
        .unwrap();
    db.apply_storage_authority_decision(
        &ReviewedStorageAuthorityDecision {
            plan_id: id,
            apply_idempotency_key: "exact-apply".into(),
            confirmation_hash: confirmation,
            actor_kind: "user".into(),
            actor_id: 7,
            actor_incarnation: None,
        },
        &input,
    )
    .await
    .unwrap();
}

async fn advance(db: &Database) {
    let desired = db
        .desired_storage_authority_admission(&authority_id())
        .await
        .unwrap();
    apply(
        db,
        StorageAuthorityDecisionInput::SetAdmission(SetStorageAuthorityAdmission {
            authority_id: authority_id(),
            expected_generation: desired.as_ref().map_or(0, |value| value.generation),
            expected_digest: desired.map(|value| value.digest),
            guard_namespace_id: NAMESPACE.into(),
            state: StorageAuthorityAdmissionState::Blocked,
            attestation_id: None,
            association_ids: vec![],
        }),
    )
    .await;
}

async fn database(path: &std::path::Path) -> Arc<Database> {
    let db = Arc::new(Database::open(path).await.unwrap());
    apply(
        &db,
        StorageAuthorityDecisionInput::Create(CreatePhysicalStorageAuthority {
            authority_id: authority_id(),
            guard_namespace_id: NAMESPACE.into(),
            physical_resource_evidence_digest: "1".repeat(64),
            qualification_digest: "2".repeat(64),
            qualified_managed_prefix: "fresh".into(),
        }),
    )
    .await;
    advance(&db).await;
    db
}

#[derive(Clone, Copy, Default)]
enum Fault {
    #[default]
    None,
    WrongSignature,
    WrongNonce,
    SqlAdvance,
    PreflightSqlAdvance,
    RemoteAdvance,
    ResponseLoss,
}

#[derive(Default)]
struct Ledger {
    watermark: Option<StorageAuthorityRemoteWatermark>,
    receipts: BTreeMap<i64, String>,
    denial_requests: usize,
    nonces: Vec<String>,
    publications: usize,
    fault: Fault,
}

#[derive(Clone)]
struct Mock {
    ledger: Arc<Mutex<Ledger>>,
    db: Arc<Database>,
}

async fn control(
    State(mock): State<Mock>,
    headers: HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    let key = StorageWorkKey::new(KEY).unwrap();
    verify_authority_message(
        &key,
        false,
        headers
            .get(STORAGE_WORK_SIGNATURE_HEADER)
            .unwrap()
            .to_str()
            .unwrap(),
        &body,
    )
    .unwrap();
    let request: StorageAuthorityRequest = serde_json::from_slice(&body).unwrap();
    let now = aos_hub_core::clock::now_unix_secs();
    request
        .validate("paired-deployment", NAMESPACE, now)
        .unwrap();
    let mut ledger = mock.ledger.lock().await;
    assert!(!ledger.nonces.contains(&request.nonce));
    ledger.nonces.push(request.nonce.clone());
    let mut receipt = None;
    if matches!(request.operation, StorageAuthorityOperation::Watermark(_))
        && matches!(ledger.fault, Fault::PreflightSqlAdvance)
        && ledger.publications == 0
    {
        advance(&mock.db).await;
    }
    if let StorageAuthorityOperation::Publish(publication)
    | StorageAuthorityOperation::DenyFromWatermark(StorageAuthorityDeniedTransition {
        publication,
        ..
    }) = &request.operation
    {
        publication.validate(NAMESPACE, EXECUTOR).unwrap();
        let digest = canonical_digest(publication).unwrap();
        if let Some(previous) = ledger.receipts.get(&publication.generation) {
            assert_eq!(previous, &digest);
        } else {
            publication.validate_admission_time(now).unwrap();
            let predecessor = ledger.watermark.as_ref();
            if let StorageAuthorityOperation::DenyFromWatermark(transition) = &request.operation {
                transition.validate(NAMESPACE, EXECUTOR).unwrap();
                assert_eq!(transition.expected_remote, ledger.watermark);
                assert!(publication.generation > predecessor.map_or(0, |head| head.generation));
                ledger.denial_requests += 1;
            } else {
                assert_eq!(
                    predecessor.map_or(0, |value| value.generation),
                    publication.admission.expected_generation
                );
                assert_eq!(
                    predecessor.map(|value| value.digest.clone()),
                    publication.admission.expected_digest
                );
            }
            ledger
                .receipts
                .insert(publication.generation, digest.clone());
            ledger.watermark = Some(watermark(publication));
        }
        ledger.publications += 1;
        receipt = Some(StorageAuthorityControlReceipt {
            generation: publication.generation,
            digest: publication.digest.clone(),
            publication_digest: digest,
        });
        match ledger.fault {
            Fault::SqlAdvance => advance(&mock.db).await,
            Fault::RemoteAdvance => ledger.watermark.as_mut().unwrap().generation += 1,
            Fault::ResponseLoss => {
                ledger.fault = Fault::None;
                return (
                    axum::http::StatusCode::SERVICE_UNAVAILABLE,
                    "committed but response lost",
                )
                    .into_response();
            }
            _ => {}
        }
    }
    let mut reply = StorageAuthorityResponse {
        version: 1,
        request_digest: canonical_digest(&request).unwrap(),
        nonce: request.nonce,
        deployment_id: request.deployment_id,
        guard_namespace_id: request.guard_namespace_id,
        issued_at: now,
        expires_at: request.expires_at,
        watermark: ledger.watermark.clone(),
        control_receipt: receipt,
    };
    if matches!(ledger.fault, Fault::WrongNonce) {
        reply.nonce = "0".repeat(64);
    }
    let bytes = serde_json::to_vec(&reply).unwrap();
    let signature = if matches!(ledger.fault, Fault::WrongSignature) {
        sign_authority_message(
            &StorageWorkKey::new(b"different-test-signing-key-32byte").unwrap(),
            true,
            &bytes,
        )
        .unwrap()
    } else {
        sign_authority_message(&key, true, &bytes).unwrap()
    };
    ([(STORAGE_WORK_SIGNATURE_HEADER, signature)], bytes).into_response()
}

fn watermark(publication: &StorageAuthorityPublication) -> StorageAuthorityRemoteWatermark {
    StorageAuthorityRemoteWatermark {
        authority_id: authority_id(),
        guard_namespace_id: NAMESPACE.into(),
        generation: publication.generation,
        digest: publication.digest.clone(),
    }
}

async fn client(mock: Mock) -> (RemoteStorageWorkClient, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let router = Router::new()
        .route(STORAGE_AUTHORITY_CONTROL_PATH, post(control))
        .with_state(mock);
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let mut client =
        RemoteStorageWorkClient::new("https://worker.example", "paired-deployment".into(), KEY)
            .unwrap();
    client.endpoint = format!("http://{address}/");
    (client, server)
}

fn acknowledged(path: &std::path::Path) -> Option<i64> {
    rusqlite::Connection::open(path).unwrap().query_row(
        "SELECT acknowledged_generation FROM storage_authority_admission_heads WHERE authority_id = ?1",
        [authority_id().as_str()], |row| row.get(0),
    ).unwrap()
}

#[tokio::test]
async fn signed_control_sync_response_loss_retry_records_metadata_only() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("hub.db");
    let db = database(&path).await;
    let ledger = Arc::new(Mutex::new(Ledger {
        fault: Fault::ResponseLoss,
        ..Ledger::default()
    }));
    let (client, server) = client(Mock {
        ledger: ledger.clone(),
        db: db.clone(),
    })
    .await;
    let error = client
        .synchronize_storage_authority(&db, &authority_id(), NAMESPACE, EXECUTOR)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("503"));
    assert_eq!(acknowledged(&path), None);
    assert_eq!(
        ledger.lock().await.watermark.as_ref().unwrap().generation,
        1
    );

    let result = client
        .synchronize_storage_authority(&db, &authority_id(), NAMESPACE, EXECUTOR)
        .await
        .unwrap();
    assert!(result.control_synchronized);
    assert!(!result.provider_readiness_evaluated);
    assert_eq!(result.desired_generation, 1);
    assert_eq!(acknowledged(&path), Some(1));
    // Losing the CLI result after SQL acknowledgement can also retry safely.
    let replay = client
        .synchronize_storage_authority(&db, &authority_id(), NAMESPACE, EXECUTOR)
        .await
        .unwrap();
    assert_eq!(replay, result);
    assert_eq!(ledger.lock().await.publications, 3);
    assert_eq!(ledger.lock().await.receipts.len(), 1);
    assert_eq!(ledger.lock().await.nonces.len(), 8);
    server.abort();
}

#[tokio::test]
async fn signed_control_sync_rejects_authentication_scope_and_concurrent_changes() {
    for (fault, expected) in [
        (Fault::WrongSignature, "signature"),
        (Fault::WrongNonce, "fresh request"),
        (Fault::SqlAdvance, "facts changed"),
        (Fault::PreflightSqlAdvance, "facts changed"),
        (Fault::RemoteAdvance, "latest remote watermark"),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("hub.db");
        let db = database(&path).await;
        let ledger = Arc::new(Mutex::new(Ledger {
            fault,
            ..Ledger::default()
        }));
        let (client, server) = client(Mock {
            ledger: ledger.clone(),
            db: db.clone(),
        })
        .await;
        let error = client
            .synchronize_storage_authority(&db, &authority_id(), NAMESPACE, EXECUTOR)
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains(expected), "{error:#}");
        assert_eq!(acknowledged(&path), None);
        if matches!(fault, Fault::PreflightSqlAdvance) {
            assert_eq!(ledger.lock().await.publications, 0);
        }
        server.abort();
    }
}

#[tokio::test]
async fn signed_control_sync_refuses_restored_sql_and_same_generation_fork() {
    for scenario in ["restored-sql", "same-generation-fork", "predecessor-fork"] {
        let directory = tempfile::tempdir().unwrap();
        let mut path = directory.path().join("hub.db");
        let mut db = database(&path).await;
        let first = db
            .storage_authority_publication(&authority_id(), NAMESPACE, EXECUTOR)
            .await
            .unwrap();
        let mut ledger = Ledger::default();
        ledger.watermark = Some(watermark(&first));
        ledger.receipts.insert(1, canonical_digest(&first).unwrap());
        match scenario {
            "restored-sql" => {
                // Capture an actual SQL generation1 backup, then independently
                // advance SQL/remote to2 before opening that older snapshot.
                rusqlite::Connection::open(&path)
                    .unwrap()
                    .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
                    .unwrap();
                let snapshot = directory.path().join("restored.db");
                std::fs::copy(&path, &snapshot).unwrap();
                advance(&db).await;
                let second = db
                    .storage_authority_publication(&authority_id(), NAMESPACE, EXECUTOR)
                    .await
                    .unwrap();
                ledger.watermark = Some(watermark(&second));
                ledger
                    .receipts
                    .insert(2, canonical_digest(&second).unwrap());
                db = Arc::new(Database::open(&snapshot).await.unwrap());
                path = snapshot;
                assert_eq!(
                    db.desired_storage_authority_admission(&authority_id())
                        .await
                        .unwrap()
                        .unwrap()
                        .generation,
                    1
                );
            }
            "same-generation-fork" => ledger.watermark.as_mut().unwrap().digest = "f".repeat(64),
            "predecessor-fork" => {
                advance(&db).await;
                ledger.watermark.as_mut().unwrap().digest = "f".repeat(64);
            }
            _ => unreachable!(),
        }
        let ledger = Arc::new(Mutex::new(ledger));
        let (client, server) = client(Mock {
            ledger: ledger.clone(),
            db: db.clone(),
        })
        .await;
        let error = client
            .synchronize_storage_authority(&db, &authority_id(), NAMESPACE, EXECUTOR)
            .await
            .unwrap_err();
        let expected = "exact predecessor";
        assert!(error.to_string().contains(expected), "{error:#}");
        assert_eq!(ledger.lock().await.publications, 0);
        assert_eq!(ledger.lock().await.nonces.len(), 1);
        assert_eq!(acknowledged(&path), None);
        server.abort();
    }
}
