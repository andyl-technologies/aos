//! Signed denial selection and exact current SQL acknowledgement.

use super::*;
use aos_hub_core::db::NewBindingWriteRevision;
use aos_hub_core::storage_authority::{
    ApproveStorageAuthorityAlias, AssociateStorageAuthorityBinding,
    AttestStorageAuthorityExclusivity, StorageAuthorityAliasSpec, StorageAuthorityCredentialMember,
    StorageAuthorityHost,
};
use sha2::Digest as _;

async fn admitted_fixture(
    db: &Database,
) -> (
    AssociateStorageAuthorityBinding,
    AttestStorageAuthorityExclusivity,
) {
    let alias = ApproveStorageAuthorityAlias {
        alias_id: "alias-one".into(),
        authority_id: authority_id(),
        spec: StorageAuthorityAliasSpec {
            host: StorageAuthorityHost::Dns("storage.example.test".into()),
            port: 443,
            bucket: "bucket-one".into(),
        },
        equivalence_evidence_digest: "3".repeat(64),
    };
    apply(db, StorageAuthorityDecisionInput::ApproveAlias(alias)).await;
    let org = db
        .create_org("authority-owner", "Authority owner")
        .await
        .unwrap();
    let owner = db.org_by_id(org).await.unwrap().unwrap();
    let binding_id = db
        .create_topology_binding(
            Some(org),
            "binding-one",
            &owner.stable_id,
            "exclusive",
            "s3",
            None,
            Some("bucket-one"),
            Some("fresh"),
            Some("https"),
            Some("dns"),
            Some(b"storage.example.test"),
            Some(443),
            Some("fixture-region"),
            Some("private"),
        )
        .await
        .unwrap();
    let credential = db
        .set_binding_credential_revision(
            binding_id,
            "write",
            "secret://authority/write/v1",
            0,
            &"4".repeat(64),
            "fixture",
        )
        .await
        .unwrap();
    let credential = db
        .validate_binding_credential_revision(
            binding_id,
            "write",
            credential.generation,
            "valid",
            None,
            credential.head_resource_version,
        )
        .await
        .unwrap();
    let writer = db
        .create_binding_write_revision(&NewBindingWriteRevision {
            binding_id,
            write_credential_generation: credential.generation,
            writes_supported: true,
            conditional_writes_supported: false,
            revision_fingerprint: "writer-one".into(),
            capability_fingerprint: "write".into(),
        })
        .await
        .unwrap();
    let binding = db.binding(binding_id).await.unwrap().unwrap();
    let association = AssociateStorageAuthorityBinding {
        association_id: "association-one".into(),
        authority_id: authority_id(),
        alias_id: "alias-one".into(),
        binding_id,
        binding_stable_id: binding.stable_id,
        binding_resource_version: binding.resource_version,
        binding_write_revision: writer.revision,
        binding_prefix: "fresh".into(),
    };
    apply(
        db,
        StorageAuthorityDecisionInput::AssociateBinding(association.clone()),
    )
    .await;
    let attestation = AttestStorageAuthorityExclusivity {
        attestation_id: "initial-attestation".into(),
        authority_id: authority_id(),
        managed_prefix: "fresh".into(),
        qualification_digest: "2".repeat(64),
        provider_policy_evidence_digest: "5".repeat(64),
        executor_identity: EXECUTOR.into(),
        credentials: vec![StorageAuthorityCredentialMember {
            association_id: association.association_id.clone(),
            purpose: "write".into(),
            generation: credential.generation,
            secret_version_ref: credential.secret_version_ref,
            credential_fingerprint: credential.credential_fingerprint,
        }],
        valid_until: aos_hub_core::clock::now_unix_secs() + 600,
    };
    apply(
        db,
        StorageAuthorityDecisionInput::Attest(attestation.clone()),
    )
    .await;
    (association, attestation)
}

async fn set_admitted(
    db: &Database,
    association: &AssociateStorageAuthorityBinding,
    attestation: &AttestStorageAuthorityExclusivity,
) {
    let desired = db
        .desired_storage_authority_admission(&authority_id())
        .await
        .unwrap()
        .unwrap();
    apply(
        db,
        StorageAuthorityDecisionInput::SetAdmission(SetStorageAuthorityAdmission {
            authority_id: authority_id(),
            expected_generation: desired.generation,
            expected_digest: Some(desired.digest),
            guard_namespace_id: NAMESPACE.into(),
            state: StorageAuthorityAdmissionState::Admitted,
            attestation_id: Some(attestation.attestation_id.clone()),
            association_ids: vec![association.association_id.clone()],
        }),
    )
    .await;
}

#[derive(Default)]
struct Journal {
    values: BTreeMap<String, serde_json::Value>,
}

impl actual_ledger::AuthorityJournal for Journal {
    async fn get(&mut self, key: &str) -> Result<Option<serde_json::Value>> {
        Ok(self.values.get(key).cloned())
    }

    async fn put_atomic(&mut self, values: BTreeMap<String, serde_json::Value>) -> Result<()> {
        self.values.extend(values);
        Ok(())
    }
}

#[derive(Clone)]
struct ActualMock {
    journal: Arc<Mutex<Journal>>,
    lose_response: Arc<Mutex<bool>>,
}

async fn actual_control(
    State(mock): State<ActualMock>,
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
    let reply = match actual_ledger::handle(
        &mut *mock.journal.lock().await,
        &request,
        "paired-deployment",
        NAMESPACE,
        EXECUTOR,
        now,
    )
    .await
    {
        Ok(reply) => reply,
        Err(error) => return (axum::http::StatusCode::CONFLICT, error.to_string()).into_response(),
    };
    if matches!(
        request.operation,
        StorageAuthorityOperation::DenyFromWatermark(_)
    ) {
        let mut lose = mock.lose_response.lock().await;
        if *lose {
            *lose = false;
            return (
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                "denial committed but response lost",
            )
                .into_response();
        }
    }
    let bytes = serde_json::to_vec(&reply).unwrap();
    let signature = sign_authority_message(&key, true, &bytes).unwrap();
    ([(STORAGE_WORK_SIGNATURE_HEADER, signature)], bytes).into_response()
}

async fn actual_client(mock: ActualMock) -> (RemoteStorageWorkClient, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let router = Router::new()
        .route(STORAGE_AUTHORITY_CONTROL_PATH, post(actual_control))
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

#[tokio::test]
async fn signed_actual_ledger_denial_response_loss_acknowledges_only_current_generation() {
    for absent in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("hub.db");
        let db = database(&path).await;
        let journal = Arc::new(Mutex::new(Journal::default()));
        let (client, server) = actual_client(ActualMock {
            journal: journal.clone(),
            lose_response: Arc::new(Mutex::new(true)),
        })
        .await;
        if !absent {
            let first = db
                .storage_authority_publication(&authority_id(), NAMESPACE, EXECUTOR)
                .await
                .unwrap();
            client.publish_storage_authority(first).await.unwrap();
        }
        advance(&db).await;
        advance(&db).await;
        let third = db
            .storage_authority_publication(&authority_id(), NAMESPACE, EXECUTOR)
            .await
            .unwrap();
        journal.lock().await.values.insert(
            "object/pending".into(),
            serde_json::json!({"operation":"unknown"}),
        );
        assert!(client
            .synchronize_storage_authority(&db, &authority_id(), NAMESPACE, EXECUTOR)
            .await
            .unwrap_err()
            .to_string()
            .contains("503"));
        assert_eq!(acknowledged(&path), None);
        assert!(acknowledged_outbox(&path).is_empty());

        client
            .synchronize_storage_authority(&db, &authority_id(), NAMESPACE, EXECUTOR)
            .await
            .unwrap();
        assert_eq!(acknowledged(&path), Some(3));
        assert_eq!(acknowledged_outbox(&path), vec![3]);
        let state = journal.lock().await;
        let base = format!("authority/{}/", authority_id().as_str());
        assert!(!state.values.contains_key(&format!("{base}receipt/2")));
        assert!(state
            .values
            .contains_key(&format!("{base}denial-transition/3")));
        assert_eq!(
            state.values["object/pending"],
            serde_json::json!({"operation":"unknown"})
        );
        assert_eq!(
            state.values[&format!("{base}head")],
            serde_json::to_value(&third).unwrap()
        );
        server.abort();
    }
}

#[tokio::test]
async fn signed_actual_ledger_expired_undelivered_admission_is_never_published_or_acknowledged() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("hub.db");
    let db = database(&path).await;
    let (association, initial) = admitted_fixture(&db).await;
    let blocked = db
        .storage_authority_publication(&authority_id(), NAMESPACE, EXECUTOR)
        .await
        .unwrap();
    set_admitted(&db, &association, &initial).await;
    let first = db
        .storage_authority_publication(&authority_id(), NAMESPACE, EXECUTOR)
        .await
        .unwrap();
    assert_eq!(first.generation, 2);
    let journal = Arc::new(Mutex::new(Journal::default()));
    let (client, server) = actual_client(ActualMock {
        journal: journal.clone(),
        lose_response: Arc::new(Mutex::new(false)),
    })
    .await;
    // Seed the initial SQL blocked generation and then admit through strict Publish.
    assert_eq!(
        first.admission.expected_digest,
        Some(blocked.digest.clone())
    );
    client.publish_storage_authority(blocked).await.unwrap();
    client
        .publish_storage_authority(first.clone())
        .await
        .unwrap();
    let mut renewal = initial.clone();
    renewal.attestation_id = "undelivered-expired-renewal".into();
    renewal.valid_until = aos_hub_core::clock::now_unix_secs() + 3;
    apply(&db, StorageAuthorityDecisionInput::Attest(renewal.clone())).await;
    set_admitted(&db, &association, &renewal).await;
    let undispatched = db
        .storage_authority_publication(&authority_id(), NAMESPACE, EXECUTOR)
        .await
        .unwrap();
    advance(&db).await;
    let current = db
        .storage_authority_publication(&authority_id(), NAMESPACE, EXECUTOR)
        .await
        .unwrap();
    let wait = renewal.valid_until - aos_hub_core::clock::now_unix_secs() + 1;
    if wait > 0 {
        tokio::time::sleep(std::time::Duration::from_secs(wait as u64)).await;
    }
    assert!(undispatched
        .validate_admission_time(aos_hub_core::clock::now_unix_secs())
        .is_err());

    let result = client
        .synchronize_storage_authority(&db, &authority_id(), NAMESPACE, EXECUTOR)
        .await
        .unwrap();
    assert_eq!(result.desired_generation, 4);
    assert_eq!(acknowledged_outbox(&path), vec![4]);
    assert_eq!(current.admission.expected_digest, Some(undispatched.digest));
    let state = journal.lock().await;
    let base = format!("authority/{}/", authority_id().as_str());
    assert!(!state.values.contains_key(&format!("{base}receipt/3")));
    assert!(state
        .values
        .contains_key(&format!("{base}denial-transition/4")));
    let key = format!(
        "attestation/{}",
        hex::encode(sha2::Sha256::digest(renewal.attestation_id.as_bytes()))
    );
    assert!(!state.values.contains_key(&key));
    assert_eq!(
        state.values[&format!("{base}head")],
        serde_json::to_value(&current).unwrap()
    );
    server.abort();
}

fn acknowledged_outbox(path: &std::path::Path) -> Vec<i64> {
    let connection = rusqlite::Connection::open(path).unwrap();
    let mut statement = connection.prepare("SELECT generation FROM storage_authority_control_requests WHERE acknowledged_at IS NOT NULL ORDER BY generation").unwrap();
    statement
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<std::result::Result<_, _>>()
        .unwrap()
}

#[tokio::test]
async fn signed_denial_gap_acknowledges_only_current_sql_and_replays_full_bundle() {
    for scenario in ["skipped-predecessor", "missing-remote", "response-loss"] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("hub.db");
        let db = database(&path).await;
        let first = db
            .storage_authority_publication(&authority_id(), NAMESPACE, EXECUTOR)
            .await
            .unwrap();
        let mut state = Ledger::default();
        if scenario != "missing-remote" {
            state.watermark = Some(watermark(&first));
            state.receipts.insert(1, canonical_digest(&first).unwrap());
        }
        advance(&db).await;
        advance(&db).await;
        let third = db
            .storage_authority_publication(&authority_id(), NAMESPACE, EXECUTOR)
            .await
            .unwrap();
        assert_eq!(third.admission.expected_generation, 2);
        let frozen_digest = third.digest.clone();
        if scenario == "response-loss" {
            state.fault = Fault::ResponseLoss;
        }
        let ledger = Arc::new(Mutex::new(state));
        let (client, server) = client(Mock {
            ledger: ledger.clone(),
            db: db.clone(),
        })
        .await;

        if scenario == "response-loss" {
            assert!(client
                .synchronize_storage_authority(&db, &authority_id(), NAMESPACE, EXECUTOR)
                .await
                .unwrap_err()
                .to_string()
                .contains("503"));
            assert_eq!(acknowledged(&path), None);
            assert!(acknowledged_outbox(&path).is_empty());
        }
        let result = client
            .synchronize_storage_authority(&db, &authority_id(), NAMESPACE, EXECUTOR)
            .await
            .unwrap();
        assert!(result.control_synchronized);
        assert!(!result.provider_readiness_evaluated);
        assert_eq!(result.desired_generation, 3);
        assert_eq!(result.desired_digest, frozen_digest);
        assert_eq!(acknowledged(&path), Some(3));
        assert_eq!(acknowledged_outbox(&path), vec![3]);
        assert_eq!(ledger.lock().await.denial_requests, 1);
        assert!(!ledger.lock().await.receipts.contains_key(&2));
        assert_eq!(
            db.storage_authority_publication(&authority_id(), NAMESPACE, EXECUTOR)
                .await
                .unwrap(),
            third
        );

        // Exact-current sync still publishes to verify the entire immutable
        // publication receipt; an admission watermark alone cannot acknowledge it.
        assert_eq!(
            client
                .synchronize_storage_authority(&db, &authority_id(), NAMESPACE, EXECUTOR)
                .await
                .unwrap(),
            result
        );
        assert_eq!(ledger.lock().await.denial_requests, 1);
        assert_eq!(
            ledger.lock().await.publications,
            if scenario == "response-loss" { 3 } else { 2 }
        );
        server.abort();
    }
}
