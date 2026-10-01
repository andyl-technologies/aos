//! File-backed custody restart, unknown probe, retention and cold adoption tests.

use super::state::HeldCredential;
use aos_hub_core::{
    backend::{Backend, SqlxBackend},
    storage_work::{
        binding_custody::*, StorageBindingSnapshot, StorageCredentialMaterial,
        StorageCredentialReference, StorageCredentialSelector,
    },
    topology_probe::StorageCredentialProbeEvidence,
    value::Value,
};
use base64::Engine as _;
use sha2::{Digest as _, Sha256};

fn stage() -> StorageCredentialCustodyStage {
    StorageCredentialCustodyStage {
        request: StorageCredentialCustodyProbe {
            version: 1,
            nonce: "aa".repeat(32),
            issued_at: 100,
            expires_at: 130,
            operation_id: "fixture-queued-original".into(),
            probe_token: "bb".repeat(32),
            head_resource_version: 7,
            snapshot: StorageBindingSnapshot {
                version: 1,
                deployment_id: "fixture-deployment".into(),
                binding_id: 2,
                binding_resource_version: 3,
                binding_stable_id: "fixture-binding".into(),
                binding_kind: "s3".into(),
                object_bucket: "private-bucket".into(),
                object_prefix: "protected".into(),
                endpoint_scheme: "https".into(),
                endpoint_host_kind: "dns".into(),
                endpoint_host_bytes: b"storage.example.test".to_vec(),
                endpoint_port: Some(443),
                signing_region: "fixture-region".into(),
                access_mode: "private".into(),
                credentials: vec![StorageCredentialReference {
                    purpose: "read".into(),
                    generation: 5,
                    secret_version_ref: "secret://fixture/provider/v5".into(),
                    fingerprint: hex::encode(Sha256::digest(b"fixture-provider-material")),
                }],
                issued_at: 100,
                expires_at: 130,
            },
        },
        material: StorageCredentialMaterial {
            selector: StorageCredentialSelector {
                purpose: "read".into(),
                generation: 5,
            },
            value_base64: base64::engine::general_purpose::STANDARD
                .encode(b"fixture-provider-material"),
        },
        material_not_after: 500,
    }
}

#[tokio::test]
async fn sqlite_restart_retains_unknown_original_and_positive_cold_material_proof() {
    let path =
        std::env::temp_dir().join(format!("binding-custody-{}.sqlite", uuid::Uuid::new_v4()));
    let db = SqlxBackend::connect_sqlite(path.to_str().unwrap())
        .await
        .unwrap();
    db.execute_batch("CREATE TABLE custody (key TEXT PRIMARY KEY,value TEXT NOT NULL)")
        .await
        .unwrap();
    let mut held = HeldCredential::new(stage());
    let mut expected = held.original.snapshot.clone();
    expected.issued_at = 110;
    expected.expires_at = 3710;
    assert!(held.require_adoption(&expected, 110).is_err());
    held.pending = true;
    db.execute(
        "INSERT INTO custody VALUES ('original',?1)",
        &[Value::Text(serde_json::to_string(&held).unwrap())],
    )
    .await
    .unwrap();
    drop(db);

    let restarted = SqlxBackend::connect_sqlite(path.to_str().unwrap())
        .await
        .unwrap();
    let row = restarted
        .query_opt("SELECT value FROM custody", &[])
        .await
        .unwrap()
        .unwrap();
    let mut retained: HeldCredential =
        serde_json::from_str(&row.get::<String>(0).unwrap()).unwrap();
    let mut next_task = retained.original.clone();
    next_task.operation_id = "fixture-new-task".into();
    next_task.head_resource_version += 1;
    assert!(retained.accept_replacement(&next_task).is_err());
    assert!(retained.require_adoption(&expected, 110).is_err());

    retained.pending = false;
    retained.positive = Some(StorageCredentialProbeEvidence {
        valid: true,
        conditional_writes_supported: false,
        error: None,
        evidence: serde_json::json!({"getStatus":404}),
    });
    retained.renew_validated(&expected, 110).unwrap();
    assert_eq!(
        retained.material_not_after,
        110 + MAX_CREDENTIAL_CUSTODY_SECONDS
    );
    let mut changed = expected.clone();
    changed.credentials[0].fingerprint = "cc".repeat(32);
    assert!(retained.require_adoption(&changed, 111).is_err());
    restarted
        .execute(
            "UPDATE custody SET value = ?1",
            &[Value::Text(serde_json::to_string(&retained).unwrap())],
        )
        .await
        .unwrap();
    drop(restarted);

    let cold = SqlxBackend::connect_sqlite(path.to_str().unwrap())
        .await
        .unwrap();
    let row = cold
        .query_opt("SELECT value FROM custody", &[])
        .await
        .unwrap()
        .unwrap();
    let mut retained: HeldCredential =
        serde_json::from_str(&row.get::<String>(0).unwrap()).unwrap();
    // Cold Native metadata adoption can use held material after the old snapshot
    // expires, without provider keys or an expired hydration receipt in Native.
    expected.issued_at = 200;
    expected.expires_at = 3800;
    retained.renew_validated(&expected, 200).unwrap();
    assert!(retained.publication(expected.clone(), 200).is_ok());
    retained.revoke();
    assert!(retained.require_adoption(&expected, 201).is_err());
    assert!(retained.accept_replacement(&next_task).is_err());
    drop(cold);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn idle_expiry_removes_material_without_erasing_unknown_or_original_proof() {
    let mut held = HeldCredential::new(stage());
    held.pending = true;
    let original = held.original.clone();
    assert!(held.expire(500));
    assert!(held.material.is_none());
    assert!(held.pending);
    assert_eq!(held.original, original);
    assert!(!held.expire(501));
    let mut recovery = original;
    recovery.operation_id = "different-task".into();
    recovery.head_resource_version += 1;
    assert!(held.accept_replacement(&recovery).is_err());
}
