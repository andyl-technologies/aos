//! Persistent SQLite restart, immutable originals and fresh lookup binding tests.

use aos_hub_core::{
    backend::{Backend, SqlxBackend},
    direct_upload::*,
    storage_work::StorageWorkKey,
    value::Value,
};

use super::{
    fixture,
    state::{authenticate_native_permission, Reservation},
};
use crate::direct_upload::journal::Effect;

#[tokio::test]
async fn sqlite_restart_keeps_original_source_unknown_fence_and_unacknowledged_publication() {
    let path = std::env::temp_dir().join(format!("direct-guard-{}.sqlite", uuid::Uuid::new_v4()));
    let path_string = path.to_str().unwrap();
    let first = SqlxBackend::connect_sqlite(path_string).await.unwrap();
    first
        .execute_batch("CREATE TABLE guard_fixture (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        .await
        .unwrap();
    let owner = fixture::reservation("fixture-deployment", "fixture/final");
    owner.validate().unwrap();
    let effect = Effect::new("aa".repeat(32), &(&owner.binding, &owner.source), false).unwrap();
    let (pending, _) = effect.begin(&effect, &"bb".repeat(32)).unwrap();
    first
        .execute(
            "INSERT INTO guard_fixture VALUES ('owner', ?1), ('effect', ?2)",
            &[
                Value::Text(serde_json::to_string(&owner).unwrap()),
                Value::Text(serde_json::to_string(&pending).unwrap()),
            ],
        )
        .await
        .unwrap();
    drop(first);

    let restarted = SqlxBackend::connect_sqlite(path_string).await.unwrap();
    let rows = restarted
        .query("SELECT key, value FROM guard_fixture ORDER BY key", &[])
        .await
        .unwrap();
    let persisted_effect: Effect =
        serde_json::from_str(&rows[0].get::<String>(1).unwrap()).unwrap();
    let persisted_owner: Reservation =
        serde_json::from_str(&rows[1].get::<String>(1).unwrap()).unwrap();
    persisted_owner.validate_original(&owner).unwrap();
    assert!(persisted_effect.begin(&effect, &"cc".repeat(32)).is_err());

    let mut changed_source = owner.clone();
    changed_source.source.incarnation = DirectObjectIncarnation::ProviderVersion {
        version: "replacement-source".into(),
    };
    assert!(persisted_owner.validate_original(&changed_source).is_err());
    let changed_complete = fixture::changed_complete(&owner);
    assert!(persisted_owner
        .validate_original(&changed_complete)
        .is_err());

    let receipt = fixture::final_record(&owner);
    let published = persisted_owner
        .acknowledge_publication(receipt.clone())
        .unwrap();
    assert!(!published.native_committed);
    restarted
        .execute(
            "UPDATE guard_fixture SET value = ?1 WHERE key = 'owner'",
            &[Value::Text(serde_json::to_string(&published).unwrap())],
        )
        .await
        .unwrap();
    drop(restarted);

    let after_lost_ack = SqlxBackend::connect_sqlite(path_string).await.unwrap();
    let row = after_lost_ack
        .query_opt("SELECT value FROM guard_fixture WHERE key = 'owner'", &[])
        .await
        .unwrap()
        .unwrap();
    let held: Reservation = serde_json::from_str(&row.get::<String>(0).unwrap()).unwrap();
    assert!(!held.native_committed);
    assert_eq!(held.final_record, Some(receipt.clone()));
    let mut changed = receipt.clone();
    changed.final_incarnation = DirectObjectIncarnation::ProviderVersion {
        version: "replacement-final".into(),
    };
    assert!(held.acknowledge_publication(changed.clone()).is_err());
    assert!(held.acknowledge_native(&changed).is_err());
    assert!(held.acknowledge_native(&receipt).unwrap().native_committed);
    drop(after_lost_ack);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn fresh_independent_lookup_requires_original_body_nonce_and_incarnation() {
    let owner = fixture::reservation("fixture-deployment", "fixture/final");
    let record = fixture::final_record(&owner);
    let key = StorageWorkKey::new("independent-fixture-guard-key-0001").unwrap();
    let lookup = DirectFinalGuardLookup {
        admission: owner.admission.clone(),
        complete: owner.complete.clone(),
        expected: record.clone(),
        request_nonce: "aa".repeat(32),
        issued_at: WireInteger::new(100),
        expires_at: WireInteger::new(130),
    };
    let signed = sign_direct_final_guard_reply(
        &key,
        &DirectFinalGuardReply {
            request: lookup.clone(),
            record,
        },
    )
    .unwrap();
    verify_direct_final_guard_reply(&key, &signed.signature, &signed.body, &lookup, 110).unwrap();
    let mut changed = lookup.clone();
    changed.request_nonce = "bb".repeat(32);
    assert!(
        verify_direct_final_guard_reply(&key, &signed.signature, &signed.body, &changed, 110)
            .is_err()
    );
    let mut changed_body = signed.body.clone();
    changed_body.push(b' ');
    assert!(
        verify_direct_final_guard_reply(&key, &signed.signature, &changed_body, &lookup, 110)
            .is_err()
    );
    assert!(
        verify_direct_final_guard_reply(&key, &signed.signature, &signed.body, &lookup, 130)
            .is_err()
    );
    let broker_key = StorageWorkKey::new("different-fixture-broker-key-0002").unwrap();
    assert!(verify_direct_final_guard_reply(
        &broker_key,
        &signed.signature,
        &signed.body,
        &lookup,
        110
    )
    .is_err());
}

#[test]
fn provider_dispatch_requires_exact_native_signed_permission() {
    let owner = fixture::reservation("fixture-deployment", "fixture/final");
    let context = DirectRequestContext {
        deployment_id: owner.binding.deployment_id.clone(),
        executor_public_origin: "https://fixture.example".into(),
        public_authority: "fixture.example".into(),
        foreground: DirectForegroundBudget {
            invocation_id: "ab".repeat(32),
            issued_at: WireInteger::new(100),
            expires_at: WireInteger::new(130),
        },
        request_nonce: "bc".repeat(32),
        request_body_sha256: "cd".repeat(32),
        public_method: "POST".into(),
        public_path: "/aos.hub.v1.DirectUploadService/CompleteBatch".into(),
        issued_at: WireInteger::new(100),
        expires_at: WireInteger::new(130),
    };
    let permission = DirectDestinationBaselinePermission {
        binding: owner.binding,
        baseline_digest: "de".repeat(32),
        witness_digest: "ef".repeat(32),
        request_nonce: context.request_nonce.clone(),
        expires_at: WireInteger::new(130),
    };
    let reply = DirectUploadLogicalReply {
        admissions: Vec::new(),
        sessions: Vec::new(),
        session_summaries: Vec::new(),
        authorizations: vec![DirectSessionAuthorization {
            session: owner.complete.session.clone(),
            expected_resource_version: Some(owner.complete.expected_resource_version),
            operation_id: owner.complete.operation_id.clone(),
            complete_intent: Some(owner.complete.clone()),
        }],
        baseline_permissions: vec![permission.clone()],
        errors: Vec::new(),
    };
    let native_key = StorageWorkKey::new("fixture-independent-native-key-0003").unwrap();
    let signed = sign_direct_logical_reply(
        &native_key,
        &DirectLogicalReplyEnvelope {
            context: context.clone(),
            reply,
        },
    )
    .unwrap();
    authenticate_native_permission(
        &native_key,
        &permission,
        &context,
        &signed.body,
        &signed.signature,
        110,
    )
    .unwrap();

    let broker_key = StorageWorkKey::new("fixture-different-broker-key-0004").unwrap();
    assert!(authenticate_native_permission(
        &broker_key,
        &permission,
        &context,
        &signed.body,
        &signed.signature,
        110,
    )
    .is_err());
    let mut changed = permission.clone();
    changed.witness_digest = "fa".repeat(32);
    assert!(authenticate_native_permission(
        &native_key,
        &changed,
        &context,
        &signed.body,
        &signed.signature,
        110,
    )
    .is_err());
    let mut changed_context = context.clone();
    changed_context.request_nonce = "fb".repeat(32);
    assert!(authenticate_native_permission(
        &native_key,
        &permission,
        &changed_context,
        &signed.body,
        &signed.signature,
        110,
    )
    .is_err());
    assert!(authenticate_native_permission(
        &native_key,
        &permission,
        &context,
        &signed.body,
        &signed.signature,
        130,
    )
    .is_err());
}
