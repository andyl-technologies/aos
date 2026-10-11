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
async fn expired_stage_journal_requires_all_exact_positive_effects_after_restart() {
    use super::state::positive_effect_terminal;
    use crate::direct_upload::acceptance_window::AcceptedProducerWindow;

    let path = std::env::temp_dir().join(format!("direct-stage-{}.sqlite", uuid::Uuid::new_v4()));
    let owner = fixture::reservation("fixture-deployment", "fixture/final");
    let originals = [
        Effect::new("a1".repeat(32), &(&owner.admission, &owner.source), false).unwrap(),
        Effect::new("a2".repeat(32), &(&owner.complete, &owner.source), false).unwrap(),
        Effect::new(
            "a3".repeat(32),
            &(&owner.admission, &owner.complete, &owner.source),
            true,
        )
        .unwrap(),
    ];
    let mut retained = Vec::new();
    for (index, original) in originals.iter().enumerate() {
        let (pending, _) = original.begin(original, &"bb".repeat(32)).unwrap();
        retained.push(if index == 2 {
            pending
        } else {
            pending
                .finish(
                    &"bb".repeat(32),
                    serde_json::json!({"original": original.intent_digest}),
                )
                .unwrap()
        });
    }
    let first = SqlxBackend::connect_sqlite(path.to_str().unwrap())
        .await
        .unwrap();
    first
        .execute_batch(
            "CREATE TABLE stage_fixture (position INTEGER PRIMARY KEY, effect TEXT NOT NULL)",
        )
        .await
        .unwrap();
    for (index, effect) in retained.iter().enumerate() {
        first
            .execute(
                "INSERT INTO stage_fixture VALUES (?1, ?2)",
                &[
                    Value::Int(index as i64),
                    Value::Text(serde_json::to_string(effect).unwrap()),
                ],
            )
            .await
            .unwrap();
    }
    drop(first);

    let producer = AcceptedProducerWindow::new(100, 130, 1).unwrap();
    assert!(producer.latest_now(200).is_err());
    let restarted = SqlxBackend::connect_sqlite(path.to_str().unwrap())
        .await
        .unwrap();
    let rows = restarted
        .query("SELECT effect FROM stage_fixture ORDER BY position", &[])
        .await
        .unwrap();
    let effects = rows
        .iter()
        .map(|row| serde_json::from_str::<Effect>(&row.get::<String>(0).unwrap()).unwrap())
        .collect::<Vec<_>>();
    assert!(positive_effect_terminal(&effects[0], &originals[0]).is_ok());
    assert!(positive_effect_terminal(&effects[1], &originals[1]).is_ok());
    assert!(positive_effect_terminal(&effects[2], &originals[2]).is_err());
    let positive = effects[2]
        .finish(
            &"bb".repeat(32),
            serde_json::json!({"original": originals[2].intent_digest}),
        )
        .unwrap();
    restarted
        .execute(
            "UPDATE stage_fixture SET effect = ?1 WHERE position = 2",
            &[Value::Text(serde_json::to_string(&positive).unwrap())],
        )
        .await
        .unwrap();
    drop(restarted);

    let after_ack = SqlxBackend::connect_sqlite(path.to_str().unwrap())
        .await
        .unwrap();
    let rows = after_ack
        .query("SELECT effect FROM stage_fixture ORDER BY position", &[])
        .await
        .unwrap();
    for (index, row) in rows.iter().enumerate() {
        let actual: Effect = serde_json::from_str(&row.get::<String>(0).unwrap()).unwrap();
        positive_effect_terminal(&actual, &originals[index]).unwrap();
        let mut changed = originals[index].clone();
        changed.operation_id = "cc".repeat(32);
        assert!(positive_effect_terminal(&actual, &changed).is_err());
        changed = originals[index].clone();
        changed.intent_digest = "dd".repeat(32);
        assert!(positive_effect_terminal(&actual, &changed).is_err());
        changed = originals[index].clone();
        changed.immutable_read = !changed.immutable_read;
        assert!(positive_effect_terminal(&actual, &changed).is_err());
        let mut unknown = actual.clone();
        unknown.pending_attempt = Some("ee".repeat(32));
        assert!(positive_effect_terminal(&unknown, &originals[index]).is_err());
        let mut missing = actual;
        missing.terminal = None;
        assert!(positive_effect_terminal(&missing, &originals[index]).is_err());
    }
    let evidence = DirectVerifiedStageEvidence {
        session_id: owner.admission.session_id.clone(),
        logical_fingerprint: owner.admission.logical_fingerprint.clone(),
        operation_id: owner.complete.operation_id.clone(),
        part_count: owner.admission.intent.part_count().unwrap(),
        sha256: owner.source.sha256.clone(),
        byte_size: owner.source.byte_size,
        placements: owner
            .complete
            .manifests
            .iter()
            .map(|manifest| DirectStagePlacementEvidence {
                placement: manifest.placement.clone(),
                manifest: manifest.clone(),
                verification_operation_id: originals[2].operation_id.clone(),
                staging_incarnation: owner.source.incarnation.clone(),
            })
            .collect(),
        projection: None,
    };
    let challenge = DirectAuthorityLookup {
        deployment_id: owner.binding.deployment_id.clone(),
        request_nonce: "f1".repeat(32),
        issued_at: WireInteger::new(200),
        expires_at: WireInteger::new(230),
        operation: DirectAuthorityLookupOperation::Stage {
            admission: owner.admission.clone(),
            complete: owner.complete.clone(),
            evidence,
        },
    };
    let key = StorageWorkKey::new("independent-stage-guard-role-key").unwrap();
    let producer_key = StorageWorkKey::new("different-expired-producer-role-key").unwrap();
    let signed = sign_direct_authority_lookup(&key, &challenge).unwrap();
    verify_direct_authority_lookup(
        &key,
        &signed.signature,
        &signed.body,
        &challenge.deployment_id,
        201,
    )
    .unwrap();
    assert!(verify_direct_authority_lookup(
        &producer_key,
        &signed.signature,
        &signed.body,
        &challenge.deployment_id,
        201
    )
    .is_err());
    let reply = sign_direct_authority_lookup_reply(
        &key,
        &DirectAuthorityLookupReply {
            request: challenge.clone(),
        },
    )
    .unwrap();
    verify_direct_authority_lookup_reply(&key, &reply.signature, &reply.body, &challenge, 201)
        .unwrap();
    let mut changed = challenge.clone();
    changed.request_nonce = "f2".repeat(32);
    assert!(verify_direct_authority_lookup_reply(
        &key,
        &reply.signature,
        &reply.body,
        &changed,
        201
    )
    .is_err());
    assert!(verify_direct_authority_lookup_reply(
        &key,
        &reply.signature,
        &reply.body,
        &challenge,
        230
    )
    .is_err());
    drop(after_ack);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn expired_producer_cannot_dispatch_but_exact_fresh_native_commit_releases_positive() {
    use super::state::authenticate_native_commit;
    use crate::direct_upload::acceptance_window::AcceptedProducerWindow;
    use sha2::{Digest as _, Sha256};

    let producer = AcceptedProducerWindow::new(100, 130, 1).unwrap();
    let mut dispatches = 0;
    let attempted = (|| -> anyhow::Result<()> {
        producer.latest_now(200)?;
        dispatches += 1;
        Ok(())
    })();
    assert!(attempted.is_err());
    assert_eq!(dispatches, 0);

    let original = fixture::reservation("fixture-deployment", "fixture/final");
    let record = fixture::final_record(&original);
    let owner = original.acknowledge_publication(record.clone()).unwrap();
    let public_body = encode_direct_control(&DirectBatch {
        operation_id: "aa".repeat(32),
        items: vec![owner.complete.clone()],
    })
    .unwrap();
    let context = DirectRequestContext {
        deployment_id: owner.binding.deployment_id.clone(),
        executor_public_origin: "https://fixture.example".into(),
        public_authority: "fixture.example".into(),
        foreground: DirectForegroundBudget {
            invocation_id: "bb".repeat(32),
            issued_at: WireInteger::new(200),
            expires_at: WireInteger::new(230),
        },
        request_nonce: "cc".repeat(32),
        request_body_sha256: hex::encode(Sha256::digest(&public_body)),
        public_method: "POST".into(),
        public_path: "/aos.hub.v1.DirectUploadService/CompleteBatch".into(),
        issued_at: WireInteger::new(200),
        expires_at: WireInteger::new(230),
    };
    let key = StorageWorkKey::new("independent-native-commit-test-key").unwrap();
    let mut envelope = DirectLogicalReplyEnvelope {
        context: context.clone(),
        reply: DirectUploadLogicalReply {
            admissions: Vec::new(),
            session_summaries: Vec::new(),
            sessions: vec![DirectSessionStatus {
                session: owner.complete.session.clone(),
                resource_version: WireInteger::new(8),
                intent: owner.admission.intent.clone(),
                placements: owner
                    .complete
                    .manifests
                    .iter()
                    .map(|manifest| manifest.placement.clone())
                    .collect(),
                state: DirectSessionState::Committed,
                parts: Vec::new(),
                next_cursor: None,
                outstanding_grants: true,
            }],
            authorizations: Vec::new(),
            baseline_permissions: Vec::new(),
            errors: Vec::new(),
        },
    };
    let signed = sign_direct_logical_reply(&key, &envelope).unwrap();
    let committed = authenticate_native_commit(
        &key,
        &owner,
        &record,
        &context,
        &public_body,
        &signed.body,
        &signed.signature,
        201,
    )
    .unwrap();
    assert!(committed.native_committed);
    assert!(
        authenticate_native_commit(
            &key,
            &committed,
            &record,
            &context,
            &public_body,
            &signed.body,
            &signed.signature,
            201
        )
        .unwrap()
        .native_committed
    );
    let mut changed = context.clone();
    changed.request_nonce = "dd".repeat(32);
    assert!(authenticate_native_commit(
        &key,
        &owner,
        &record,
        &changed,
        &public_body,
        &signed.body,
        &signed.signature,
        201
    )
    .is_err());
    let mut changed_record = record.clone();
    changed_record.final_etag = "\"replacement\"".into();
    assert!(authenticate_native_commit(
        &key,
        &owner,
        &changed_record,
        &context,
        &public_body,
        &signed.body,
        &signed.signature,
        201
    )
    .is_err());
    envelope.reply.sessions[0].state = DirectSessionState::Creating;
    let uncommitted = sign_direct_logical_reply(&key, &envelope).unwrap();
    assert!(authenticate_native_commit(
        &key,
        &owner,
        &record,
        &context,
        &public_body,
        &uncommitted.body,
        &uncommitted.signature,
        201
    )
    .is_err());
    assert!(authenticate_native_commit(
        &key,
        &owner,
        &record,
        &context,
        &public_body,
        &signed.body,
        &signed.signature,
        230
    )
    .is_err());
}

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
