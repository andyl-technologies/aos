//! Exact pending immutable-read recovery; every mutation retains logical expiry.

use super::*;
use aos_hub_core::storage_authority::external_object::stage::{
    ExternalStageAdmissionMode as Mode, ExternalStageRequest,
};

async fn interrupted() -> (Fixture, Head, Receipt, Turn) {
    let mut f = Fixture::new(1).await;
    f.context.logical_expires_at = WireInteger::new(110);
    let (head, closed) = f.closed_source();
    let operation = Operation::VerifyClosedStage {
        upload_id: Some("source-upload".into()),
        close_receipt_digest: protocol::digest(&closed).unwrap(),
    };
    let (head, turn) = f
        .begin(&head, f.intent("retained-verify", operation), None, None)
        .unwrap();
    (f, head, closed, turn)
}

async fn resume(
    f: &Fixture,
    head: &Head,
    closed: &Receipt,
    turn: &Turn,
) -> anyhow::Result<(Head, Turn)> {
    let read = token_at(&f.object, 1, 3, 120).await;
    state::begin(
        head,
        &f.object,
        &f.config,
        turn.intent.clone(),
        Mode::ResumeImmutableRead,
        Some(closed),
        &[],
        &read,
        turn.dispatch_nonce.clone(),
        None,
        None,
        clock(122),
    )
}

#[tokio::test]
async fn exact_pending_read_recovers_after_expiry_without_allocating_identity() {
    let (f, head, closed, turn) = interrupted().await;
    let projected =
        state::recovery_read(&head, &f.object, &f.config, &turn.intent, &closed).unwrap();
    assert!(projected == turn);
    let serialized = serde_json::to_vec(&head).unwrap();
    let restarted: Head = serde_json::from_slice(&serialized).unwrap();
    let (next, recovered) = resume(&f, &restarted, &closed, &turn).await.unwrap();
    assert!(recovered == turn);
    assert_eq!(next.incarnation.get(), head.incarnation.get());
    assert!(next.stage.as_ref().unwrap().closed == head.stage.as_ref().unwrap().closed);
    assert!(next.stage.as_ref().unwrap().manifest == head.stage.as_ref().unwrap().manifest);
}

#[tokio::test]
async fn recovery_probe_and_begin_refuse_missing_changed_or_conflicting_pending() {
    let (f, head, closed, turn) = interrupted().await;
    let mut cases = Vec::new();
    let mut missing = head.clone();
    missing.stage.as_mut().unwrap().pending = None;
    cases.push(missing);
    let mut changed = head.clone();
    changed
        .stage
        .as_mut()
        .unwrap()
        .pending
        .as_mut()
        .unwrap()
        .intent
        .operation_id = "other-owner".into();
    cases.push(changed);
    let mut stamp = head.clone();
    stamp.incarnation = WireInteger::new(2);
    cases.push(stamp);
    for candidate in cases {
        assert!(
            state::recovery_read(&candidate, &f.object, &f.config, &turn.intent, &closed).is_err()
        );
        assert!(resume(&f, &candidate, &closed, &turn).await.is_err());
    }
    let mut actor = turn.clone();
    actor.intent.context.principal_id = "different-actor".into();
    assert!(resume(&f, &head, &closed, &actor).await.is_err());
    let mut manifest = closed.clone();
    if let Operation::CompleteStage { manifest, .. } = &mut manifest.turn.intent.operation {
        manifest.manifest_digest = "e".repeat(64);
    }
    assert!(resume(&f, &head, &manifest, &turn).await.is_err());
    let mut fresh_nonce = turn.clone();
    fresh_nonce.dispatch_nonce = "c".repeat(64);
    assert!(resume(&f, &head, &closed, &fresh_nonce).await.is_err());
}

#[tokio::test]
async fn recovered_read_never_reopens_mutation_or_publication_eligibility() {
    let (f, head, closed, turn) = interrupted().await;
    let (next, recovered) = resume(&f, &head, &closed, &turn).await.unwrap();
    let (verified, _) = f.terminal(
        &next,
        recovered,
        Outcome::Verified {
            sha256: f.context.intent.expected_sha256.clone(),
            byte_size: f.context.intent.byte_size,
            close_receipt_digest: protocol::digest(&closed).unwrap(),
        },
    );
    let read = token_at(&f.object, 1, 3, 120).await;
    for operation in [
        Operation::CreateStage,
        Operation::CompleteStage {
            upload_id: "source-upload".into(),
            manifest: f.manifest().0,
        },
        Operation::CreateDestination {
            verified_stage_receipt_digest: "f".repeat(64),
        },
        Operation::AbortStage {
            upload_id: "source-upload".into(),
        },
    ] {
        let intent = f.intent("new-effect", operation.clone());
        for mode in [Mode::Fresh, Mode::ResumeImmutableRead] {
            assert!(state::begin(
                &verified,
                &f.object,
                &f.config,
                intent.clone(),
                mode,
                Some(&closed),
                &f.write,
                &read,
                "b".repeat(64),
                None,
                None,
                clock(122)
            )
            .is_err());
        }
        let mut work = request(&f, operation);
        work.admission_mode = Mode::ResumeImmutableRead;
        assert!(work.validate(DEPLOYMENT, 122).is_err());
    }
    // A fresh verification cannot acquire a new turn even for the same immutable bytes.
    assert!(state::begin(
        &head,
        &f.object,
        &f.config,
        turn.intent.clone(),
        Mode::Fresh,
        None,
        &[],
        &read,
        turn.dispatch_nonce.clone(),
        None,
        None,
        clock(122)
    )
    .is_err());
}

fn request(f: &Fixture, operation: Operation) -> ExternalStageRequest {
    ExternalStageRequest::new(
        DEPLOYMENT.into(),
        "retained-verify".into(),
        WireInteger::new(120),
        WireInteger::new(150),
        f.context.clone(),
        String::new(),
        String::new(),
        operation,
    )
}

#[tokio::test]
async fn recovery_keeps_fresh_request_lease_snapshot_and_clock_checks() {
    let (f, head, closed, turn) = interrupted().await;
    let read = token_at(&f.object, 1, 3, 120).await;
    let validated = f
        .object
        .verifier()
        .unwrap()
        .validate_lease(
            &read,
            &f.object.cohorts[1],
            &profile(),
            &head.floor,
            &head.scope.full_key,
            LeaseEffect::Read,
            clock(122),
        )
        .unwrap();
    let cohort = &f.object.cohorts[1];
    let mut snapshot = aos_hub_core::storage_work::StorageBindingSnapshot {
        version: 1,
        deployment_id: DEPLOYMENT.into(),
        binding_id: cohort.association.binding_id.get(),
        binding_resource_version: cohort.association.binding_resource_version.get(),
        binding_stable_id: cohort.association.binding_stable_id.clone(),
        binding_kind: "s3".into(),
        object_bucket: cohort.alias.spec.bucket.clone(),
        object_prefix: cohort.association.binding_prefix.clone(),
        endpoint_scheme: "https".into(),
        endpoint_host_kind: "dns".into(),
        endpoint_host_bytes: b"objects.example.invalid".to_vec(),
        endpoint_port: Some(443),
        signing_region: "auto".into(),
        access_mode: "private".into(),
        credentials: vec![],
        issued_at: 120,
        expires_at: 160,
    };
    let mut work = request(&f, turn.intent.operation.clone());
    work.admission_mode = Mode::ResumeImmutableRead;
    assert!(work
        .check_dispatch_time(&snapshot, &validated, &head.floor, clock(122))
        .is_ok());
    assert!(work
        .check_dispatch_time(&snapshot, &validated, &head.floor, clock(148))
        .is_err());
    assert!(work.validate(DEPLOYMENT, 150).is_err());
    snapshot.expires_at = 121;
    assert!(work
        .check_dispatch_time(&snapshot, &validated, &head.floor, clock(122))
        .is_err());
    assert!(state::begin(
        &head,
        &f.object,
        &f.config,
        turn.intent.clone(),
        Mode::ResumeImmutableRead,
        Some(&closed),
        &[],
        &read,
        turn.dispatch_nonce.clone(),
        None,
        None,
        clock(148)
    )
    .is_err());
}

#[tokio::test]
async fn recovered_terminal_is_only_history_after_restart() {
    let (f, head, closed, turn) = interrupted().await;
    let (next, recovered) = resume(&f, &head, &closed, &turn).await.unwrap();
    let (done, receipt) = f.terminal(
        &next,
        recovered,
        Outcome::Verified {
            sha256: f.context.intent.expected_sha256.clone(),
            byte_size: f.context.intent.byte_size,
            close_receipt_digest: protocol::digest(&closed).unwrap(),
        },
    );
    let restarted: Head = serde_json::from_slice(&serde_json::to_vec(&done).unwrap()).unwrap();
    assert!(state::replay(&restarted, &f.config, &turn.intent, &receipt).unwrap() == restarted);
    assert!(state::recovery_read(&restarted, &f.object, &f.config, &turn.intent, &closed).is_err());
    assert!(resume(&f, &restarted, &closed, &turn).await.is_err());
}

#[tokio::test]
async fn required_recovery_mode_is_mac_bound_and_rejected_by_legacy_closed_shapes() {
    let (f, _, _, turn) = interrupted().await;
    let key = StorageWorkKey::new([3; 32]).unwrap();
    let mut work = request(&f, turn.intent.operation.clone());
    work.admission_mode = Mode::ResumeImmutableRead;
    let (body, signature) = work.sign(&key, DEPLOYMENT, 122).unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["admission_mode"], "resume_immutable_read");
    value["admission_mode"] = "fresh".into();
    assert!(ExternalStageRequest::authenticate(
        &key,
        &signature,
        &serde_json::to_vec(&value).unwrap(),
        DEPLOYMENT,
        122
    )
    .is_err());
    value.as_object_mut().unwrap().remove("admission_mode");
    assert!(serde_json::from_value::<ExternalStageRequest>(value).is_err());

    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    #[allow(dead_code)]
    struct LegacyRequest {
        version: serde_json::Value,
        domain: serde_json::Value,
        deployment_id: serde_json::Value,
        operation_id: serde_json::Value,
        issued_at: serde_json::Value,
        expires_at: serde_json::Value,
        context: serde_json::Value,
        write_lease: serde_json::Value,
        read_lease: serde_json::Value,
        operation: serde_json::Value,
    }
    assert!(serde_json::from_slice::<LegacyRequest>(&body).is_err());
    let begin = super::super::protocol::Operation::Begin {
        admission_mode: Mode::ResumeImmutableRead,
        intent: turn.intent,
        write_lease: String::new(),
        read_lease: String::new(),
        source: None,
    };
    let mut inner = serde_json::to_value(begin).unwrap();
    #[derive(serde::Deserialize)]
    #[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
    #[allow(dead_code)]
    enum LegacyOperation {
        Begin {
            intent: serde_json::Value,
            write_lease: String,
            read_lease: String,
            source: Option<serde_json::Value>,
        },
    }
    assert!(serde_json::from_value::<LegacyOperation>(inner.clone()).is_err());
    inner.as_object_mut().unwrap().remove("admission_mode");
    assert!(serde_json::from_value::<super::super::protocol::Operation>(inner).is_err());
}
