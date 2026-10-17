//! Signed real lease fixtures for positive identity and exact read-slot ordering.

use aos_hub_core::storage_authority::{
    external_object::{observation::*, ExternalObjectHead},
    GuardIncarnation, StorageGuardStamp,
};
use aos_hub_core::storage_work::StorageWorkKey;

use super::super::{
    protocol::{digest, Effect},
    tests as fixture,
};
use super::{
    protocol::{Intent, Receipt},
    state,
};

fn observation(turn: super::protocol::Pending) -> Receipt {
    Receipt {
        observation: ExternalObservation {
            operation_id: turn.intent.object.operation_id.clone(),
            intent_digest: turn.intent.fingerprint().unwrap(),
            turn_digest: digest(&turn).unwrap(),
            guard_stamp: turn.stamp.clone(),
            observed_at: "102".into(),
            object: Some(ExternalObjectHead {
                provider_version: None,
                bytes: "3".into(),
                etag: "\"object\"".into(),
            }),
        },
        turn,
    }
}

#[tokio::test]
async fn positive_managed_incarnation_is_required_before_head_dispatch() {
    let config = fixture::config();
    let object = fixture::intent(&config, 1, "observe-one");
    let head =
        super::super::state::Head::initialize(&config, &object, fixture::clock(100)).unwrap();
    let intent = Intent {
        object,
        expectation: ObservationExpectation::CaptureCurrentIdentity,
    };
    assert!(state::begin(
        &head,
        &config,
        intent,
        &fixture::token(&config, 1, 0).await,
        "b".repeat(64),
        fixture::clock(101)
    )
    .is_err());
    assert!(head.observation.is_none());
}

#[tokio::test]
async fn known_stamp_locks_positive_identity_and_blocks_all_other_metadata_turns() {
    let config = fixture::config();
    let (pending, _) = fixture::pending(&config, 0).await;
    let head = pending.terminal(&fixture::receipt(&pending)).unwrap();
    let stamp = StorageGuardStamp {
        physical_authority_id: head.scope.physical_authority_id.clone(),
        incarnation: GuardIncarnation::parse("1").unwrap(),
    };
    let intent = Intent {
        object: fixture::intent(&config, 1, "observe-one"),
        expectation: ObservationExpectation::KnownStamp {
            stamp: stamp.clone(),
        },
    };
    let lease = fixture::token(&config, 1, 1).await;
    let (next, turn) = state::begin(
        &head,
        &config,
        intent.clone(),
        &lease,
        "b".repeat(64),
        fixture::clock(102),
    )
    .unwrap();
    assert!(turn.stamp == stamp && next.observation.as_ref() == Some(&turn));
    assert!(state::begin(
        &next,
        &config,
        intent,
        &lease,
        "c".repeat(64),
        fixture::clock(103)
    )
    .is_err());
    assert!(next
        .begin(
            &config,
            fixture::intent(&config, 0, "other-write"),
            &fixture::token(&config, 0, 2).await,
            "c".repeat(64),
            fixture::clock(103)
        )
        .is_err());
    assert!(next
        .begin(
            &config,
            fixture::intent(&config, 1, "old-head"),
            &lease,
            "c".repeat(64),
            fixture::clock(103)
        )
        .is_err());
    let receipt = observation(turn);
    let cleared = state::terminal(&next, &receipt).unwrap();
    assert!(cleared.observation.is_none());
    assert_eq!(cleared.incarnation, head.incarnation);
    assert_eq!(cleared.receipts.get(), head.receipts.get() + 1);
}

#[tokio::test]
async fn changed_stamp_scope_and_terminal_nonce_never_clear_read_slot() {
    let config = fixture::config();
    let (pending, _) = fixture::pending(&config, 0).await;
    let head = pending.terminal(&fixture::receipt(&pending)).unwrap();
    let mut intent = Intent {
        object: fixture::intent(&config, 1, "observe-one"),
        expectation: ObservationExpectation::KnownStamp {
            stamp: StorageGuardStamp {
                physical_authority_id: head.scope.physical_authority_id.clone(),
                incarnation: GuardIncarnation::parse("2").unwrap(),
            },
        },
    };
    let lease = fixture::token(&config, 1, 1).await;
    assert!(state::begin(
        &head,
        &config,
        intent.clone(),
        &lease,
        "b".repeat(64),
        fixture::clock(102)
    )
    .is_err());
    intent.expectation = ObservationExpectation::CaptureCurrentIdentity;
    let (next, turn) = state::begin(
        &head,
        &config,
        intent,
        &lease,
        "b".repeat(64),
        fixture::clock(102),
    )
    .unwrap();
    let mut changed = observation(turn.clone());
    changed.turn.dispatch_nonce = "c".repeat(64);
    changed.observation.turn_digest = digest(&changed.turn).unwrap();
    assert!(state::terminal(&next, &changed).is_err());
    let mut corrupt = next.clone();
    corrupt
        .observation
        .as_mut()
        .unwrap()
        .intent
        .object
        .scope
        .full_key
        .push_str("-fork");
    assert!(corrupt.validate(&config, &corrupt.scope).is_err());
    assert!(next.observation.as_ref() == Some(&turn));
}

#[tokio::test]
async fn expired_read_lease_and_pending_mutation_refuse_new_observation() {
    let config = fixture::config();
    let (pending, _) = fixture::pending(&config, 0).await;
    let mut intent = Intent {
        object: fixture::intent(&config, 1, "observe-one"),
        expectation: ObservationExpectation::CaptureCurrentIdentity,
    };
    assert!(state::begin(
        &pending,
        &config,
        intent.clone(),
        &fixture::token(&config, 1, 1).await,
        "b".repeat(64),
        fixture::clock(102)
    )
    .is_err());
    let head = pending.terminal(&fixture::receipt(&pending)).unwrap();
    assert!(state::begin(
        &head,
        &config,
        intent.clone(),
        &fixture::token(&config, 1, 1).await,
        "b".repeat(64),
        fixture::clock(128)
    )
    .is_err());
    intent.object.effect = Effect::Put {
        sha256: "a".repeat(64),
        bytes: 3,
    };
    assert!(intent.validate().is_err());
}

#[test]
fn request_mode_mac_and_reply_identity_are_closed_and_exact() {
    let mut authorization = fixture::application();
    authorization.plan.operation = aos_hub_core::storage_work::StorageWorkOperation::Head {
        path: "blob".into(),
    };
    let request = ExternalObservationRequest {
        version: 1,
        domain: OBSERVATION_APPLICATION_DOMAIN.into(),
        authorization,
        expectation: ObservationExpectation::CaptureCurrentIdentity,
    };
    let key = StorageWorkKey::new([3; 32]).unwrap();
    let (body, mac) = request.sign(&key, "fixture-deployment", 100).unwrap();
    ExternalObservationRequest::authenticate(&key, &mac, &body, "fixture-deployment", 100).unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    value.as_object_mut().unwrap().remove("expectation");
    let missing = serde_json::to_vec(&value).unwrap();
    assert!(ExternalObservationRequest::authenticate(
        &key,
        &key.sign_body(&missing).unwrap(),
        &missing,
        "fixture-deployment",
        100
    )
    .is_err());
    value["expectation"] = serde_json::json!({"kind":"capture_current_identity"});
    value["extra"] = serde_json::json!(true);
    let unknown = serde_json::to_vec(&value).unwrap();
    assert!(ExternalObservationRequest::authenticate(
        &key,
        &key.sign_body(&unknown).unwrap(),
        &unknown,
        "fixture-deployment",
        100
    )
    .is_err());
}

#[test]
fn authenticated_reply_distinguishes_exact_history_and_rejects_another_request() {
    let authorization = fixture::application();
    let request = ExternalObservationRequest {
        version: 1,
        domain: OBSERVATION_APPLICATION_DOMAIN.into(),
        authorization,
        expectation: ObservationExpectation::CaptureCurrentIdentity,
    };
    let key = StorageWorkKey::new([3; 32]).unwrap();
    let (body, _) = request.sign(&key, "fixture-deployment", 101).unwrap();
    let observation = ExternalObservation {
        operation_id: request.authorization.operation_id.clone(),
        intent_digest: "a".repeat(64),
        turn_digest: "b".repeat(64),
        guard_stamp: StorageGuardStamp {
            physical_authority_id: fixture::config().publications[0]
                .authority
                .authority_id
                .clone(),
            incarnation: GuardIncarnation::parse("1").unwrap(),
        },
        observed_at: "102".into(),
        object: None,
    };
    for fresh in [false, true] {
        let outcome = if fresh {
            ExternalObservationOutcome::ObservedThisInvocation(observation.clone())
        } else {
            ExternalObservationOutcome::HistoricalObservation(observation.clone())
        };
        let reply = ExternalObservationReply::new(&body, outcome).unwrap();
        let (encoded, mac) = reply.sign(&key, &body).unwrap();
        let parsed = ExternalObservationReply::authenticate(&key, &mac, &encoded, &body).unwrap();
        assert!(parsed.outcome == reply.outcome);
        let mut changed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        changed["authorization"]["operation_id"] = serde_json::json!("another-observation");
        let other = serde_json::to_vec(&changed).unwrap();
        assert!(ExternalObservationReply::authenticate(&key, &mac, &encoded, &other).is_err());
    }
    let mut wrong = observation;
    wrong.operation_id = "another-observation".into();
    assert!(ExternalObservationReply::new(
        &body,
        ExternalObservationOutcome::HistoricalObservation(wrong)
    )
    .is_err());
}

#[tokio::test]
async fn old_metadata_receipt_replay_never_relabels_latest_publication_or_read_slot() {
    let config = fixture::config();
    let (first_pending, first_intent) = fixture::pending(&config, 0).await;
    let first_receipt = fixture::receipt(&first_pending);
    let first = first_pending.terminal(&first_receipt).unwrap();
    let (second_pending, _) = first
        .begin(
            &config,
            fixture::intent(&config, 0, "put-two"),
            &fixture::token(&config, 0, 1).await,
            "c".repeat(64),
            fixture::clock(102),
        )
        .unwrap();
    let second_receipt = fixture::receipt(&second_pending);
    let second = second_pending.terminal(&second_receipt).unwrap();
    let visible = second.visible_receipt.as_ref().unwrap();
    assert_eq!(second.incarnation.get(), 2);
    assert_eq!(visible.operation_id, "put-two");
    assert_eq!(visible.receipt_digest, digest(&second_receipt).unwrap());
    let (replayed, _) = second.replay(&first_intent, &first_receipt).unwrap();
    assert!(replayed == second);
    assert!(second.terminal(&first_receipt).is_err());

    let intent = Intent {
        object: fixture::intent(&config, 1, "observe-latest"),
        expectation: ObservationExpectation::CaptureCurrentIdentity,
    };
    let (observing, _) = state::begin(
        &second,
        &config,
        intent,
        &fixture::token(&config, 1, 2).await,
        "d".repeat(64),
        fixture::clock(103),
    )
    .unwrap();
    let (replayed, _) = observing.replay(&first_intent, &first_receipt).unwrap();
    assert!(replayed == observing && replayed.observation.is_some());
    assert!(observing.terminal(&first_receipt).is_err());
}
