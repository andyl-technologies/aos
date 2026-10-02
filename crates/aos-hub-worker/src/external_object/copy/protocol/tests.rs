//! Private guard response bindings and continuation substitution refusals.

use aos_hub_core::storage_authority::{
    external_object::copy::session::{CopyOutcome, CopySession},
    lease::LeaseClock,
};

use super::*;

fn pending_part() -> (Request, CopyTurn, EpochLeaseFloor, OciSha256State) {
    let (object, config, original) = super::super::config::tests::fixture();
    let domain = config.domain(&object, &original).unwrap();
    let scope = domain.scope(&object, &original, true).unwrap();
    let floor = EpochLeaseFloor::initialize_fresh_guard(
        domain.write_cohort.authority.clone(),
        object.executor_identity.clone(),
        scope.full_key.clone(),
        &object.timing_profile,
        LeaseClock {
            observed_at: 105,
            uncertainty: 2,
        },
    )
    .unwrap();
    let request = Request {
        domain: DOMAIN.into(),
        request_nonce: "c".repeat(64),
        permission_expires_at: LeaseInteger::new(200).unwrap(),
        scope,
        original: original.clone(),
        operation: Operation::Begin {
            control: CopyControl::Advance,
            write_lease: "opaque-lease".into(),
        },
    };
    let mut session = CopySession::initialize(original.clone()).unwrap();
    let create = session
        .begin(&original, CopyAction::Create, "a".repeat(64))
        .unwrap();
    session
        .acknowledge(&CopyReceipt {
            turn: create,
            outcome: CopyOutcome::Created {
                upload_id: "positive-original-upload".into(),
            },
        })
        .unwrap();
    let turn = session
        .begin(&original, session.next_action().unwrap(), "b".repeat(64))
        .unwrap();
    let source = session.source_continuation_for(&turn).unwrap();
    (request, turn, floor, source)
}

#[test]
fn private_continuation_authenticates_exact_request_and_independent_guard_key() {
    let (request, turn, floor, source) = pending_part();
    let key = StorageWorkKey::new([7_u8; 32]).unwrap();
    let (body, signature) = sign_reply(
        &key,
        &request,
        Reply::Dispatch {
            turn: turn.clone(),
            floor,
            source_state: Some(source.clone()),
            destination_stamp: None,
        },
    )
    .unwrap();
    let Reply::Dispatch {
        turn: observed,
        source_state,
        ..
    } = verify_reply(&key, &request, &signature, &body).unwrap()
    else {
        panic!("expected private dispatch")
    };
    assert_eq!(observed, turn);
    assert_eq!(source_state, Some(source));

    let app_key = StorageWorkKey::new([8_u8; 32]).unwrap();
    assert!(verify_reply(&app_key, &request, &signature, &body).is_err());
    let plain = key.sign_body(&body).unwrap();
    assert!(verify_reply(&key, &request, &plain, &body).is_err());
    let mut changed = request.clone();
    changed
        .original
        .source_object
        .provider_version
        .as_mut()
        .unwrap()
        .push_str("-replacement");
    assert!(verify_reply(&key, &changed, &signature, &body).is_err());
    let mut changed = request.clone();
    changed.request_nonce = "d".repeat(64);
    assert!(verify_reply(&key, &changed, &signature, &body).is_err());
}

#[test]
fn authenticated_words_cannot_replace_the_pending_continuation_or_turn() {
    let (request, turn, floor, mut source) = pending_part();
    let key = StorageWorkKey::new([7_u8; 32]).unwrap();
    source.update(b"forged prior bytes").unwrap();
    assert!(sign_reply(
        &key,
        &request,
        Reply::Dispatch {
            turn: turn.clone(),
            floor: floor.clone(),
            source_state: Some(source),
            destination_stamp: None,
        }
    )
    .is_err());
    assert!(sign_reply(
        &key,
        &request,
        Reply::Dispatch {
            turn: turn.clone(),
            floor: floor.clone(),
            source_state: None,
            destination_stamp: None,
        }
    )
    .is_err());
    let mut changed = turn;
    changed.original_digest = "f".repeat(64);
    assert!(sign_reply(
        &key,
        &request,
        Reply::Dispatch {
            turn: changed,
            floor,
            source_state: Some(OciSha256State::initial()),
            destination_stamp: None,
        }
    )
    .is_err());
}

#[test]
fn another_private_domain_and_public_continuation_fields_refuse() {
    let (request, _, _, _) = pending_part();
    let key = StorageWorkKey::new([7_u8; 32]).unwrap();
    let body = serde_json::to_vec(&request).unwrap();
    let signature = key.sign_body(&body).unwrap();
    authenticate(&key, &signature, &body).unwrap();
    let mut changed = serde_json::to_value(&request).unwrap();
    changed["source_state"] = serde_json::to_value(OciSha256State::initial()).unwrap();
    let body = serde_json::to_vec(&changed).unwrap();
    assert!(authenticate(&key, &key.sign_body(&body).unwrap(), &body).is_err());
    let mut changed = request;
    changed.domain = "aos.external-stage-compact-turn.v1".into();
    let body = serde_json::to_vec(&changed).unwrap();
    assert!(authenticate(&key, &key.sign_body(&body).unwrap(), &body).is_err());
}
