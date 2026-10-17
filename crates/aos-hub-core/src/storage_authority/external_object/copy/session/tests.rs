//! Restart, unknown-effect and positive multipart closure regression tests.

use super::*;
use crate::storage_authority::external_object::copy::tests::original;

fn reload(session: &CopySession) -> CopySession {
    serde_json::from_slice(&serde_json::to_vec(session).unwrap()).unwrap()
}

fn create(session: &mut CopySession) -> CopyReceipt {
    let original = session.original().clone();
    let turn = session.begin(&original, CopyAction::Create, "c".repeat(64));
    let receipt = CopyReceipt {
        turn: turn.unwrap(),
        outcome: CopyOutcome::Created {
            upload_id: "provider-original-upload".into(),
        },
    };
    session.acknowledge(&receipt).unwrap();
    receipt
}

fn part(session: &mut CopySession) -> CopyReceipt {
    let original = session.original().clone();
    let turn = session
        .begin(&original, session.next_action().unwrap(), "d".repeat(64))
        .unwrap();
    let mut source_state = OciSha256State::initial();
    for chunk in [b"hello".as_slice(), b" ", b"world"] {
        source_state.update(chunk).unwrap();
    }
    CopyReceipt {
        turn,
        outcome: CopyOutcome::Part {
            etag: "\"actual-part-tag\"".into(),
            sha256: source_state.final_digest().unwrap().encoded(),
            source_state,
        },
    }
}

#[test]
fn unknown_create_survives_restart_and_cannot_reissue_or_abort() {
    let original = original();
    let mut session = CopySession::initialize(original.clone()).unwrap();
    let turn = session
        .begin(&original, CopyAction::Create, "c".repeat(64))
        .unwrap();
    let mut restarted = reload(&session);

    assert_eq!(restarted.pending(), Some(&turn));
    assert!(restarted.next_action().is_err());
    assert!(restarted
        .begin(&original, CopyAction::Create, "e".repeat(64))
        .is_err());
    assert!(restarted
        .begin(
            &original,
            CopyAction::Abort {
                upload_id: "guessed".into()
            },
            "e".repeat(64)
        )
        .is_err());

    let mut changed = original;
    changed.source_object.provider_version = Some("replacement".into());
    assert_eq!(
        changed.copy_id().unwrap(),
        restarted.original().copy_id().unwrap()
    );
    assert!(restarted.validate(&changed).is_err());
}

#[test]
fn private_continuation_requires_exact_retained_part_and_abort_requires_positive_create() {
    let original = original();
    let mut session = CopySession::initialize(original.clone()).unwrap();
    assert!(session.abort_action().is_err());
    let created = create(&mut session);
    assert!(session.source_continuation_for(&created.turn).is_err());
    assert_eq!(session.abort_action().unwrap(), CopyAction::Abort {
        upload_id: "provider-original-upload".into()
    });

    let receipt = part(&mut session);
    assert_eq!(session.source_continuation_for(&receipt.turn).unwrap(), OciSha256State::initial());
    let restarted = reload(&session);
    assert_eq!(restarted.source_continuation_for(&receipt.turn).unwrap(), OciSha256State::initial());
    assert!(restarted.abort_action().is_err());

    let mut changed = receipt.turn.clone();
    changed.dispatch_nonce = "e".repeat(64);
    assert!(restarted.source_continuation_for(&changed).is_err());
    if let CopyAction::Part { source_state_digest, .. } = &mut changed.action {
        *source_state_digest = "f".repeat(64);
    }
    assert!(restarted.source_continuation_for(&changed).is_err());
}

#[test]
fn positive_create_and_part_close_once_after_actual_conditional_read() {
    let original = original();
    let mut session = CopySession::initialize(original.clone()).unwrap();
    let create_receipt = create(&mut session);
    session = reload(&session);
    assert_eq!(session.phase(), CopyPhase::Active);
    assert!(session.acknowledge(&create_receipt).is_err());

    let part_receipt = part(&mut session);
    let mut restarted = reload(&session);
    assert!(restarted.next_action().is_err());
    let mut wrong = part_receipt.clone();
    wrong.turn.dispatch_nonce = "e".repeat(64);
    assert!(restarted.acknowledge(&wrong).is_err());
    restarted.acknowledge(&part_receipt).unwrap();
    assert!(restarted.acknowledge(&part_receipt).is_err());

    let complete = restarted.next_action().unwrap();
    let CopyAction::Complete { sha256, .. } = &complete else {
        panic!("expected complete")
    };
    let hash = sha256.clone();
    let turn = restarted
        .begin(&original, complete, "f".repeat(64))
        .unwrap();
    let receipt = CopyReceipt {
        turn,
        outcome: CopyOutcome::Closed {
            destination: CopySourceObject {
                provider_version: Some("actual-destination-version".into()),
                etag: "\"actual-destination-tag\"".into(),
                bytes: original.source_object.bytes,
                guard_stamp: None,
            },
            sha256: hash,
        },
    };
    restarted.acknowledge(&receipt).unwrap();
    let closed = reload(&restarted);
    closed.validate(&original).unwrap();
    assert_eq!(closed.phase(), CopyPhase::Closed);
    assert_eq!(
        closed.destination().unwrap().provider_version.as_deref(),
        Some("actual-destination-version")
    );
    assert!(closed.next_action().is_err());
}

#[test]
fn short_range_and_wrong_provider_close_do_not_clear_pending() {
    let mut session = CopySession::initialize(original()).unwrap();
    create(&mut session);
    let mut receipt = part(&mut session);
    let before = session.clone();
    if let CopyOutcome::Part { source_state, .. } = &mut receipt.outcome {
        *source_state = OciSha256State::initial();
        source_state.update(b"short").unwrap();
    }
    assert!(session.acknowledge(&receipt).is_err());
    assert_eq!(session, before);

    let receipt = part_from_existing_turn(&session);
    session.acknowledge(&receipt).unwrap();
    let original = session.original().clone();
    let turn = session
        .begin(&original, session.next_action().unwrap(), "f".repeat(64))
        .unwrap();
    let wrong = CopyReceipt {
        turn,
        outcome: CopyOutcome::Closed {
            destination: CopySourceObject {
                provider_version: Some("null".into()),
                etag: "\"tag\"".into(),
                bytes: original.source_object.bytes,
                guard_stamp: None,
            },
            sha256: "0".repeat(64),
        },
    };
    let before = session.clone();
    assert!(session.acknowledge(&wrong).is_err());
    assert_eq!(session, before);
}

fn part_from_existing_turn(session: &CopySession) -> CopyReceipt {
    let mut source_state = OciSha256State::initial();
    source_state.update(b"hello world").unwrap();
    CopyReceipt {
        turn: session.pending().unwrap().clone(),
        outcome: CopyOutcome::Part {
            etag: "\"tag\"".into(),
            sha256: source_state.final_digest().unwrap().encoded(),
            source_state,
        },
    }
}

#[test]
fn source_hash_mismatch_refuses_complete_but_positive_abort_can_settle() {
    let mut original = original();
    original.expected_sha256 = Some("0".repeat(64));
    let mut session = CopySession::initialize(original.clone()).unwrap();
    create(&mut session);
    let receipt = part(&mut session);
    session.acknowledge(&receipt).unwrap();
    assert!(session.next_action().is_err());

    let turn = session
        .begin(
            &original,
            CopyAction::Abort {
                upload_id: "provider-original-upload".into(),
            },
            "f".repeat(64),
        )
        .unwrap();
    let mut restarted = reload(&session);
    assert!(restarted.next_action().is_err());
    restarted
        .acknowledge(&CopyReceipt {
            turn,
            outcome: CopyOutcome::Aborted,
        })
        .unwrap();
    assert_eq!(restarted.phase(), CopyPhase::Aborted);
}

#[test]
fn empty_copy_requires_positive_versioned_put_and_never_creates_multipart() {
    let mut original = original();
    original.source_object.bytes = crate::storage_authority::lease::LeaseInteger::new(0).unwrap();
    let mut session = CopySession::initialize(original.clone()).unwrap();
    assert_eq!(session.next_action().unwrap(), CopyAction::EmptyPut);
    assert!(session
        .begin(&original, CopyAction::Create, "c".repeat(64))
        .is_err());
    let turn = session
        .begin(&original, CopyAction::EmptyPut, "c".repeat(64))
        .unwrap();
    session
        .acknowledge(&CopyReceipt {
            turn,
            outcome: CopyOutcome::Closed {
                destination: CopySourceObject {
                    provider_version: Some("empty-positive-version".into()),
                    etag: "\"empty-tag\"".into(),
                    bytes: original.source_object.bytes,
                    guard_stamp: None,
                },
                sha256: OciSha256State::initial().final_digest().unwrap().encoded(),
            },
        })
        .unwrap();
    assert_eq!(reload(&session).phase(), CopyPhase::Closed);
}

#[test]
fn protected_source_replacement_cannot_escape_a_lost_create_turn() {
    let original = super::super::tests::protected_original();
    let mut session = CopySession::initialize(original.clone()).unwrap();
    let turn = session
        .begin(&original, CopyAction::Create, "c".repeat(64))
        .unwrap();
    let mut restarted = reload(&session);
    assert_eq!(restarted.pending(), Some(&turn));
    assert!(restarted.next_action().is_err());

    let mut replacement = original.clone();
    replacement
        .source_object
        .guard_stamp
        .as_mut()
        .unwrap()
        .incarnation = crate::storage_authority::GuardIncarnation::parse("8").unwrap();
    assert_eq!(replacement.copy_id().unwrap(), original.copy_id().unwrap());
    assert!(restarted.validate(&replacement).is_err());
    assert!(restarted
        .begin(&replacement, CopyAction::Create, "e".repeat(64))
        .is_err());
    assert!(restarted.abort_action().is_err());
}

#[test]
fn protected_copy_closes_with_guard_incarnation_and_rejects_foreign_closure() {
    let mut original = super::super::tests::protected_original();
    let mut expected = OciSha256State::initial();
    expected.update(b"hello world").unwrap();
    original.expected_sha256 = Some(expected.final_digest().unwrap().encoded());
    let mut session = CopySession::initialize(original.clone()).unwrap();
    create(&mut session);
    let part_receipt = part(&mut session);
    session.acknowledge(&part_receipt).unwrap();
    let action = session.next_action().unwrap();
    let CopyAction::Complete { sha256, .. } = &action else {
        panic!("expected complete after actual full source hash")
    };
    let hash = sha256.clone();
    let turn = session.begin(&original, action, "f".repeat(64)).unwrap();
    let mut receipt = CopyReceipt {
        turn,
        outcome: CopyOutcome::Closed {
            destination: CopySourceObject {
                provider_version: None,
                etag: "\"actual-destination-tag\"".into(),
                bytes: original.source_object.bytes,
                guard_stamp: original.source_object.guard_stamp.clone(),
            },
            sha256: hash,
        },
    };
    if let CopyOutcome::Closed { destination, .. } = &mut receipt.outcome {
        destination.guard_stamp.as_mut().unwrap().incarnation =
            crate::storage_authority::GuardIncarnation::parse("11").unwrap();
    }
    let mut foreign = receipt.clone();
    if let CopyOutcome::Closed { destination, .. } = &mut foreign.outcome {
        destination
            .guard_stamp
            .as_mut()
            .unwrap()
            .physical_authority_id = crate::storage_authority::PhysicalStorageAuthorityId::parse(
            "00000000-0000-4000-8000-000000000002",
        )
        .unwrap();
    }
    assert!(session.acknowledge(&foreign).is_err());
    assert!(session.pending().is_some());
    session.acknowledge(&receipt).unwrap();
    let mut restarted = reload(&session);
    let closed = restarted.progress().unwrap();
    assert_eq!(closed.phase, CopyPhase::Closed);
    assert!(closed
        .destination
        .as_ref()
        .unwrap()
        .provider_version
        .is_none());
    assert_eq!(
        closed
            .destination
            .as_ref()
            .unwrap()
            .guard_stamp
            .as_ref()
            .unwrap()
            .incarnation
            .as_str(),
        "11"
    );
    assert!(restarted.acknowledge(&receipt).is_err());
    assert_eq!(restarted.progress().unwrap(), closed);
}

#[test]
fn protected_copy_trusted_hash_mismatch_never_selects_complete() {
    let original = super::super::tests::protected_original();
    let mut session = CopySession::initialize(original).unwrap();
    create(&mut session);
    let positive = part(&mut session);
    session.acknowledge(&positive).unwrap();
    assert!(session.next_action().is_err());
    assert_eq!(session.phase(), CopyPhase::Active);
    assert!(session.destination().is_none());
    assert!(matches!(
        session.abort_action().unwrap(),
        CopyAction::Abort { .. }
    ));
}
