//! Same-head destination closure and read-slot barriers using real stage turns.

use super::*;
use crate::external_object::observation::{
    protocol as observation_protocol, state as observation_state,
};
use crate::external_object::protocol::{Effect as ObjectEffect, Intent as ObjectIntent};
use aos_hub_core::storage_authority::external_object::observation::ObservationExpectation;

fn observation_intent(f: &Fixture, head: &Head) -> observation_protocol::Intent {
    observation_protocol::Intent {
        object: ObjectIntent {
            scope: head.scope.clone(),
            operation_id: "fresh-final-head".into(),
            context: "a".repeat(64),
            cohort_digest: protocol::digest(&f.object.cohorts[1]).unwrap(),
            effect: ObjectEffect::Head,
        },
        expectation: ObservationExpectation::CaptureCurrentIdentity,
    }
}

#[tokio::test]
async fn active_destination_and_pending_parts_refuse_head_observation() {
    let f = Fixture::new(1).await;
    let (head, proof) = f.destination();
    assert!(observation_state::begin(
        &head,
        &f.object,
        observation_intent(&f, &head),
        &f.read,
        "c".repeat(64),
        clock(102)
    )
    .is_err());
    let (pending, _) = f
        .begin(&head, f.copy_intent(&proof, 1), Some(proof), None)
        .unwrap();
    assert!(observation_state::begin(
        &pending,
        &f.object,
        observation_intent(&f, &pending),
        &f.read,
        "c".repeat(64),
        clock(102)
    )
    .is_err());
}

#[tokio::test]
async fn positive_closed_destination_retains_owner_and_admits_exact_read_slot() {
    let f = Fixture::new(1).await;
    let (head, proof) = f.destination();
    let (head, copy) = f
        .begin(&head, f.copy_intent(&proof, 1), Some(proof.clone()), None)
        .unwrap();
    let (head, _) = f.terminal(
        &head,
        copy,
        Outcome::Copied {
            part: f.part(1),
            etag: "\"copy\"".into(),
        },
    );
    let (manifest, _) = f.manifest();
    let complete = f.intent(
        "complete-final",
        Operation::CompleteDestination {
            verified_stage_receipt_digest: protocol::digest(&proof.verified).unwrap(),
            upload_id: "destination-upload".into(),
            manifest,
        },
    );
    let proof_for_replacement = proof.clone();
    let (head, completion) = f.begin(&head, complete, Some(proof), None).unwrap();
    let stamp = f.stamp(&completion);
    let (closed, receipt) = f.terminal(
        &head,
        completion,
        Outcome::Closed {
            upload_id: "destination-upload".into(),
            etag: "\"final\"".into(),
            guard_stamp: stamp.clone(),
        },
    );
    assert!(closed.stage.is_none());
    let visible = closed.visible_receipt.as_ref().unwrap();
    assert_eq!(visible.operation_id, receipt.turn.intent.operation_id);
    assert_eq!(visible.receipt_digest, protocol::digest(&receipt).unwrap());
    assert_eq!(
        visible.context_digest,
        protocol::digest(&receipt.turn.intent.context).unwrap()
    );
    assert_eq!(visible.incarnation, closed.incarnation);
    let (observing, turn) = observation_state::begin(
        &closed,
        &f.object,
        observation_intent(&f, &closed),
        &f.read,
        "c".repeat(64),
        clock(102),
    )
    .unwrap();
    assert!(turn.stamp == stamp && observing.stage == closed.stage);
    observing.validate(&f.object, &observing.scope).unwrap();
    let mut corrupted = observing.clone();
    corrupted.visible_receipt.as_mut().unwrap().incarnation = WireInteger::new(0);
    assert!(corrupted.validate(&f.object, &corrupted.scope).is_err());
    let mut missing = closed.clone();
    missing.visible_receipt = None;
    assert!(observation_state::begin(
        &missing,
        &f.object,
        observation_intent(&f, &missing),
        &f.read,
        "c".repeat(64),
        clock(102)
    )
    .is_err());

    let read_receipt = observation_protocol::Receipt {
        observation:
            aos_hub_core::storage_authority::external_object::observation::ExternalObservation {
                operation_id: turn.intent.object.operation_id.clone(),
                intent_digest: turn.intent.fingerprint().unwrap(),
                turn_digest: protocol::digest(&turn).unwrap(),
                guard_stamp: turn.stamp.clone(),
                observed_at: "102".into(),
                object: None,
            },
        turn,
    };
    let settled = observation_state::terminal(&observing, &read_receipt).unwrap();
    let replacement = f.intent(
        "replacement-create",
        Operation::CreateDestination {
            verified_stage_receipt_digest: protocol::digest(&proof_for_replacement.verified)
                .unwrap(),
        },
    );
    let (active, _) = f
        .begin(&settled, replacement, Some(proof_for_replacement), None)
        .unwrap();
    assert!(active.stage.is_some() && active.visible_receipt == settled.visible_receipt);
    assert!(observation_state::begin(
        &active,
        &f.object,
        observation_intent(&f, &active),
        &f.read,
        "c".repeat(64),
        clock(102)
    )
    .is_err());
}

#[tokio::test]
async fn immutable_private_stage_is_not_a_mutable_delivery_observation_target() {
    let f = Fixture::new(0).await;
    let (closed, _) = f.closed_source();
    assert!(closed.incarnation.get() > 0);
    assert!(observation_state::begin(
        &closed,
        &f.object,
        observation_intent(&f, &closed),
        &f.read,
        "c".repeat(64),
        clock(102)
    )
    .is_err());
}
