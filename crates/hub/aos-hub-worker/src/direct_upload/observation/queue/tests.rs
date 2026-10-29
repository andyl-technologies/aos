//! Exercises actual shared object admission and complete observation lifecycles.

use aos_hub_db::direct_upload::{DirectDependencyPhase, WireInteger};

use super::*;
use crate::direct_upload::verification_capacity::Capacity;

fn attempt() -> QueueObservation {
    let object = observation::Object {
        session: observation::Session::new("session", "original"),
        client_operation_digest: observation::digest("operation"),
        placement_digest: observation::digest("placement"),
        operation_digest: Some(observation::digest("verification")),
        complete_operation_digest: Some(observation::digest("complete")),
        dependency_phase: DirectDependencyPhase::Visibility,
        byte_size: WireInteger::new(32),
    };
    let mut event = observation::Event::new(observation::Kind::QueueStart, Some(object), "attempt");
    event.delivery_digest = Some(observation::digest("delivery"));
    QueueObservation::new(event)
}

#[test]
fn shared_capacity_refusal_retries_without_an_unstarted_finish() {
    let _ = observation::take_events();
    let bulk = Capacity::acquire(DirectDependencyPhase::Content, 3).unwrap();
    let metadata = Capacity::acquire(DirectDependencyPhase::Visibility, 3).unwrap();
    let other = Capacity::acquire(DirectDependencyPhase::Visibility, 3).unwrap();

    let observed = attempt();
    let admission = Capacity::acquire(DirectDependencyPhase::Visibility, 3);
    assert!(admission.is_err());
    observation::emit(&observed.finish(false, None));

    let events = observation::take_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, observation::Kind::QueueRetry);
    assert_eq!(events[0].outcome, observation::Outcome::Refused);
    assert_eq!(events[0].aggregate_active, 3);
    assert_eq!(events[0].bulk_active, 1);
    assert_eq!(events[0].metadata_active, 2);

    drop((bulk, metadata, other));
}

#[test]
fn admitted_read_failure_retains_both_boundaries_and_retry() {
    let _ = observation::take_events();
    let observed = attempt();
    let capacity = Capacity::acquire(DirectDependencyPhase::Visibility, 3).unwrap();
    observed.start();

    drop(capacity);
    observation::emit(&observed.finish(false, None));

    let events = observation::take_events();
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].kind, observation::Kind::QueueStart);
    assert_eq!(events[0].metadata_active, 1);
    assert_eq!(events[1].kind, observation::Kind::QueueFinish);
    assert_eq!(events[1].outcome, observation::Outcome::Refused);
    assert_eq!(events[2].kind, observation::Kind::QueueRetry);
    assert!(events.iter().all(|event| event.aggregate_active <= 3));
    assert!(events
        .iter()
        .all(|event| event.attempt_digest == events[0].attempt_digest
            && event.delivery_digest == events[0].delivery_digest));
}

#[test]
fn admitted_success_finishes_before_acknowledgement() {
    let _ = observation::take_events();
    let observed = attempt();
    let capacity = Capacity::acquire(DirectDependencyPhase::Visibility, 3).unwrap();
    observed.start();

    drop(capacity);
    observation::emit(&observed.finish(true, Some(false)));

    let events = observation::take_events();
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].kind, observation::Kind::QueueStart);
    assert_eq!(events[1].kind, observation::Kind::QueueFinish);
    assert_eq!(events[1].outcome, observation::Outcome::Positive);
    assert_eq!(events[1].replayed, Some(false));
    assert_eq!(events[2].kind, observation::Kind::QueueAck);
    assert_eq!(events[2].aggregate_active, 0);
}
