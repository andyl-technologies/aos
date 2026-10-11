//! Actual provider conflicts retain originals and separately observe hostile frames.
//!
//! These tests qualify transport mechanics for discovery/not-started controls
//! only. Native mutating, retirement and reconnect populations remain separate.

use super::*;

fn limits(count: usize) -> OriginalConflictLimits {
    OriginalConflictLimits {
        maximum_transmissions: count,
        maximum_bytes: 8 * 1024 * 1024,
    }
}

fn discover(controller: &mut ReferenceController, name: &str) -> ResponseBody {
    controller
        .call(
            fixture::id(name),
            None,
            Method::Discover,
            false,
            DiscoverRequest {
                profile_ids: Vec::new(),
                cursor: None,
                extensions: Extensions::new(),
            },
        )
        .unwrap()
}

fn originals(handle: &ObservationHandle, names: &[&str]) -> RecordedReferenceObservation {
    let keys = names
        .iter()
        .map(|name| ObservedRequestKey {
            origin: RequestOrigin::Controller,
            request_id: fixture::id(name),
        })
        .collect::<Vec<_>>();
    handle.snapshot(&keys, &[], output_limits()).unwrap()
}

fn children(pid: u32) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/task/{pid}/children")).unwrap()
}

fn snapshot(handle: &OriginalConflictObservationHandle) -> Value {
    serde_json::to_value(handle.snapshot(8 * 1024 * 1024).unwrap()).unwrap()
}

fn frame(arena: &Bytes, range: &Value) -> Envelope {
    let start = range[0].as_u64().unwrap() as usize;
    let length = range[1].as_u64().unwrap() as usize;
    Envelope::decode(&arena.as_slice()[start..start + length], 1_048_576).unwrap()
}

#[test]
fn actual_changed_discovery_and_refusal_frames_keep_original_journals() {
    let names = ["conflict-discover", "conflict-invalid-realize"];
    let (service, handshake, mut controller, original_observer) = observed_controller(256);
    let conflicts = controller.observe_original_conflicts(limits(2)).unwrap();
    let repeats = controller
        .observe_resends(TransmissionLimits {
            maximum_transmissions: 2,
            maximum_bytes: 8 * 1024 * 1024,
        })
        .unwrap();
    let before = children(service.process.id());
    assert!(before.trim().is_empty());
    let discovery = discover(&mut controller, names[0]);
    let invalid = RealizeRequest {
        realization_id: controller.bootstrap.authority.realization_id.clone(),
        configuration: canonical::content_ref(b"invalid original configuration", "text/plain")
            .unwrap(),
        requested_node_ids: vec![controller.bootstrap.node_id.clone()],
        resource_limits: controller.bootstrap.resource_limits.clone(),
        extensions: Extensions::new(),
    };
    let refusal = controller
        .call(
            fixture::id(names[1]),
            None,
            Method::Realize,
            false,
            invalid.clone(),
        )
        .unwrap();
    assert!(matches!(refusal.shape, ResponseShape::Error {
        operation_state:OperationState::NotStarted,ref error,.. }
        if error.effect == EffectCertainty::NotStarted));
    let original = originals(&original_observer, &names);
    let original_bytes = original.encode(8 * 1024 * 1024).unwrap();
    let changed_discovery = body(DiscoverRequest {
        profile_ids: vec![fixture::id("explicitly-unavailable-profile")],
        cursor: None,
        extensions: Extensions::new(),
    });
    let mut changed_invalid = invalid;
    changed_invalid.realization_id = fixture::id("different-realization-id");
    for (name, altered) in [
        (names[0], changed_discovery),
        (names[1], body(changed_invalid)),
    ] {
        let response = controller
            .probe_original_body_conflict(&fixture::id(name), &altered)
            .unwrap();
        assert!(matches!(response.shape,ResponseShape::Error {
            operation_state:OperationState::NotStarted,ref error,.. }
            if error.code == "CONFLICT" && error.effect == EffectCertainty::NotStarted));
        assert_eq!(children(service.process.id()), before);
        assert_eq!(
            originals(&original_observer, &names)
                .encode(8 * 1024 * 1024)
                .unwrap(),
            original_bytes
        );
    }
    // Independent unchanged wire retries prove the provider retained both
    // originals; a local cached return cannot establish that fact.
    assert_eq!(
        controller
            .resend_original_control(&fixture::id(names[0]))
            .unwrap(),
        discovery
    );
    assert_eq!(
        controller
            .resend_original_control(&fixture::id(names[1]))
            .unwrap(),
        refusal
    );
    let value = snapshot(&conflicts);
    assert_eq!(
        value["schema"],
        "crucible.reference.original-wire-conflicts.v1"
    );
    assert_eq!(value["incomplete"], false);
    assert_eq!(value["rows"].as_array().unwrap().len(), 2);
    let arena: Bytes = serde_json::from_value(value["bytes"].clone()).unwrap();
    for (index, row) in value["rows"].as_array().unwrap().iter().enumerate() {
        assert_eq!(row["conflict_refusal_verified"], true);
        assert_eq!(row["write_completed"], true);
        let original_request = frame(&arena, &row["original_request"]);
        let original_response = frame(&arena, &row["original_response"]);
        let actual = frame(
            &arena,
            &json!([row["request_start"], row["request_length"]]),
        );
        let received = frame(&arena, &row["received"]);
        assert_eq!(actual.request_id, original_request.request_id);
        assert_eq!(
            actual.request_id.0.as_ref(),
            Some(&fixture::id(names[index]))
        );
        assert_ne!(actual.body, original_request.body);
        assert_ne!(actual.sequence, original_request.sequence);
        let mut expected = original_request.clone();
        expected.sequence = actual.sequence;
        expected.body = actual.body.clone();
        assert_eq!(expected, actual);
        assert_eq!(
            serde_json::to_value(
                original_request
                    .request_hash(RequestOrigin::Controller)
                    .unwrap()
            )
            .unwrap(),
            row["original_identity"]
        );
        assert_eq!(
            serde_json::to_value(actual.request_hash(RequestOrigin::Controller).unwrap()).unwrap(),
            row["attempted_identity"]
        );
        assert_ne!(row["original_identity"], row["attempted_identity"]);
        original_request
            .matches_response(&original_response)
            .unwrap();
        actual.matches_response(&received).unwrap();
    }
    assert_eq!(
        serde_json::to_value(repeats.snapshot(8 * 1024 * 1024).unwrap()).unwrap()["rows"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    controller.fence();
    drop(controller);
    drop(handshake);
    drop(service);
    assert_eq!(snapshot(&conflicts), value);
}

#[test]
fn unavailable_unchanged_invalid_and_exhausted_controls_emit_no_extra_frames() {
    let (service, handshake, mut controller, _) = observed_controller(256);
    let altered = body(DiscoverRequest {
        profile_ids: Vec::new(),
        cursor: Some(fixture::id("cursor")),
        extensions: Extensions::new(),
    });
    assert!(
        controller
            .probe_original_body_conflict(&fixture::id("absent"), &altered)
            .is_err()
    );
    let conflicts = controller.observe_original_conflicts(limits(1)).unwrap();
    assert!(
        controller
            .probe_original_body_conflict(&fixture::id("absent"), &altered)
            .is_err()
    );
    discover(&mut controller, "one-conflict-original");
    let zero = snapshot(&conflicts);
    assert!(controller.observe_original_conflicts(limits(1)).is_err());
    assert!(
        controller
            .probe_original_body_conflict(
                &fixture::id("one-conflict-original"),
                &body(DiscoverRequest {
                    profile_ids: Vec::new(),
                    cursor: None,
                    extensions: Extensions::new()
                })
            )
            .is_err()
    );
    assert!(
        controller
            .probe_original_body_conflict(&fixture::id("one-conflict-original"), &Map::new())
            .is_err()
    );
    assert!(
        controller
            .probe_completed_lifecycle_body_conflict(
                &fixture::id("one-conflict-original"),
                &altered
            )
            .is_err()
    );
    let private = body(DiscoverRequest {
        profile_ids: Vec::new(),
        cursor: None,
        extensions: Extensions::new(),
    });
    let mut private = private;
    private.insert(
        "admission_token".to_owned(),
        json!("never-export-private-controls"),
    );
    assert!(
        controller
            .probe_original_body_conflict(&fixture::id("one-conflict-original"), &private)
            .is_err()
    );
    assert_eq!(snapshot(&conflicts), zero);
    controller
        .probe_original_body_conflict(&fixture::id("one-conflict-original"), &altered)
        .unwrap();
    let full = snapshot(&conflicts);
    assert!(matches!(
        controller.probe_original_body_conflict(&fixture::id("one-conflict-original"), &altered),
        Err(ProviderError::ResourceExhausted(_))
    ));
    assert_eq!(snapshot(&conflicts), full);
    assert!(children(service.process.id()).trim().is_empty());
    controller.fence();
    drop(controller);
    drop(handshake);
    drop(service);
}

#[test]
fn actual_provider_loss_fences_conflict_retry_and_retains_both_originals() {
    let (mut service, handshake, mut controller, original_observer) = observed_controller(256);
    let conflicts = controller.observe_original_conflicts(limits(2)).unwrap();
    discover(&mut controller, "lost-conflict-original");
    let original = originals(&original_observer, &["lost-conflict-original"])
        .encode(8 * 1024 * 1024)
        .unwrap();
    service.process.kill().unwrap();
    service.process.wait().unwrap();
    let altered = body(DiscoverRequest {
        profile_ids: Vec::new(),
        cursor: Some(fixture::id("cursor")),
        extensions: Extensions::new(),
    });
    assert!(
        controller
            .probe_original_body_conflict(&fixture::id("lost-conflict-original"), &altered)
            .is_err()
    );
    let failed = snapshot(&conflicts);
    assert_eq!(failed["incomplete"], true);
    assert_eq!(failed["rows"].as_array().unwrap().len(), 1);
    assert_eq!(failed["rows"][0]["conflict_refusal_verified"], false);
    assert!(
        controller
            .probe_original_body_conflict(&fixture::id("lost-conflict-original"), &altered)
            .is_err()
    );
    assert_eq!(snapshot(&conflicts), failed);
    assert_eq!(
        originals(&original_observer, &["lost-conflict-original"])
            .encode(8 * 1024 * 1024)
            .unwrap(),
        original
    );
    drop(controller);
    drop(handshake);
    drop(service);
    assert_eq!(snapshot(&conflicts), failed);
}
