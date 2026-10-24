//! Actual provider transmissions, original cache separation and bounded loss custody.
//!
//! These process tests exercise source-built discovery and one authentic
//! pre-realization refusal. They do not qualify mutating or reconnect behavior.

use super::*;

fn limits(count: usize) -> TransmissionLimits {
    TransmissionLimits {
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

fn children(pid: u32) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/task/{pid}/children")).unwrap()
}

fn decoded_frames(value: &Value) -> Vec<(Envelope, Envelope)> {
    let bytes: Bytes = serde_json::from_value(value["bytes"].clone()).unwrap();
    value["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            let start = row["request_start"].as_u64().unwrap() as usize;
            let length = row["request_length"].as_u64().unwrap() as usize;
            let received = row["received"].as_array().unwrap();
            let response_start = received[0].as_u64().unwrap() as usize;
            let response_length = received[1].as_u64().unwrap() as usize;
            (
                Envelope::decode(&bytes.as_slice()[start..start + length], 1_048_576).unwrap(),
                Envelope::decode(
                    &bytes.as_slice()[response_start..response_start + response_length],
                    1_048_576,
                )
                .unwrap(),
            )
        })
        .collect()
}

fn originals(
    handle: &ObservationHandle,
    names: &[&str],
) -> Vec<(Envelope, Option<Envelope>, HashRef)> {
    let keys: Vec<_> = names
        .iter()
        .map(|name| ObservedRequestKey {
            origin: RequestOrigin::Controller,
            request_id: fixture::id(name),
        })
        .collect();
    let snapshot = handle.snapshot(&keys, &[], output_limits()).unwrap();
    snapshot
        .evidence
        .requests
        .iter()
        .map(|original| {
            (
                Envelope::decode(original.request.bytes.as_slice(), 1_048_576).unwrap(),
                original
                    .response
                    .0
                    .as_ref()
                    .map(|value| Envelope::decode(value.bytes.as_slice(), 1_048_576).unwrap()),
                original.identity.clone(),
            )
        })
        .collect()
}

#[test]
fn actual_discovery_and_not_started_refusal_resends_preserve_original_journals() {
    // The supported case population and complete transmission credits precede
    // the first native provider. Fresh authority remains in original envelopes.
    let names = ["wire-discover", "wire-invalid-realize"];
    let bounds = limits(4);
    let (service, handshake, mut controller, observed_originals) = observed_controller(256);
    let wire = controller.observe_resends(bounds).unwrap();
    let before = children(service.process.id());
    assert!(before.trim().is_empty());
    let discovery = discover(&mut controller, names[0]);
    let invalid = canonical::content_ref(b"different configuration", "text/plain").unwrap();
    let refusal = controller
        .call(
            fixture::id(names[1]),
            None,
            Method::Realize,
            false,
            RealizeRequest {
                realization_id: controller.bootstrap.authority.realization_id.clone(),
                configuration: invalid,
                requested_node_ids: vec![controller.bootstrap.node_id.clone()],
                resource_limits: controller.bootstrap.resource_limits.clone(),
                extensions: Extensions::new(),
            },
        )
        .unwrap();
    assert!(matches!(
        refusal.shape,
        ResponseShape::Error {
            operation_state: OperationState::NotStarted,
            ref error,
            ..
        } if error.effect == EffectCertainty::NotStarted
    ));
    let original_rows = originals(&observed_originals, &names);

    for _ in 0..2 {
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
        assert_eq!(children(service.process.id()), before);
    }
    // Ordinary exchange still serves its cached original and emits no row.
    assert_eq!(discover(&mut controller, names[0]), discovery);
    let observed = serde_json::to_value(wire.snapshot(8 * 1024 * 1024).unwrap()).unwrap();
    assert_eq!(observed["incomplete"], false);
    assert_eq!(observed["rows"].as_array().unwrap().len(), 4);
    let frames = decoded_frames(&observed);
    for (index, (sent, received)) in frames.iter().enumerate() {
        let original = &original_rows[index % 2];
        assert_eq!(
            sent.request_hash(RequestOrigin::Controller).unwrap(),
            original.2
        );
        assert_ne!(sent.sequence, original.0.sequence);
        assert_eq!(sent.body, original.0.body);
        sent.matches_response(received).unwrap();
        let mut expected = original.1.clone().unwrap();
        expected.sequence = received.sequence;
        assert_eq!(*received, expected);
        if index > 0 {
            assert!(sent.sequence > frames[index - 1].0.sequence);
            assert!(received.sequence > frames[index - 1].1.sequence);
        }
    }
    assert_eq!(originals(&observed_originals, &names), original_rows);
    let secret = serde_json::to_value(&controller.bootstrap.admission_token).unwrap();
    assert!(
        !canonical::canonical_json(&observed)
            .unwrap()
            .windows(secret.as_str().unwrap().len())
            .any(|part| part == secret.as_str().unwrap().as_bytes())
    );
    controller.fence();
    drop(controller);
    drop(handshake);
    drop(service);
    assert_eq!(
        decoded_frames(&serde_json::to_value(wire.snapshot(8 * 1024 * 1024).unwrap()).unwrap()),
        frames
    );
}

#[test]
fn unreserved_absent_and_exhausted_resends_never_add_a_transmission() {
    let (service, handshake, mut controller, _) = observed_controller(256);
    assert!(
        controller
            .resend_original_control(&fixture::id("absent"))
            .is_err()
    );
    let wire = controller.observe_resends(limits(1)).unwrap();
    assert!(
        controller
            .resend_original_control(&fixture::id("absent"))
            .is_err()
    );
    discover(&mut controller, "one-original");
    controller
        .resend_original_control(&fixture::id("one-original"))
        .unwrap();
    let original = serde_json::to_value(wire.snapshot(8 * 1024 * 1024).unwrap()).unwrap();
    assert!(matches!(
        controller.resend_original_control(&fixture::id("one-original")),
        Err(ProviderError::ResourceExhausted(_))
    ));
    assert_eq!(
        serde_json::to_value(wire.snapshot(8 * 1024 * 1024).unwrap()).unwrap(),
        original
    );
    assert!(children(service.process.id()).trim().is_empty());
    controller.fence();
    drop(controller);
    drop(handshake);
    drop(service);
}

#[test]
fn actual_provider_loss_retains_original_and_incomplete_transmission() {
    let (mut service, handshake, mut controller, observed_originals) = observed_controller(256);
    let wire = controller.observe_resends(limits(2)).unwrap();
    discover(&mut controller, "lost-provider-original");
    let original_rows = originals(&observed_originals, &["lost-provider-original"]);
    service.process.kill().unwrap();
    service.process.wait().unwrap();
    assert!(
        controller
            .resend_original_control(&fixture::id("lost-provider-original"))
            .is_err()
    );
    assert_eq!(
        originals(&observed_originals, &["lost-provider-original"]),
        original_rows
    );
    let value = serde_json::to_value(wire.snapshot(8 * 1024 * 1024).unwrap()).unwrap();
    assert_eq!(value["incomplete"], true);
    assert_eq!(value["rows"].as_array().unwrap().len(), 1);
    assert_eq!(value["rows"][0]["semantic_response_verified"], false);
    drop(controller);
    drop(handshake);
    drop(service);
    assert_eq!(
        serde_json::to_value(wire.snapshot(8 * 1024 * 1024).unwrap()).unwrap(),
        value
    );
}
