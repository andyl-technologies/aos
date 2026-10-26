//! Exercises real baseline decoder owners and whole-component admission.

use super::*;
use crate::bodies::*;
use crate::retained_metadata::{MetadataObserver, requested_metadata_backing_storage_data};
use crucible_node_format::*;
use serde_json::{Map, Value, json};
use std::collections::BTreeSet;

#[test]
fn body_quote_requires_the_whole_independent_row() {
    for frame in [1, 2, 43, 4096, 65_536] {
        let row = storage_data(frame, usize::MAX).unwrap();
        let requested = row[0].checked_add(row[1]).unwrap();

        assert_eq!(storage_data(frame, requested).unwrap(), row);
        assert!(storage_data(frame, requested - 1).is_err());
        assert_eq!(row[1], counter_scratch_data());
    }

    for frame in [0, 65_537, usize::MAX] {
        assert!(storage_data(frame, usize::MAX).is_err());
    }

    // Adding decoder companions must preserve the independently derived Vec
    // geometry of the existing closed method and Begin field graph.
    assert_eq!(
        bodies::typed_vector_storage_data(65_536, usize::MAX).unwrap(),
        [4_849_664, 10_420_224],
    );
}

#[test]
fn poll_decoding_keeps_three_independent_literal_populations() {
    let request = RequestBody::Poll(PollRequest {
        after_observation_sequence: 0.into(),
        extensions: Extensions::new(),
    });

    for population in [0, 1, 31, 512] {
        // These marker-shaped objects are literal data in every owner. The
        // raw_value configuration must not reinterpret their contents.
        let literal = json!({
            "$serde_json::private::RawValue": "literal",
            "rows": vec![json!({"": [0, "text"]}); population],
        });
        let outcome = json!({
            "status": "completed",
            "operation_state": "completed",
            "result": {"literal": literal},
            "extensions": {},
        });
        let body = completed(json!({
            "operation_id": "operation/1",
            "operation_state": "completed",
            "outcome": outcome,
            "observations": [],
            "next_observation_sequence": "0",
        }));
        let frame = serde_json::to_vec(&body).unwrap().len();
        let response = decode_response(&request, &body).unwrap();
        let Some(MethodResult::Poll(poll)) = &response.result else {
            panic!("Poll result missing");
        };
        let typed_outcome = poll.outcome.0.as_ref().unwrap();
        let nested = bodies::decode_response_shape(typed_outcome).unwrap();
        let ResponseShape::Completed { result: raw, .. } = &response.shape else {
            panic!("outer completed shape missing");
        };
        let ResponseShape::Completed { result: third, .. } = &nested else {
            panic!("nested completed shape missing");
        };

        assert_eq!(raw["outcome"]["result"]["literal"], literal);
        assert_eq!(typed_outcome["result"]["literal"], literal);
        assert_eq!(third["literal"], literal);
        let raw_literal = &raw["outcome"]["result"]["literal"];
        let typed_literal = &typed_outcome["result"]["literal"];
        assert!(!std::ptr::eq(raw_literal, typed_literal));
        assert!(!std::ptr::eq(typed_literal, &third["literal"]));

        let mut observer = MetadataObserver::new();
        observer.observe(raw).unwrap();
        observer.observe(poll).unwrap();
        observer.observe(third).unwrap();
        let backing = requested_metadata_backing_storage_data(&observer.finish()).unwrap();

        assert!(frame <= 65_536);
        assert!(backing <= storage_data(frame, usize::MAX).unwrap()[0]);

        let mut invalid = poll.clone();
        invalid
            .outcome
            .0
            .as_mut()
            .unwrap()
            .insert("status".into(), json!("accepted"));
        assert!(invalid.validate().is_err());
    }
}

#[test]
fn input_correspondence_prices_owned_ids_and_refuses_changed_identity() {
    for population in [0, 1, 31, 63] {
        let request = input(population);
        request.validate().unwrap();
        let result = InputResult {
            accepted_event_ids: request
                .events
                .iter()
                .map(|event| event.id.clone())
                .collect(),
            input_watermark: request.batch_sequence,
            custody_receipt: canonical::content_ref(b"receipt", "application/octet-stream")
                .unwrap(),
            inventory_hash: canonical::hash("cnp.inventory.v1", b"inventory").unwrap(),
        };
        let request_body = RequestBody::Input(request.clone());
        let body = completed(serde_json::to_value(&result).unwrap());
        decode_response(&request_body, &body).unwrap();

        let set: BTreeSet<_> = request
            .events
            .iter()
            .map(|event| event.id.clone())
            .collect();
        let mut set_observer = MetadataObserver::new();
        set_observer.observe(&set).unwrap();
        let set_backing = requested_metadata_backing_storage_data(&set_observer.finish()).unwrap();
        let ids: Vec<_> = set.into_iter().collect();
        let mut vector_observer = MetadataObserver::new();
        vector_observer.observe(&ids).unwrap();
        let vector_backing =
            requested_metadata_backing_storage_data(&vector_observer.finish()).unwrap();
        let frame = serde_json::to_vec(&request).unwrap().len();

        assert!(frame <= 65_536);
        assert!(set_backing + vector_backing <= validation::storage_data(frame).unwrap());

        let mut changed = result.clone();
        changed.input_watermark = 0.into();
        assert!(
            decode_response(
                &request_body,
                &completed(serde_json::to_value(changed).unwrap())
            )
            .is_err()
        );

        if population > 0 {
            let mut missing = result;
            missing.accepted_event_ids.pop();
            assert!(
                decode_response(
                    &request_body,
                    &completed(serde_json::to_value(missing).unwrap())
                )
                .is_err()
            );
        }
    }
}

#[test]
fn detail_validation_covers_notification_and_nested_poll_errors() {
    for population in [0, 1, 31, 512] {
        let details = json!({"rows": vec![json!({"": [0, "text"]}); population]})
            .as_object()
            .unwrap()
            .clone();
        let error = ErrorRecord {
            code: "INVALID_ARGUMENT".into(),
            message: "invalid request".into(),
            effect: EffectCertainty::NotStarted,
            retryable: false,
            details: details.clone(),
        };
        let notification = NotificationBody {
            operation_state: OperationState::Completed,
            last_observation_sequence: 0.into(),
            details,
            extensions: Extensions::new(),
        };
        error.validate().unwrap();
        notification.validate().unwrap();

        let body = completed(json!({
            "operation_id": "operation/1",
            "operation_state": "completed",
            "outcome": {
                "status": "error",
                "operation_state": "completed",
                "error": error,
                "extensions": {},
            },
            "observations": [],
            "next_observation_sequence": "0",
        }));
        let request = RequestBody::Poll(PollRequest {
            after_observation_sequence: 0.into(),
            extensions: Extensions::new(),
        });
        let response = decode_response(&request, &body).unwrap();
        let Some(MethodResult::Poll(poll)) = &response.result else {
            panic!("Poll result missing");
        };
        let nested = bodies::decode_response_shape(poll.outcome.0.as_ref().unwrap()).unwrap();
        let ResponseShape::Error { error, .. } = nested else {
            panic!("nested refusal missing");
        };
        let frame = serde_json::to_vec(&body).unwrap().len();
        let mut observer = MetadataObserver::new();
        observer.observe(poll).unwrap();
        observer.observe(&error).unwrap();

        assert!(frame <= 65_536);
        assert!(
            requested_metadata_backing_storage_data(&observer.finish()).unwrap()
                <= storage_data(frame, usize::MAX).unwrap()[0]
        );

        // The validator clones the code before rejecting it. A successful
        // short code alone would miss this failed-prefix owner.
        let mut invalid = error;
        invalid.code = " ".repeat(4096);
        assert!(invalid.validate().is_err());
    }
}

fn completed(result: Value) -> Map<String, Value> {
    json!({
        "status": "completed",
        "operation_state": "completed",
        "result": result,
        "extensions": {},
    })
    .as_object()
    .unwrap()
    .clone()
}

fn input(population: usize) -> InputRequest {
    let id = |text: &str| Id::new(text).unwrap();
    let publication = Position::new(1.into(), 0.into(), Phase::Publication);
    let delivery = Position::new(1.into(), 0.into(), Phase::Delivery);
    let reference = canonical::content_ref(b"payload", "application/octet-stream").unwrap();
    let endpoint = || Endpoint {
        node_id: id("node"),
        port_id: id("port"),
        lane_id: id("lane"),
    };
    let events = (0..population)
        .map(|index| Event {
            schema_version: 1,
            id: id(&format!("event/{index:05}")),
            source: endpoint(),
            destination: endpoint(),
            position: delivery,
            stage: EventStage::Delivery,
            publication_position: publication,
            delivery_position: Some(delivery),
            source_sequence: U64::new(index as u64 + 1),
            causal_parent_ids: Vec::new(),
            payload: reference.clone(),
            provenance_ref: reference.clone(),
            extensions: Extensions::new(),
        })
        .collect();

    InputRequest {
        binding_hash: canonical::hash("cnp.owner-binding.v1", b"owner").unwrap(),
        owner_generation: 1.into(),
        batch_id: id("batch"),
        batch_sequence: 1.into(),
        input_epoch: id("epoch"),
        events,
        batch_hash: canonical::hash("cnp.input-batch.v1", b"batch").unwrap(),
        extensions: Extensions::new(),
    }
}
