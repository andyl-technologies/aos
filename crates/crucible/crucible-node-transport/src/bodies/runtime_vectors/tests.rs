//! Checks real borrowed typed vectors and nested malformed decoder prefixes.

use super::*;
use serde::Deserialize;
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn observation(events: usize, parents: usize) -> ObservationBatch {
    let reference = canonical::content_ref(b"proof", "application/octet-stream").unwrap();
    let position = Position::new(U64::new(1), U64::new(0), Phase::Publication);
    let endpoint = || Endpoint {
        node_id: id("node"),
        port_id: id("port"),
        lane_id: id("lane"),
    };
    let events = (0..events)
        .map(|index| Event {
            schema_version: 1,
            id: id(&format!("event/{index}")),
            source: endpoint(),
            destination: endpoint(),
            position,
            stage: EventStage::Publication,
            publication_position: position,
            delivery_position: None,
            source_sequence: U64::new(index as u64 + 1),
            causal_parent_ids: (0..parents)
                .map(|parent| id(&format!("parent/{parent:05}")))
                .collect(),
            payload: reference.clone(),
            provenance_ref: reference.clone(),
            extensions: Extensions::new(),
        })
        .collect();
    ObservationBatch {
        schema_version: 1,
        execution_owner_id: id("owner"),
        owner_binding_hash: canonical::hash("cnp.owner-binding.v1", b"owner").unwrap(),
        world_binding_hash: canonical::hash("cnp.world-binding.v1", b"world").unwrap(),
        activation_id: id("activation"),
        world_generation: U64::new(1),
        owner_generation: U64::new(1),
        operation_id: id("operation"),
        grant_id: None,
        first_sequence: U64::new(1),
        last_sequence: U64::new(1),
        events,
        visibility: Visibility::Committed,
        measurement_ref: reference,
        extensions: Extensions::new(),
    }
}

fn vector_backing(value: &ObserveResult) -> usize {
    value.observations.capacity() * size_of::<ObservationBatch>()
        + value
            .observations
            .iter()
            .map(|batch| {
                batch.events.capacity() * size_of::<Event>()
                    + batch
                        .events
                        .iter()
                        .map(|event| event.causal_parent_ids.capacity() * size_of::<Id>())
                        .sum::<usize>()
            })
            .sum::<usize>()
}

#[test]
fn completed_borrowed_populations_fit_with_independent_nested_capacities() -> TestResult {
    for (batches, events, parents) in [(0, 0, 0), (1, 0, 0), (1, 1, 3), (1, 2050, 0), (3, 2, 257)] {
        let original = ObserveResult {
            observations: vec![observation(events, parents); batches],
            next_sequence: U64::new(1),
            complete: true,
            inventory_hash: canonical::hash("cnp.inventory.v1", b"inventory")?,
        };
        let wire = serde_json::to_vec(&original)?;
        let input: Value = serde_json::from_slice(&wire)?;
        let row = typed_vector_storage_data(wire.len(), usize::MAX)?;

        let decoded = ObserveResult::deserialize(&input)?;

        assert_eq!(decoded, original);
        assert!(vector_backing(&decoded) <= row[0]);
        assert!(row[0] <= row[1]);
        if events == 2050 {
            // This actual Event vector crosses Serde's cautious initial bank.
            assert!(decoded.observations[0].events.capacity() > events);
        }
        drop(input);
        assert_eq!(decoded.observations.len(), batches);
    }
    Ok(())
}

#[test]
fn nested_invalid_first_elements_still_receive_partial_vector_credit() -> TestResult {
    // Lexicographic field traversal reaches all three Vec visitors before the
    // first invalid Id. No Event or ObservationBatch can complete here.
    let mut parents = vec![Value::Null; 3000];
    parents[0] = json!(false);
    let mut events = vec![Value::Null; 2100];
    events[0] = json!({"causal_parent_ids": parents});
    let mut observations = vec![Value::Null; 2500];
    observations[0] = json!({"events": events});
    let input = json!({"observations": observations});
    let wire = serde_json::to_vec(&input)?;
    assert!(wire.len() <= 65_536);
    let row = typed_vector_storage_data(wire.len(), usize::MAX)?;

    assert!(ObserveResult::deserialize(&input).is_err());
    assert_eq!(RUNTIME.vector_depth, 3);
    assert!(row[1] - row[0] >= 3 * 1024 * 1024);
    Ok(())
}

#[test]
fn independent_restrictions_refuse_without_arithmetic_wraparound() -> TestResult {
    let row = typed_vector_storage_data(65536, usize::MAX)?;

    assert_eq!(typed_vector_storage_data(65536, row[1])?, row);
    assert!(typed_vector_storage_data(65536, row[1] - 1).is_err());
    assert!(typed_vector_storage_data(0, usize::MAX).is_err());
    assert!(typed_vector_storage_data(usize::MAX, usize::MAX).is_err());
    assert_eq!(RUNTIME.element_bytes, size_of::<Event>());
    Ok(())
}

#[test]
fn begin_capture_results_include_their_typed_reference_vector() -> TestResult {
    let reference = canonical::content_ref(b"state", "application/octet-stream")?;
    let original = CaptureResult {
        capture_manifest: reference.clone(),
        owner_state_refs: vec![reference.clone(); 12_000],
        unchanged_cut_receipt: reference,
    };
    let wire = serde_json::to_vec(&original)?;
    let input: Value = serde_json::from_slice(&wire)?;

    let decoded = CaptureResult::deserialize(&input)?;
    let row = typed_vector_storage_data(wire.len(), usize::MAX)?;

    assert_eq!(decoded, original);
    assert!(decoded.owner_state_refs.capacity() * size_of::<ContentRef>() <= row[0]);
    assert!(decoded.owner_state_refs.capacity() > decoded.owner_state_refs.len());
    Ok(())
}

#[test]
fn actual_serde_initial_reservations_match_the_pinned_failed_prefix_bound() -> TestResult {
    struct ReservationHint;

    impl<'de> serde::de::SeqAccess<'de> for ReservationHint {
        type Error = serde_json::Error;

        fn next_element_seed<T: serde::de::DeserializeSeed<'de>>(
            &mut self,
            _: T,
        ) -> Result<Option<T::Value>, Self::Error> {
            Ok(None)
        }

        fn size_hint(&self) -> Option<usize> {
            // Isolate the visitor's initial reservation without requiring an
            // allocator hook. Live borrowed Value arrays provide their real
            // lengths; the malformed nested control exercises that path.
            Some(usize::MAX)
        }
    }

    fn verify<T: serde::de::DeserializeOwned>() -> Result<(), serde_json::Error> {
        let sequence = serde::de::value::SeqAccessDeserializer::new(ReservationHint);

        let values = Vec::<T>::deserialize(sequence)?;

        assert!(values.is_empty());
        assert_eq!(
            values.capacity(),
            CAUTIOUS_RESERVATION_BYTES / size_of::<T>()
        );
        Ok(())
    }

    verify::<Id>()?;
    verify::<ContentRef>()?;
    verify::<Event>()?;
    verify::<ObservationBatch>()?;
    Ok(())
}
