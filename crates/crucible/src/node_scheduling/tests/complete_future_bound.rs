//! Complete original future closure without fictitious producer progress.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crate::node_scheduling::event::Delivery;

#[test]
fn complete_output_closure_allows_consumer_progress_without_producer_run() {
    for ceiling in [
        ExactCeiling::StrictPredecessor,
        ExactCeiling::InputBlocked {
            proof_ref: reference(),
        },
    ] {
        let mut scheduler = fixture(exact(ceiling), 1, Some(7));
        let activation = scheduler.activation.clone();
        scheduler
            .observe_bound(
                &activation,
                &id("Z"),
                OutputBound::AfterInstant(U64::new(u64::MAX)),
            )
            .unwrap();
        let producer_position = scheduler.position(&id("Z")).unwrap();
        assert_eq!(
            scheduler
                .earliest_arrival(&scheduler.schedule(&id("A")).unwrap().inputs[0])
                .unwrap(),
            None
        );
        assert_eq!(
            scheduler
                .preview_exact_input_cut(&id("A"), 500.into())
                .unwrap(),
            position(500, 0, Phase::BoundaryControl)
        );
        let stage = scheduler
            .prepare_input_batch(
                &id("A"),
                id("stage/closed"),
                id("batch/closed"),
                position(500, 0, Phase::BoundaryControl),
            )
            .unwrap();
        assert!(stage.deliveries().is_empty());
        scheduler.abandon_input_undispatched(stage).unwrap();
        let grant = scheduler
            .admit_exact(&id("A"), id("consumer-only"), 500.into())
            .unwrap();
        assert_eq!(grant.limit(), position(500, 0, Phase::BoundaryControl));
        assert_eq!(scheduler.position(&id("Z")).unwrap(), producer_position);
        assert_eq!(scheduler.operations.len(), 1);
        assert!(scheduler.operations.contains_key(&id("consumer-only")));
    }
}

#[test]
fn complete_future_closure_retains_the_original_pending_delivery() {
    let mut scheduler = fixture(exact(ExactCeiling::StrictPredecessor), 1, Some(7));
    let payload = crucible_node_contract::canonical::content_ref(
        b"original retained request",
        "application/octet-stream",
    )
    .unwrap();
    let original = Delivery {
        connection_id: None,
        connection_policy_ref: None,
        external_root: None,
        provenance_ref: reference(),
        publication_id: id("original-publication"),
        producer: id("Z"),
        consumer: id("A"),
        producer_endpoint: Endpoint {
            node_id: id("Z"),
            port_id: id("data"),
            lane_id: id("output"),
        },
        consumer_endpoint: Endpoint {
            node_id: id("A"),
            port_id: id("data"),
            lane_id: id("input"),
        },
        source_sequence: 0.into(),
        native_sequence: 1.into(),
        evaluation: None,
        causal_parents: Vec::new(),
        publication: position(10, 0, Phase::Publication),
        delivery: position(17, 0, Phase::Delivery),
        payload: payload.clone(),
    };
    scheduler.pending.insert(original.key(), original.clone());
    scheduler
        .payloads
        .insert(payload, b"original retained request".to_vec());
    observe(
        &mut scheduler,
        OutputBound::AfterInstant(U64::new(u64::MAX)),
    );

    let grant = scheduler
        .admit_exact(&id("A"), id("before-original-input"), 500.into())
        .unwrap();
    assert_eq!(grant.limit(), position(16, 0, Phase::BoundaryControl));
    assert_eq!(scheduler.pending.values().next(), Some(&original));
    scheduler.abandon_undispatched(grant).unwrap();

    let stage = scheduler
        .prepare_input_batch(
            &id("A"),
            id("stage/original-input"),
            id("batch/original-input"),
            position(500, 0, Phase::BoundaryControl),
        )
        .unwrap();
    assert_eq!(stage.deliveries(), &[original]);
    scheduler.abandon_input_undispatched(stage).unwrap();
    assert_eq!(scheduler.pending.len(), 1);
}

#[test]
fn finite_arrival_overflow_preserves_original_producer_reservation() {
    for finite in [
        OutputBound::At(position(u64::MAX, 0, Phase::Publication)),
        OutputBound::AfterInstant(U64::new(u64::MAX - 1)),
    ] {
        let mut scheduler = fixture(exact(ExactCeiling::StrictPredecessor), 1, Some(1));
        let original = scheduler
            .admit_exact(&id("Z"), id("original-producer"), 100.into())
            .unwrap();
        let activation = scheduler.activation.clone();
        scheduler
            .observe_bound(&activation, &id("Z"), finite)
            .unwrap();
        assert!(matches!(
            scheduler.admit_exact(&id("A"), id("overflowing-consumer"), 50.into()),
            Err(SchedulingError::Contract(
                crucible_node_contract::ContractError::Overflow
            ))
        ));
        assert!(matches!(
            scheduler.preview_exact_input_cut(&id("A"), 50.into()),
            Err(SchedulingError::Contract(
                crucible_node_contract::ContractError::Overflow
            ))
        ));
        assert_eq!(scheduler.operations.len(), 1);
        assert!(scheduler.operations.contains_key(&id("original-producer")));
        assert_eq!(scheduler.position(&id("Z")).unwrap(), original.start());
        assert_eq!(
            scheduler.position(&id("A")).unwrap(),
            position(0, 0, Phase::BoundaryControl)
        );
    }
}
