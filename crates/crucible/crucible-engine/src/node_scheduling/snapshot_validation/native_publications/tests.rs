//! Checks native publication identity independently of recipient fanout.
//!
//! These are inert delivery records. They issue no admitted graph, native
//! receipt, Source or restoration authority.

use super::*;
use crucible_node_format::{Endpoint, Phase, canonical};

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn publication() -> Delivery {
    let payload = canonical::content_ref(b"original payload", "application/octet-stream").unwrap();
    Delivery {
        connection_id: Some(id("route/original")),
        connection_policy_ref: Some(payload.clone()),
        external_root: None,
        provenance_ref: payload.clone(),
        publication_id: id("publication/original"),
        producer: id("producer"),
        consumer: id("first-recipient"),
        producer_endpoint: Endpoint {
            node_id: id("producer"),
            port_id: id("output"),
            lane_id: id("lane"),
        },
        consumer_endpoint: Endpoint {
            node_id: id("first-recipient"),
            port_id: id("input"),
            lane_id: id("lane"),
        },
        source_sequence: 2.into(),
        native_sequence: 7.into(),
        evaluation: None,
        causal_parents: Vec::new(),
        publication: Position::new(1.into(), 0.into(), Phase::Publication),
        delivery: Position::new(1.into(), 0.into(), Phase::Delivery),
        payload,
    }
}

#[test]
fn same_publication_keeps_pending_and_staged_copies_and_independent_fanout() {
    let original = publication();
    let mut recipient = original.clone();
    recipient.consumer = id("second-recipient");
    recipient.consumer_endpoint.node_id = recipient.consumer.clone();
    recipient.source_sequence = 3.into();
    recipient.connection_id = Some(id("route/second"));
    recipient.connection_policy_ref =
        Some(canonical::content_ref(b"second delivery policy", "application/json").unwrap());
    recipient.delivery = Position::new(9.into(), 0.into(), Phase::Delivery);

    let mut publications = Publications::new();
    record(&mut publications, &original).unwrap();
    record(&mut publications, &original).unwrap();
    record(&mut publications, &recipient).unwrap();

    assert_eq!(publications.len(), 1);
    assert!(std::ptr::eq(
        *publications.values().next().unwrap(),
        &original
    ));
}

#[test]
fn every_original_publication_operand_remains_fixed_across_recipients() {
    let mutations: [fn(&mut Delivery); 7] = [
        |delivery| delivery.publication_id = id("publication/changed"),
        |delivery| {
            delivery.provenance_ref =
                canonical::content_ref(b"changed proof", "application/json").unwrap();
        },
        |delivery| delivery.publication = Position::new(2.into(), 0.into(), Phase::Publication),
        |delivery| {
            delivery.payload =
                canonical::content_ref(b"changed payload", "application/octet-stream").unwrap();
        },
        |delivery| {
            delivery.evaluation = Some(Position::new(1.into(), 0.into(), Phase::Reaction));
        },
        |delivery| {
            delivery
                .causal_parents
                .push(Position::new(0.into(), 0.into(), Phase::Delivery));
        },
        |delivery| delivery.external_root = Some(delivery.producer_endpoint.clone()),
    ];
    for mutate in mutations {
        let original = publication();
        let mut changed = original.clone();
        mutate(&mut changed);
        let mut publications = Publications::new();
        record(&mut publications, &original).unwrap();

        assert!(matches!(
            record(&mut publications, &changed),
            Err(SchedulingError::InvalidSnapshot)
        ));
        assert_eq!(publications.len(), 1);
        assert!(std::ptr::eq(
            *publications.values().next().unwrap(),
            &original
        ));
    }
}

#[test]
fn distinct_native_occurrences_keep_independent_publication_data() {
    let original = publication();
    let mut next = original.clone();
    next.native_sequence = 8.into();
    next.publication_id = id("publication/next");
    let mut other_endpoint = original.clone();
    other_endpoint.producer_endpoint.port_id = id("other-output");
    other_endpoint.publication_id = id("publication/other-output");
    let mut publications = Publications::new();

    for delivery in [&original, &next, &other_endpoint] {
        record(&mut publications, delivery).unwrap();
    }

    assert_eq!(publications.len(), 3);
}
