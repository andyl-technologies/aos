//! Checks exact deferred-publication seals independently of modeled source callbacks.

use super::*;
use crate::node_scheduling::DeferredPublicationAuthorization;

fn deferred_fixture() -> (CausalScheduler, SchedulingReceipt) {
    let (mut scheduler, endpoint) = routed_fixture();
    let prior = scheduler
        .admit_exact_position(
            &id("Z"),
            id("run/reaction"),
            position(10, 1, Phase::Publication),
        )
        .unwrap();
    let receipt = exact_receipt(&scheduler, &prior, prior.limit(), StopReason::HorizonPark);
    scheduler.accept_receipt(receipt).unwrap();

    let current = scheduler
        .admit_exact(&id("Z"), id("run/publication"), U64::new(100))
        .unwrap();
    let observation = publication_observation(&scheduler, &endpoint, b"retained payload");
    let receipt = SchedulingReceipt::new(
        scheduler.activation.clone(),
        id("Z"),
        current.operation().clone(),
        ProgressEvidence::Exact {
            reached: current.limit(),
            stop: StopReason::HorizonPark,
        },
        vec![id("output/1")],
        Some(observation),
    );
    (scheduler, receipt)
}

#[test]
fn deferred_publication_without_original_source_seal_retains_reservation() {
    let (mut scheduler, receipt) = deferred_fixture();

    assert!(matches!(
        scheduler.accept_receipt(receipt),
        Err(SchedulingError::InvalidPublication)
    ));
    assert_eq!(
        scheduler.position(&id("Z")).unwrap(),
        position(10, 1, Phase::Publication)
    );
    assert!(scheduler.owners[&id("owner/Z")].reserved.is_some());
    assert!(scheduler.pending.is_empty());
}

#[test]
fn deferred_publication_exact_seal_preserves_original_geometry_and_bytes() {
    let (mut scheduler, receipt) = deferred_fixture();
    // This component models the installed source conjunction; production alone
    // issues the seal after validating both opaque runtime outcomes and source.
    let authorization = DeferredPublicationAuthorization::new(
        &receipt.observation.as_ref().unwrap().publications[0],
        &id("run/reaction"),
    );

    scheduler
        .accept_receipt(receipt.retain_deferred_evaluations(vec![authorization]))
        .unwrap();

    let delivery = scheduler.pending.values().next().unwrap();
    assert_eq!(delivery.delivery, position(11, 0, Phase::Delivery));
    assert_eq!(scheduler.payloads[&delivery.payload], b"retained payload");
    assert_eq!(
        *scheduler.native_sequences.values().next().unwrap(),
        U64::new(7)
    );
}

#[test]
fn deferred_publication_seal_refuses_changed_tuple_and_unknown_prior() {
    for mutation in 0..8 {
        let (mut scheduler, mut receipt) = deferred_fixture();
        let publication = &mut receipt.observation.as_mut().unwrap().publications[0];
        let authorization = DeferredPublicationAuthorization::new(
            publication,
            &id(if mutation == 7 {
                "run/foreign"
            } else {
                "run/reaction"
            }),
        );
        match mutation {
            0 => publication.native_sequence = U64::new(8),
            1 => {
                publication.publication_id = id("output/changed");
                receipt.retained_outputs[0] = publication.publication_id.clone();
            }
            2 => publication.endpoint.port_id = id("port/changed"),
            3 => publication.publication = position(10, 2, Phase::Publication),
            4 => publication.evaluation = Some(position(9, 0, Phase::Reaction)),
            5 => {
                publication.payload_bytes = b"changed payload".to_vec();
                publication.payload = crucible_node_format::canonical::content_ref(
                    &publication.payload_bytes,
                    "application/octet-stream",
                )
                .unwrap();
            }
            6 => publication
                .causal_parents
                .push(position(10, 0, Phase::Delivery)),
            7 => {}
            _ => unreachable!(),
        }

        assert!(
            scheduler
                .accept_receipt(receipt.retain_deferred_evaluations(vec![authorization]))
                .is_err(),
            "mutation {mutation}"
        );
        assert_eq!(
            scheduler.position(&id("Z")).unwrap(),
            position(10, 1, Phase::Publication)
        );
        assert!(scheduler.owners[&id("owner/Z")].reserved.is_some());
        assert!(scheduler.pending.is_empty());
    }
}
