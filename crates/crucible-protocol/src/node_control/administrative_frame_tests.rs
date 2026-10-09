//! Closed edition-five framing and preserved earlier packet bodies.

// crucible-lint: allow panic-shortcut -- These administrative frame tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used)]

use super::*;

fn observations() -> Vec<NativeFrame> {
    let preparation = super::administrative_preparation::test_preparation();
    let scope = preparation
        .phase
        .initialization
        .preparation
        .scope
        .identity_digest()
        .unwrap();
    let commitment = preparation.identity_digest().unwrap();
    vec![
        NativeFrame::PrepareAdministration(Box::new(preparation.clone())),
        NativeFrame::QueryAdministration {
            prepared_scope_hash: scope,
            administration_commitment: commitment,
        },
        NativeFrame::AdministrationFacts(Box::new(NativeAdministrativeFacts {
            registration_id: crucible_node_contract::U64::new(1),
            thread_id: crucible_node_contract::U64::new(9),
            socket_device: crucible_node_contract::U64::new(preparation.socket_device),
            socket_inode: crucible_node_contract::U64::new(preparation.socket_inode),
            process_id: crucible_node_contract::U64::new(8),
            descriptor_slot: preparation.descriptor_slot,
            prepared_scope_hash: scope,
            role_commitment: commitment,
            realize_request_digest: preparation.phase.initialization.realize_request_digest,
            policy_digest: preparation.policy_digest,
        })),
    ]
}

#[test]
fn new_originals_round_trip_only_the_pinned_edition() {
    for (index, frame) in observations().into_iter().enumerate() {
        let encoded =
            encode_frame_for_edition(NativeControlEdition::Administration, &frame).unwrap();
        assert_eq!(&encoded[8..12], &[0, 5, 0, 26 + index as u8]);
        assert_eq!(
            decode_frame_for_edition(NativeControlEdition::Administration, &encoded).unwrap(),
            frame
        );
        for old in [
            NativeControlEdition::Original,
            NativeControlEdition::OwnedCustody,
            NativeControlEdition::PhaseProjection,
            NativeControlEdition::PreparationSuccessor,
        ] {
            assert!(encode_frame_for_edition(old, &frame).is_err());
            assert!(decode_frame_for_edition(old, &encoded).is_err());
            let mut substituted = encoded.clone();
            substituted[8..10].copy_from_slice(&old.version().to_be_bytes());
            assert!(decode_frame_for_edition(old, &substituted).is_err());
        }
    }
}

#[test]
fn every_truncation_and_trailing_byte_is_refused() {
    for frame in observations() {
        let encoded =
            encode_frame_for_edition(NativeControlEdition::Administration, &frame).unwrap();
        for length in 0..encoded.len() {
            assert!(
                decode_frame_for_edition(NativeControlEdition::Administration, &encoded[..length])
                    .is_err()
            );
        }
        let mut trailing = encoded;
        trailing.push(0);
        assert!(decode_frame_for_edition(NativeControlEdition::Administration, &trailing).is_err());
    }
    assert!(
        encode_frame_for_edition(
            NativeControlEdition::Administration,
            &NativeFrame::QueryAdministration {
                prepared_scope_hash: [0; 32],
                administration_commitment: [1; 32],
            }
        )
        .is_err()
    );
}

#[test]
fn prior_packet_kind_and_body_are_identical() {
    let prior = NativeFrame::QueryPreparationSuccessor(NativePreparationSuccessorQuery {
        prepared_scope_hash: [1; 32],
        initialization_sequence: crucible_node_contract::U64::new(1),
        original_cut_digest: [2; 32],
        offset: crucible_node_contract::U64::new(0),
    });
    let old = encode_frame_for_edition(NativeControlEdition::PreparationSuccessor, &prior).unwrap();
    let new = encode_frame_for_edition(NativeControlEdition::Administration, &prior).unwrap();
    assert_eq!(&old[..8], &new[..8]);
    assert_eq!(&old[10..], &new[10..]);
    assert_eq!(
        decode_frame_for_edition(NativeControlEdition::Administration, &new).unwrap(),
        prior
    );
}

#[test]
fn construction_lane_preserves_original_body_and_refuses_compute_header_substitution() {
    let query = NativeFrame::QueryPreparationSuccessor(NativePreparationSuccessorQuery {
        prepared_scope_hash: [1; 32],
        initialization_sequence: crucible_node_contract::U64::new(1),
        original_cut_digest: [2; 32],
        offset: crucible_node_contract::U64::new(0),
    });
    let historical =
        encode_frame_for_edition(NativeControlEdition::Administration, &query).unwrap();
    let construction =
        encode_frame_for_edition(NativeControlEdition::Construction, &query).unwrap();
    assert_eq!(&construction[8..10], &[0, 6]);
    assert_eq!(&historical[..8], &construction[..8]);
    assert_eq!(&historical[10..], &construction[10..]);
    assert_eq!(
        decode_frame_for_edition(NativeControlEdition::Construction, &construction).unwrap(),
        query
    );
    assert!(decode_frame_for_edition(NativeControlEdition::Administration, &construction).is_err());
    assert!(decode_frame_for_edition(NativeControlEdition::Construction, &historical).is_err());

    let preparation = super::administrative_preparation::test_preparation();
    let start = preparation.phase.initialization.preparation.boundary;
    let mut limit = start;
    limit.time_ps = crucible_node_contract::U64::new(start.time_ps.get() + 100);
    let hash = crucible_node_contract::HashRef {
        algorithm: "blake3-256".into(),
        domain: "cnp.input-batch.v1".into(),
        digest: "01".repeat(32),
    };
    let command = NativeFrame::Command(Box::new(ExecutionCommand {
        sequence: crucible_node_contract::U64::new(1),
        scope: preparation.phase.initialization.preparation.scope,
        operation: crucible_node_contract::Id::new("operation/1").unwrap(),
        grant: crucible_node_contract::Id::new("grant/1").unwrap(),
        input_epoch: crucible_node_contract::Id::new("epoch/1").unwrap(),
        input_batch: crucible_node_contract::Id::new("batch/1").unwrap(),
        input_batch_hash: hash,
        closed_input_prefix: limit,
        authorization_digest: [7; 32],
        kind: ExecutionKind::ExactRun {
            start,
            limit,
            boundary_policy: BoundaryPolicy::HorizonPark,
        },
    }));
    assert!(encode_frame_for_edition(NativeControlEdition::Construction, &command).is_err());
    let mut forged =
        encode_frame_for_edition(NativeControlEdition::Administration, &command).unwrap();
    forged[8..10].copy_from_slice(&NativeControlEdition::Construction.version().to_be_bytes());
    assert!(decode_frame_for_edition(NativeControlEdition::Construction, &forged).is_err());
}
