//! Initialization channel framing and immutable edition boundaries.

// crucible-lint: allow panic-shortcut -- These initialization frame tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used)]

use crucible_node_contract::U64;

use super::{NativeControlEdition, decode_frame_for_edition, encode_frame_for_edition};
use crate::node_control::{
    NativeFrame, NativeInitializationAcknowledgement, NativeInitializationCommand,
    NativeInitializationCut, NativeInitializationQuery, NativeInitializationReceipt,
    NativeInitializationStatus,
};

fn frames() -> Vec<NativeFrame> {
    let preparation = crate::node_control::initialization::test_preparation();
    let mut cut = NativeInitializationCut {
        hold_generation: U64::new(1),
        prepared_scope_hash: preparation.preparation.scope.identity_digest().unwrap(),
        initialization_commitment: preparation.identity_digest().unwrap(),
        original_cut_digest: [0; 32],
        rows: Vec::new(),
    };
    cut.original_cut_digest = cut.computed_digest().unwrap();
    let command = NativeInitializationCommand {
        sequence: U64::new(1),
        class_mask: preparation.class_mask,
        maximum_callbacks: preparation.maximum_callbacks,
        prepared_scope_hash: cut.prepared_scope_hash,
        initialization_commitment: cut.initialization_commitment,
        realize_request_digest: preparation.realize_request_digest,
        policy_digest: preparation.policy_digest,
        original_cut_digest: cut.original_cut_digest,
    };
    let receipt = NativeInitializationReceipt {
        status: NativeInitializationStatus::Applied,
        applied_callbacks: 0,
        sequence: command.sequence,
        hold_generation: cut.hold_generation,
        prepared_scope_hash: cut.prepared_scope_hash,
        initialization_commitment: cut.initialization_commitment,
        original_cut_digest: cut.original_cut_digest,
        realize_request_digest: preparation.realize_request_digest,
    };
    let acknowledgement = NativeInitializationAcknowledgement {
        prepared_scope_hash: cut.prepared_scope_hash,
        initialization_commitment: cut.initialization_commitment,
        sequence: command.sequence,
        command_digest: command.identity_digest().unwrap(),
    };
    vec![
        NativeFrame::PrepareInitialization(Box::new(preparation)),
        NativeFrame::QueryInitialization(NativeInitializationQuery {
            prepared_scope_hash: cut.prepared_scope_hash,
            initialization_commitment: cut.initialization_commitment,
        }),
        NativeFrame::InitializationCut(Box::new(cut)),
        NativeFrame::Initialize(Box::new(command)),
        NativeFrame::InitializationStopped(Box::new(receipt)),
        NativeFrame::AcknowledgeInitialization(acknowledgement.clone()),
        NativeFrame::InitializationAcknowledged(acknowledgement),
    ]
}

#[test]
fn original_edition_never_adopts_initialization_and_new_kinds_are_fixed() {
    for (kind, frame) in (14u16..=20).zip(frames()) {
        let encoded = encode_frame_for_edition(NativeControlEdition::OwnedCustody, &frame).unwrap();
        assert_eq!(&encoded[8..10], &[0, 2]);
        assert_eq!(&encoded[10..12], &kind.to_be_bytes());
        assert_eq!(
            decode_frame_for_edition(NativeControlEdition::OwnedCustody, &encoded).unwrap(),
            frame
        );
        assert!(encode_frame_for_edition(NativeControlEdition::Original, &frame).is_err());
        assert!(decode_frame_for_edition(NativeControlEdition::Original, &encoded).is_err());
        assert!(crate::node_control::encode_frame(&frame).is_err());
    }
}

#[test]
fn every_truncated_frame_trailing_byte_foreign_version_and_unknown_kind_is_refused() {
    for frame in frames() {
        let encoded = encode_frame_for_edition(NativeControlEdition::OwnedCustody, &frame).unwrap();
        for length in 0..encoded.len() {
            assert!(
                decode_frame_for_edition(NativeControlEdition::OwnedCustody, &encoded[..length])
                    .is_err()
            );
        }
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(decode_frame_for_edition(NativeControlEdition::OwnedCustody, &trailing).is_err());
        let mut changed = encoded.clone();
        changed[8..10].copy_from_slice(&3u16.to_be_bytes());
        assert!(decode_frame_for_edition(NativeControlEdition::OwnedCustody, &changed).is_err());
        let mut changed = encoded;
        changed[10..12].copy_from_slice(&21u16.to_be_bytes());
        assert!(decode_frame_for_edition(NativeControlEdition::OwnedCustody, &changed).is_err());
    }
}
