//! Adversarial codecs for original construction preparation, without native claims.

// crucible-lint: allow panic-shortcut -- These initialization tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used)]

use crucible_node_contract::{HashRef, Id, Phase, Position, U64};

use super::NativeInitializationPreparation;
use crate::node_control::{NativeFrame, NativePreparation, OwnerScope};

pub(super) fn original() -> NativeInitializationPreparation {
    NativeInitializationPreparation {
        preparation: NativePreparation {
            scope: OwnerScope {
                session: Id::new("session/model").unwrap(),
                incarnation: Id::new("incarnation/model").unwrap(),
                activation: Id::new("activation/model").unwrap(),
                node: Id::new("node/model").unwrap(),
                owner: Id::new("owner/model").unwrap(),
                world_generation: U64::new(1),
                owner_generation: U64::new(1),
                world_binding: HashRef {
                    algorithm: "blake3-256".into(),
                    domain: "cnp.world-binding.v1".into(),
                    digest: "01".repeat(32),
                },
                owner_binding: HashRef {
                    algorithm: "blake3-256".into(),
                    domain: "cnp.owner-binding.v1".into(),
                    digest: "02".repeat(32),
                },
            },
            boundary: Position {
                time_ps: U64::new(0),
                microstep: U64::new(0),
                phase: Phase::BoundaryControl,
            },
            maximum_commands: U64::new(4),
        },
        realize_operation: Id::new("operation/realize-model").unwrap(),
        realize_request_digest: [3; 32],
        policy_digest: [4; 32],
        class_mask: 7,
        maximum_callbacks: 64,
    }
}

#[test]
fn early_source_pin_is_fixed_width_and_binds_all_original_fields_before_launch() {
    let preparation = original();
    let argument = preparation.early_launch_argument().unwrap();

    assert_eq!(argument.len(), 275);
    assert!(argument.starts_with("v1:"));
    assert_eq!(&argument[259..], "0700000040000000");
    assert!(
        argument[3..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    );

    let mut changed = preparation;
    changed.realize_request_digest[0] ^= 1;
    assert_ne!(changed.early_launch_argument().unwrap(), argument);
}

#[test]
fn preparation_preserves_original_version_one_bytes_and_bound_fields() {
    let preparation = original();
    let encoded = preparation.encode().unwrap();
    let legacy = crate::node_control::encode_frame(&NativeFrame::Prepare(Box::new(
        preparation.preparation.clone(),
    )))
    .unwrap();

    assert_eq!(&encoded[..4], &(legacy.len() as u32).to_be_bytes());
    assert_eq!(&encoded[4..4 + legacy.len()], legacy);
    assert_eq!(
        NativeInitializationPreparation::decode(&encoded).unwrap(),
        preparation
    );
    assert_eq!(&encoded[encoded.len() - 8..], &[0, 0, 0, 7, 0, 0, 0, 64]);
}

#[test]
fn every_truncation_trailing_byte_and_oversized_length_is_refused() {
    let encoded = original().encode().unwrap();
    for length in 0..encoded.len() {
        assert!(NativeInitializationPreparation::decode(&encoded[..length]).is_err());
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(NativeInitializationPreparation::decode(&trailing).is_err());

    let mut excessive = encoded;
    excessive[..4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(NativeInitializationPreparation::decode(&excessive).is_err());
}

#[test]
fn changed_original_realize_policy_scope_and_allowance_change_launch_commitment() {
    let preparation = original();
    let expected = preparation.identity_digest().unwrap();
    let mut changes = Vec::new();
    let mut changed = preparation.clone();
    changed.realize_operation = Id::new("operation/another-model").unwrap();
    changes.push(changed);
    let mut changed = preparation.clone();
    changed.realize_request_digest[0] ^= 1;
    changes.push(changed);
    let mut changed = preparation.clone();
    changed.policy_digest[0] ^= 1;
    changes.push(changed);
    let mut changed = preparation.clone();
    changed.preparation.scope.owner_generation = U64::new(2);
    changes.push(changed);
    let mut changed = preparation.clone();
    changed.preparation.maximum_commands = U64::new(5);
    changes.push(changed);
    let mut changed = preparation.clone();
    changed.class_mask = 1;
    changes.push(changed);
    let mut changed = preparation;
    changed.maximum_callbacks = 1;
    changes.push(changed);

    for changed in changes {
        assert_ne!(changed.identity_digest().unwrap(), expected);
    }
}

#[test]
fn restored_cuts_noncontrol_phases_and_open_policies_are_refused() {
    for field in 0..8 {
        let mut preparation = original();
        match field {
            0 => preparation.preparation.boundary.time_ps = U64::new(1),
            1 => preparation.preparation.boundary.microstep = U64::new(1),
            2 => preparation.preparation.boundary.phase = Phase::Reaction,
            3 => preparation.realize_request_digest = [0; 32],
            4 => preparation.policy_digest = [0; 32],
            5 => preparation.class_mask = 8,
            6 => preparation.maximum_callbacks = 0,
            _ => preparation.maximum_callbacks = 65,
        }
        assert!(preparation.encode().is_err());
    }
}
