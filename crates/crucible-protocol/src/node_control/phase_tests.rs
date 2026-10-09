//! Closed phase policy and original preparation byte regressions, without native claims.

#![allow(clippy::unwrap_used)]

use crucible_node_contract::{Id, Phase, Position, U64};

use super::{NativePhaseMapping, NativePhasePolicy, NativePhasePreparation};

pub(super) fn original() -> NativePhasePreparation {
    NativePhasePreparation {
        initialization: super::super::initialization::test_preparation(),
        policy_digest: [5; 32],
        mapping: NativePhaseMapping::InstructionReaction,
        maximum_microstep: U64::new(9),
    }
}

#[test]
fn original_companion_bytes_and_fixed_policy_layout_remain_distinct() {
    let preparation = original();
    let companion = preparation.initialization.encode().unwrap();
    let encoded = preparation.encode().unwrap();

    assert_eq!(&encoded[..4], &(companion.len() as u32).to_be_bytes());
    assert_eq!(&encoded[4..4 + companion.len()], companion);
    assert_eq!(
        NativePhasePreparation::decode(&encoded).unwrap(),
        preparation
    );

    let policy = preparation.policy().unwrap();
    let bytes = policy.encode().unwrap();
    assert_eq!(bytes.len(), 152);
    assert_eq!(
        &bytes[..16],
        &[0, 0, 0, 1, 0, 0, 0, 152, 0, 0, 0, 1, 0, 0, 0, 0]
    );
    assert_eq!(&bytes[16..24], &9u64.to_be_bytes());
    assert_eq!(
        &bytes[24..56],
        &preparation
            .initialization
            .preparation
            .scope
            .identity_digest()
            .unwrap()
    );
    assert_eq!(&bytes[56..88], &preparation.identity_digest().unwrap());
    assert_eq!(&bytes[88..120], &[3; 32]);
    assert_eq!(&bytes[120..152], &[5; 32]);
    assert_eq!(NativePhasePolicy::decode(&bytes).unwrap(), policy);
}

#[test]
fn early_pin_is_exactly_140_bytes_with_native_little_endian_scalars() {
    let preparation = original();
    let pin = preparation.early_launch_argument().unwrap();

    assert_eq!(pin.len(), 283);
    assert!(pin.starts_with("v1:"));
    assert_eq!(&pin[259..], "010000000900000000000000");
    assert!(
        pin[3..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    );
}

#[test]
fn every_original_scope_realize_companion_and_policy_change_alters_pin() {
    let original = original();
    let expected = original.early_launch_argument().unwrap();
    let mut changes = Vec::new();
    for field in 0..9 {
        let mut changed = original.clone();
        let initialization = &mut changed.initialization;
        match field {
            0 => initialization.preparation.scope.session = Id::new("session/changed").unwrap(),
            1 => {
                initialization.preparation.scope.incarnation =
                    Id::new("incarnation/changed").unwrap()
            }
            2 => initialization.preparation.scope.owner_generation = U64::new(2),
            3 => initialization.preparation.maximum_commands = U64::new(5),
            4 => initialization.realize_operation = Id::new("realize/changed").unwrap(),
            5 => initialization.realize_request_digest[0] ^= 1,
            6 => initialization.policy_digest[0] ^= 1,
            7 => changed.policy_digest[0] ^= 1,
            _ => changed.maximum_microstep = U64::new(10),
        }
        changes.push(changed);
    }

    for changed in changes {
        assert_ne!(changed.early_launch_argument().unwrap(), expected);
        assert!(
            original
                .policy()
                .unwrap()
                .validate_against(&changed)
                .is_err()
        );
    }
}

#[test]
fn malformed_preparation_and_fixed_policy_bytes_are_refused_before_use() {
    let preparation = original().encode().unwrap();
    let policy = original().policy().unwrap().encode().unwrap();
    for length in 0..preparation.len() {
        assert!(NativePhasePreparation::decode(&preparation[..length]).is_err());
    }
    for length in 0..policy.len() {
        assert!(NativePhasePolicy::decode(&policy[..length]).is_err());
    }
    let mut trailing = preparation.clone();
    trailing.push(0);
    assert!(NativePhasePreparation::decode(&trailing).is_err());
    let mut excessive = preparation.clone();
    excessive[..4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(NativePhasePreparation::decode(&excessive).is_err());
    let mut open_mapping = preparation;
    let mapping = open_mapping.len() - 12;
    open_mapping[mapping..mapping + 4].copy_from_slice(&2u32.to_be_bytes());
    assert!(NativePhasePreparation::decode(&open_mapping).is_err());

    for (offset, value) in [(0, 2u32), (4, 151), (8, 0), (8, 2), (12, 1)] {
        let mut bytes = policy;
        bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        assert!(NativePhasePolicy::decode(&bytes).is_err());
    }
    for offset in [24, 56, 88, 120] {
        let mut bytes = policy;
        bytes[offset..offset + 32].fill(0);
        assert!(NativePhasePolicy::decode(&bytes).is_err());
    }
}

#[test]
fn fresh_only_preparation_refuses_late_cuts_and_unbounded_microsteps() {
    for field in 0..6 {
        let mut preparation = original();
        match field {
            0 => preparation.initialization.preparation.boundary.time_ps = U64::new(1),
            1 => preparation.initialization.preparation.boundary.microstep = U64::new(1),
            2 => preparation.initialization.preparation.boundary.phase = Phase::Reaction,
            3 => preparation.policy_digest = [0; 32],
            4 => preparation.maximum_microstep = U64::new(0),
            _ => preparation.maximum_microstep = U64::new(1_000_001),
        }
        assert!(preparation.encode().is_err());
        assert!(preparation.early_launch_argument().is_err());
    }
}

#[test]
fn finite_position_checks_preserve_full_phase_and_exclusive_microstep_count() {
    let mut preparation = original();
    preparation.maximum_microstep = U64::new(1);
    let policy = preparation.policy().unwrap();
    for phase in [
        Phase::BoundaryControl,
        Phase::Publication,
        Phase::Delivery,
        Phase::Reaction,
    ] {
        let position = Position::new(U64::new(10), U64::new(0), phase);
        assert!(policy.validate_position(position).is_ok());
        assert_eq!(position.phase, phase);
        assert!(
            policy
                .validate_position(Position {
                    microstep: U64::new(1),
                    ..position
                })
                .is_err()
        );
    }
    assert!(
        policy
            .validate_position(Position::new(
                U64::new(i64::MAX as u64 + 1),
                U64::new(0),
                Phase::BoundaryControl
            ))
            .is_err()
    );
}

#[test]
fn finite_same_time_ranges_preserve_full_endpoints_and_refuse_physical_progress() {
    let policy = original().policy().unwrap();
    let start = Position::new(U64::new(10), U64::new(0), Phase::Reaction);
    let limit = Position::new(U64::new(10), U64::new(1), Phase::Publication);

    assert!(policy.validate_same_time_range(start, limit).is_ok());
    assert_eq!(start.phase, Phase::Reaction);
    assert_eq!(limit.phase, Phase::Publication);
    assert!(policy.validate_same_time_range(limit, start).is_err());
    assert!(policy.validate_same_time_range(start, start).is_err());
    assert!(
        policy
            .validate_same_time_range(
                start,
                Position {
                    time_ps: U64::new(11),
                    ..limit
                }
            )
            .is_err()
    );
    assert!(
        policy
            .validate_same_time_range(
                start,
                Position {
                    microstep: policy.maximum_microstep,
                    ..limit
                }
            )
            .is_err()
    );
}
