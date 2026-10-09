//! Closed root-policy bytes and finite pre-effect bounds, without native qualification.

// crucible-lint: allow panic-shortcut -- Test-only codec assertions panic on malformed original policy acceptance.
#![allow(clippy::unwrap_used)]

use super::*;

fn preparation() -> NativeFixedMicrovmPreparation {
    let mut administration = super::super::administrative_preparation::test_preparation();
    administration.phase.maximum_microstep = U64::new(1024);
    NativeFixedMicrovmPreparation {
        administration,
        policy_digest: [19; 32],
        firmware_sha256: [37; 32],
        firmware_length: U64::new(64 * 1024),
        ram_length: U64::new(32 * 1024 * 1024),
        seed: U64::new(8254),
        maximum_microstep: U64::new(1024),
        maximum_service_span: U64::new(1_000_000),
        mapping: NativeFixedMicrovmMapping::InstructionThenTimers,
        maximum_callbacks: 64,
    }
}

#[test]
fn closed_original_companions_and_every_pin_offset_round_trip() {
    let preparation = preparation();
    let original = preparation.administration.encode().unwrap();
    let encoded = preparation.encode().unwrap();
    assert_eq!(&encoded[..8], b"CNMICR01");
    assert_eq!(&encoded[12..12 + original.len()], &original);
    assert_eq!(
        NativeFixedMicrovmPreparation::decode(&encoded).unwrap(),
        preparation
    );
    let pin = preparation.early_pin().unwrap();
    let phase = &preparation.administration.phase;
    let digests = [
        phase
            .initialization
            .preparation
            .scope
            .identity_digest()
            .unwrap(),
        preparation.identity_digest().unwrap(),
        phase.initialization.realize_request_digest,
        preparation.policy_digest,
        phase.initialization.identity_digest().unwrap(),
        phase.identity_digest().unwrap(),
        preparation.administration.identity_digest().unwrap(),
        preparation.firmware_sha256,
    ];
    for (index, digest) in digests.iter().enumerate() {
        assert_eq!(&pin[index * 32..(index + 1) * 32], digest);
    }
    for (index, value) in [64 * 1024u64, 32 * 1024 * 1024, 8254, 1024, 1_000_000]
        .iter()
        .enumerate()
    {
        assert_eq!(&pin[256 + index * 8..264 + index * 8], &value.to_le_bytes());
    }
    for (index, value) in [2u32, 7, 1, 1, 64, 0].iter().enumerate() {
        assert_eq!(&pin[296 + index * 4..300 + index * 4], &value.to_le_bytes());
    }
    let policy = preparation.native_policy().unwrap();
    assert_eq!(&policy[..8], &[1, 0, 0, 0, 72, 1, 0, 0]);
    assert_eq!(&policy[8..], &pin);
    let argument = preparation.early_launch_argument().unwrap();
    assert_eq!(argument.len(), 643);
    assert!(argument.starts_with("v1:"));
    assert!(
        argument[3..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
}

#[test]
fn every_truncation_trailing_byte_unknown_mapping_and_hostile_extent_is_refused() {
    let encoded = preparation().encode().unwrap();
    for length in 0..encoded.len() {
        assert!(NativeFixedMicrovmPreparation::decode(&encoded[..length]).is_err());
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(NativeFixedMicrovmPreparation::decode(&trailing).is_err());
    let mut hostile_extent = encoded.clone();
    hostile_extent[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(NativeFixedMicrovmPreparation::decode(&hostile_extent).is_err());
    let mut unknown = encoded;
    let mapping_offset = unknown.len() - 8;
    unknown[mapping_offset..mapping_offset + 4].copy_from_slice(&1u32.to_be_bytes());
    assert!(NativeFixedMicrovmPreparation::decode(&unknown).is_err());
}

#[test]
fn finite_native_policy_ceilings_are_checked_before_any_source_call() {
    let original = preparation();
    for invalid in [0, 64 * 1024 - 1, 16 * 1024 * 1024 + 1, u64::MAX] {
        let mut changed = original.clone();
        changed.firmware_length = U64::new(invalid);
        assert!(changed.early_pin().is_err());
    }
    for invalid in [
        0,
        16 * 1024 * 1024 - 1,
        3 * 1024 * 1024 * 1024 + 1,
        u64::MAX,
    ] {
        let mut changed = original.clone();
        changed.ram_length = U64::new(invalid);
        assert!(changed.encode().is_err());
    }
    for invalid in [0, MAXIMUM_MICROSTEP + 1, u64::MAX] {
        let mut changed = original.clone();
        changed.maximum_microstep = U64::new(invalid);
        assert!(changed.native_policy().is_err());
    }
    for invalid in [0, MAXIMUM_SERVICE_SPAN + 1, u64::MAX] {
        let mut changed = original.clone();
        changed.maximum_service_span = U64::new(invalid);
        assert!(changed.encode().is_err());
    }
    for invalid in [0, 65, u32::MAX] {
        let mut changed = original.clone();
        changed.maximum_callbacks = invalid;
        assert!(changed.native_policy().is_err());
    }
}

#[test]
fn all_measurements_policy_and_original_companions_contribute_to_commitment() {
    let original = preparation();
    let digest = original.identity_digest().unwrap();
    let mut variations = Vec::new();
    let mut changed = original.clone();
    changed.firmware_sha256[0] ^= 1;
    variations.push(changed);
    let mut changed = original.clone();
    changed.policy_digest[0] ^= 1;
    variations.push(changed);
    let mut changed = original.clone();
    changed.seed = U64::new(0);
    variations.push(changed);
    let mut changed = original.clone();
    changed.maximum_callbacks = 1;
    variations.push(changed);
    let mut changed = original.clone();
    changed.maximum_microstep = U64::new(1);
    changed.administration.phase.maximum_microstep = U64::new(1);
    variations.push(changed);
    let mut changed = original.clone();
    changed.maximum_service_span = U64::new(1);
    variations.push(changed);
    let mut changed = original.clone();
    changed.firmware_length = U64::new(16 * 1024 * 1024);
    variations.push(changed);
    let mut changed = original.clone();
    changed.ram_length = U64::new(3 * 1024 * 1024 * 1024);
    variations.push(changed);
    let mut changed = original.clone();
    changed.administration.socket_inode += 1;
    variations.push(changed);
    let mut changed = original.clone();
    changed
        .administration
        .phase
        .initialization
        .realize_request_digest[0] ^= 1;
    variations.push(changed);
    for changed in variations {
        assert_ne!(changed.identity_digest().unwrap(), digest);
    }
    let mut missing = original;
    missing.firmware_sha256 = [0; 32];
    assert!(missing.encode().is_err());
}

#[test]
fn contradictory_original_phase_ceiling_refuses_before_native_construction() {
    let mut changed = preparation();
    changed.administration.phase.maximum_microstep = U64::new(1023);
    assert!(changed.encode().is_err());
    assert!(changed.early_pin().is_err());
}

#[test]
fn complete_root_bootstrap_requires_edition_seven_and_cannot_forge_old_compute() {
    use super::super::{
        NativeControlEdition, NativeFrame, decode_frame_for_edition, encode_frame_for_edition,
    };
    let frame = NativeFrame::PrepareFixedMicrovm(Box::new(preparation()));
    let bytes = encode_frame_for_edition(NativeControlEdition::FixedMicrovm, &frame).unwrap();
    assert_eq!(&bytes[8..12], &[0, 7, 0, 29]);
    assert_eq!(&bytes[16..], &preparation().encode().unwrap());
    assert_eq!(
        decode_frame_for_edition(NativeControlEdition::FixedMicrovm, &bytes).unwrap(),
        frame
    );
    for prior in [
        NativeControlEdition::Original,
        NativeControlEdition::OwnedCustody,
        NativeControlEdition::PhaseProjection,
        NativeControlEdition::PreparationSuccessor,
        NativeControlEdition::Administration,
        NativeControlEdition::Construction,
    ] {
        assert!(encode_frame_for_edition(prior, &frame).is_err());
        let mut downgraded = bytes.clone();
        downgraded[8..10].copy_from_slice(&prior.version().to_be_bytes());
        assert!(decode_frame_for_edition(prior, &downgraded).is_err());
    }
    for length in 0..bytes.len() {
        assert!(
            decode_frame_for_edition(NativeControlEdition::FixedMicrovm, &bytes[..length]).is_err()
        );
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert!(decode_frame_for_edition(NativeControlEdition::FixedMicrovm, &trailing).is_err());

    // A rewritten header cannot import the broad legacy compute lane. This
    // record uses its genuine prior encoder, not a hand-authored forged body.
    let id = |value| crucible_node_contract::Id::new(value).unwrap();
    let position = |time| crucible_node_contract::Position {
        time_ps: U64::new(time),
        microstep: U64::new(0),
        phase: crucible_node_contract::Phase::BoundaryControl,
    };
    let command = super::super::ExecutionCommand {
        sequence: U64::new(1),
        scope: preparation()
            .administration
            .phase
            .initialization
            .preparation
            .scope,
        operation: id("original/operation"),
        grant: id("original/grant"),
        input_epoch: id("original/epoch"),
        input_batch: id("original/batch"),
        input_batch_hash: crucible_node_contract::HashRef {
            algorithm: "blake3-256".into(),
            domain: "cnp.input-batch.v1".into(),
            digest: "01".repeat(32),
        },
        closed_input_prefix: position(200),
        authorization_digest: [9; 32],
        kind: super::super::ExecutionKind::ExactRun {
            start: position(0),
            limit: position(200),
            boundary_policy: super::super::BoundaryPolicy::HorizonPark,
        },
    };
    let frame = NativeFrame::Command(Box::new(command));
    assert!(encode_frame_for_edition(NativeControlEdition::FixedMicrovm, &frame).is_err());
    let mut old = super::super::encode_frame(&frame).unwrap();
    old[8..10].copy_from_slice(&NativeControlEdition::FixedMicrovm.version().to_be_bytes());
    assert!(decode_frame_for_edition(NativeControlEdition::FixedMicrovm, &old).is_err());
}

#[test]
fn fixed_bootstrap_preserves_prior_query_bytes_but_requires_whole_preparation() {
    use super::super::{
        NativeControlEdition, NativeFrame, decode_frame_for_edition, encode_frame_for_edition,
    };
    let frame = NativeFrame::QueryAdministration {
        prepared_scope_hash: [7; 32],
        administration_commitment: [8; 32],
    };
    let previous = encode_frame_for_edition(NativeControlEdition::Construction, &frame).unwrap();
    let current = encode_frame_for_edition(NativeControlEdition::FixedMicrovm, &frame).unwrap();
    assert_eq!(&previous[..8], &current[..8]);
    assert_eq!(&previous[10..], &current[10..]);
    assert_eq!(
        decode_frame_for_edition(NativeControlEdition::FixedMicrovm, &current).unwrap(),
        frame
    );

    let partial = NativeFrame::PrepareAdministration(Box::new(preparation().administration));
    assert!(encode_frame_for_edition(NativeControlEdition::FixedMicrovm, &partial).is_err());
    let mut previous =
        encode_frame_for_edition(NativeControlEdition::Construction, &partial).unwrap();
    previous[8..10].copy_from_slice(&NativeControlEdition::FixedMicrovm.version().to_be_bytes());
    assert!(decode_frame_for_edition(NativeControlEdition::FixedMicrovm, &previous).is_err());
}
