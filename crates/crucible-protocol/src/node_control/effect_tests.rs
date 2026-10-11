//! Original finite command, empty-input and retained-prefix adversaries.

// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::node_control::{
    NativeControlEdition, NativeEffectCompute, NativeEffectProgress, NativeEffectProgressStatus,
    decode_frame_for_edition, encode_frame_for_edition,
};

fn compute() -> NativeEffectCompute {
    let mut command = command();
    let batch = crucible_node_contract::InputBatch {
        schema_version: 1,
        execution_owner_id: command.scope.owner.clone(),
        input_epoch: command.input_epoch.clone(),
        batch_id: command.input_batch.clone(),
        batch_sequence: U64::new(1),
        events: Vec::new(),
        extensions: Default::default(),
    };
    command.input_batch_hash = batch.identity().unwrap();
    NativeEffectCompute {
        command,
        effect_preparation: [8; 32],
        maximum_callbacks: 64,
        maximum_service_span: U64::new(1),
        input_batch_sequence: U64::new(1),
    }
}

fn progress(original: &NativeEffectCompute) -> NativeEffectProgress {
    let evaluated = Position {
        phase: Phase::Reaction,
        ..position(50)
    };
    NativeEffectProgress {
        scope: original.command.scope.identity_digest().unwrap(),
        effect_preparation: original.effect_preparation,
        grant_digest: original.command.authorization_digest,
        command_digest: original.command.identity_digest().unwrap(),
        sequence: original.command.sequence,
        cut_id: U64::new(1),
        raw_before: U64::new(0),
        raw_after: U64::new(1),
        evaluated,
        evaluation_id: U64::new(1),
        evaluation_generation: U64::new(17),
        resulting: evaluated,
        returned_service_count: U64::new(1),
        status: NativeEffectProgressStatus::PartialPrefix,
        end_result: 0,
    }
}

#[test]
fn effect_frames_preserve_original_command_and_exact_partial_result() {
    let original = compute();
    let result = progress(&original);
    result.validate_against(&original).unwrap();

    for frame in [
        NativeFrame::EffectCompute(Box::new(original)),
        NativeFrame::EffectProgress(Box::new(result)),
    ] {
        let bytes = encode_frame_for_edition(NativeControlEdition::FiniteEffect, &frame).unwrap();
        assert_eq!(
            decode_frame_for_edition(NativeControlEdition::FiniteEffect, &bytes).unwrap(),
            frame
        );
        for length in 0..bytes.len() {
            assert!(
                decode_frame_for_edition(NativeControlEdition::FiniteEffect, &bytes[..length])
                    .is_err()
            );
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(decode_frame_for_edition(NativeControlEdition::FiniteEffect, &trailing).is_err());
    }
}

#[test]
fn previous_editions_refuse_effect_records_even_with_substituted_header() {
    let frame = NativeFrame::EffectCompute(Box::new(compute()));
    let bytes = encode_frame_for_edition(NativeControlEdition::FiniteEffect, &frame).unwrap();
    for edition in [
        NativeControlEdition::Original,
        NativeControlEdition::OwnedCustody,
        NativeControlEdition::PhaseProjection,
        NativeControlEdition::PreparationSuccessor,
        NativeControlEdition::Administration,
        NativeControlEdition::Construction,
        NativeControlEdition::FixedMicrovm,
    ] {
        assert!(encode_frame_for_edition(edition, &frame).is_err());
        let mut forged = bytes.clone();
        forged[8..10].copy_from_slice(&edition.version().to_be_bytes());
        assert!(decode_frame_for_edition(edition, &forged).is_err());
    }
}

#[test]
fn original_complete_empty_batch_cannot_be_replaced_by_an_input_hash() {
    let original = compute();
    original.validate().unwrap();
    let mut changed = original.clone();
    changed.input_batch_sequence = U64::new(2);
    assert!(changed.validate().is_err());
    changed = original;
    changed.command.input_batch_hash.digest = "09".repeat(32);
    assert!(changed.validate().is_err());
}

#[test]
fn prefix_does_not_become_completion_or_exceed_its_original_service_budget() {
    let original = compute();
    let mut result = progress(&original);
    result.status = NativeEffectProgressStatus::Completed;
    assert!(result.validate_against(&original).is_err());
    result = progress(&original);
    result.raw_after = U64::new(2);
    result.returned_service_count = U64::new(2);
    assert!(result.validate_against(&original).is_err());
}

#[test]
fn original_unknown_counter_and_start_cursor_remain_exact_diagnostics() {
    let original = compute();
    let mut result = progress(&original);
    result.status = NativeEffectProgressStatus::EffectsUnknown;
    result.raw_before = U64::new(2);
    result.raw_after = U64::new(1);
    result.returned_service_count = U64::new(0);
    result.resulting = original.command.kind.start();
    result.end_result = -116;
    result.validate_against(&original).unwrap();
    assert_eq!(
        NativeEffectProgress::decode(&result.encode().unwrap()).unwrap(),
        result
    );

    result.status = NativeEffectProgressStatus::PartialPrefix;
    assert!(result.validate_against(&original).is_err());
}

#[test]
fn source_unknown_does_not_authorize_foreign_command_identity() {
    let original = compute();
    let mut result = progress(&original);
    result.status = NativeEffectProgressStatus::EffectsUnknown;
    result.command_digest[0] ^= 1;
    assert!(result.validate_against(&original).is_err());
}

#[test]
fn source_result_reserved_phase_status_and_flags_are_closed() {
    let bytes = progress(&compute()).encode().unwrap();
    assert_eq!(bytes.len(), 256);
    for (offset, value) in [(188, 1), (224, 9), (240, 9), (244, 1), (252, 1)] {
        let mut changed = bytes.clone();
        changed[offset..offset + 4].copy_from_slice(&u32::to_be_bytes(value));
        assert!(NativeEffectProgress::decode(&changed).is_err());
    }
}
