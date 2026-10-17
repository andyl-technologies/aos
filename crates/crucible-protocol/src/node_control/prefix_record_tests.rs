//! Typed CPU/timer prefix counts, exact history links and canonical ACK controls.

// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::node_control::{
    NativeEffectCompute, NativeEffectProgress, NativeEffectProgressStatus,
    NativePrefixAcknowledgement, NativePrefixContinuation, NativePrefixEvaluationKind,
    NativePrefixProgress,
};
use sha2::{Digest, Sha256};

fn original() -> NativeEffectCompute {
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
        effect_preparation: [9; 32],
        maximum_callbacks: 2,
        maximum_service_span: U64::new(1),
        input_batch_sequence: U64::new(1),
    }
}

fn initial(original: &NativeEffectCompute) -> NativeEffectProgress {
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
        evaluation_generation: U64::new(26),
        resulting: evaluated,
        returned_service_count: U64::new(1),
        status: NativeEffectProgressStatus::PartialPrefix,
        end_result: 0,
    }
}

fn timer(original: &NativeEffectCompute) -> NativePrefixProgress {
    let previous = initial(original);
    NativePrefixProgress {
        scope: previous.scope,
        prefix_preparation: previous.effect_preparation,
        grant_digest: previous.grant_digest,
        command_digest: previous.command_digest,
        sequence: previous.sequence,
        cut_id: U64::new(2),
        previous_cut_id: previous.cut_id,
        acknowledgement_sequence: U64::new(1),
        raw_before: previous.raw_after,
        raw_after: previous.raw_after,
        evaluated: Position {
            phase: Phase::Reaction,
            ..position(60)
        },
        evaluation_kind: NativePrefixEvaluationKind::TimerCallback,
        parent_kind: None,
        evaluation_id: U64::new(7),
        evaluation_generation: U64::new(3),
        parent_id: U64::new(0),
        parent_generation: U64::new(0),
        resulting: Position {
            phase: Phase::Reaction,
            ..position(60)
        },
        cpu_retirements: U64::new(0),
        timer_callbacks: U64::new(1),
        cumulative_cpu_retirements: U64::new(1),
        cumulative_timer_callbacks: U64::new(1),
        status: NativeEffectProgressStatus::PartialPrefix,
        end_result: 0,
    }
}

#[test]
fn quiet_cpu_prefix_correlates_multiple_retirements_without_renewing_allowance() {
    let mut original = original();
    original.maximum_service_span = U64::new(4);
    original.command.closed_input_prefix = position(350);
    original.command.kind = ExecutionKind::ExactRun {
        start: position(0),
        limit: position(350),
        boundary_policy: BoundaryPolicy::HorizonPark,
    };
    let previous = initial(&original);
    let mut prefix = timer(&original);
    prefix.evaluation_kind = NativePrefixEvaluationKind::CpuService;
    prefix.evaluation_id = previous.evaluation_id;
    prefix.evaluation_generation = previous.evaluation_generation;
    prefix.raw_after = U64::new(4);
    prefix.cpu_retirements = U64::new(3);
    prefix.timer_callbacks = U64::new(0);
    prefix.cumulative_cpu_retirements = U64::new(4);
    prefix.cumulative_timer_callbacks = U64::new(0);
    prefix.evaluated = Position {
        phase: Phase::Reaction,
        ..position(100)
    };
    prefix.resulting = Position {
        phase: Phase::Reaction,
        ..position(200)
    };

    prefix.validate_after_initial(&original, &previous).unwrap();
    let encoded = prefix.encode().unwrap();
    assert_eq!(encoded.len(), 320);
    assert_eq!(NativePrefixProgress::decode(&encoded).unwrap(), prefix);

    let mut renewed = prefix.clone();
    renewed.raw_after = U64::new(5);
    renewed.cpu_retirements = U64::new(4);
    renewed.cumulative_cpu_retirements = U64::new(5);
    assert!(
        renewed
            .validate_after_initial(&original, &previous)
            .is_err()
    );

    let mut dropped_history = prefix;
    dropped_history.cumulative_cpu_retirements = U64::new(3);
    assert!(
        dropped_history
            .validate_after_initial(&original, &previous)
            .is_err()
    );
}

#[test]
fn timer_prefix_preserves_effects_with_unchanged_raw_and_exhausted_cpu_allowance() {
    let original = original();
    let previous = initial(&original);
    let prefix = timer(&original);

    prefix.validate_after_initial(&original, &previous).unwrap();
    assert_eq!(prefix.cpu_retirements.get(), 0);
    assert_eq!(prefix.timer_callbacks.get(), 1);
    assert_eq!(prefix.raw_before, prefix.raw_after);
    let bytes = prefix.encode().unwrap();
    assert_eq!(bytes.len(), 320);
    assert_eq!(&bytes[208..216], &[0, 0, 0, 2, 0, 0, 0, 0]);
    assert_eq!(NativePrefixProgress::decode(&bytes).unwrap(), prefix);

    let mut renewed_cpu = prefix;
    renewed_cpu.evaluation_kind = NativePrefixEvaluationKind::CpuService;
    renewed_cpu.cpu_retirements = U64::new(1);
    renewed_cpu.timer_callbacks = U64::new(0);
    renewed_cpu.cumulative_cpu_retirements = U64::new(2);
    renewed_cpu.cumulative_timer_callbacks = U64::new(0);
    renewed_cpu.raw_after = U64::new(2);
    assert!(
        renewed_cpu
            .validate_after_initial(&original, &previous)
            .is_err()
    );
}

#[test]
fn typed_history_rejects_foreign_links_and_renewed_callback_counts() {
    let original = original();
    let previous = timer(&original);
    let mut next = previous.clone();
    next.cut_id = U64::new(3);
    next.previous_cut_id = previous.cut_id;
    next.acknowledgement_sequence = U64::new(2);
    next.cumulative_timer_callbacks = U64::new(2);
    next.evaluated.microstep = U64::new(1);
    next.resulting = next.evaluated;
    next.parent_kind = Some(NativePrefixEvaluationKind::TimerCallback);
    next.parent_id = previous.evaluation_id;
    next.parent_generation = previous.evaluation_generation;
    next.validate_after_progress(&original, &previous).unwrap();

    for field in 0..7 {
        let mut foreign = next.clone();
        match field {
            0 => foreign.previous_cut_id = U64::new(7),
            1 => foreign.acknowledgement_sequence = U64::new(1),
            2 => foreign.raw_before = U64::new(0),
            3 => foreign.cumulative_cpu_retirements = U64::new(0),
            4 => foreign.cumulative_timer_callbacks = U64::new(1),
            5 => foreign.cumulative_timer_callbacks = U64::new(3),
            _ => foreign.command_digest[0] ^= 1,
        }
        assert!(
            foreign
                .validate_after_progress(&original, &previous)
                .is_err(),
            "field {field}"
        );
    }
    for status in [
        NativeEffectProgressStatus::Completed,
        NativeEffectProgressStatus::EffectsUnknown,
    ] {
        let mut terminal = previous.clone();
        terminal.status = status;
        if status == NativeEffectProgressStatus::Completed {
            terminal.resulting = original.command.kind.limit();
        }
        assert!(next.validate_after_progress(&original, &terminal).is_err());
    }
}

#[test]
fn original_ack_domains_and_versions_preserve_exact_history_and_cursor() {
    let original = original();
    let initial = initial(&original);
    let prefix = timer(&original);
    let first = NativePrefixAcknowledgement::from_initial(&initial).unwrap();
    let second = NativePrefixAcknowledgement::from_progress(&prefix).unwrap();

    let mut initial_hash = Sha256::new();
    initial_hash.update(b"crucible.native-effect-prefix.v1\0");
    initial_hash.update(initial.encode().unwrap());
    assert_eq!(
        first.result_digest,
        <[u8; 32]>::from(initial_hash.finalize())
    );
    let mut typed_hash = Sha256::new();
    typed_hash.update(b"crucible.native-effect-prefix.v2\0");
    typed_hash.update(prefix.encode().unwrap());
    assert_eq!(
        second.result_digest,
        <[u8; 32]>::from(typed_hash.finalize())
    );
    assert_eq!(first.acknowledgement_sequence.get(), 1);
    assert_eq!(second.acknowledgement_sequence.get(), 2);
    assert!(first.validate_progress(&prefix).is_err());
    assert!(second.validate_initial(&initial).is_err());

    for acknowledgement in [first, second] {
        let continuation = NativePrefixContinuation {
            acknowledgement,
            expected_cursor: prefix.resulting,
        };
        let bytes = continuation.encode().unwrap();
        assert_eq!(bytes.len(), 216);
        assert_eq!(
            NativePrefixContinuation::decode(&bytes).unwrap(),
            continuation
        );
    }
}

#[test]
fn changed_ack_correlation_never_matches_the_original_source_history() {
    let original = original();
    let prefix = timer(&original);
    let acknowledgement = NativePrefixAcknowledgement::from_progress(&prefix).unwrap();

    for field in 0..9 {
        let mut changed = acknowledgement.clone();
        match field {
            0 => changed.result_version = 1,
            1 => changed.scope[0] ^= 1,
            2 => changed.prefix_preparation[0] ^= 1,
            3 => changed.grant_digest[0] ^= 1,
            4 => changed.command_digest[0] ^= 1,
            5 => changed.result_digest[0] ^= 1,
            6 => changed.sequence = U64::new(2),
            7 => changed.cut_id = U64::new(3),
            _ => changed.acknowledgement_sequence = U64::new(3),
        }
        assert!(changed.validate_progress(&prefix).is_err(), "field {field}");
    }
}

#[test]
fn prefix_records_reject_every_truncation_trailing_and_reserved_field() {
    let original = original();
    let prefix = timer(&original);
    let result_bytes = prefix.encode().unwrap();
    let acknowledgement = NativePrefixAcknowledgement::from_progress(&prefix).unwrap();
    let ack_bytes = acknowledgement.encode().unwrap();
    let continuation = NativePrefixContinuation {
        acknowledgement,
        expected_cursor: prefix.resulting,
    };
    let continue_bytes = continuation.encode().unwrap();

    for length in 0..result_bytes.len() {
        assert!(NativePrefixProgress::decode(&result_bytes[..length]).is_err());
    }
    for length in 0..ack_bytes.len() {
        assert!(NativePrefixAcknowledgement::decode(&ack_bytes[..length]).is_err());
    }
    for length in 0..continue_bytes.len() {
        assert!(NativePrefixContinuation::decode(&continue_bytes[..length]).is_err());
    }
    for offset in [4, 207, 211, 215, 271, 311, 319] {
        let mut changed = result_bytes.clone();
        changed[offset] ^= 1;
        assert!(
            NativePrefixProgress::decode(&changed).is_err(),
            "offset {offset}"
        );
    }
    let mut trailing = result_bytes;
    trailing.push(0);
    assert!(NativePrefixProgress::decode(&trailing).is_err());
    let mut trailing = ack_bytes;
    trailing.push(0);
    assert!(NativePrefixAcknowledgement::decode(&trailing).is_err());
    let mut trailing = continue_bytes;
    trailing.push(0);
    assert!(NativePrefixContinuation::decode(&trailing).is_err());
}

#[test]
fn independent_python_be_and_sha_vectors_match_closed_native_record_offsets() {
    fn vector(name: &str) -> Vec<u8> {
        let hex = include_str!("prefix_record_vectors.txt")
            .lines()
            .filter_map(|line| line.split_once('\t'))
            .find_map(|(key, value)| (key == name).then_some(value))
            .unwrap();
        let (pairs, remainder) = hex.as_bytes().as_chunks::<2>();
        assert!(remainder.is_empty());
        pairs
            .iter()
            .map(|pair| {
                let text = std::str::from_utf8(pair).unwrap();
                u8::from_str_radix(text, 16).unwrap()
            })
            .collect()
    }

    let initial_bytes = vector("result256_hex");
    let typed_bytes = vector("result320_hex");
    let initial = NativeEffectProgress::decode(&initial_bytes).unwrap();
    let typed = NativePrefixProgress::decode(&typed_bytes).unwrap();

    assert_eq!(initial.encode().unwrap(), initial_bytes);
    assert_eq!(typed.encode().unwrap(), typed_bytes);
    assert_eq!(
        typed.evaluation_kind,
        NativePrefixEvaluationKind::TimerCallback
    );
    assert_eq!(typed.evaluated.time_ps.get(), 60);
    assert_eq!(typed.evaluated.microstep.get(), 0);
    assert_eq!(typed.previous_cut_id.get(), 1);
    assert_eq!(typed.cpu_retirements.get(), 0);
    assert_eq!(typed.timer_callbacks.get(), 1);
    assert_eq!(
        typed.identity_digest().unwrap().as_slice(),
        vector("result320_sha256")
    );

    let first = NativePrefixAcknowledgement::from_initial(&initial).unwrap();
    let second = NativePrefixAcknowledgement::from_progress(&typed).unwrap();
    assert_eq!(first.result_digest.as_slice(), vector("result256_sha256"));
    assert_eq!(first.encode().unwrap(), vector("ack1_hex"));
    assert_eq!(second.encode().unwrap(), vector("ack2_hex"));
}

#[test]
fn continuation_keeps_the_exact_acknowledged_cursor_and_refuses_terminal_history() {
    let original = original();
    let previous = timer(&original);
    let continuation = NativePrefixContinuation {
        acknowledgement: NativePrefixAcknowledgement::from_progress(&previous).unwrap(),
        expected_cursor: previous.resulting,
    };

    continuation.validate_progress(&previous).unwrap();
    let mut foreign_cursor = continuation.clone();
    foreign_cursor.expected_cursor.microstep = U64::new(1);
    assert!(foreign_cursor.validate_progress(&previous).is_err());

    for status in [
        NativeEffectProgressStatus::Completed,
        NativeEffectProgressStatus::EffectsUnknown,
    ] {
        let mut terminal = previous.clone();
        terminal.status = status;
        let offered = NativePrefixContinuation {
            acknowledgement: NativePrefixAcknowledgement::from_progress(&terminal).unwrap(),
            expected_cursor: terminal.resulting,
        };
        assert!(offered.validate_progress(&terminal).is_err());
    }
}

#[test]
fn prefix_envelope_is_explicit_and_prior_endpoints_refuse_every_new_record() {
    use crate::node_control::{
        NativeControlEdition, NativeFrame, decode_frame_for_edition, encode_frame_for_edition,
    };

    let original = original();
    let prefix = timer(&original);
    let acknowledgement = NativePrefixAcknowledgement::from_progress(&prefix).unwrap();
    let continuation = NativePrefixContinuation {
        acknowledgement: acknowledgement.clone(),
        expected_cursor: prefix.resulting,
    };
    for frame in [
        NativeFrame::AcknowledgePrefix(acknowledgement.clone()),
        NativeFrame::PrefixAcknowledged(acknowledgement),
        NativeFrame::ContinuePrefix(Box::new(continuation)),
        NativeFrame::PrefixProgress(Box::new(prefix)),
    ] {
        let bytes = encode_frame_for_edition(NativeControlEdition::PrefixEffect, &frame).unwrap();
        assert_eq!(
            decode_frame_for_edition(NativeControlEdition::PrefixEffect, &bytes).unwrap(),
            frame
        );
        for edition in [
            NativeControlEdition::Original,
            NativeControlEdition::OwnedCustody,
            NativeControlEdition::PhaseProjection,
            NativeControlEdition::PreparationSuccessor,
            NativeControlEdition::Administration,
            NativeControlEdition::Construction,
            NativeControlEdition::FixedMicrovm,
            NativeControlEdition::FiniteEffect,
        ] {
            assert!(encode_frame_for_edition(edition, &frame).is_err());
            assert!(decode_frame_for_edition(edition, &bytes).is_err());
            let mut substituted = bytes.clone();
            substituted[8..10].copy_from_slice(&edition.version().to_be_bytes());
            assert!(decode_frame_for_edition(edition, &substituted).is_err());
        }
    }

    let initial = NativeFrame::EffectProgress(Box::new(initial(&original)));
    let old = encode_frame_for_edition(NativeControlEdition::FiniteEffect, &initial).unwrap();
    let prefix = encode_frame_for_edition(NativeControlEdition::PrefixEffect, &initial).unwrap();
    assert_eq!(&old[..8], &prefix[..8]);
    assert_eq!(&old[10..], &prefix[10..]);
    assert_eq!(
        decode_frame_for_edition(NativeControlEdition::PrefixEffect, &prefix).unwrap(),
        initial
    );
}
