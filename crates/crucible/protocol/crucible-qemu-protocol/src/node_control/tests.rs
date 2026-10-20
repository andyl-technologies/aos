//! Adversarial framing, original identity and retained native custody tests.

use super::*;
use crate::node_control::NativeCpuParkFacts;
use crate::node_control::{
    CommandJournal, CommandJournalDisposition, NativeFrame, NativePreparation,
    ReceiptAcknowledgement, decode_frame, encode_frame,
};

fn id(text: &str) -> Id {
    Id::new(text).unwrap()
}
fn hash(domain: &str) -> HashRef {
    HashRef {
        algorithm: "blake3-256".into(),
        domain: domain.into(),
        digest: "01".repeat(32),
    }
}
fn position(time: u64) -> Position {
    Position {
        time_ps: U64::new(time),
        microstep: U64::new(0),
        phase: Phase::BoundaryControl,
    }
}
fn command() -> ExecutionCommand {
    ExecutionCommand {
        sequence: U64::new(1),
        scope: OwnerScope {
            session: id("session/a"),
            incarnation: id("incarnation/a"),
            activation: id("activation/1"),
            node: id("machine/a"),
            owner: id("owner/a"),
            world_generation: U64::new(1),
            owner_generation: U64::new(3),
            world_binding: hash("cnp.world-binding.v1"),
            owner_binding: hash("cnp.owner-binding.v1"),
        },
        operation: id("operation/1"),
        grant: id("grant/1"),
        input_epoch: id("input/epoch"),
        input_batch: id("batch/1"),
        input_batch_hash: hash("cnp.input-batch.v1"),
        closed_input_prefix: position(100),
        authorization_digest: [7; 32],
        kind: ExecutionKind::ExactRun {
            start: position(0),
            limit: position(100),
            boundary_policy: BoundaryPolicy::HorizonPark,
        },
    }
}

#[test]
fn framing_preserves_all_authority_scope_and_exclusive_coordinates() {
    let original = command();
    let encoded = encode_command(&original).unwrap();
    assert_eq!(&encoded[..8], b"CNQEMU01");
    assert_eq!(&encoded[8..12], &[0, 1, 0, 1]);
    assert_eq!(decode_command(&encoded).unwrap(), original);
    assert_eq!(
        encode_command(&decode_command(&encoded).unwrap()).unwrap(),
        encoded
    );
}

#[test]
fn preparation_and_native_acknowledgement_are_closed_distinct_frames() {
    let original = command();
    let acknowledgement = ReceiptAcknowledgement {
        sequence: original.sequence,
        command_digest: original.identity_digest().unwrap(),
        authorization_digest: original.authorization_digest,
    };
    for frame in [
        NativeFrame::Prepare(Box::new(NativePreparation {
            scope: original.scope,
            boundary: position(0),
            maximum_commands: U64::new(4),
        })),
        NativeFrame::Acknowledge(acknowledgement.clone()),
        NativeFrame::Acknowledged(acknowledgement),
    ] {
        let encoded = encode_frame(&frame).unwrap();
        assert_eq!(decode_frame(&encoded).unwrap(), frame);
        for length in 0..encoded.len() {
            assert!(decode_frame(&encoded[..length]).is_err());
        }
        let mut extra = encoded;
        extra.push(0);
        let body_length = (extra.len() - NODE_CONTROL_HEADER_BYTES) as u32;
        extra[12..16].copy_from_slice(&body_length.to_be_bytes());
        assert!(decode_frame(&extra).is_err());
    }
}

#[test]
fn rejects_every_truncated_prefix_and_trailing_data() {
    let encoded = encode_command(&command()).unwrap();
    for length in 0..encoded.len() {
        assert!(decode_command(&encoded[..length]).is_err());
    }
    let mut extra = encoded.clone();
    extra.push(0);
    assert!(decode_command(&extra).is_err());
    let length = (extra.len() - NODE_CONTROL_HEADER_BYTES) as u32;
    extra[12..16].copy_from_slice(&length.to_be_bytes());
    assert!(decode_command(&extra).is_err());
}

#[test]
fn unknown_versions_kinds_phases_and_oversized_bodies_fail_closed() {
    let encoded = encode_command(&command()).unwrap();
    let mut version = encoded.clone();
    version[9] = 2;
    assert_eq!(
        decode_command(&version),
        Err(NativeCommandError::UnsupportedVersion(2))
    );
    let mut kind = encoded.clone();
    kind[11] = 3;
    assert!(decode_command(&kind).is_err());
    let mut phase = encoded.clone();
    let last = phase.len();
    phase[last - 2] = 4;
    assert!(decode_command(&phase).is_err());
    let mut oversized = encoded;
    oversized[12..16].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(
        decode_command(&oversized),
        Err(NativeCommandError::ResourceLimit)
    );
}

#[test]
fn settlement_is_same_time_and_cannot_invent_complete_input_closure() {
    let mut settle = command();
    let start = position(100);
    let limit = Position {
        microstep: U64::new(1),
        ..start
    };
    settle.kind = ExecutionKind::BoundarySettle { start, limit };
    assert!(encode_command(&settle).is_err());
    settle.closed_input_prefix = limit;
    assert_eq!(
        decode_command(&encode_command(&settle).unwrap()).unwrap(),
        settle
    );
    settle.kind = ExecutionKind::BoundarySettle {
        start,
        limit: position(101),
    };
    assert!(encode_command(&settle).is_err());
}

#[test]
fn lost_reply_recovers_original_without_duplicate_native_submission() {
    let original = command();
    let mut journal = CommandJournal::new(original.scope.clone(), position(0), 2).unwrap();
    assert_eq!(
        journal.retain(original.clone()).unwrap(),
        CommandJournalDisposition::New
    );
    assert_eq!(
        journal.retain(original.clone()).unwrap(),
        CommandJournalDisposition::Outstanding
    );
    let mut conflict = original.clone();
    conflict.authorization_digest[0] ^= 1;
    assert_eq!(journal.retain(conflict), Err(NativeCommandError::Conflict));
    assert_eq!(journal.original(U64::new(1)), Some(&original));
    assert!(
        journal
            .record_native_stop(U64::new(1), position(101))
            .is_err()
    );
    journal
        .record_native_stop(U64::new(1), position(100))
        .unwrap();
    assert_eq!(
        journal.retain(original.clone()).unwrap(),
        CommandJournalDisposition::Stopped
    );
    assert!(journal.acknowledge(U64::new(1), &[0; 32]).is_err());
    journal
        .acknowledge(U64::new(1), &original.authorization_digest)
        .unwrap();
    journal
        .acknowledge(U64::new(1), &original.authorization_digest)
        .unwrap();
    assert_eq!(
        journal.retain(original.clone()).unwrap(),
        CommandJournalDisposition::Acknowledged
    );
    let mut reused = original;
    reused.sequence = U64::new(2);
    reused.kind = ExecutionKind::ExactRun {
        start: position(100),
        limit: position(200),
        boundary_policy: BoundaryPolicy::HorizonPark,
    };
    reused.closed_input_prefix = position(200);
    assert_eq!(journal.retain(reused), Err(NativeCommandError::Conflict));
}

#[test]
fn native_stop_does_not_release_the_owner_until_original_acknowledgement() {
    let original = command();
    let mut journal = CommandJournal::new(original.scope.clone(), position(0), 2).unwrap();
    journal.retain(original.clone()).unwrap();
    journal
        .record_native_stop(U64::new(1), position(100))
        .unwrap();
    let mut next = original.clone();
    next.sequence = U64::new(2);
    next.operation = id("operation/2");
    next.grant = id("grant/2");
    next.kind = ExecutionKind::ExactRun {
        start: position(100),
        limit: position(200),
        boundary_policy: BoundaryPolicy::HorizonPark,
    };
    next.closed_input_prefix = position(200);
    assert!(journal.retain(next.clone()).is_err());
    journal
        .acknowledge(U64::new(1), &original.authorization_digest)
        .unwrap();
    assert_eq!(
        journal.retain(next).unwrap(),
        CommandJournalDisposition::New
    );
}

#[test]
fn cpu_only_frames_are_closed_bounded_and_never_generic_coverage() {
    let facts = NativeCpuParkFacts {
        coverage: 1,
        cpu_count: 1,
        current_ps: U64::new(0),
        retired_count: U64::new(0),
        next_service_deadline_ps: None,
        pending_service_credit_ps: U64::new(0),
        prepared_scope_hash: [1; 32],
        roster_sha256: [2; 32],
    };
    for frame in [
        NativeFrame::CpuPark(facts.clone()),
        NativeFrame::QueryCpuPark([1; 32]),
    ] {
        let encoded = encode_frame(&frame).unwrap();
        assert_eq!(decode_frame(&encoded).unwrap(), frame);
        for end in 0..encoded.len() {
            assert!(decode_frame(&encoded[..end]).is_err());
        }
        let mut appended = encoded;
        appended.push(0);
        assert!(decode_frame(&appended).is_err());
    }
    for (coverage, count) in [(0, 1), (3, 1), (1, 0), (1, 1025)] {
        let invalid = NativeCpuParkFacts {
            coverage,
            cpu_count: count,
            ..facts.clone()
        };
        assert!(encode_frame(&NativeFrame::CpuPark(invalid)).is_err());
    }
    assert!(encode_frame(&NativeFrame::QueryCpuPark([0; 32])).is_err());
}

#[path = "effect_tests.rs"]
mod effect;

#[path = "prefix_record_tests.rs"]
mod prefix_records;
