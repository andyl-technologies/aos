//! Inert canonical DATA vectors exercise full-position closure and receipt joins.
// crucible-lint: allow panic-shortcut -- Inert vectors fail at their defining assertion.

use super::*;
use crate::node_control::{
    BoundaryPolicy, NativeControlEdition, NativeFrame, OwnerScope, decode_frame_for_edition,
    encode_frame_for_edition,
};
use crucible_node_format::{HashRef, Id, InputBatch};

fn at(t: u64, m: u64, phase: Phase) -> Position {
    Position::new(U64::new(t), U64::new(m), phase)
}
fn id(s: &str) -> Id {
    Id::new(s).unwrap()
}
fn hash(domain: &str) -> HashRef {
    HashRef {
        algorithm: "blake3-256".into(),
        domain: domain.into(),
        digest: "01".repeat(32),
    }
}
fn quiet(start: Position, limit: Position, settle: bool) -> NativeQuietCommand {
    let mut command = ExecutionCommand {
        sequence: U64::new(2),
        scope: OwnerScope {
            session: id("s"),
            incarnation: id("i"),
            activation: id("a"),
            node: id("n"),
            owner: id("o"),
            world_generation: U64::new(1),
            owner_generation: U64::new(1),
            world_binding: hash("cnp.world-binding.v1"),
            owner_binding: hash("cnp.owner-binding.v1"),
        },
        operation: id("operation2"),
        grant: id("grant2"),
        input_epoch: id("epoch"),
        input_batch: id("batch"),
        input_batch_hash: hash("cnp.input-batch.v1"),
        closed_input_prefix: limit,
        authorization_digest: [7; 32],
        kind: if settle {
            ExecutionKind::BoundarySettle { start, limit }
        } else {
            ExecutionKind::ExactRun {
                start,
                limit,
                boundary_policy: BoundaryPolicy::HorizonPark,
            }
        },
    };
    command.input_batch_hash = InputBatch {
        schema_version: 1,
        execution_owner_id: command.scope.owner.clone(),
        input_epoch: command.input_epoch.clone(),
        batch_id: command.input_batch.clone(),
        batch_sequence: U64::new(2),
        events: vec![],
        extensions: Default::default(),
    }
    .identity()
    .unwrap();
    NativeQuietCommand {
        command,
        preparation: [2; 32],
        predecessor_commit: [3; 32],
        input_batch_sequence: U64::new(2),
    }
}
fn put64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_be_bytes());
}
fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_be_bytes());
}
fn put_position(bytes: &mut [u8], offset: usize, p: Position) {
    put64(bytes, offset, p.time_ps.get());
    put64(bytes, offset + 8, p.microstep.get());
    put32(
        bytes,
        offset + 16,
        match p.phase {
            Phase::BoundaryControl => 0,
            Phase::Publication => 1,
            Phase::Delivery => 2,
            Phase::Reaction => 3,
        },
    );
    put32(bytes, offset + 20, 0);
}
fn census(original: &NativeQuietCommand, cursor: Position) -> [u8; 408] {
    let mut bytes = [0; 408];
    for (index, byte) in include_str!("testdata/stopped-initial-v1.hex")
        .split_ascii_whitespace()
        .enumerate()
    {
        bytes[index] = u8::from_str_radix(byte, 16).unwrap();
    }
    put_position(&mut bytes, 24, cursor);
    put64(&mut bytes, 48, 3);
    put_position(&mut bytes, 80, at(200, 0, Phase::Reaction));
    bytes[192..224].copy_from_slice(&original.command.scope.identity_digest().unwrap());
    put64(&mut bytes, 344, 1);
    put64(&mut bytes, 352, 2);
    put64(&mut bytes, 360, 2);
    put64(&mut bytes, 368, 1);
    put32(&mut bytes, 396, 0);
    put32(&mut bytes, 400, 0);
    bytes
}
fn progress(
    original: &NativeQuietCommand,
    before: &[u8; 408],
    after: &[u8; 408],
    status: u32,
) -> NativeQuietProgress {
    let mut bytes = [0; 952];
    bytes[..104].copy_from_slice(
        &NativeLiveIdentity::from_command(&original.command, original.preparation)
            .unwrap()
            .encode()
            .unwrap(),
    );
    put32(&mut bytes, 104, status);
    put64(&mut bytes, 112, 1234);
    put64(&mut bytes, 120, 7);
    put64(&mut bytes, 128, 2);
    bytes[136..544].copy_from_slice(before);
    bytes[544..].copy_from_slice(after);
    NativeQuietProgress::decode(&bytes).unwrap()
}

#[test]
fn quiet_completion_and_due_cpu_refusal_keep_actual_raw_and_half_open_cursor_distinct() {
    let original = quiet(
        at(151, 0, Phase::BoundaryControl),
        at(175, 0, Phase::BoundaryControl),
        false,
    );
    let before = census(&original, original.command.kind.start());
    let after = census(&original, original.command.kind.limit());
    let result = progress(&original, &before, &after, 1);
    assert_eq!(
        result.validate_original(&original, 1234).unwrap(),
        NativeQuietStatus::Completed
    );
    assert_eq!(result.after().unwrap().raw().unwrap(), 3);
    assert!(result.validate_original(&original, 9999).is_err());

    let due = quiet(
        at(199, 0, Phase::BoundaryControl),
        at(201, 0, Phase::BoundaryControl),
        false,
    );
    let before = census(&due, due.command.kind.start());
    let false_after = census(&due, due.command.kind.limit());
    // The claimed overshoot cannot even decode: nextCPU200 precedes cursor201.
    let mut invalid = *progress(&due, &before, &before, 2).bytes();
    invalid[544..].copy_from_slice(&false_after);
    assert!(NativeQuietProgress::decode(&invalid).is_err());
    let refusal = progress(&due, &before, &before, 2);
    assert_eq!(
        refusal.validate_original(&due, 1234).unwrap(),
        NativeQuietStatus::NeedsEvaluation
    );
    let false_completion = progress(&due, &before, &before, 1);
    assert!(false_completion.validate_original(&due, 1234).is_err());
}

#[test]
fn same_tick_settlement_respects_timer_reaction_and_microstep_frontiers() {
    let original = quiet(
        at(175, 0, Phase::BoundaryControl),
        at(175, 0, Phase::Reaction),
        true,
    );
    let mut before = census(&original, original.command.kind.start());
    put32(&mut before, 384, 1);
    put32(&mut before, 388, 2);
    for offset in [104, 112, 120] {
        put64(&mut before, offset, 1);
    }
    put64(&mut before, 128, 175);
    put_position(&mut before, 136, at(175, 0, Phase::Reaction));
    let mut after = before;
    put_position(&mut after, 24, original.command.kind.limit());
    assert_eq!(
        progress(&original, &before, &after, 1)
            .validate_original(&original, 1234)
            .unwrap(),
        NativeQuietStatus::Completed
    );

    let later = quiet(
        at(175, 0, Phase::BoundaryControl),
        at(175, 1, Phase::BoundaryControl),
        true,
    );
    let refusal = progress(&later, &before, &before, 2);
    assert_eq!(
        refusal.validate_original(&later, 1234).unwrap(),
        NativeQuietStatus::NeedsEvaluation
    );
    let false_completion = progress(&later, &before, &before, 1);
    assert!(false_completion.validate_original(&later, 1234).is_err());
}

#[test]
fn receipt_commit_and_edition_vectors_refuse_changed_durable_or_native_lineage() {
    let original = quiet(
        at(151, 0, Phase::BoundaryControl),
        at(175, 0, Phase::BoundaryControl),
        false,
    );
    let before = census(&original, original.command.kind.start());
    let after = census(&original, original.command.kind.limit());
    let progress = progress(&original, &before, &after, 1);
    let identity = progress.identity().unwrap();
    let mut bytes = [0; 640];
    put32(&mut bytes, 0, 1);
    put32(&mut bytes, 4, 640);
    bytes[8..112].copy_from_slice(&identity.encode().unwrap());
    put64(&mut bytes, 112, 1234);
    put64(&mut bytes, 120, 7);
    put64(&mut bytes, 128, 3);
    put64(&mut bytes, 136, 2);
    put_position(&mut bytes, 152, original.command.kind.limit());
    bytes[176..208].copy_from_slice(&Sha256::digest(progress.bytes()));
    bytes[208..616].copy_from_slice(&after);
    let proposal = NativeRetirementProposal::decode(&bytes).unwrap();
    let mut bytes = [0; 128];
    bytes[..32].copy_from_slice(&proposal.digest());
    bytes[32..64].fill(5);
    put64(&mut bytes, 64, 1234);
    put64(&mut bytes, 72, 7);
    put64(&mut bytes, 80, 2);
    put64(&mut bytes, 88, 2);
    put_position(&mut bytes, 96, original.command.kind.limit());
    put64(&mut bytes, 120, 3);
    let receipt = NativeRetirementReceipt::decode(&bytes).unwrap();
    receipt.validate_original(&proposal, [5; 32]).unwrap();
    assert!(receipt.validate_original(&proposal, [6; 32]).is_err());
    let mut bytes = [0; 160];
    bytes[..32].copy_from_slice(&receipt.digest());
    bytes[32..64].fill(6);
    bytes[64..96].copy_from_slice(&proposal.digest());
    put64(&mut bytes, 96, 2);
    put64(&mut bytes, 104, 2);
    put_position(&mut bytes, 112, original.command.kind.limit());
    put64(&mut bytes, 136, 3);
    put64(&mut bytes, 144, 7);
    put64(&mut bytes, 152, 1234);
    let committed = NativeRetirementCommitted::decode(&bytes).unwrap();
    committed.validate_original(&receipt, [6; 32]).unwrap();
    assert!(committed.validate_original(&receipt, [7; 32]).is_err());
    for frame in [
        NativeFrame::RetireOriginal(Box::new(NativeRetireOriginal {
            identity: identity.clone(),
            final_acknowledgement: [0; 192],
        })),
        NativeFrame::AcceptTerminal(NativeLiveAccept {
            identity: identity.clone(),
            native_digest: proposal.digest(),
            archive_digest: [5; 32],
        }),
        NativeFrame::AcknowledgeRetirement(NativeLiveAccept {
            identity,
            native_digest: receipt.digest(),
            archive_digest: [6; 32],
        }),
        NativeFrame::QuietAdvance(Box::new(original)),
        NativeFrame::QuietProgress(Box::new(progress)),
        NativeFrame::RetirementProposed(Box::new(proposal)),
        NativeFrame::RetirementReceipt(Box::new(receipt)),
        NativeFrame::RetirementCommitted(Box::new(committed)),
    ] {
        let wire = encode_frame_for_edition(NativeControlEdition::LiveQuiet, &frame).unwrap();
        assert_eq!(
            decode_frame_for_edition(NativeControlEdition::LiveQuiet, &wire).unwrap(),
            frame
        );
        assert!(encode_frame_for_edition(NativeControlEdition::PrefixObservation, &frame).is_err());
        assert!(decode_frame_for_edition(NativeControlEdition::PrefixObservation, &wire).is_err());
        for len in 0..wire.len() {
            assert!(
                decode_frame_for_edition(NativeControlEdition::LiveQuiet, &wire[..len]).is_err()
            );
        }
        let mut trailing = wire;
        trailing.push(0);
        assert!(decode_frame_for_edition(NativeControlEdition::LiveQuiet, &trailing).is_err());
    }
}
