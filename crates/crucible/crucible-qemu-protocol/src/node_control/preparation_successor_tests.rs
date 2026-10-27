//! Adversarial schema and byte-custody checks, without native qualification.
// crucible-lint: allow panic-shortcut -- These preparation successor tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::node_control::{
    NativePhaseTimerArm, NativeTimerArm, NativeTimerList, NativeWriterAio, NativeWriterBh,
    NativeWriterCpu, NativeWriterHandler, NativeWriterWork,
};

pub(crate) fn fixture() -> (NativePreparationSuccessorFacts, Vec<u8>) {
    let scope = [1; 32];
    let commitment = [2; 32];
    let receipt = NativeInitializationReceipt {
        status: NativeInitializationStatus::Applied,
        applied_callbacks: 3,
        sequence: U64::new(1),
        hold_generation: U64::new(7),
        prepared_scope_hash: scope,
        initialization_commitment: commitment,
        original_cut_digest: [3; 32],
        realize_request_digest: [4; 32],
    };
    let writer = NativeWriterObservation {
        prepared_scope_hash: scope,
        sequence: U64::new(0),
        command_digest: [0; 32],
        gate_generation: U64::new(7),
        current_ps: U64::new(0),
        retired_count: U64::new(0),
        aio_generation: U64::new(8),
        bh_generation: U64::new(9),
        handler_generation: U64::new(10),
        admissions_in_flight: U64::new(0),
        coverage: 7,
        flags: 15,
        roster_sha256: [5; 32],
        cpus: vec![NativeWriterCpu {
            cpu_index: 0,
            interrupt_mask: 0,
            exception_index: -1,
            flags: 0,
            work_count: U64::new(1),
            next_work_sequence: U64::new(11),
        }],
        work: vec![NativeWriterWork {
            cpu_index: 0,
            flags: 1,
            work_id: U64::new(4),
            fifo_ordinal: U64::new(1),
        }],
        aio: vec![NativeWriterAio {
            context_id: U64::new(2),
            home_thread_id: -42,
            active_polls: 0,
            active_dispatches: 0,
            pending_bhs: 1,
            active_bhs: 0,
            queued_coroutines: 0,
            flags: 1,
        }],
        bottom_halves: vec![NativeWriterBh {
            bh_id: U64::new(3),
            context_id: U64::new(2),
            active_callbacks: 0,
            flags: 1,
        }],
        handlers: vec![NativeWriterHandler {
            handler_id: U64::new(6),
            context_id: U64::new(2),
            descriptor_slot: -9,
            active_callbacks: 0,
            flags: 1,
        }],
    };
    let timers = NativePhaseTimerObservation {
        prepared_scope_hash: scope,
        sequence: U64::new(0),
        command_digest: [0; 32],
        current_ps: U64::new(0),
        mutation_generation: U64::new(3),
        gate_generation: U64::new(7),
        lists: vec![NativeTimerList {
            identity: U64::new(1),
            timer_count: 2,
            flags: 3,
        }],
        timers: vec![
            NativePhaseTimerArm {
                arm: NativeTimerArm {
                    identity: U64::new(1),
                    list: U64::new(1),
                    arm_generation: U64::new(1),
                    expiry_ps: U64::new(1000),
                    fifo_ordinal: U64::new(0),
                    attributes: 0,
                    scale: 1,
                },
                birth: NativeTimerBirth::Construction {
                    prepared_scope_hash: scope,
                    initialization_commitment: commitment,
                },
            },
            NativePhaseTimerArm {
                arm: NativeTimerArm {
                    identity: U64::new(2),
                    list: U64::new(1),
                    arm_generation: U64::new(2),
                    expiry_ps: U64::new(1000),
                    fifo_ordinal: U64::new(1),
                    attributes: 0,
                    scale: 1,
                },
                birth: NativeTimerBirth::Unknown { parent: None },
            },
        ],
    };
    let receipt_bytes = receipt.encode().unwrap();
    let mut receipt_hash = Sha256::new();
    receipt_hash.update(RECEIPT_TAG);
    receipt_hash.update(receipt_bytes);
    let mut facts = NativePreparationSuccessorFacts {
        initialization_sequence: U64::new(1),
        hold_generation: U64::new(7),
        current_ps: U64::new(0),
        retired_count: U64::new(0),
        prepared_scope_hash: scope,
        initialization_commitment: commitment,
        realize_request_digest: [4; 32],
        original_cut_digest: [3; 32],
        applied_receipt_sha256: receipt_hash.finalize().into(),
        content_length: U64::new(1),
        content_sha256: [1; 32],
    };
    let mut bytes = Vec::new();
    bytes.extend_from_slice(OBJECT_TAG);
    bytes.extend_from_slice(&facts.encode().unwrap()[..208]);
    bytes.extend_from_slice(&receipt_bytes);
    for value in [1u32, 112, 1, 1] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    for value in [0u64, 0, u64::MAX, 0] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    bytes.extend_from_slice(&scope);
    bytes.extend_from_slice(&writer.roster_sha256);
    let writer_bytes = writer.encode().unwrap();
    for value in [1u32, 160, writer.coverage, writer.flags, 1, 1, 1, 1, 1, 0] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    bytes.extend_from_slice(&writer_bytes[80..136]);
    bytes.extend_from_slice(&scope);
    bytes.extend_from_slice(&writer.roster_sha256);
    let timer_bytes = timers.encode().unwrap();
    bytes.extend_from_slice(&timer_bytes[..112]);
    bytes.extend_from_slice(&writer_bytes[196..]);
    bytes.extend_from_slice(&timer_bytes[112..]);
    facts.content_length = U64::new(bytes.len() as u64);
    facts.content_sha256 = Sha256::digest(&bytes).into();
    (facts, bytes)
}

fn rehash(facts: &mut NativePreparationSuccessorFacts, bytes: &[u8]) {
    facts.content_length = U64::new(bytes.len() as u64);
    facts.content_sha256 = Sha256::digest(bytes).into();
}

#[test]
#[ignore = "requires original canonical facts/object emitted by the actual native source fixture"]
fn actual_native_source_object_matches_the_closed_portable_decoder() {
    // These are test evidence files, not a native-admission or execution path.
    let facts_path = std::env::var("CRUCIBLE_NATIVE_SUCCESSOR_FACTS").unwrap();
    let object_path = std::env::var("CRUCIBLE_NATIVE_SUCCESSOR_OBJECT").unwrap();
    let facts =
        NativePreparationSuccessorFacts::decode(&std::fs::read(facts_path).unwrap()).unwrap();
    let bytes = std::fs::read(object_path).unwrap();
    let decoded = NativePreparationSuccessorObservation::decode(facts.clone(), &bytes).unwrap();
    assert_eq!(
        decoded.initialization.status,
        NativeInitializationStatus::Applied
    );
    assert_eq!(
        decoded.writers.roster_sha256,
        decoded.cpu_park.roster_sha256
    );
    assert_eq!(decoded.cpu_park.current_ps.get(), 0);
    assert_eq!(decoded.cpu_park.retired_count.get(), 0);
    assert_eq!(decoded.writers.flags, 15);
    assert!(
        decoded
            .timers
            .timers
            .iter()
            .all(|timer| timer.birth.position().is_none())
    );
    assert_eq!(
        NativePreparationSuccessorFacts::decode(&facts.encode().unwrap()).unwrap(),
        facts
    );
}

#[test]
fn canonical_source_rows_preserve_signed_fields_unknown_birth_and_pending_work() {
    let (facts, bytes) = fixture();
    let decoded = NativePreparationSuccessorObservation::decode(facts.clone(), &bytes).unwrap();
    assert_eq!(decoded.facts, facts);
    assert_eq!(decoded.writers.flags, 15);
    assert_eq!(decoded.writers.cpus[0].exception_index, -1);
    assert_eq!(decoded.writers.aio[0].home_thread_id, -42);
    assert_eq!(decoded.writers.handlers[0].descriptor_slot, -9);
    assert_eq!(decoded.writers.work[0].work_id.get(), 4);
    assert_eq!(decoded.timers.timers[1].birth.position(), None);
    assert_eq!(decoded.timers.timers[0].birth.position(), None);
    assert_eq!(
        NativePreparationSuccessorFacts::decode(&facts.encode().unwrap()).unwrap(),
        facts
    );
}

#[test]
fn all_truncations_and_trailing_bytes_refuse_without_extent_repair() {
    let (mut facts, bytes) = fixture();
    for extent in 0..bytes.len() {
        rehash(&mut facts, &bytes[..extent]);
        assert!(
            NativePreparationSuccessorObservation::decode(facts.clone(), &bytes[..extent]).is_err()
        );
    }
    let mut trailing = bytes;
    trailing.push(0);
    rehash(&mut facts, &trailing);
    assert!(NativePreparationSuccessorObservation::decode(facts, &trailing).is_err());
}

#[test]
fn facts_reject_open_flags_reserved_fields_and_oversized_object_before_allocation() {
    let (facts, _) = fixture();
    for offset in [0, 4, 8, 12] {
        let mut encoded = facts.encode().unwrap();
        encoded[offset + 3] ^= 8;
        assert!(NativePreparationSuccessorFacts::decode(&encoded).is_err());
    }
    for extent in 0..248 {
        assert!(
            NativePreparationSuccessorFacts::decode(&facts.encode().unwrap()[..extent]).is_err()
        );
    }
    let mut changed = facts;
    changed.content_length = U64::new(NATIVE_PREPARATION_SUCCESSOR_MAX_BYTES as u64 + 1);
    assert!(changed.validate().is_err());
}

#[test]
fn changed_source_identity_receipt_progress_and_nested_hold_are_refused() {
    let (facts, bytes) = fixture();
    let writer_start = OBJECT_TAG.len() + 208 + 160 + 112;
    let timer_start = writer_start + 160;
    for offset in [
        OBJECT_TAG.len() + 48,
        OBJECT_TAG.len() + 208 + 32,
        writer_start + 40,
        writer_start + 96,
        timer_start + 32,
        timer_start + 48,
    ] {
        let mut changed = bytes.clone();
        changed[offset] ^= 1;
        let mut altered_facts = facts.clone();
        rehash(&mut altered_facts, &changed);
        assert!(NativePreparationSuccessorObservation::decode(altered_facts, &changed).is_err());
    }
}

#[test]
fn malicious_inventory_counts_reserved_fields_and_active_writers_are_refused() {
    let (facts, bytes) = fixture();
    let writer_start = OBJECT_TAG.len() + 208 + 160 + 112;
    let timer_start = writer_start + 160;
    for (offset, value) in [
        (writer_start + 16, u32::MAX),
        (writer_start + 36, 1),
        (timer_start + 8, 65),
        (timer_start + 12, 4097),
    ] {
        let mut changed = bytes.clone();
        changed[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        let mut altered_facts = facts.clone();
        rehash(&mut altered_facts, &changed);
        assert!(NativePreparationSuccessorObservation::decode(altered_facts, &changed).is_err());
    }
    let mut changed = bytes;
    changed[writer_start + 88..writer_start + 96].copy_from_slice(&1u64.to_be_bytes());
    let mut altered_facts = facts;
    rehash(&mut altered_facts, &changed);
    assert!(NativePreparationSuccessorObservation::decode(altered_facts, &changed).is_err());
}

#[test]
fn cleared_unknown_coverage_service_credit_and_foreign_constructor_epoch_refuse() {
    let (facts, bytes) = fixture();
    let park_start = OBJECT_TAG.len() + 208 + 160;
    let writer_start = park_start + 112;
    let rows_start = writer_start + 160 + 112;
    let timer_start = rows_start + 32 + 24 + 40 + 24 + 32 + 16;
    for (offset, changed_byte) in [
        (writer_start + 15, 1),
        (park_start + 47, 1),
        (timer_start + 199, 9),
    ] {
        let mut changed = bytes.clone();
        changed[offset] = changed_byte;
        let mut altered_facts = facts.clone();
        rehash(&mut altered_facts, &changed);
        assert!(NativePreparationSuccessorObservation::decode(altered_facts, &changed).is_err());
    }
}
