//! Model-only original-prefix failure recovery, without native qualification.

// crucible-lint: allow panic-shortcut -- These preparation successor custody tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used)]

use super::*;
use crucible_node_contract::U64;
use std::cell::{Cell, RefCell};

thread_local! {
    static SOURCE: RefCell<NativePreparationSuccessorAbi> = RefCell::new(facts());
    static QUERIES: Cell<u32> = const { Cell::new(0) };
    static OFFSETS: RefCell<Vec<u64>> = const { RefCell::new(Vec::new()) };
    static QUERY_FAILURE: Cell<bool> = const { Cell::new(false) };
    static COPIED_ON_FAILURE: Cell<bool> = const { Cell::new(false) };
}

fn facts() -> NativePreparationSuccessorAbi {
    NativePreparationSuccessorAbi {
        version: 1,
        size: 248,
        flags: 3,
        initialization_sequence: 1,
        hold_generation: 7,
        prepared_scope_hash: [1; 32],
        initialization_commitment: [2; 32],
        realize_request_digest: [3; 32],
        original_cut_digest: [4; 32],
        applied_receipt_digest: [5; 32],
        content_length: 6000,
        content_digest: [6; 32],
        ..Default::default()
    }
}

fn receipt() -> NativeInitializationReceipt {
    NativeInitializationReceipt {
        status: NativeInitializationStatus::Applied,
        applied_callbacks: 0,
        sequence: U64::new(1),
        hold_generation: U64::new(7),
        prepared_scope_hash: [1; 32],
        initialization_commitment: [2; 32],
        realize_request_digest: [3; 32],
        original_cut_digest: [4; 32],
    }
}

#[test]
fn authentic_ack_waits_for_busy_cache_but_foreign_query_or_failed_source_never_waits() {
    let (initializer, command, source_receipt) =
        super::super::initialization_custody::tests::fixture();
    initializer.retain(command.clone()).unwrap();
    let receipt = initializer.record_receipt(source_receipt).unwrap();
    let query = NativePreparationSuccessorQuery {
        prepared_scope_hash: initializer.scope,
        initialization_sequence: receipt.sequence,
        original_cut_digest: receipt.original_cut_digest,
        offset: U64::new(0),
    };
    let successor = custody();
    assert!(
        successor
            .try_acknowledged_original_chunk(&initializer, &query)
            .is_err()
    );
    initializer
        .acknowledge(
            &crucible_protocol::node_control::NativeInitializationAcknowledgement {
                prepared_scope_hash: initializer.scope,
                initialization_commitment: initializer.commitment,
                sequence: command.sequence,
                command_digest: command.identity_digest().unwrap(),
            },
        )
        .unwrap();

    assert_eq!(
        successor
            .try_acknowledged_original_chunk(&initializer, &query)
            .unwrap(),
        None
    );
    let mut storage = successor.original.lock().unwrap();
    storage.receipt = Some(receipt);
    storage.bytes.extend_from_slice(&[9, 8, 7]);
    assert_eq!(
        successor
            .try_acknowledged_original_chunk(&initializer, &query)
            .unwrap(),
        None
    );
    let mut foreign = query.clone();
    foreign.original_cut_digest = [99; 32];
    assert!(
        successor
            .try_acknowledged_original_chunk(&initializer, &foreign)
            .is_err()
    );
    assert_eq!(storage.bytes, [9, 8, 7]);
    storage.failed = true;
    drop(storage);

    assert!(
        successor
            .try_acknowledged_original_chunk(&initializer, &query)
            .is_err()
    );
    assert_eq!(successor.original.lock().unwrap().bytes, [9, 8, 7]);
    QUERIES.with(|count| assert_eq!(count.get(), 0));
    OFFSETS.with(|offsets| assert!(offsets.borrow().is_empty()));
}

extern "C" fn query(
    _scope: *const u8,
    _sequence: u64,
    _cut: *const u8,
    output: *mut NativePreparationSuccessorAbi,
) -> i32 {
    QUERIES.with(|count| count.set(count.get() + 1));
    SOURCE.with(|source| {
        // SAFETY: The synchronous custody call owns a live correctly sized
        // output slot for this exact scalar ABI.
        unsafe { output.write(*source.borrow()) };
    });
    if QUERY_FAILURE.with(Cell::get) { -1 } else { 0 }
}

extern "C" fn read(
    _scope: *const u8,
    _sequence: u64,
    _digest: *const u8,
    offset: u64,
    output: *mut u8,
    capacity: u32,
    copied: *mut u32,
) -> i32 {
    OFFSETS.with(|offsets| offsets.borrow_mut().push(offset));
    if offset != 0 {
        // SAFETY: The synchronous caller owns this live copied-count slot.
        unsafe { copied.write(u32::from(COPIED_ON_FAILURE.with(Cell::get))) };
        return -1;
    }

    // SAFETY: The synchronous caller supplies capacity writable bytes and a
    // live count slot. No pointer is retained by this model-only callback.
    unsafe {
        std::slice::from_raw_parts_mut(output, capacity as usize).fill(17);
        copied.write(capacity);
    }
    0
}

fn custody() -> PreparationSuccessorCustody {
    SOURCE.with(|source| *source.borrow_mut() = facts());
    QUERIES.with(|count| count.set(0));
    OFFSETS.with(|offsets| offsets.borrow_mut().clear());
    QUERY_FAILURE.with(|value| value.set(false));
    COPIED_ON_FAILURE.with(|value| value.set(false));
    PreparationSuccessorCustody::new(query, read)
}

#[test]
fn transient_read_retries_original_offset_without_requery_or_prefix_replacement() {
    let custody = custody();
    assert!(custody.observe_after_applied(&receipt()).is_err());
    {
        let original = custody.try_original().unwrap();
        assert_eq!(original.receipt, Some(receipt()));
        assert_eq!(original.bytes, vec![17; 3000]);
        assert!(!original.failed);
        assert!(original.decoded.is_none());
    }

    SOURCE.with(|source| source.borrow_mut().prepared_scope_hash = [9; 32]);
    assert!(custody.observe_after_applied(&receipt()).is_err());
    QUERIES.with(|count| assert_eq!(count.get(), 1));
    OFFSETS.with(|offsets| assert_eq!(*offsets.borrow(), vec![0, 3000, 3000]));
    assert_eq!(custody.try_original().unwrap().bytes, vec![17; 3000]);
}

#[test]
fn partial_native_copy_on_failure_is_sticky_and_keeps_original_prefix() {
    let custody = custody();
    COPIED_ON_FAILURE.with(|value| value.set(true));
    assert!(custody.observe_after_applied(&receipt()).is_err());
    assert!(custody.try_original().unwrap().failed);
    COPIED_ON_FAILURE.with(|value| value.set(false));

    assert!(custody.observe_after_applied(&receipt()).is_err());
    QUERIES.with(|count| assert_eq!(count.get(), 1));
    OFFSETS.with(|offsets| assert_eq!(*offsets.borrow(), vec![0, 3000]));
    assert_eq!(custody.try_original().unwrap().bytes, vec![17; 3000]);
}

#[test]
fn foreign_facts_and_nonzero_failure_outputs_cannot_be_rehabilitated() {
    for failure_output in [false, true] {
        let custody = custody();
        if failure_output {
            QUERY_FAILURE.with(|value| value.set(true));
        } else {
            SOURCE.with(|source| source.borrow_mut().original_cut_digest = [9; 32]);
        }
        assert!(custody.observe_after_applied(&receipt()).is_err());
        assert!(custody.try_original().unwrap().failed);
        SOURCE.with(|source| *source.borrow_mut() = facts());
        QUERY_FAILURE.with(|value| value.set(false));

        assert!(custody.observe_after_applied(&receipt()).is_err());
        QUERIES.with(|count| assert_eq!(count.get(), 1));
        OFFSETS.with(|offsets| assert!(offsets.borrow().is_empty()));
    }
}

#[test]
fn changed_receipt_and_busy_owner_refuse_before_more_source_reads() {
    let custody = custody();
    assert!(custody.observe_after_applied(&receipt()).is_err());
    let mut changed = receipt();
    changed.sequence = U64::new(2);
    assert!(custody.observe_after_applied(&changed).is_err());

    let original = custody.try_original().unwrap();
    assert!(custody.observe_after_applied(&receipt()).is_err());
    assert_eq!(original.receipt, Some(receipt()));
    assert_eq!(original.bytes, vec![17; 3000]);
    QUERIES.with(|count| assert_eq!(count.get(), 1));
    OFFSETS.with(|offsets| assert_eq!(*offsets.borrow(), vec![0, 3000]));
}
