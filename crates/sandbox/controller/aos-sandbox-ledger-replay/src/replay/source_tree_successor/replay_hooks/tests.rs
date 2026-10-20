//! Complete portable Source hook regressions over raw transaction DATA.

use super::*;
use aos_sandbox_protocol::domain_ledger::transaction::JournalLimits;
type H = DomainLedgerDataError;
type R = crate::genesis::SourceGenesisReceiptDataErrorV1;

#[test]
fn unrelated_raw_commit_remains_accepted_and_both_prefix_modes_complete() {
    let state = State::new();
    let transaction = JournalTransaction::new([1; 16], vec![JournalRecord::put(
        RecordNamespace::DesiredState, b"unrelated".to_vec(), vec![1],
    )]).expect("ordinary unrelated transaction");

    assert!(!validate_replayed_transaction::<JournalError, H, R>(
        &state, &transaction, JournalLimits::default()).expect("unchanged ordinary hook"));
    validate_replayed_state::<JournalError, H, R>(&state, false).expect("ordinary prefix");
    validate_replayed_state::<JournalError, H, R>(&state, true).expect("compacted prefix");
}

#[test]
fn complete_raw_fold_refuses_orphan_ack_and_keeps_first_original_cause() {
    let project = ProjectId::from_bytes([2; 16]);
    let ack = SourceFirstSuccessorAckV2::new(crate::replay::phase_records::SourceFirstSuccessorAckFieldsV2 {
        instance: [1; 32], project, receipt: ObjectDigest::from_bytes([3; 32]),
        root_floor: ObjectDigest::from_bytes([4; 32]), controller_anchored: ObjectDigest::from_bytes([5; 32]),
    }).expect("canonical orphan ACK DATA");
    let mut state = State::new();
    state.insert((RecordNamespace::DesiredState, ack_key(project)), ack.as_bytes().to_vec());
    let transaction = JournalTransaction::new([6; 16], vec![JournalRecord::put(
        RecordNamespace::DesiredState, b"unrelated".to_vec(), vec![1],
    )]).expect("ordinary unrelated transaction");
    let mut original = SourceReplayTransactionOriginalsV1::<JournalError, H, R>::new();

    assert!(original.observe_once(&state, &transaction, JournalLimits::default()).is_err());
    let cause = original.cause().expect("original typed refusal") as *const dyn std::error::Error;
    assert!(original.observe_once(&State::new(), &transaction, JournalLimits::default()).is_err());
    assert!(std::ptr::addr_eq(original.cause().expect("same original cause"), cause));
    assert!(original.require_complete().is_err());
}
