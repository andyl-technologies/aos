//! Refuses a real canonical native COMMIT carrying a malformed pending batch.
//!
//! This offline parser fixture creates no Source original, financial loan,
//! currentness proof, signing key or positive role owner.

use super::*;
use aos_sandbox_broker::canonical_journal::{
    CanonicalReplayOriginalV1,
    coordinator::indexed_replay::{CanonicalIndexedReplayV1, CanonicalReplayIndexOriginalsV1},
};
use aos_sandbox_protocol::domain_ledger::transaction::{
    JournalLimits, JournalRecord, JournalTransaction, encode_transaction,
};
use std::io::Write as _;

#[test]
fn malformed_actual_pending_commit_retains_its_typed_first_error_and_never_lends_proof() {
    let query = SourceDeleteCurrentQueryDataV1 {
        nonce: [1; 16],
        project: [2; 16],
        operation: [3; 16],
        batch: [4; 32],
        boot: [5; 16],
        started: 100,
        cutoff: 1_000,
    };
    let transaction = JournalTransaction::new(
        query.operation,
        vec![JournalRecord::put(
            RecordNamespace::SourceDomainPolicyHold,
            crate::source_policy_hold::DELETE_PENDING_KEY.to_vec(),
            b"malformed batch".to_vec(),
        )],
    )
    .unwrap();
    let limits = JournalLimits {
        maximum_records_per_transaction: 8,
        maximum_record_bytes: 4096,
        maximum_key_bytes: 1024,
        maximum_transaction_bytes: 16 * 1024,
        maximum_transactions: 8,
        maximum_materialized_records: 16,
        maximum_materialized_bytes: 64 * 1024,
        maximum_journal_bytes: 64 * 1024,
    };
    let mut file = tempfile::tempfile().unwrap();
    for frame in encode_transaction(&transaction, 1).unwrap() {
        file.write_all(&frame).unwrap();
    }
    let end = file.metadata().unwrap().len();
    let mut replay = CanonicalReplayOriginalV1::new();
    let mut index_original = CanonicalReplayIndexOriginalsV1::new();
    let mut index = std::collections::BTreeMap::new();
    let cursor = replay
        .begin_semantic_cursor_once(&mut file, limits, end)
        .unwrap();
    let mut indexed =
        CanonicalIndexedReplayV1::from_supplied_data_v1(cursor, &mut index, &mut index_original);
    let mut observer = SourceDeletePendingReplayDataV1::new(query);

    assert!(indexed.advance_once().unwrap());
    assert!(
        observer
            .observe_commit(indexed.current_commit().unwrap())
            .is_err()
    );
    let first = observer.failure().unwrap() as *const dyn Error;
    assert!(matches!(
        observer.failure().unwrap().downcast_ref::<PendingErrorV1>(),
        Some(PendingErrorV1::Batch(_))
    ));
    assert!(observer.proof(query).is_err());

    assert!(
        observer
            .observe_commit(indexed.current_commit().unwrap())
            .is_err()
    );
    assert!(std::ptr::eq(
        observer.failure().unwrap() as *const dyn Error,
        first
    ));
    assert!(observer.proof(query).is_err());
}
