//! Exercises the finite observer through real canonical COMMITs and Cold EOF.

use std::collections::BTreeMap;
use std::io::Write as _;

use aos_sandbox_broker::canonical_journal::{
    CanonicalReplayOriginalV1, NativeJournalDataErrorV1,
    coordinator::indexed_replay::{CanonicalIndexedReplayV1, CanonicalReplayIndexOriginalsV1},
};
use aos_sandbox_model::RecordNamespace;
use aos_sandbox_journal::protected_storage::FileIdentity;
use aos_sandbox_protocol::cache_state::fixed_journals::{
    CACHE_HOLD_GENESIS_KEY_V1, CACHE_HOLD_GENESIS_V1,
};
use aos_sandbox_protocol::domain_ledger::{
    JournalTransactionDataError,
    transaction::{
        JournalLimits, JournalRecord, JournalTransaction, encode_transaction, validate_transaction,
    },
};

use super::*;
use crate::cold::ColdReplayOriginalV1;
use crate::git_coverage_prefix::cache::policy_hold_transaction_data_v1;

fn observe(second: Option<JournalTransaction>, omit_commit: bool) -> (bool, bool) {
    let genesis =
        policy_hold_transaction_data_v1(CACHE_HOLD_GENESIS_KEY_V1, CACHE_HOLD_GENESIS_V1).unwrap();
    let mut transactions = vec![genesis];
    transactions.extend(second);
    let mut file = tempfile::tempfile().unwrap();
    let mut next = 1;
    for transaction in &transactions {
        let frames = encode_transaction(transaction, next).unwrap();
        let count = frames.len() - usize::from(omit_commit);
        for frame in &frames[..count] {
            file.write_all(frame).unwrap();
        }
        next += frames.len() as u64;
    }

    let identity = FileIdentity::of::<CanonicalJournalMechanicalErrorV1>(&file).unwrap();
    let limits = JournalLimits::default();
    let mut native = CanonicalReplayOriginalV1::new();
    let mut index = BTreeMap::new();
    let mut index_original = CanonicalReplayIndexOriginalsV1::new();
    let cursor = native
        .begin_ordinary_semantic_cursor_once(&file, limits, identity.byte_len())
        .unwrap();
    let mut indexed =
        CanonicalIndexedReplayV1::from_supplied_data_v1(cursor, &mut index, &mut index_original);
    let mut cold = ColdReplayOriginalV1::new();
    let mut comparison = CacheGitPrefixReplayDataV1::policy_native_prefix_v1();

    let observed = cold.observe_indexed_with_cache_git_prefix_once_v1(
        &mut indexed,
        identity,
        limits,
        &mut comparison,
    );
    let selected = cold.cache_git_prefix_failure_is_selected_v1();
    if observed.is_ok() {
        comparison.require_origin_v1([0; 32]).unwrap();
        assert_eq!(comparison.prefix_data_v1().counts_v1(), (1, 1));
        assert!(cold.take_remainder_once().is_some());
        assert!(comparison.failure().is_none());
    } else {
        assert!(cold.take_remainder_once().is_none());
        if omit_commit {
            // Ordinary parsing completes the durable empty prefix, retaining
            // the uncommitted tail. Cache must reject its captured-end mismatch.
            let prefix = indexed.completed_prefix().unwrap();
            assert_eq!(prefix.coordinates().durable_end, 0);
            assert_eq!(prefix.coordinates().durable_next_sequence, 1);
            assert!(identity.byte_len() > 0);
            assert_eq!(comparison.prefix_data_v1().counts_v1(), (0, 0));
            assert!(matches!(
                comparison.failure(),
                Some(CanonicalJournalMechanicalErrorV1::StaleAuthoritySnapshot)
            ));
            assert!(indexed.failure().is_none());
            assert!(!cold.native_failure_is_selected_v1());
        } else if selected {
            // The history hook refuses this actual second COMMIT before its
            // malformed capacity model can reach the later semantic validator.
            let commit = indexed.current_commit().unwrap();
            assert_eq!(commit.transaction(), &transactions[1]);
            assert_eq!(commit.begin_position().0, 4);
            assert_eq!(commit.commit_sequence(), 6);
            assert_eq!(commit.prior_state().len(), 1);
            assert!(validate_transaction(commit.transaction(), limits).is_ok());
            assert!(
                crate::replay::root_original_inventory::replay_edge(
                    commit.prior_state(),
                    commit.transaction(),
                    limits,
                )
                .is_err()
            );
            assert_eq!(comparison.prefix_data_v1().counts_v1(), (1, 1));
            assert!(matches!(
                comparison.failure(),
                Some(CanonicalJournalMechanicalErrorV1::ProtectedBoundary)
            ));
            assert!(indexed.failure().is_none());
            assert!(!cold.native_failure_is_selected_v1());
        } else {
            // Malformed Idempotency DATA fails in the actual native COMMIT
            // validator, before the Cache history hook can observe it.
            assert_eq!(comparison.prefix_data_v1().counts_v1(), (1, 1));
            assert!(comparison.failure().is_none());
            assert!(cold.native_failure_is_selected_v1());
            assert!(matches!(
                indexed
                    .failure()
                    .unwrap()
                    .downcast_ref::<NativeJournalDataErrorV1>(),
                Some(NativeJournalDataErrorV1::Transaction(
                    JournalTransactionDataError::MalformedRecord("invalid idempotency decision")
                ))
            ));
        }
    }
    (observed.is_ok(), selected)
}

#[test]
fn actual_policy_genesis_requires_full_canonical_eof() {
    assert_eq!(observe(None, false), (true, false));
    assert_eq!(observe(None, true), (false, true));
}

#[test]
fn cache_history_refusal_precedes_later_semantic_model_refusal() {
    // This second transaction is canonically framed but is neither the sole
    // paired birth nor a valid capacity model. Native structural validation
    // accepts it, so the original history hook must select Cache's comparison
    // before later semantic validation. The helper checks both real frontiers.
    let unrelated = JournalTransaction::new(
        [9; 16],
        vec![JournalRecord::put(
            RecordNamespace::GlobalCapacityReservation,
            b"invalid".to_vec(),
            vec![1],
        )],
    )
    .unwrap();
    assert_eq!(observe(Some(unrelated), false), (false, true));
}

#[test]
fn native_record_refusal_precedes_cache_history_comparison() {
    let malformed = JournalTransaction::new(
        [9; 16],
        vec![JournalRecord::put(
            RecordNamespace::Idempotency,
            b"invalid".to_vec(),
            vec![1],
        )],
    )
    .unwrap();

    assert_eq!(observe(Some(malformed), false), (false, false));
}
