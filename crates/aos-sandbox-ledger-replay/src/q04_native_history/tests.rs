//! Checks exact suffix DATA against the existing canonical cursor and Cold recipe.

use super::*;
use crate::cold::ColdReplayOriginalV1;
use aos_sandbox_broker::canonical_journal::{
    CanonicalReplayOriginalV1,
    coordinator::indexed_replay::{CanonicalIndexedReplayV1, CanonicalReplayIndexOriginalsV1},
};
use aos_sandbox_core::RecordNamespace;
use aos_sandbox_journal::protected_storage::FileIdentity;
use aos_sandbox_protocol::domain_ledger::transaction::{
    JournalLimits, JournalRecord, JournalTransaction, encode_transaction,
};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;

fn transaction(id: u8) -> JournalTransaction {
    JournalTransaction::new(
        [id; 16],
        vec![JournalRecord::put(
            RecordNamespace::DesiredState,
            vec![id],
            vec![id],
        )],
    )
    .unwrap()
}

fn observe(
    transactions: &[JournalTransaction],
    recipes: &[JournalTransaction],
    original_next: u64,
) -> bool {
    let limits = JournalLimits::default();
    let mut file = tempfile::tempfile().unwrap();
    let mut next = 1;
    for transaction in transactions {
        let frames = encode_transaction(transaction, next).unwrap();
        for frame in &frames {
            file.write_all(frame).unwrap();
        }
        next += frames.len() as u64;
    }
    let identity = FileIdentity::of::<CanonicalJournalMechanicalErrorV1>(&file).unwrap();
    let mut native = CanonicalReplayOriginalV1::new();
    let mut index = BTreeMap::new();
    let mut index_original = CanonicalReplayIndexOriginalsV1::new();
    let cursor = native
        .begin_ordinary_semantic_cursor_once(&file, limits, identity.byte_len())
        .unwrap();
    let mut indexed =
        CanonicalIndexedReplayV1::from_supplied_data_v1(cursor, &mut index, &mut index_original);
    let mut cold = ColdReplayOriginalV1::new();
    let mut audit = Q04NativeRecipeAuditDataV1::new(
        recipes,
        limits.maximum_transactions,
        Some(original_next),
        None,
        None,
    )
    .unwrap();

    let replayed = cold.observe_indexed_with_q04_native_recipe_once_v1(
        &mut indexed,
        identity,
        limits,
        &mut audit,
    );
    if replayed.is_err() {
        return false;
    }
    let ids: BTreeSet<_> = transactions
        .iter()
        .map(|transaction| *transaction.id())
        .collect();
    audit
        .finish_after_replay_v1(&ids, None, identity.byte_len(), next)
        .is_ok()
        && audit.completed_data_v1()
        && cold.take_remainder_once().is_some()
}

#[test]
fn exact_native_suffix_cannot_skip_a_foreign_transaction_or_reuse_its_prior_uuid() {
    assert!(observe(
        &[transaction(1), transaction(2)],
        &[transaction(2)],
        4
    ));
    assert!(!observe(
        &[transaction(1), transaction(9), transaction(2)],
        &[transaction(2)],
        4
    ));
    assert!(!observe(
        &[transaction(1), transaction(2)],
        &[transaction(1), transaction(2)],
        4
    ));
}

#[test]
fn duplicate_selected_uuids_refuse_before_any_cursor_entry() {
    let recipes = [transaction(1), transaction(1)];
    assert!(
        Q04NativeRecipeAuditDataV1::new(
            &recipes,
            JournalLimits::default().maximum_transactions,
            Some(1),
            None,
            None
        )
        .is_err()
    );
}
