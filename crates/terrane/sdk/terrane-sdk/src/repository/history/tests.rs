//! Checks history selection against incomplete and contradictory backend data.

#![allow(
    clippy::unwrap_used,
    reason = "These assertions intentionally panic on failed invariants."
)]

use super::*;
use terrane_format::refs::{Locality, RefLogReason};

const REFERENCE: &str = "refs/heads/_/main";

fn next(previous: Option<&RefLogRecord>) -> RefLogRecord {
    let seq = previous.map_or(1, |entry| entry.record.seq + 1);
    RefLogRecord {
        record: RefRecord {
            commit: [seq as u8; 32],
            seq,
            writer_epoch: 1,
            home: Locality::default(),
            policy: None,
            candidate_id: Some([seq as u8; 32]),
        },
        previous_commit: previous.map(|entry| entry.record.commit),
        principal: "writer".into(),
        reason: RefLogReason::Commit,
        timestamp: seq,
        expected_previous: Some(previous.map(|entry| entry.record.clone())),
        committed_previous: None,
    }
}

#[test]
fn exact_horizon_excludes_append_first_candidates() {
    let first = next(None);
    let second = next(Some(&first));
    let result = checked_suffix(REFERENCE, 1, &first.record, vec![first.clone(), second]).unwrap();
    assert_eq!(result, vec![first]);
}

#[test]
fn ordered_suffix_must_reach_the_exact_whole_head() {
    let first = next(None);
    let second = next(Some(&first));
    let third = next(Some(&second));
    let records = vec![second, third.clone()];
    assert_eq!(
        checked_suffix(REFERENCE, 2, &third.record, records.clone()).unwrap(),
        records
    );

    let mut different_head = third.record;
    different_head.candidate_id = Some([42; 32]);
    assert!(checked_suffix(REFERENCE, 2, &different_head, records).is_err());
}

#[test]
fn missing_duplicate_and_reordered_committed_sequences_refuse() {
    let first = next(None);
    let second = next(Some(&first));
    let third = next(Some(&second));
    for records in [
        vec![],
        vec![first.clone(), third.clone()],
        vec![second.clone(), third.clone()],
        vec![first.clone(), second.clone(), second.clone(), third.clone()],
        vec![second.clone(), first.clone(), third.clone()],
        vec![first, second],
    ] {
        assert!(checked_suffix(REFERENCE, 1, &third.record, records).is_err());
    }
}

#[test]
fn equal_commit_predecessor_with_a_different_selector_refuses() {
    let first = next(None);
    let mut second = next(Some(&first));
    let mut unrelated = first.record.clone();
    unrelated.candidate_id = Some([42; 32]);
    second.expected_previous = Some(Some(unrelated));
    assert!(checked_suffix(REFERENCE, 1, &second.record, vec![first, second.clone()]).is_err());
}

#[test]
fn legacy_history_checks_initial_absence_and_committed_predecessors() {
    let mut first = next(None);
    first.record.candidate_id = None;
    first.expected_previous = None;
    let mut second = next(Some(&first));
    second.record.candidate_id = None;
    second.expected_previous = None;
    assert!(
        checked_suffix(
            REFERENCE,
            1,
            &second.record,
            vec![first.clone(), second.clone()]
        )
        .is_ok()
    );

    let mut changed = second.clone();
    changed.previous_commit = Some([42; 32]);
    assert!(
        checked_suffix(
            REFERENCE,
            1,
            &changed.record,
            vec![first.clone(), changed.clone()]
        )
        .is_err()
    );

    first.previous_commit = Some([42; 32]);
    assert!(checked_suffix(REFERENCE, 1, &first.record, vec![first.clone()]).is_err());
}

#[test]
fn selected_log_without_its_cas_expectation_refuses() {
    let mut first = next(None);
    first.expected_previous = None;
    assert!(checked_suffix(REFERENCE, 1, &first.record, vec![first.clone()]).is_err());
}
