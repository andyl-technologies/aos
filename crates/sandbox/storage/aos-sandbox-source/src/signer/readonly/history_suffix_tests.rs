//! Exercises exact suffix coordinates through the existing Native parser.
//!
//! These are offline DATA fixtures, not genuine PID1/F/currentness originals.
//! Finite ceilings are derived from each actual fixture's existing Native and
//! semantic shape suppliers. No production constructor or installed authority
//! is fabricated, and success here is only parser/comparison behavior.

use std::io::Write as _;

use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    HEAD_BYTES, KeyV1, LatestHeadV1, OwnerV1, PhaseV1, RecordCoordinatesV1,
    RecordEnvelopeV1, RECORD_OVERHEAD_BYTES,
};
use aos_sandbox_protocol::domain_ledger::transaction::encode_transaction;

use super::*;
use aos_sandbox_protocol::domain_ledger::create_storage_history::native_suffix::{
    HistoryPairNativeSuffixProgressV1, HistoryPairSuffixErrorV1,
};
use aos_sandbox_protocol::domain_ledger::create_storage_history::prepare_history_pair_v1;
use aos_sandbox_protocol::domain_ledger::transaction::{JournalLimits, JournalRecord};
use aos_sandbox_broker::canonical_journal::CanonicalReplayExtentDataV1 as ProtectedJournalPreopenReplayExtentV1;

fn pair() -> JournalTransaction {
    let key = KeyV1::new([7; 16], OwnerV1::Source, 1).unwrap();
    let phase = PhaseV1::new(OwnerV1::Source, 1).unwrap();
    let mut record = vec![0; RECORD_OVERHEAD_BYTES + 3];
    let checksum = RecordEnvelopeV1::encode_into(RecordCoordinatesV1 {
        key, phase, predecessor: [0; 32], correlation: [9; 32],
    }, b"cut", &mut record).unwrap();
    let head: [u8; HEAD_BYTES] = LatestHeadV1::new(1, checksum).unwrap().encode();
    prepare_history_pair_v1(key, phase, &record, &head).unwrap()
}

fn limits() -> JournalLimits {
    JournalLimits {
        maximum_records_per_transaction: 8,
        maximum_record_bytes: 4096,
        maximum_key_bytes: 1024,
        maximum_transaction_bytes: 16 * 1024,
        maximum_transactions: 8,
        maximum_materialized_records: 16,
        maximum_materialized_bytes: 64 * 1024,
        maximum_journal_bytes: 64 * 1024,
    }
}

fn append(file: &mut std::fs::File, transaction: &JournalTransaction, next: u64) {
    for frame in encode_transaction(transaction, next).unwrap() {
        file.write_all(&frame).unwrap();
    }
}

fn fixture_ceiling(
    extent: &ProtectedJournalPreopenReplayExtentV1,
    transactions: &[&JournalTransaction],
) -> ResourceVector {
    let mut state = State::new();
    let mut semantic = ResourceVector::ZERO;
    for transaction in transactions {
        semantic = semantic.componentwise_max(
            aos_sandbox_ledger_replay::geometry::complete_replay_demand_v1(&state, Some(transaction)).unwrap(),
        );
        for record in transaction.records() {
            let key = (record.namespace(), record.key().to_vec());
            if let Some(value) = record.value() {
                state.insert(key, value.to_vec());
            } else {
                state.remove(&key);
            }
        }
    }
    semantic = semantic.componentwise_max(
        aos_sandbox_ledger_replay::geometry::complete_replay_demand_v1(&state, None).unwrap(),
    );
    SourceReadonlyReceivingContextV1::fixed_demand().unwrap()
        .checked_add(extent.dominant_native_receiving_demand_v1().unwrap()).unwrap()
        .checked_add(extent.dominant_semantic_receiving_demand_v1().unwrap()).unwrap()
        .checked_add(CanonicalReplayIndexOriginalsV1::dynamic_demand_v1(*extent).unwrap()).unwrap()
        .checked_add(aos_sandbox_ledger_replay::geometry::retained_challenge_history_demand_v1(extent.native_bytes()).unwrap()).unwrap()
        .checked_add(semantic).unwrap()
        // This fixture tests arithmetic/parser DATA only. It neither fabricates
        // a permanent FD proof nor enters the real checked Original constructor.
        .with(D::OpenFiles, 0)
}

#[test]
fn actual_native_commit_and_final_coordinates_complete_only_the_exact_pair() {
    let expected = pair();
    let mut file = tempfile::tempfile().unwrap();
    append(&mut file, &expected, 1);
    let end = file.metadata().unwrap().len();
    let extent = ProtectedJournalPreopenReplayExtentV1::new(limits(), end).unwrap();
    let ceiling = fixture_ceiling(&extent, &[&expected]);
    let mut ledger = ComponentServiceReceivingLedgerV1::new(ceiling);
    let mut peak = SourceReadonlyPeakV1::new();
    peak.begin().unwrap();
    let mut progress = HistoryPairNativeSuffixProgressV1::new();

    let observed = {
        let suffix = HistoryPairNativeSuffixV1::new(
            &expected, &mut progress, 1, 0, 5, end,
        ).unwrap();
        let mut context = SourceReadonlyReceivingContextV1::new(&mut ledger, &mut peak).unwrap();
        context.attach_history_pair_once(suffix).unwrap();
        context.admit_fixed().unwrap();
        context.admit_captured_native(&extent).unwrap();
        let observed = SourceReadonlyReplayFixtureV1::observe(&mut file, limits(), &mut context);
        context.require_history_pair_finished().unwrap();
        observed
    };

    assert_eq!(observed.positive_coordinates(), Some((5, end)));
    assert!(progress.is_complete());
    assert!(progress.failure().is_none());
    assert!(ledger.failure().is_none());
    assert_eq!(ledger.charged(), ceiling);
}

#[test]
fn actual_extra_committed_transaction_is_not_a_membership_only_positive() {
    let expected = pair();
    let extra = JournalTransaction::new([99; 16], vec![JournalRecord::put(
        aos_sandbox_model::RecordNamespace::DesiredState, b"foreign".to_vec(), vec![7],
    )]).unwrap();
    let mut file = tempfile::tempfile().unwrap();
    append(&mut file, &expected, 1);
    let expected_end = file.metadata().unwrap().len();
    append(&mut file, &extra, 5);
    let end = file.metadata().unwrap().len();
    let extent = ProtectedJournalPreopenReplayExtentV1::new(limits(), end).unwrap();
    let mut ledger = ComponentServiceReceivingLedgerV1::new(fixture_ceiling(&extent, &[&expected, &extra]));
    let mut peak = SourceReadonlyPeakV1::new();
    peak.begin().unwrap();
    let mut progress = HistoryPairNativeSuffixProgressV1::new();

    let observed = {
        let suffix = HistoryPairNativeSuffixV1::new(
            &expected, &mut progress, 1, 0, 5, expected_end,
        ).unwrap();
        let mut context = SourceReadonlyReceivingContextV1::new(&mut ledger, &mut peak).unwrap();
        context.attach_history_pair_once(suffix).unwrap();
        context.admit_fixed().unwrap();
        context.admit_captured_native(&extent).unwrap();
        let observed = SourceReadonlyReplayFixtureV1::observe(&mut file, limits(), &mut context);
        assert!(context.require_history_pair_finished().is_err());
        assert!(context.finish_native_replay(5, expected_end).is_err());
        observed
    };

    assert!(observed.retained_failure());
    assert_eq!(progress.failure(), Some(&HistoryPairSuffixErrorV1::Transaction));
    let first = progress.failure().unwrap() as *const HistoryPairSuffixErrorV1;
    assert!(HistoryPairNativeSuffixV1::new(
        &expected, &mut progress, 1, 0, 5, expected_end,
    ).is_err());
    assert_eq!(progress.failure().unwrap() as *const HistoryPairSuffixErrorV1, first);
}

#[test]
fn actual_partial_tail_uses_the_original_captured_end_before_positive_completion() {
    let expected = pair();
    let extra = JournalTransaction::new([98; 16], vec![JournalRecord::put(
        aos_sandbox_model::RecordNamespace::DesiredState, b"foreign".to_vec(), vec![7],
    )]).unwrap();
    let mut file = tempfile::tempfile().unwrap();
    append(&mut file, &expected, 1);
    let expected_end = file.metadata().unwrap().len();
    // A fully framed BEGIN followed by EOF is an actual incomplete transaction.
    // The durable pair remains present, so membership alone would miss it.
    file.write_all(&encode_transaction(&extra, 5).unwrap()[0]).unwrap();
    let end = file.metadata().unwrap().len();
    let extent = ProtectedJournalPreopenReplayExtentV1::new(limits(), end).unwrap();
    let mut ledger = ComponentServiceReceivingLedgerV1::new(fixture_ceiling(&extent, &[&expected]));
    let mut peak = SourceReadonlyPeakV1::new();
    peak.begin().unwrap();
    let mut progress = HistoryPairNativeSuffixProgressV1::new();

    let observed = {
        let suffix = HistoryPairNativeSuffixV1::new(
            &expected, &mut progress, 1, 0, 5, expected_end,
        ).unwrap();
        let mut context = SourceReadonlyReceivingContextV1::new(&mut ledger, &mut peak).unwrap();
        context.attach_history_pair_once(suffix).unwrap();
        context.admit_fixed().unwrap();
        context.admit_captured_native(&extent).unwrap();
        let observed = SourceReadonlyReplayFixtureV1::observe(&mut file, limits(), &mut context);
        assert!(context.require_history_pair_finished().is_err());
        observed
    };

    assert!(end > expected_end);
    assert!(observed.retained_failure());
    assert_eq!(progress.failure(), Some(&HistoryPairSuffixErrorV1::Coordinates));
}

#[test]
fn mismatched_admitted_extent_refuses_before_parser_or_suffix_growth() {
    let expected = pair();
    let mut file = tempfile::tempfile().unwrap();
    append(&mut file, &expected, 1);
    let actual_end = file.metadata().unwrap().len();
    let extent = ProtectedJournalPreopenReplayExtentV1::new(
        limits(), actual_end - 1,
    ).unwrap();
    let mut ledger = ComponentServiceReceivingLedgerV1::new(
        fixture_ceiling(&extent, &[&expected]),
    );
    let mut peak = SourceReadonlyPeakV1::new();
    peak.begin().unwrap();
    let mut progress = HistoryPairNativeSuffixProgressV1::new();

    let observed = {
        let suffix = HistoryPairNativeSuffixV1::new(
            &expected, &mut progress, 1, 0, 5, actual_end,
        ).unwrap();
        let mut context = SourceReadonlyReceivingContextV1::new(&mut ledger, &mut peak).unwrap();
        context.attach_history_pair_once(suffix).unwrap();
        context.admit_fixed().unwrap();
        context.admit_captured_native(&extent).unwrap();
        SourceReadonlyReplayFixtureV1::observe(&mut file, limits(), &mut context)
    };

    assert!(observed.failed_before_parser());
    assert!(peak.closed);
    assert!(peak.active);
    assert!(progress.failure().is_none());
}

#[cfg(test)]
use aos_sandbox_model::component_receiving::ComponentServiceReceivingLedgerV1;

// Offline DATA only. This exercises the SAME private Source C/S cursor and
// semantic driver used in production without constructing any Source original.
struct SourceReadonlyReplayFixtureV1 {
    returned: Result<(u64, u64), JournalError>,
    replay: aos_sandbox_broker::canonical_journal::CanonicalReplayOriginalV1,
    index: CanonicalReplayIndexOriginalsV1,
    semantic: crate::native::semantic::FixedColdSemanticOriginalV1<
        crate::native::semantic::SourcePaidReplayErrorV1<JournalError>>,
    parser_entered: bool,
}

impl SourceReadonlyReplayFixtureV1 {
    fn observe(file: &mut std::fs::File, limits: JournalLimits,
        receiving: &mut SourceReadonlyReceivingContextV1<'_, '_>,
    ) -> Self {
        use crate::native::semantic::{FixedColdNativeStageV1 as _, SourcePaidReplayV1};
        use aos_sandbox_broker::canonical_journal::coordinator::indexed_replay::CanonicalIndexedReplayV1;
        let mut owner = Self { returned: Err(JournalError::ProtectedBoundary),
            replay: aos_sandbox_broker::canonical_journal::CanonicalReplayOriginalV1::new(),
            index: CanonicalReplayIndexOriginalsV1::new(),
            semantic: crate::native::semantic::FixedColdSemanticOriginalV1::new(),
            parser_entered: false };
        let mut decisions = std::collections::BTreeMap::new();
        owner.returned = (|| {
            let bytes = file.metadata()?.len();
            receiving.require_captured_file_end(bytes)?;
            let identity = aos_sandbox_journal::protected_storage::FileIdentity::of::<JournalError>(file)?;
            owner.parser_entered = true;
            let cursor = owner.replay.begin_semantic_cursor_once(file, limits, bytes)
                .map_err(|_| JournalError::ProtectedBoundary)?;
            let indexed = CanonicalIndexedReplayV1::from_supplied_data_v1(cursor, &mut decisions, &mut owner.index);
            let mut paid = SourcePaidReplayV1::new(indexed, receiving);
            owner.semantic.observe_native_once(&mut paid, identity, limits)
                .map_err(|_| JournalError::ProtectedBoundary)?;
            let coordinates = paid.completed_prefix().ok_or(JournalError::ProtectedBoundary)?.coordinates();
            Ok((coordinates.durable_next_sequence, coordinates.durable_end))
        })();
        owner
    }

    fn positive_coordinates(&self) -> Option<(u64, u64)> { self.returned.as_ref().ok().copied() }
    fn retained_failure(&self) -> bool { self.returned.is_err() && self.parser_entered }
    fn failed_before_parser(&self) -> bool { self.returned.is_err() && !self.parser_entered }
}
