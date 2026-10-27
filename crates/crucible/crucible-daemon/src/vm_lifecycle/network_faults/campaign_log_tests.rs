//! Unit tests for the segmented campaign effect log and its replay.

use super::super::tests::{campaign_frame_record_at, object_id};
use super::*;
use crucible_engine::segment_store::SharedSegmentStore;

fn log_in(store: &SharedSegmentStore) -> CampaignRecordLog {
    CampaignRecordLog::new(Arc::new(store.clone()), FaultResourceLimits::default())
}

fn record(sequence: u64) -> ResolvedEffectRecord {
    campaign_frame_record_at(object_id("segment-primary"), sequence)
}

fn exported_records(log: &CampaignRecordLog) -> Vec<ResolvedEffectRecord> {
    log.export(FaultReplayMode::RecomputedCause)
        .unwrap_or_else(|error| panic!("export: {error}"))
        .items()
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|error| panic!("items: {error}"))
        .into_iter()
        .flat_map(|item| item.records)
        .collect()
}

#[test]
fn one_coordinate_run_groups_records_by_owner() {
    let store = SharedSegmentStore::new();
    let mut log = log_in(&store);
    log.push(record(0))
        .unwrap_or_else(|error| panic!("first: {error}"));
    log.push(record(0))
        .unwrap_or_else(|error| panic!("same owner: {error}"));
    log.push(record(1))
        .unwrap_or_else(|error| panic!("later sequence: {error}"));

    let trace = log
        .export(FaultReplayMode::RecomputedCause)
        .unwrap_or_else(|error| panic!("export: {error}"));
    let items = trace
        .items()
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|error| panic!("items: {error}"));
    assert_eq!(items.len(), 2);
    assert_eq!(items[0].records.len(), 2);
    assert_eq!(items[1].same_coordinate_sequence, 1);
    assert_eq!(log.records(), 3);

    // The later sequence closed the first run into the writer.
    let position = log.position();
    assert_eq!(position.position.work_items(), 1);
    assert_eq!(position.open_run.len(), 1);
    assert_eq!(position.records(), 3);
}

#[test]
fn records_out_of_scheduler_order_are_refused() {
    let store = SharedSegmentStore::new();
    let mut log = log_in(&store);
    log.push(record(2))
        .unwrap_or_else(|error| panic!("first: {error}"));

    assert!(log.push(record(1)).is_err());
}

#[test]
fn a_restored_log_seals_and_exports_like_an_uninterrupted_one() {
    // Enough records to seal several segments: the restored log must seal at
    // the same points (RFC-0020 CCOMP-21).
    let uninterrupted_store = SharedSegmentStore::new();
    let mut uninterrupted = log_in(&uninterrupted_store);
    let resumed_store = SharedSegmentStore::new();
    let mut first_half = log_in(&resumed_store);

    let mut sequence = 0;
    while first_half.position().position.sealed().is_empty() {
        first_half
            .push(record(sequence))
            .unwrap_or_else(|error| panic!("push {sequence}: {error}"));
        sequence += 1;
    }
    let midpoint = sequence;
    let encoded = serde_json::to_vec(&first_half.position())
        .unwrap_or_else(|error| panic!("encode position: {error}"));
    let position: CampaignRecordLogPosition =
        serde_json::from_slice(&encoded).unwrap_or_else(|error| panic!("decode position: {error}"));
    let mut resumed = CampaignRecordLog::restore(
        Arc::new(resumed_store.clone()),
        FaultResourceLimits::default(),
        position,
    )
    .unwrap_or_else(|error| panic!("restore: {error}"));
    for later in midpoint..midpoint + 64 {
        resumed
            .push(record(later))
            .unwrap_or_else(|error| panic!("push {later}: {error}"));
    }
    for each in 0..midpoint + 64 {
        uninterrupted
            .push(record(each))
            .unwrap_or_else(|error| panic!("push {each}: {error}"));
    }

    let left = uninterrupted
        .export(FaultReplayMode::RecomputedCause)
        .unwrap_or_else(|error| panic!("uninterrupted export: {error}"));
    let right = resumed
        .export(FaultReplayMode::RecomputedCause)
        .unwrap_or_else(|error| panic!("resumed export: {error}"));
    assert_eq!(left.manifest(), right.manifest());
    assert!(!left.manifest().segments().is_empty());
}

#[test]
fn replay_compares_every_record_and_skips_a_committed_prefix() {
    let store = SharedSegmentStore::new();
    let mut expected_log = log_in(&store);
    for sequence in 0..4 {
        expected_log
            .push(record(sequence))
            .unwrap_or_else(|error| panic!("push: {error}"));
    }
    let expected = expected_log
        .export(FaultReplayMode::RecomputedCause)
        .unwrap_or_else(|error| panic!("export: {error}"));

    let mut committed = log_in(&store);
    for sequence in 0..2 {
        committed
            .push(record(sequence))
            .unwrap_or_else(|error| panic!("push: {error}"));
    }
    let mut replay = CampaignRecordReplay::new(expected.clone(), FaultResourceLimits::default())
        .unwrap_or_else(|error| panic!("replay: {error}"));
    replay
        .skip_committed(&committed)
        .unwrap_or_else(|error| panic!("skip: {error}"));
    assert!(replay.consume_expected(&record(3)).is_err());
    replay
        .consume_expected(&record(2))
        .unwrap_or_else(|error| panic!("third record: {error}"));
    assert!(!replay.exhausted());
    replay
        .consume_expected(&record(3))
        .unwrap_or_else(|error| panic!("fourth record: {error}"));
    assert!(replay.exhausted());
    assert!(replay.consume_expected(&record(4)).is_err());
    assert_eq!(exported_records(&expected_log).len(), 4);

    let mut diverged = log_in(&store);
    diverged
        .push(record(1))
        .unwrap_or_else(|error| panic!("push: {error}"));
    let mut fresh = CampaignRecordReplay::new(expected, FaultResourceLimits::default())
        .unwrap_or_else(|error| panic!("replay: {error}"));
    assert!(fresh.skip_committed(&diverged).is_err());
}
