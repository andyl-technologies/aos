//! Paged pin-retention inventory reads.

// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts.
#![allow(clippy::expect_used)]

use std::collections::BTreeMap;

use super::*;
use crate::repository::tests::fixture;
use crate::{CampaignCommandId, PinChange};

const CAMPAIGN: &str = "pin-retention-pages";

/// Creates a campaign whose genesis carries one exact pin.
fn pinned_campaign() -> (CampaignRepository, CampaignSnapshotId, CampaignSnapshotId) {
    let (repository, lineage, policy) = fixture();
    let genesis = repository
        .create(CAMPAIGN, &lineage, &policy, &BTreeMap::new())
        .expect("create campaign");
    let pin = PinRequest {
        command: CampaignCommandId::from_hash(CampaignHash::derive("test", b"paged-pin")),
        expected_snapshot: genesis.snapshot_id(),
        change: PinChange::new(lineage.genesis(), Some(PinRetention::Exact), "paged")
            .expect("exact pin"),
    };
    let pinned = repository.apply_pin(CAMPAIGN, &pin).expect("apply pin");
    (repository, genesis.snapshot_id(), pinned.new_snapshot)
}

#[test]
fn pages_return_exactly_the_streamed_inventory() {
    let (repository, _genesis, snapshot) = pinned_campaign();
    let mut streamed = Vec::new();
    repository
        .visit_pin_retention_roots_at(snapshot, &mut |record| streamed.push(record))
        .expect("stream pin inventory");

    let mut paged = Vec::new();
    let mut cursor = None;
    loop {
        let page = repository
            .pin_retention_page_at(snapshot, cursor, 1)
            .expect("read pin page");
        paged.extend_from_slice(page.records());
        let Some(next) = page.next() else {
            break;
        };
        assert_eq!(next.snapshot(), snapshot);
        cursor = Some(next);
    }

    assert_eq!(streamed.len(), 1);
    assert_eq!(paged, streamed);
}

#[test]
fn page_after_the_last_entry_is_empty_and_final() {
    let (repository, _genesis, snapshot) = pinned_campaign();
    let page = repository
        .pin_retention_page_at(snapshot, None, MAX_PIN_RETENTION_PAGE_ENTRIES)
        .expect("read pin page");
    let last = page
        .records()
        .last()
        .map(|record| pin_configuration_key(record.request().change.configuration()))
        .expect("one pin");

    let after = CampaignPinRetentionCursor {
        snapshot,
        after: last,
    };
    let resumed = repository
        .pin_retention_page_at(snapshot, Some(after), 1)
        .expect("resume after last pin");

    assert!(resumed.records().is_empty());
    assert_eq!(resumed.next(), None);
}

#[test]
fn page_rejects_invalid_sizes_and_cursors_from_another_snapshot() {
    let (repository, genesis, snapshot) = pinned_campaign();
    let foreign = CampaignPinRetentionCursor {
        snapshot: genesis,
        after: CampaignHash::derive("test", b"foreign-cursor"),
    };

    for (maximum_entries, cursor, expected) in [
        (0, None, "pin-retention-page-size"),
        (
            MAX_PIN_RETENTION_PAGE_ENTRIES + 1,
            None,
            "pin-retention-page-size",
        ),
        (1, Some(foreign), "pin-retention-cursor-snapshot-mismatch"),
    ] {
        let result = repository.pin_retention_page_at(snapshot, cursor, maximum_entries);
        assert!(
            matches!(
                result,
                Err(CampaignRepositoryError::InvalidRequest { reason }) if reason == expected
            ),
            "{expected}: {result:?}"
        );
    }
}
