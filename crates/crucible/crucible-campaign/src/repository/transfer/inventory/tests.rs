//! Page spooling, inventory replay, closure folding, and spilled reachability.

// crucible-lint: allow panic-shortcut -- fixture failures localize exact spill behavior.
#![allow(clippy::expect_used)]

use crucible_store::content_store::{
    ObjectProfile, Reconstructibility, RetentionRole, SensitivityClass,
};

use super::*;

fn id(seed: u32) -> ContentId {
    ContentId::for_bytes(ObjectKind::Observation, 1, &seed.to_be_bytes())
}

fn entry(id: ContentId) -> ArchiveObjectEntry {
    ArchiveObjectEntry::from_profile(
        id,
        ObjectProfile::new(
            id.kind(),
            u64::from(id.digest()[0]),
            SensitivityClass::Evidence,
            Reconstructibility::Canonical,
            RetentionRole::Evidence,
        ),
    )
}

fn sorted_entries(count: u32) -> Vec<ArchiveObjectEntry> {
    let mut ids = (0..count).map(id).collect::<Vec<_>>();
    ids.sort();
    ids.into_iter().map(entry).collect()
}

fn storages(parent: &std::path::Path) -> [SpillStorage; 2] {
    [
        SpillStorage::directory(parent, ".crucible-test-archive-spill").expect("spill directory"),
        SpillStorage::Memory,
    ]
}

fn replay(cursor: &mut InventoryCursor<'_, '_>) -> Vec<ArchiveObjectEntry> {
    let mut entries = Vec::new();
    while let Some(entry) = cursor.next_entry().expect("replay entry") {
        entries.push(entry);
    }
    entries
}

#[test]
fn spooled_pages_replay_across_page_boundaries_with_the_canonical_digest() {
    let parent = tempfile::tempdir().expect("spill parent");
    let entries = sorted_entries(2 * MAX_ARCHIVE_INVENTORY_PAGE_ENTRIES as u32 + 3);
    for storage in storages(parent.path()) {
        let mut spooler =
            PageSpooler::new(&storage, ArchiveInventoryDisposition::Omitted).expect("spooler");
        for entry in &entries {
            spooler.push(*entry).expect("spool entry");
        }

        let spooled = spooler.finish().expect("finish spool");
        let summary = spooled.summary().expect("second-pass digest");
        let mut cursor = InventoryCursor::spool(
            &spooled.file,
            &spooled.pages,
            ArchiveInventoryDisposition::Omitted,
        )
        .expect("open spool");

        assert_eq!(spooled.pages.len(), 3);
        assert_eq!(summary, InventorySummary::of(&entries));
        assert_eq!(replay(&mut cursor), entries);
    }
}

#[test]
fn spool_replay_fails_closed_when_pages_disagree_with_the_manifest() {
    let entries = sorted_entries(MAX_ARCHIVE_INVENTORY_PAGE_ENTRIES as u32 + 1);
    let mut spooler =
        PageSpooler::new(&SpillStorage::Memory, ArchiveInventoryDisposition::Selected)
            .expect("spooler");
    for entry in &entries {
        spooler.push(*entry).expect("spool entry");
    }
    let spooled = spooler.finish().expect("finish spool");

    let mut swapped = spooled.pages.clone();
    swapped.swap(0, 1);
    let mut reordered = InventoryCursor::spool(
        &spooled.file,
        &swapped,
        ArchiveInventoryDisposition::Selected,
    )
    .expect("open spool");
    let mut truncated = InventoryCursor::spool(
        &spooled.file,
        &spooled.pages[..1],
        ArchiveInventoryDisposition::Selected,
    )
    .expect("open spool");
    let mut wrong_disposition = InventoryCursor::spool(
        &spooled.file,
        &spooled.pages,
        ArchiveInventoryDisposition::Omitted,
    )
    .expect("open spool");

    for cursor in [&mut reordered, &mut truncated, &mut wrong_disposition] {
        let failure = loop {
            match cursor.next_entry() {
                Ok(Some(_)) => {}
                Ok(None) => panic!("an inconsistent spool replayed to completion"),
                Err(error) => break error,
            }
        };
        assert!(matches!(failure, CampaignRepositoryError::Integrity { .. }));
    }
}

#[test]
fn closure_cursor_folds_repeated_identities_and_their_exact_flags() {
    let parent = tempfile::tempdir().expect("spill parent");
    for storage in storages(parent.path()) {
        let mut spill = ClosureSpill::new(&storage);
        for (seed, exact_leaf) in [(3, false), (1, false), (3, true), (2, true), (1, false)] {
            spill.push(id(seed), exact_leaf).expect("spill closure id");
        }
        let file = spill.finish().expect("sort closure");
        let mut expected = vec![(id(1), false), (id(2), true), (id(3), true)];
        expected.sort();

        let mut cursor = ClosureCursor::open(&file).expect("open closure");
        let mut folded = Vec::new();
        while let Some(item) = cursor.next().expect("next closure id") {
            folded.push(item);
        }

        assert_eq!(folded, expected);
    }
}

#[test]
fn reachability_follows_spilled_edges_from_the_root_only() {
    let parent = tempfile::tempdir().expect("spill parent");
    // 0 -> 1 -> 2 -> 3 and 1 -> 3 form the reachable part, with a cycle back
    // to 0; 4 -> 5 and 6 -> 0 are unreachable from 0.
    let edges = [(0, 1), (1, 2), (2, 3), (1, 3), (3, 0), (4, 5), (6, 0)];
    for storage in storages(parent.path()) {
        let mut spill = EdgeSpill::new(&storage);
        for (parent_seed, child_seed) in edges {
            spill
                .push(id(parent_seed), id(child_seed))
                .expect("spill edge");
        }
        let edges = spill.finish().expect("sort edges");

        let reachable = reachable_from(&storage, id(0), &edges).expect("reachability");

        let mut members = IdMembership::open(&reachable).expect("open reachable set");
        let mut found = Vec::new();
        while let Some(member) = members.next().expect("next reachable id") {
            found.push(member);
        }
        let mut expected = [0, 1, 2, 3].map(id).to_vec();
        expected.sort();
        assert_eq!(found, expected);
    }
}
