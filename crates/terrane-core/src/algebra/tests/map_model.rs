//! Checks current trunk algebra against independently transformed ordered maps.
//!
//! Model operations never call Tree builders, mutations, or algebra operations.
//! Conversion prepares inputs or checks a canonical root only after map equality.

mod composition;
mod merge;
mod model;
mod traversal;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::{Entry, EntryKind, LeafItem, Tree, TreeUse, entry, fixture_properties};

type Map<'a> = BTreeMap<Vec<u8>, Entry<'a>>;

fn map(items: &[(&[u8], Entry<'static>)]) -> Map<'static> {
    items
        .iter()
        .map(|(key, value)| (key.to_vec(), value.clone()))
        .collect()
}

fn symlink(target: &'static [u8]) -> Entry<'static> {
    entry(EntryKind::Symlink { target })
}

fn build<'a>(entries: &Map<'a>) -> Tree<'a> {
    Tree::build(
        items(entries),
        fixture_properties(),
        4096,
        TreeUse::OverlayLayer,
    )
    .unwrap()
}

fn items<'a>(entries: &Map<'a>) -> Vec<LeafItem<'a>> {
    entries
        .iter()
        .map(|(key, entry)| LeafItem {
            key: key.clone(),
            entry: entry.clone(),
        })
        .collect()
}

fn assert_map(actual: &Tree<'_>, expected: &Map<'_>) {
    let observed: Map<'_> = actual
        .iter()
        .map(|item| (item.key.clone(), item.entry.clone()))
        .collect();
    assert_eq!(&observed, expected);

    // The builder checks representation only after the independent semantic oracle.
    let canonical = build(expected);
    assert_eq!(actual.root_identity(), canonical.root_identity());
}

pub(super) use composition::{
    diff_witness, flatten_witness, graft_witness, overlay_witness, split_witness,
};
pub(super) use merge::randomized_merge_witness;
pub(super) use traversal::equal_internal_subtree_witness;
