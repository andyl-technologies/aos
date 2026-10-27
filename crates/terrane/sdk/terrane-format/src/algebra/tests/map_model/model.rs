//! Defines ordered-map namespace transformations and three-way policy semantics.

use alloc::boxed::Box;
use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use super::{Entry, EntryKind, Map, entry};
use crate::algebra::{Change, MergePolicy};
use crate::tree_format::LeafItem;

fn beneath(path: &[u8], prefix: &[u8]) -> bool {
    path.strip_prefix(prefix)
        .is_some_and(|suffix| suffix.first() == Some(&b'/'))
}

/// Replaces the selected entry and, with permission, removes its inline keys.
///
/// # Errors
/// Returns an error when inline descendants exist without replacement permission.
pub(super) fn graft(
    parent: &Map<'static>,
    at: &[u8],
    target: Entry<'static>,
    replace: bool,
) -> Result<Map<'static>, ()> {
    if !replace && parent.keys().any(|key| beneath(key, at)) {
        return Err(());
    }

    let mut result = parent.clone();
    result.retain(|key, _| !beneath(key, at));
    result.insert(at.to_vec(), target);
    Ok(result)
}

/// Extracts precisely the slash-delimited descendants with relative keys.
pub(super) fn split(parent: &Map<'static>, at: &[u8]) -> Map<'static> {
    parent
        .iter()
        .filter(|(key, _)| beneath(key, at))
        .map(|(key, entry)| (key[at.len() + 1..].to_vec(), entry.clone()))
        .collect()
}

/// Inlines target entries when independently supplied boundary facts agree.
///
/// # Errors
/// Returns an error when the fixture's effective boundary facts are incompatible.
///
/// # Panics
/// Panics if the supplied fixture does not contain the mount entry.
pub(super) fn flatten(
    parent: &Map<'static>,
    at: &[u8],
    target: &Map<'static>,
    compatible: bool,
) -> Result<Map<'static>, ()> {
    if !compatible {
        return Err(());
    }

    let mut result = parent.clone();
    let mut directory = result.get(at).unwrap().clone();
    directory.kind = EntryKind::Directory { mode: 0o755 };
    result.insert(at.to_vec(), directory);
    for (key, value) in target {
        if matches!(value.kind, EntryKind::Whiteout) {
            continue;
        }
        let mut path = at.to_vec();
        path.push(b'/');
        path.extend_from_slice(key);
        result.insert(path, value.clone());
    }
    Ok(result)
}

/// Applies ordered layer values and whiteout deletions from bottom to top.
pub(super) fn overlay(layers: &[&Map<'static>]) -> Map<'static> {
    let mut result = Map::new();
    for layer in layers.iter().rev() {
        for (key, value) in *layer {
            if matches!(value.kind, EntryKind::Whiteout) {
                result.remove(key);
            } else {
                result.insert(key.clone(), value.clone());
            }
        }
    }
    result
}

/// Enumerates the complete sorted union of keys with unequal optional values.
pub(super) fn diff(old: &Map<'static>, new: &Map<'static>) -> Vec<Change<'static>> {
    let keys: BTreeSet<_> = old.keys().chain(new.keys()).collect();
    keys.into_iter()
        .filter_map(|key| match (old.get(key), new.get(key)) {
            (None, Some(value)) => Some(Change::Added(LeafItem {
                key: key.clone(),
                entry: value.clone(),
            })),
            (Some(value), None) => Some(Change::Removed(LeafItem {
                key: key.clone(),
                entry: value.clone(),
            })),
            (Some(old), Some(new)) if old != new => Some(Change::Modified {
                path: key.clone(),
                old: old.clone(),
                new: new.clone(),
            }),
            _ => None,
        })
        .collect()
}

/// Independent fixture facts authenticated by the signed SUT input histories.
#[derive(Clone, Copy)]
pub(super) struct Evidence {
    /// Whether each side's original signing capability contains the baseline group.
    pub(super) baseline: [bool; 2],
    /// Introducing commit times in the same ordered side pair.
    pub(super) timestamps: [u64; 2],
}

/// Resolves optional values independently for every key in the three-map union.
///
/// # Errors
/// Returns an error when the ordered policy list reaches `error` for a conflict.
pub(super) fn merge(
    base: &Map<'static>,
    ours: &Map<'static>,
    theirs: &Map<'static>,
    policies: &[MergePolicy],
    evidence: Evidence,
) -> Result<Map<'static>, ()> {
    let keys: BTreeSet<_> = base
        .keys()
        .chain(ours.keys())
        .chain(theirs.keys())
        .collect();
    let mut result = Map::new();
    for key in keys {
        let original = base.get(key);
        let left = ours.get(key);
        let right = theirs.get(key);
        let value = if left == right || right == original {
            left.cloned()
        } else if left == original {
            right.cloned()
        } else {
            resolve(original, [left, right], policies, evidence)?
        };
        if let Some(value) = value {
            result.insert(key.clone(), value);
        }
    }
    Ok(result)
}

fn resolve(
    base: Option<&Entry<'static>>,
    sides: [Option<&Entry<'static>>; 2],
    policies: &[MergePolicy],
    evidence: Evidence,
) -> Result<Option<Entry<'static>>, ()> {
    for policy in policies {
        let selected = match policy {
            MergePolicy::PreferOurs => Some(0),
            MergePolicy::PreferTheirs => Some(1),
            MergePolicy::PreferTrusted => {
                match [
                    sides[0].is_some() && evidence.baseline[0],
                    sides[1].is_some() && evidence.baseline[1],
                ] {
                    [true, false] => Some(0),
                    [false, true] => Some(1),
                    _ => None,
                }
            }
            MergePolicy::PreferNewer if sides.iter().all(Option::is_some) => {
                match evidence.timestamps[0].cmp(&evidence.timestamps[1]) {
                    core::cmp::Ordering::Greater => Some(0),
                    core::cmp::Ordering::Less => Some(1),
                    core::cmp::Ordering::Equal => None,
                }
            }
            MergePolicy::PreferNewer => None,
            MergePolicy::KeepConflict => break,
            MergePolicy::Error => return Err(()),
        };
        if let Some(side) = selected {
            return Ok(sides[side].cloned());
        }
    }

    let mut candidates = Vec::new();
    for side in sides {
        match side {
            Some(Entry {
                kind:
                    EntryKind::Conflict {
                        candidates: previous,
                        ..
                    },
                ..
            }) => candidates.extend(previous.clone()),
            Some(value) => candidates.push(value.clone()),
            None => candidates.push(entry(EntryKind::Whiteout)),
        }
    }
    Ok(Some(entry(EntryKind::Conflict {
        candidates,
        base: Some(base.cloned().map(Box::new)),
    })))
}
