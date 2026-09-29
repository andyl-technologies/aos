//! Maintains hard-link set summaries in a persistent AVL index.
//!
//! The index is auxiliary memory, never part of canonical tree identity.
//! Point edits inspect and copy one search path instead of scanning leaves.

use super::Error;
use crate::tree_format::{Entry, EntryKind, LeafItem};
use alloc::{rc::Rc, vec::Vec};

pub(super) type Links<'a> = Option<Rc<Link<'a>>>;

#[derive(Clone, Debug)]
pub(super) struct Link<'a> {
    key: Vec<u8>,
    entry: Entry<'a>,
    count: u64,
    height: u8,
    left: Links<'a>,
    right: Links<'a>,
}

pub(super) fn link_id<'a>(entry: &Entry<'a>) -> Option<&'a [u8]> {
    match &entry.kind {
        EntryKind::File { link_id, .. } => *link_id,
        _ => None,
    }
}

fn same_value(left: &Entry<'_>, right: &Entry<'_>) -> bool {
    match (&left.kind, &right.kind) {
        (
            EntryKind::File {
                mode: lm,
                size: ls,
                content: lc,
                ..
            },
            EntryKind::File {
                mode: rm,
                size: rs,
                content: rc,
                ..
            },
        ) => {
            lm == rm
                && ls == rs
                && lc == rc
                && left.attrs == right.attrs
                && left.attrs_present == right.attrs_present
                && left.xattrs == right.xattrs
                && left.xattrs_present == right.xattrs_present
        }
        _ => false,
    }
}

fn height(link: &Links<'_>) -> u8 {
    link.as_ref().map_or(0, |node| node.height)
}

fn make<'a>(
    key: Vec<u8>,
    entry: Entry<'a>,
    count: u64,
    left: Links<'a>,
    right: Links<'a>,
) -> Rc<Link<'a>> {
    Rc::new(Link {
        height: 1 + height(&left).max(height(&right)),
        key,
        entry,
        count,
        left,
        right,
    })
}

fn balanced<'a>(node: Rc<Link<'a>>) -> Rc<Link<'a>> {
    if height(&node.left) > height(&node.right) + 1 {
        let Some(left) = node.left.as_ref() else {
            return node;
        };
        if height(&left.left) < height(&left.right) {
            let Some(middle) = left.right.as_ref() else {
                return node;
            };
            let lower_left = make(
                left.key.clone(),
                left.entry.clone(),
                left.count,
                left.left.clone(),
                middle.left.clone(),
            );
            let lower_right = make(
                node.key.clone(),
                node.entry.clone(),
                node.count,
                middle.right.clone(),
                node.right.clone(),
            );
            return make(
                middle.key.clone(),
                middle.entry.clone(),
                middle.count,
                Some(lower_left),
                Some(lower_right),
            );
        }
        let right = make(
            node.key.clone(),
            node.entry.clone(),
            node.count,
            left.right.clone(),
            node.right.clone(),
        );
        return make(
            left.key.clone(),
            left.entry.clone(),
            left.count,
            left.left.clone(),
            Some(right),
        );
    }
    if height(&node.right) > height(&node.left) + 1 {
        let Some(right) = node.right.as_ref() else {
            return node;
        };
        if height(&right.right) < height(&right.left) {
            let Some(middle) = right.left.as_ref() else {
                return node;
            };
            let lower_left = make(
                node.key.clone(),
                node.entry.clone(),
                node.count,
                node.left.clone(),
                middle.left.clone(),
            );
            let lower_right = make(
                right.key.clone(),
                right.entry.clone(),
                right.count,
                middle.right.clone(),
                right.right.clone(),
            );
            return make(
                middle.key.clone(),
                middle.entry.clone(),
                middle.count,
                Some(lower_left),
                Some(lower_right),
            );
        }
        let left = make(
            node.key.clone(),
            node.entry.clone(),
            node.count,
            node.left.clone(),
            right.left.clone(),
        );
        return make(
            right.key.clone(),
            right.entry.clone(),
            right.count,
            Some(left),
            right.right.clone(),
        );
    }
    node
}

fn find<'tree, 'a>(
    links: &'tree Links<'a>,
    key: &[u8],
    reads: &mut usize,
) -> Option<&'tree Link<'a>> {
    let mut current = links.as_deref();
    while let Some(node) = current {
        *reads += 1;
        match key.cmp(&node.key) {
            core::cmp::Ordering::Less => current = node.left.as_deref(),
            core::cmp::Ordering::Greater => current = node.right.as_deref(),
            core::cmp::Ordering::Equal => return Some(node),
        }
    }
    None
}

fn set<'a>(
    links: &Links<'a>,
    key: &[u8],
    entry: &Entry<'a>,
    count: u64,
    reads: &mut usize,
) -> Links<'a> {
    let Some(node) = links else {
        return Some(make(key.to_vec(), entry.clone(), count, None, None));
    };
    *reads += 1;
    let (left, right) = match key.cmp(&node.key) {
        core::cmp::Ordering::Less => (
            set(&node.left, key, entry, count, reads),
            node.right.clone(),
        ),
        core::cmp::Ordering::Greater => (
            node.left.clone(),
            set(&node.right, key, entry, count, reads),
        ),
        core::cmp::Ordering::Equal => {
            return Some(make(
                node.key.clone(),
                entry.clone(),
                count,
                node.left.clone(),
                node.right.clone(),
            ));
        }
    };
    Some(balanced(make(
        node.key.clone(),
        node.entry.clone(),
        node.count,
        left,
        right,
    )))
}

fn remove<'a>(links: &Links<'a>, key: &[u8], reads: &mut usize) -> Links<'a> {
    let node = links.as_ref()?;
    *reads += 1;
    let (left, right) = match key.cmp(&node.key) {
        core::cmp::Ordering::Less => (remove(&node.left, key, reads), node.right.clone()),
        core::cmp::Ordering::Greater => (node.left.clone(), remove(&node.right, key, reads)),
        core::cmp::Ordering::Equal => {
            if node.left.is_none() {
                return node.right.clone();
            }
            if node.right.is_none() {
                return node.left.clone();
            }
            let mut successor = node.right.as_deref()?;
            while let Some(left) = successor.left.as_deref() {
                *reads += 1;
                successor = left;
            }
            let right = remove(&node.right, &successor.key, reads);
            return Some(balanced(make(
                successor.key.clone(),
                successor.entry.clone(),
                successor.count,
                node.left.clone(),
                right,
            )));
        }
    };
    Some(balanced(make(
        node.key.clone(),
        node.entry.clone(),
        node.count,
        left,
        right,
    )))
}

pub(super) fn build<'a>(entries: &[LeafItem<'a>]) -> Result<Links<'a>, Error> {
    let mut links = None;
    let mut reads = 0;
    for item in entries {
        if let Some(id) = link_id(&item.entry) {
            let count = find(&links, id, &mut reads).map_or(0, |node| node.count);
            links = set(
                &links,
                id,
                &item.entry,
                count.checked_add(1).ok_or(Error::Limit)?,
                &mut reads,
            );
        }
    }
    Ok(links)
}

pub(super) fn update<'a>(
    links: &Links<'a>,
    key: &[u8],
    old: Option<&Entry<'a>>,
    new: Option<&Entry<'a>>,
    reads: &mut usize,
) -> Result<Links<'a>, Error> {
    let mut result = links.clone();
    let old_id = old.and_then(link_id);
    let new_id = new.and_then(link_id);
    if let Some(id) = old_id {
        let group = find(&result, id, reads).ok_or(Error::Tree)?;
        if group.count == 0 {
            return Err(Error::Tree);
        }
        if key == id && group.count > 1 && new_id != old_id {
            return Err(Error::Tree);
        }
        if new_id == old_id {
            let replacement = new.ok_or(Error::Tree)?;
            if group.count > 1 && !same_value(&group.entry, replacement) {
                return Err(Error::Tree);
            }
            return Ok(set(&result, id, replacement, group.count, reads));
        }
        result = if group.count == 1 {
            remove(&result, id, reads)
        } else {
            set(&result, id, &group.entry, group.count - 1, reads)
        };
    }
    if let Some(id) = new_id {
        let entry = new.ok_or(Error::Tree)?;
        let group = find(&result, id, reads);
        let count = group.map_or(0, |node| node.count);
        if count == 0 {
            if key != id {
                return Err(Error::Tree);
            }
        } else if key < id || !group.is_some_and(|node| same_value(&node.entry, entry)) {
            return Err(Error::Tree);
        }
        result = set(
            &result,
            id,
            entry,
            count.checked_add(1).ok_or(Error::Limit)?,
            reads,
        );
    }
    Ok(result)
}

pub(super) fn replace_changes<'a>(
    links: &Links<'a>,
    changes: &[super::splice::Change<'a>],
    tree: &super::Tree<'a>,
    reads: &mut usize,
) -> Result<Links<'a>, Error> {
    use alloc::collections::BTreeMap;
    let mut groups: BTreeMap<&[u8], (u64, Vec<&Entry<'a>>)> = BTreeMap::new();
    for change in changes {
        if let Some(id) = change.old.as_ref().and_then(link_id) {
            let group = groups.entry(id).or_default();
            group.0 = group.0.checked_add(1).ok_or(Error::Limit)?;
        }
        if let Some(entry) = &change.new
            && let Some(id) = link_id(entry)
        {
            if change.key.as_slice() < id {
                return Err(Error::Tree);
            }
            groups.entry(id).or_default().1.push(entry);
        }
    }
    let mut result = links.clone();
    for (id, (removed, added)) in groups {
        let old = find(links, id, reads);
        let remaining = old
            .map_or(0, |group| group.count)
            .checked_sub(removed)
            .ok_or(Error::Tree)?;
        let count = remaining
            .checked_add(added.len() as u64)
            .ok_or(Error::Limit)?;
        if count == 0 {
            result = remove(&result, id, reads);
            continue;
        }
        let first = super::mutation::lookup(tree, id, reads).ok_or(Error::Tree)?;
        if link_id(first) != Some(id)
            || (remaining > 0 && !old.is_some_and(|group| same_value(&group.entry, first)))
            || added.iter().any(|entry| !same_value(entry, first))
        {
            return Err(Error::Tree);
        }
        result = set(&result, id, first, count, reads);
    }
    Ok(result)
}
