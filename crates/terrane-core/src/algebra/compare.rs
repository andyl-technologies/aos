//! Compares Merkle frontiers without visiting shared subtree entries.

use alloc::rc::Rc;
use alloc::vec;
use alloc::vec::Vec;

use crate::tree_builder::{StoredNode, Tree};
use crate::tree_format::{Entry, LeafItem, NodeItems, Property};

/// A deterministic path-ordered change between two trees.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Change<'a> {
    /// Introduces a value absent from the old tree.
    Added(LeafItem<'a>),
    /// Removes a value present in the old tree.
    Removed(LeafItem<'a>),
    /// Replaces a value, including its metadata and provenance.
    Modified {
        /// Root-relative path of the changed value.
        path: Vec<u8>,
        /// Previous complete value.
        old: Entry<'a>,
        /// Replacement complete value.
        new: Entry<'a>,
    },
}

impl Change<'_> {
    /// Returns the root-relative path of the change.
    pub fn path(&self) -> &[u8] {
        match self {
            Self::Added(item) | Self::Removed(item) => &item.key,
            Self::Modified { path, .. } => path,
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct NodeHandle<'t, 'a> {
    node: &'t StoredNode<'a>,
    pub(super) shared: Option<&'t Rc<StoredNode<'a>>>,
}

impl NodeHandle<'_, '_> {
    pub(super) fn identity(&self) -> crate::identity::Digest {
        self.shared
            .map_or_else(|| self.node.identity(), |shared| shared.identity())
    }
}

impl<'a> core::ops::Deref for NodeHandle<'_, 'a> {
    type Target = StoredNode<'a>;

    fn deref(&self) -> &Self::Target {
        self.node
    }
}

#[derive(Clone, Copy)]
pub(super) enum Part<'t, 'a> {
    Node(NodeHandle<'t, 'a>),
    Item(&'t LeafItem<'a>),
}

impl<'t, 'a> Part<'t, 'a> {
    pub(super) fn first_key(self) -> &'t [u8] {
        match self {
            Self::Item(item) => &item.key,
            Self::Node(node) => first_key(node.node),
        }
    }
}

fn first_key<'t>(node: &'t StoredNode<'_>) -> &'t [u8] {
    match node.items() {
        NodeItems::Leaf(items) => items.first().map_or(&[], |item| item.key.as_slice()),
        NodeItems::Internal(_) => node
            .children()
            .first()
            .map_or(&[], |child| first_key(child)),
    }
}

pub(super) struct Frontier<'t, 'a> {
    pub(super) parts: Vec<Part<'t, 'a>>,
    pub(super) expanded_nodes: usize,
}

impl<'t, 'a> Frontier<'t, 'a> {
    pub(super) fn new(tree: &'t Tree<'a>) -> Self {
        Self {
            parts: vec![Part::Node(NodeHandle {
                node: tree.root(),
                shared: None,
            })],
            expanded_nodes: 0,
        }
    }

    pub(super) fn top(&self) -> Option<Part<'t, 'a>> {
        self.parts.last().copied()
    }

    pub(super) fn expand(&mut self) {
        if let Some(Part::Node(node)) = self.parts.pop() {
            self.expanded_nodes += 1;
            match node.node.items() {
                NodeItems::Leaf(items) => self.parts.extend(items.iter().rev().map(Part::Item)),
                NodeItems::Internal(_) => {
                    self.parts
                        .extend(node.node.children().iter().rev().map(|child| {
                            Part::Node(NodeHandle {
                                node: child,
                                shared: Some(child),
                            })
                        }))
                }
            }
        }
    }

    pub(super) fn next_item(&mut self) -> Option<&'t LeafItem<'a>> {
        loop {
            match self.top()? {
                Part::Node(_) => self.expand(),
                Part::Item(item) => {
                    self.parts.pop();
                    return Some(item);
                }
            }
        }
    }
}

/// Produces ordered changes while skipping every aligned identical subtree.
///
/// Graft target changes remain a single value change at the graft path.
/// Callers requesting target descent can apply this function recursively to
/// the referenced pair of roots without reading unchanged targets.
pub fn diff<'a>(old: &Tree<'a>, new: &Tree<'a>) -> Vec<Change<'a>> {
    diff_with_work(old, new).changes
}

/// A change set together with observable Merkle traversal work.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiffResult<'a> {
    /// Changes in ascending bytewise path order.
    pub changes: Vec<Change<'a>>,
    /// Nodes expanded across both input frontiers, excluding skipped nodes.
    pub expanded_nodes: usize,
    /// Root property changes, separate from path entry changes.
    pub properties: Option<RootPropertiesChange<'a>>,
}

/// Previous and replacement root property maps, preserving absent versus empty.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootPropertiesChange<'a> {
    /// Property map attached to the old root.
    pub old: Option<Vec<Property<'a>>>,
    /// Property map attached to the replacement root.
    pub new: Option<Vec<Property<'a>>>,
}

/// Produces a diff and counts node expansions for locality verification.
pub fn diff_with_work<'a>(old: &Tree<'a>, new: &Tree<'a>) -> DiffResult<'a> {
    let mut before = Frontier::new(old);
    let mut after = Frontier::new(new);
    let mut changes = Vec::new();

    loop {
        match (before.top(), after.top()) {
            (None, None) => break,
            (None, Some(_)) => {
                if let Some(item) = after.next_item() {
                    changes.push(Change::Added(item.clone()));
                }
            }
            (Some(_), None) => {
                if let Some(item) = before.next_item() {
                    changes.push(Change::Removed(item.clone()));
                }
            }
            (Some(Part::Node(left)), Some(Part::Node(right)))
                if left.identity() == right.identity() =>
            {
                before.parts.pop();
                after.parts.pop();
            }
            (Some(left), Some(right)) => match left.first_key().cmp(right.first_key()) {
                core::cmp::Ordering::Less => match left {
                    Part::Node(_) => before.expand(),
                    Part::Item(item) => {
                        before.parts.pop();
                        changes.push(Change::Removed(item.clone()));
                    }
                },
                core::cmp::Ordering::Greater => match right {
                    Part::Node(_) => after.expand(),
                    Part::Item(item) => {
                        after.parts.pop();
                        changes.push(Change::Added(item.clone()));
                    }
                },
                core::cmp::Ordering::Equal => match (left, right) {
                    (Part::Node(_), _) => before.expand(),
                    (_, Part::Node(_)) => after.expand(),
                    (Part::Item(left), Part::Item(right)) => {
                        before.parts.pop();
                        after.parts.pop();
                        if left.entry != right.entry {
                            changes.push(Change::Modified {
                                path: left.key.clone(),
                                old: left.entry.clone(),
                                new: right.entry.clone(),
                            });
                        }
                    }
                },
            },
        }
    }

    DiffResult {
        changes,
        expanded_nodes: before.expanded_nodes + after.expanded_nodes,
        properties: (old.props() != new.props()).then(|| RootPropertiesChange {
            old: old.props().map(<[_]>::to_vec),
            new: new.props().map(<[_]>::to_vec),
        }),
    }
}

/// A property-map change at an implied root within a descended view.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathPropertiesChange<'a> {
    /// Graft path, or an empty path for the top-level implied root.
    pub path: Vec<u8>,
    /// Previous and replacement optional property maps.
    pub properties: RootPropertiesChange<'a>,
}

/// Descended entry changes, implied-root property changes, and traversal work.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DescendedDiffResult<'a> {
    /// Changes ordered by globally prefixed paths.
    pub changes: Vec<Change<'a>>,
    /// Property changes at each visited implied root.
    pub properties: Vec<PathPropertiesChange<'a>>,
    /// Expanded Merkle nodes across all visited root pairs.
    pub expanded_nodes: usize,
}

/// Returns globally prefixed entry changes across changed graft targets.
///
/// Use [`diff_descend_with_work`] to also inspect implied-root property changes.
///
/// # Errors
/// Returns unavailable-target or excessive-depth errors from descended diff.
pub fn diff_descend<'a>(
    old: &Tree<'a>,
    new: &Tree<'a>,
    roots: &impl super::Roots<'a>,
) -> Result<Vec<Change<'a>>, super::Error> {
    Ok(diff_descend_with_work(old, new, roots)?.changes)
}

/// Expands changed graft targets into globally prefixed, ordered changes.
///
/// Changes to the graft's metadata remain visible at its own path; target-only
/// changes descend instead of emitting that graft's single modified value.
///
/// # Errors
/// Returns `MissingRoot` when a changed target is unavailable, `RootIdentity`
/// when the resolver returns a different target, or `Cycle` when
/// recursive target descent exceeds the permitted nested-root depth.
pub fn diff_descend_with_work<'a>(
    old: &Tree<'a>,
    new: &Tree<'a>,
    roots: &impl super::Roots<'a>,
) -> Result<DescendedDiffResult<'a>, super::Error> {
    fn descend<'a>(
        old: &Tree<'a>,
        new: &Tree<'a>,
        roots: &impl super::Roots<'a>,
        prefix: &[u8],
        depth: usize,
        output: &mut DescendedDiffResult<'a>,
    ) -> Result<(), super::Error> {
        if depth > crate::tree_format::MAX_GRAFT_DEPTH {
            return Err(super::Error::Cycle);
        }
        let local = diff_with_work(old, new);
        output.expanded_nodes += local.expanded_nodes;
        if let Some(properties) = local.properties {
            let mut path = prefix.to_vec();
            if path.last() == Some(&b'/') {
                path.pop();
            }
            output
                .properties
                .push(PathPropertiesChange { path, properties });
        }
        for change in local.changes {
            let mut path = prefix.to_vec();
            path.extend_from_slice(change.path());
            match change {
                Change::Modified { old, new, .. } => {
                    if let (
                        crate::tree_format::EntryKind::Tree { root: before, .. },
                        crate::tree_format::EntryKind::Tree { root: after, .. },
                    ) = (&old.kind, &new.kind)
                        && before != after
                    {
                        let before_tree = roots.resolve(before).ok_or(super::Error::MissingRoot)?;
                        let after_tree = roots.resolve(after).ok_or(super::Error::MissingRoot)?;
                        if before_tree.root_identity() != *before
                            || after_tree.root_identity() != *after
                        {
                            return Err(super::Error::RootIdentity);
                        }

                        let mut normalized = old.clone();
                        if let crate::tree_format::EntryKind::Tree { root, .. } =
                            &mut normalized.kind
                        {
                            *root = *after;
                        }
                        if normalized != new {
                            output.changes.push(Change::Modified {
                                path: path.clone(),
                                old,
                                new,
                            });
                        }
                        path.push(b'/');
                        descend(before_tree, after_tree, roots, &path, depth + 1, output)?;
                        continue;
                    }
                    output.changes.push(Change::Modified { path, old, new });
                }
                Change::Added(mut item) => {
                    item.key = path;
                    output.changes.push(Change::Added(item));
                }
                Change::Removed(mut item) => {
                    item.key = path;
                    output.changes.push(Change::Removed(item));
                }
            }
        }
        Ok(())
    }

    let mut output = DescendedDiffResult {
        changes: Vec::new(),
        properties: Vec::new(),
        expanded_nodes: 0,
    };
    descend(old, new, roots, &[], 0, &mut output)?;
    output
        .changes
        .sort_by(|left, right| left.path().cmp(right.path()));
    Ok(output)
}
