//! Certifies immutable root DAGs and caches exact nested-root heights.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::{Error, Roots};
use crate::identity::Digest;
use crate::tree_builder::{StoredNode, Tree};
use crate::tree_format::{EntryKind, MAX_GRAFT_DEPTH, NodeItems};

/// Counts graph admission independently of persistent map mutation work.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GraphWork {
    /// Previously uncertified root graphs visited.
    pub roots: usize,
    /// Previously uncertified Merkle nodes expanded.
    pub nodes: usize,
}

/// A reusable certificate registry for immutable roots and their shared nodes.
///
/// Root heights include the root itself; node heights measure the deepest root
/// target beneath that Merkle node. These distinct summaries allow a changed
/// parent to reuse certified unchanged nodes without conservative depth bounds.
/// The depth cap counts graft edges, allowing 65 roots along a 64-edge path.
#[derive(Clone, Debug, Default)]
pub struct RootGraph {
    roots: BTreeMap<Digest, usize>,
    nodes: BTreeMap<Digest, usize>,
    root_conflicts: BTreeMap<Digest, bool>,
    node_conflicts: BTreeMap<Digest, bool>,
}

impl RootGraph {
    /// Creates an empty graph-certificate registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Admits a root, rejecting cycles and caching its exact nesting depth.
    ///
    /// Newly changed Merkle frontiers are traversed once. Already certified
    /// immutable nodes and roots are skipped on subsequent admissions.
    ///
    /// # Errors
    /// Returns `MissingRoot` for an unavailable target, `RootIdentity` for a
    /// resolver returning another root, or `Cycle` for a cycle or excessive
    /// nested-root depth. Partial certificates describe only valid subgraphs.
    pub fn admit<'a>(
        &mut self,
        tree: &Tree<'a>,
        roots: &impl Roots<'a>,
    ) -> Result<GraphWork, Error> {
        let mut work = GraphWork::default();
        self.root_height(tree, roots, &mut Vec::new(), &mut work)?;
        Ok(work)
    }

    /// Returns the enclosing graph's conflict state for an admitted root.
    ///
    /// Returns `None` when the identity has not yet been certified.
    pub fn conflicted(&self, identity: &Digest) -> Option<bool> {
        self.root_conflicts.get(identity).copied()
    }

    fn root_height<'a>(
        &mut self,
        tree: &Tree<'a>,
        roots: &impl Roots<'a>,
        path: &mut Vec<Digest>,
        work: &mut GraphWork,
    ) -> Result<usize, Error> {
        let identity = tree.root_identity();
        if path.contains(&identity) || path.len() > MAX_GRAFT_DEPTH {
            return Err(Error::Cycle);
        }
        let height = if let Some(height) = self.roots.get(&identity) {
            *height
        } else {
            work.roots += 1;
            path.push(identity);
            let height = 1 + self.node_height(tree.root(), roots, path, work)?;
            path.pop();
            self.root_conflicts.insert(
                identity,
                self.node_conflicts.get(&identity).copied().unwrap_or(false),
            );
            self.roots.insert(identity, height);
            height
        };
        if path.len() + height > MAX_GRAFT_DEPTH + 1 {
            return Err(Error::Cycle);
        }
        Ok(height)
    }

    fn node_height<'a>(
        &mut self,
        node: &StoredNode<'a>,
        roots: &impl Roots<'a>,
        path: &mut Vec<Digest>,
        work: &mut GraphWork,
    ) -> Result<usize, Error> {
        if let Some(height) = self.nodes.get(&node.identity()) {
            if path.len() + height > MAX_GRAFT_DEPTH + 1 {
                return Err(Error::Cycle);
            }
            return Ok(*height);
        }
        work.nodes += 1;
        let mut height = 0;
        let mut conflicted = false;
        match node.items() {
            NodeItems::Internal(_) => {
                for child in node.children() {
                    height = height.max(self.node_height(child, roots, path, work)?);
                    conflicted |= self
                        .node_conflicts
                        .get(&child.identity())
                        .copied()
                        .unwrap_or(false);
                }
            }
            NodeItems::Leaf(items) => {
                for item in items {
                    let mut entries = alloc::vec![&item.entry];
                    while let Some(entry) = entries.pop() {
                        match &entry.kind {
                            EntryKind::Tree { root, .. } => {
                                let target = roots.resolve(root).ok_or(Error::MissingRoot)?;
                                if target.root_identity() != *root {
                                    return Err(Error::RootIdentity);
                                }
                                height = height.max(self.root_height(target, roots, path, work)?);
                                conflicted |=
                                    self.root_conflicts.get(root).copied().unwrap_or(false);
                            }
                            EntryKind::Conflict { candidates, base } => {
                                conflicted = true;
                                entries.extend(candidates);
                                if let Some(Some(base)) = base {
                                    entries.push(base);
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        self.node_conflicts.insert(node.identity(), conflicted);
        self.nodes.insert(node.identity(), height);
        Ok(height)
    }
}
