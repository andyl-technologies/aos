//! Measures ordered immutable node/item frontiers without flattening graft hops.
//!
//! Every exposed physical item is charged even when its logical state is equal.
//! Equal node identities can be removed without opening their entries. Key
//! bounds are read only for unequal frontiers; finding a first key charges each actual
//! internal/leaf access rather than assuming constant unmeasured work.

use alloc::vec;
use alloc::vec::Vec;

use super::accounting::Recorder;
use super::{Cut, Error, PhysicalEventKind};
use crate::identity::Digest;
use crate::tree_builder::StoredNode;
use crate::tree_format::{LeafItem, NodeItems};

/// A closed immutable subtree or an exposed local leaf item.
#[derive(Clone)]
pub(super) enum Part<'tree, 'value> {
    /// A physical subtree that has not exposed its entries.
    Node {
        /// Borrowed canonical physical node.
        node: &'tree StoredNode<'value>,
        /// Last-key cut supplied by the parent reference or directly read root.
        last: Option<Vec<u8>>,
    },
    /// One exposed full-key namespace entry.
    Item(&'tree LeafItem<'value>),
}

impl Part<'_, '_> {
    /// Reads a frontier's first key only after equal identities have been skipped.
    ///
    /// # Errors
    /// Rejects measured work overflow.
    pub(super) fn key(&self, work: &mut Recorder) -> Result<Vec<u8>, Error> {
        match self {
            Self::Node { node, .. } => Ok(first(node, work)?.unwrap_or_default()),
            Self::Item(item) => {
                work.charge(0, PhysicalEventKind::ItemRead, 1)?;
                Ok(item.key.clone())
            }
        }
    }

    /// Returns the actual physical level, zero for exposed entries.
    pub(super) fn level(&self) -> u8 {
        match self {
            Self::Node { node, .. } => node.level(),
            Self::Item(_) => 0,
        }
    }

    /// Borrows an actual last-key physical cut without exposing leaf entries.
    pub(super) fn cut(&self, source: Digest) -> Option<Cut> {
        match self {
            Self::Node { node, last } => Some(Cut {
                source,
                node: node.identity(),
                level: node.level(),
                last: last.clone(),
            }),
            Self::Item(_) => None,
        }
    }
}

/// An ordered local namespace stream with lazy subtree expansion.
pub(super) struct Frontier<'tree, 'value> {
    parts: Vec<Part<'tree, 'value>>,
}

impl<'tree, 'value> Frontier<'tree, 'value> {
    /// Seeds a changed-root frontier and charges its actual boundary lookup.
    ///
    /// # Errors
    /// Rejects measured work overflow.
    pub(super) fn new(root: &'tree StoredNode<'value>, work: &mut Recorder) -> Result<Self, Error> {
        work.charge(root.level(), PhysicalEventKind::NodeRead, 1)?;
        match root.items() {
            NodeItems::Leaf(items) if !items.is_empty() => {
                work.charge(0, PhysicalEventKind::ItemRead, 1)?
            }
            NodeItems::Internal(items) if !items.is_empty() => {
                work.charge(root.level(), PhysicalEventKind::ChildRead, 1)?
            }
            _ => {}
        }
        Ok(Self {
            parts: vec![Part::Node {
                node: root,
                last: root.last_key().map(<[u8]>::to_vec),
            }],
        })
    }

    /// Borrows the next unopened node or exposed entry.
    pub(super) fn top(&self) -> Option<&Part<'tree, 'value>> {
        self.parts.last()
    }

    /// Discards a skipped subtree or consumed entry.
    pub(super) fn pop(&mut self) {
        self.parts.pop();
    }

    /// Opens the next physical node and charges every exposed item.
    ///
    /// # Errors
    /// Rejects physical work counter overflow.
    pub(super) fn expand(&mut self, work: &mut Recorder) -> Result<(), Error> {
        let Some(Part::Node { node, .. }) = self.parts.pop() else {
            return Ok(());
        };
        work.charge(node.level(), PhysicalEventKind::NodeRead, 1)?;
        match node.items() {
            NodeItems::Leaf(items) => {
                work.charge(0, PhysicalEventKind::ItemRead, items.len())?;
                self.parts.extend(items.iter().rev().map(Part::Item));
            }
            NodeItems::Internal(children) => {
                work.charge(node.level(), PhysicalEventKind::ChildRead, children.len())?;
                // Leaf keys remain unread until an unequal frontier needs them.
                for (child, reference) in node.children().iter().zip(children).rev() {
                    self.parts.push(Part::Node {
                        node: child,
                        last: Some(reference.last_key.clone()),
                    });
                }
            }
        }
        Ok(())
    }

    /// Returns one leaf item while charging required physical node expansions.
    ///
    /// # Errors
    /// Rejects physical work counter overflow.
    pub(super) fn next(
        &mut self,
        work: &mut Recorder,
    ) -> Result<Option<&'tree LeafItem<'value>>, Error> {
        loop {
            match self.top() {
                None => return Ok(None),
                Some(Part::Node { .. }) => self.expand(work)?,
                Some(Part::Item(item)) => {
                    let item = *item;
                    self.pop();
                    return Ok(Some(item));
                }
            }
        }
    }
}

fn first(node: &StoredNode<'_>, work: &mut Recorder) -> Result<Option<Vec<u8>>, Error> {
    work.charge(node.level(), PhysicalEventKind::NodeRead, 1)?;
    match node.items() {
        NodeItems::Leaf(items) => {
            if let Some(item) = items.first() {
                work.charge(0, PhysicalEventKind::ItemRead, 1)?;
                Ok(Some(item.key.clone()))
            } else {
                Ok(None)
            }
        }
        NodeItems::Internal(_) => match node.children().first() {
            Some(child) => {
                work.charge(node.level(), PhysicalEventKind::ChildRead, 1)?;
                first(child, work)
            }
            None => Ok(None),
        },
    }
}

/// Charges actual repeated physical events without nominal size multiplication.
///
/// # Errors
/// Rejects counter overflow.
pub(super) fn add(counter: &mut usize, amount: usize) -> Result<(), Error> {
    *counter = counter.checked_add(amount).ok_or(Error::Limit)?;
    Ok(())
}
