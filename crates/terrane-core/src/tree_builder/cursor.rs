//! Seeks and scans immutable nodes with a bounded root-to-leaf stack.

use alloc::vec::Vec;

use crate::tree_format::{LeafItem, NodeItems};

use super::{StoredNode, Tree};

/// An ordered leaf cursor that starts at an inclusive key lower bound.
pub struct Cursor<'tree, 'a> {
    nodes: LevelCursor<'tree, 'a>,
    leaf: Option<&'tree StoredNode<'a>>,
    position: usize,
}

impl<'tree, 'a> Cursor<'tree, 'a> {
    pub(super) fn new(tree: &'tree Tree<'a>, key: &[u8]) -> Self {
        let mut nodes = LevelCursor::seek(tree.root(), 0, key);
        let leaf = nodes.next();
        let position = match leaf.map(|node| node.items()) {
            Some(NodeItems::Leaf(items)) => items.partition_point(|item| item.key.as_slice() < key),
            _ => 0,
        };
        Self {
            nodes,
            leaf,
            position,
        }
    }

    pub(super) fn node_reads(&self) -> usize {
        self.nodes.reads
    }
}

impl<'tree, 'a> Iterator for Cursor<'tree, 'a> {
    type Item = &'tree LeafItem<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let NodeItems::Leaf(items) = self.leaf?.items() else {
                return None;
            };
            if let Some(item) = items.get(self.position) {
                self.position += 1;
                return Some(item);
            }
            self.leaf = self.nodes.next();
            self.position = 0;
        }
    }
}

impl core::iter::FusedIterator for Cursor<'_, '_> {}

/// A root-first depth-first iterator over immutable nodes.
pub struct Nodes<'tree, 'a> {
    stack: Vec<&'tree StoredNode<'a>>,
}

impl<'tree, 'a> Nodes<'tree, 'a> {
    pub(super) fn new(root: &'tree StoredNode<'a>) -> Self {
        Self {
            stack: alloc::vec![root],
        }
    }
}

impl<'tree, 'a> Iterator for Nodes<'tree, 'a> {
    type Item = &'tree StoredNode<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let node = self.stack.pop()?;
        self.stack
            .extend(node.children().iter().rev().map(|child| child.as_ref()));
        Some(node)
    }
}

impl core::iter::FusedIterator for Nodes<'_, '_> {}

pub(super) struct LevelCursor<'tree, 'a> {
    level: u8,
    stack: Vec<(&'tree StoredNode<'a>, usize)>,
    pub(super) next: Option<&'tree StoredNode<'a>>,
    pub(super) reads: usize,
}

impl<'tree, 'a> LevelCursor<'tree, 'a> {
    pub(super) fn seek(root: &'tree StoredNode<'a>, level: u8, key: &[u8]) -> Self {
        let mut cursor = Self {
            level,
            stack: Vec::new(),
            next: None,
            reads: 0,
        };
        let mut node = root;
        while node.level() > level {
            cursor.reads += 1;
            let index = node
                .children()
                .partition_point(|child| child.last_key().is_some_and(|last| last < key));
            // Point insertion beyond the last key begins in the final node.
            let index = index.min(node.children().len().saturating_sub(1));
            cursor.stack.push((node, index + 1));
            let Some(child) = node.children().get(index) else {
                return cursor;
            };
            node = child;
        }
        cursor.next = Some(node);
        cursor
    }

    pub(super) fn with_predecessor(mut self) -> Self {
        let original_stack = self.stack.clone();
        while let Some((parent, next_index)) = self.stack.pop() {
            if next_index <= 1 {
                continue;
            }
            let index = next_index - 2;
            self.stack.push((parent, index + 1));
            let Some(child) = parent.children().get(index) else {
                break;
            };
            let mut node = child.as_ref();
            while node.level() > self.level {
                self.reads += 1;
                let count = node.children().len();
                self.stack.push((node, count));
                let Some(child) = node.children().last() else {
                    break;
                };
                node = child;
            }
            self.next = Some(node);
            return self;
        }
        self.stack = original_stack;
        self
    }
}

impl<'tree, 'a> Iterator for LevelCursor<'tree, 'a> {
    type Item = &'tree StoredNode<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(node) = self.next.take() {
            self.reads += 1;
            return Some(node);
        }
        while let Some((parent, index)) = self.stack.pop() {
            let Some(child) = parent.children().get(index) else {
                continue;
            };
            self.stack.push((parent, index + 1));
            let mut node = child.as_ref();
            while node.level() > self.level {
                self.reads += 1;
                self.stack.push((node, 1));
                node = node.children().first()?.as_ref();
            }
            self.reads += 1;
            return Some(node);
        }
        None
    }
}
