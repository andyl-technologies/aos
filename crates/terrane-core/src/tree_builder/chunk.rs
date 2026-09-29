//! Encodes full-key boundary items and accumulates capped nodes at any level.

use alloc::{rc::Rc, vec::Vec};

use crate::{
    boundary::{self, BoundaryDecision},
    cbor,
    tree_format::{LeafItem, Node, NodeItems, encode_entry},
};

use super::{Error, Factory, StoredNode};

pub(super) enum Item<'a> {
    Leaf(LeafItem<'a>),
    Child(Rc<StoredNode<'a>>),
}

impl Item<'_> {
    pub(super) fn canonical(&self, min_chunk_size: u64) -> Result<Vec<u8>, Error> {
        match self {
            Self::Leaf(item) => leaf_bytes(item, &[], min_chunk_size),
            Self::Child(child) => {
                let reference = child.reference()?;
                let mut bytes = Vec::new();
                cbor::write_array(&mut bytes, 4);
                cbor::write_bytes(&mut bytes, &reference.last_key);
                cbor::write_bytes(&mut bytes, &reference.child);
                cbor::write_uint(&mut bytes, reference.count);
                cbor::write_uint(&mut bytes, reference.weight);
                Ok(bytes)
            }
        }
    }
}

pub(super) fn leaf_bytes(
    item: &LeafItem<'_>,
    previous: &[u8],
    min_chunk_size: u64,
) -> Result<Vec<u8>, Error> {
    let shared = previous
        .iter()
        .zip(&item.key)
        .take_while(|(left, right)| left == right)
        .count();
    let mut bytes = Vec::new();
    cbor::write_array(&mut bytes, 3);
    cbor::write_bytes(&mut bytes, &item.key[shared..]);
    cbor::write_uint(&mut bytes, shared as u64);
    bytes.extend_from_slice(&encode_entry(&item.entry, min_chunk_size)?);
    Ok(bytes)
}

pub(super) struct Chunker<'a> {
    level: u8,
    leaves: Vec<LeafItem<'a>>,
    children: Vec<Rc<StoredNode<'a>>>,
    bytes: u64,
    pub(super) output: Vec<Rc<StoredNode<'a>>>,
}

impl<'a> Chunker<'a> {
    pub(super) fn new(level: u8) -> Self {
        Self {
            level,
            leaves: Vec::new(),
            children: Vec::new(),
            bytes: 0,
            output: Vec::new(),
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.leaves.is_empty() && self.children.is_empty()
    }

    pub(super) fn push(&mut self, item: Item<'a>, factory: &mut Factory<'a>) -> Result<(), Error> {
        let canonical = item.canonical(factory.min_chunk_size)?;
        factory.work.item_encodings += 1;
        let mut stored_length = match &item {
            Item::Leaf(leaf) => {
                let previous = self
                    .leaves
                    .last()
                    .map_or(&[][..], |prior| prior.key.as_slice());
                factory.work.item_encodings += 1;
                leaf_bytes(leaf, previous, factory.min_chunk_size)?.len() as u64
            }
            Item::Child(_) => canonical.len() as u64,
        };
        let mut decision =
            boundary::decide(self.bytes, stored_length, &canonical).map_err(|_| Error::Limit)?;
        if decision == BoundaryDecision::SplitBefore {
            self.close(factory)?;
            stored_length = canonical.len() as u64;
            decision = boundary::decide(0, stored_length, &canonical).map_err(|_| Error::Limit)?;
        }

        match item {
            Item::Leaf(leaf) if self.level == 0 => self.leaves.push(leaf),
            Item::Child(child) if self.level > 0 => self.children.push(child),
            _ => return Err(Error::Node),
        }
        self.bytes += stored_length;
        if decision == BoundaryDecision::CloseAfter {
            self.close(factory)?;
        }
        Ok(())
    }

    pub(super) fn close(&mut self, factory: &mut Factory<'a>) -> Result<(), Error> {
        if self.is_empty() {
            return Ok(());
        }
        let children = core::mem::take(&mut self.children);
        let items = if self.level == 0 {
            NodeItems::Leaf(core::mem::take(&mut self.leaves))
        } else {
            NodeItems::Internal(
                children
                    .iter()
                    .map(|child| child.reference())
                    .collect::<Result<_, _>>()?,
            )
        };
        let node = Node {
            level: self.level,
            items,
            props: None,
        };
        self.output.push(factory.make(node, children, false)?);
        self.bytes = 0;
        Ok(())
    }

    pub(super) fn finish(
        mut self,
        factory: &mut Factory<'a>,
    ) -> Result<Vec<Rc<StoredNode<'a>>>, Error> {
        self.close(factory)?;
        Ok(self.output)
    }
}

pub(super) fn leaves<'a>(
    entries: Vec<LeafItem<'a>>,
    factory: &mut Factory<'a>,
) -> Result<Vec<Rc<StoredNode<'a>>>, Error> {
    if entries.is_empty() {
        let node = Node {
            level: 0,
            items: NodeItems::Leaf(Vec::new()),
            props: None,
        };
        return Ok(alloc::vec![factory.make(node, Vec::new(), true)?]);
    }
    let mut chunker = Chunker::new(0);
    for entry in entries {
        chunker.push(Item::Leaf(entry), factory)?;
    }
    chunker.finish(factory)
}

pub(super) fn parents<'a>(
    children: Vec<Rc<StoredNode<'a>>>,
    level: u8,
    factory: &mut Factory<'a>,
) -> Result<Vec<Rc<StoredNode<'a>>>, Error> {
    let mut chunker = Chunker::new(level);
    for child in children {
        chunker.push(Item::Child(child), factory)?;
    }
    chunker.finish(factory)
}
