//! Resolves kernel node IDs and child names within one immutable checked index.
//!
//! Startup reserves a bounded sorted reverse table without assigning presented
//! inode numbers. Workers retain only touched canonical nodes; complete tables
//! remain available for offline projection checks. Lookups borrow original index
//! bytes and perform no allocation, IO, path joining or content fetch. The caller
//! separately retains the original authenticated mapping, authorizes the prepared
//! view and owns its connection.

use crate::{
    inode_policy::{self, NodeIdentity},
    structural_index::{self, Entry, Index, Kind},
};
use std::{fmt, mem::size_of};
use terrane_format::tree_format::MAX_COMPONENT;

/// Refuses unavailable startup storage or invalid immutable namespace requests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Startup storage or touched nodes exceed the explicit reverse-table budget.
    Budget,
    /// Startup cannot reserve the complete bounded table.
    Allocation,
    /// Two distinct canonical entries have the same kernel node ID.
    Collision,
    /// The requested parent node is not in this original index.
    UnknownNode,
    /// A child lookup names a non-directory parent.
    NotDirectory,
    /// A component is empty, oversized or contains a separator or NUL.
    Name,
    /// Checked metadata cannot supply its original canonical relationships.
    Index(structural_index::Error),
    /// A structural identity cannot supply a nonreserved kernel node ID.
    Inode(inode_policy::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Budget => "FUSE namespace exceeds its startup budget",
            Self::Allocation => "FUSE namespace reservation failed",
            Self::Collision => "FUSE namespace kernel node collision",
            Self::UnknownNode => "FUSE namespace does not contain the requested node",
            Self::NotDirectory => "FUSE lookup parent is not a directory",
            Self::Name => "invalid FUSE lookup component",
            Self::Index(_) => "FUSE namespace index is invalid",
            Self::Inode(_) => "FUSE namespace inode identity is invalid",
        })
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Index(error) => Some(error),
            Self::Inode(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Clone, Copy)]
struct Node {
    id: u64,
    position: u32,
}

/// Borrows one immutable namespace with a startup-reserved node reverse table.
///
/// Root uses kernel node ID one. Hard-link aliases resolve to the same canonical
/// entry; equal file contents at unrelated paths and repeated graft prefixes
/// keep distinct identities. This table provides metadata, not exposure authority
/// or proof that the kernel has already looked up a particular entry.
pub struct Namespace<'a> {
    index: Index<'a>,
    nodes: Vec<Node>,
    limit: usize,
}

impl<'a> Namespace<'a> {
    /// Reserves and validates the complete reverse table before serving requests.
    ///
    /// Both limits include the synthesized root and every original path, even
    /// when hard-link rows are later deduplicated. Sorting does not allocate.
    /// Presented inode numbers remain lazy in the separate connection table.
    ///
    /// # Errors
    /// Refuses insufficient entry/byte budgets, allocation failures, reserved or
    /// colliding node IDs and invalid canonical index relationships.
    pub fn new(index: Index<'a>, max_entries: u32, max_bytes: usize) -> Result<Self, Error> {
        let count = usize::try_from(index.len()).map_err(|_| Error::Budget)?;
        if index.len() > max_entries {
            return Err(Error::Budget);
        }
        count
            .checked_mul(size_of::<Node>())
            .filter(|bytes| *bytes <= max_bytes && *bytes <= isize::MAX as usize)
            .ok_or(Error::Budget)?;
        let mut nodes = Vec::new();
        nodes
            .try_reserve_exact(count)
            .map_err(|_| Error::Allocation)?;
        if nodes
            .capacity()
            .checked_mul(size_of::<Node>())
            .is_none_or(|bytes| bytes > max_bytes)
        {
            return Err(Error::Budget);
        }
        for position in 0..index.len() {
            nodes.push(original_node(index, position)?);
        }
        nodes.sort_unstable_by_key(|node| node.id);
        if nodes
            .windows(2)
            .any(|pair| pair[0].id == pair[1].id && pair[0].position != pair[1].position)
        {
            return Err(Error::Collision);
        }
        nodes.dedup_by_key(|node| node.id);
        Ok(Self {
            index,
            nodes,
            limit: count,
        })
    }

    /// Reserves a worker reverse table that initially contains only root.
    ///
    /// The configured node budget includes root and canonical hard-link sets,
    /// independently of how many paths the immutable mapped index contains.
    /// [`Self::remember`] records successful touches without further allocation.
    /// The reservation depends only on the configured budget, including for
    /// small trees. Collisions are refused when an identity is first touched,
    /// before it can alias a node.
    ///
    /// # Errors
    /// Refuses zero limits, insufficient bytes, allocation failure and an invalid
    /// original root. Untouched paths do not consume node records or inode IDs.
    pub fn with_touched_nodes(
        index: Index<'a>,
        max_nodes: u32,
        max_bytes: usize,
    ) -> Result<Self, Error> {
        let count = usize::try_from(max_nodes).map_err(|_| Error::Budget)?;
        if count == 0
            || count
                .checked_mul(size_of::<Node>())
                .is_none_or(|bytes| bytes > max_bytes || bytes > isize::MAX as usize)
        {
            return Err(Error::Budget);
        }
        let mut nodes = Vec::new();
        nodes
            .try_reserve_exact(count)
            .map_err(|_| Error::Allocation)?;
        if nodes
            .capacity()
            .checked_mul(size_of::<Node>())
            .is_none_or(|bytes| bytes > max_bytes)
        {
            return Err(Error::Budget);
        }
        nodes.push(original_node(index, 0)?);
        Ok(Self {
            index,
            nodes,
            limit: count,
        })
    }

    /// Retains one touched canonical entry from this original index by position.
    ///
    /// The caller validates and encodes a positive LOOKUP before exposing its
    /// returned node ID. Hard-link aliases reuse the same record. Retained node
    /// identities are never recycled while the connection lives, independently
    /// of its separate kernel reference counts and presented inode numbers.
    ///
    /// # Errors
    /// Refuses invalid positions, reserved or colliding identities and exhausted
    /// touched-node capacity. Every refusal leaves existing mappings unchanged.
    pub fn remember(&mut self, position: u32) -> Result<u64, Error> {
        let node = original_node(self.index, position)?;
        match self.nodes.binary_search_by_key(&node.id, |entry| entry.id) {
            Ok(position) => {
                if self.nodes[position].position != node.position {
                    return Err(Error::Collision);
                }
            }
            Err(position) => {
                if self.nodes.len() >= self.limit {
                    return Err(Error::Budget);
                }
                self.nodes.insert(position, node);
            }
        }
        Ok(node.id)
    }

    /// Finds an original canonical entry by its deterministic kernel node ID.
    #[must_use]
    pub fn entry(&self, node: u64) -> Option<Entry<'a>> {
        let position = self
            .nodes
            .binary_search_by_key(&node, |entry| entry.id)
            .ok()?;
        self.index.entry(self.nodes[position].position)
    }

    /// Resolves one raw child component without reconstructing a full path.
    ///
    /// Dot returns the parent; dot-dot returns its namespace parent, including
    /// across graft boundaries. Root's parent is root. Other names use binary
    /// search over the original contiguous direct-child index array.
    ///
    /// # Errors
    /// Refuses malformed names, unknown parent nodes, non-directory parents and
    /// invalid checked structural relationships. An absent valid child is `None`.
    pub fn lookup(&self, parent: u64, name: &[u8]) -> Result<Option<Entry<'a>>, Error> {
        if name.is_empty()
            || name.len() > MAX_COMPONENT
            || name.contains(&0)
            || name.contains(&b'/')
        {
            return Err(Error::Name);
        }
        let directory = self.entry(parent).ok_or(Error::UnknownNode)?;
        if !matches!(directory.kind(), Kind::Directory { .. }) {
            return Err(Error::NotDirectory);
        }
        if name == b"." {
            return Ok(Some(directory));
        }
        if name == b".." {
            let path = directory.path();
            let parent = path
                .iter()
                .rposition(|byte| *byte == b'/')
                .map_or(b"".as_slice(), |end| &path[..end]);
            return self
                .index
                .lookup(parent)
                .map(Some)
                .ok_or(Error::Index(structural_index::Error::Tree));
        }
        let mut low = 0;
        let mut high = directory.children().map_err(Error::Index)?.len();
        while low < high {
            let middle = low + (high - low) / 2;
            let child = directory
                .children()
                .map_err(Error::Index)?
                .nth(middle)
                .ok_or(Error::Index(structural_index::Error::Tree))?;
            let child_name = child
                .path()
                .rsplit(|byte| *byte == b'/')
                .next()
                .ok_or(Error::Index(structural_index::Error::Tree))?;
            match child_name.cmp(name) {
                std::cmp::Ordering::Less => low = middle + 1,
                std::cmp::Ordering::Greater => high = middle,
                std::cmp::Ordering::Equal => return Ok(Some(child)),
            }
        }
        Ok(None)
    }
}

fn original_node(index: Index<'_>, position: u32) -> Result<Node, Error> {
    let original = index
        .entry(position)
        .ok_or(Error::Index(structural_index::Error::Tree))?;
    let canonical = original.canonical_inode().map_err(Error::Index)?;
    let id = if original.path().is_empty() {
        1
    } else {
        NodeIdentity::new(
            canonical.governing_root().map_err(Error::Index)?,
            canonical.path(),
        )
        .map_err(Error::Inode)?
        .node_id()
    };
    Ok(Node {
        id,
        position: canonical.position(),
    })
}

#[cfg(test)]
mod tests;
