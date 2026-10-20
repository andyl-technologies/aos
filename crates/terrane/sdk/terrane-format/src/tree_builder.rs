//! Builds persistent, history-independent Terrane prolly trees without I/O.
//!
//! Leaf entries and child references are chunked by TREE-21 through TREE-23.
//! Immutable nodes retain canonical bytes and exact subtree summaries. Point
//! edits rechunk from the affected node until an old boundary is recovered,
//! then propagate the changed references upward while sharing other subtrees.
//! Work is proportional to tree height and the resynchronization region;
//! adversarial boundary sequences can require processing the remaining suffix.
//!
//! The encoded representation is the TREE-25 node map:
//! ```text
//! {1: level, 2: [leaf-item / child-ref, ...], ? 3: root-properties}
//! ```

mod batch;
mod chunk;
mod cursor;
mod links;
mod mutation;
mod range;
mod splice;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod splice_tests;

#[cfg(test)]
mod batch_tests;

#[cfg(test)]
mod frontier_tests;

use alloc::{rc::Rc, vec::Vec};

use crate::identity::{Digest, IdentityKind, TERRANE_V1};
use crate::tree_format::{
    ChildRef, Entry, LeafItem, Node, NodeItems, Property, TreeUse, encode_node_for,
    validate_tree_entries,
};

pub use crate::tree_format::Error;
pub use cursor::{Cursor, Nodes};
pub use links::HardlinkMembers;
pub use splice::{SpliceOutcome, SubtreeReplacement};

/// An immutable node with canonical bytes and exact subtree summaries.
#[derive(Clone, Debug)]
pub struct StoredNode<'a> {
    node: Node<'a>,
    encoded: Vec<u8>,
    identity: Digest,
    children: Vec<Rc<StoredNode<'a>>>,
    count: u64,
    conflicts: u64,
    weight: u64,
}

impl<'a> StoredNode<'a> {
    /// Returns the node's domain-separated identity.
    pub fn identity(&self) -> Digest {
        self.identity
    }

    /// Returns the canonical node encoding.
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    /// Returns the decoded node, including any root properties.
    pub fn node(&self) -> &Node<'a> {
        &self.node
    }

    /// Returns zero for a leaf and the distance from leaves otherwise.
    pub fn level(&self) -> u8 {
        self.node.level
    }

    /// Returns full-key leaf entries or exact child references.
    pub fn items(&self) -> &NodeItems<'a> {
        &self.node.items
    }

    /// Returns children in ascending key-range order.
    pub fn children(&self) -> &[Rc<StoredNode<'a>>] {
        &self.children
    }

    /// Returns the exact number of leaf entries beneath this node.
    pub fn count(&self) -> u64 {
        self.count
    }

    /// Returns the total encoded bytes of this node and its descendants.
    pub fn weight(&self) -> u64 {
        self.weight
    }

    /// Returns the greatest key, or `None` for the empty root.
    pub fn last_key(&self) -> Option<&[u8]> {
        match &self.node.items {
            NodeItems::Leaf(items) => items.last().map(|item| item.key.as_slice()),
            NodeItems::Internal(items) => items.last().map(|item| item.last_key.as_slice()),
        }
    }

    /// Returns the least key, or `None` for the empty root.
    pub fn first_key(&self) -> Option<&[u8]> {
        match &self.node.items {
            NodeItems::Leaf(items) => items.first().map(|item| item.key.as_slice()),
            NodeItems::Internal(_) => self.children.first().and_then(|child| child.first_key()),
        }
    }

    fn reference(&self) -> Result<ChildRef, Error> {
        Ok(ChildRef {
            last_key: self.last_key().ok_or(Error::Node)?.to_vec(),
            child: self.identity,
            count: self.count,
            weight: self.weight,
        })
    }
}

/// Counts observable canonical-stream operations, independently of logical changes.
///
/// Byte counts measure canonical encoding outputs and hash preimages, not
/// allocator traffic, memory copies, or codec validation instructions.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StreamWork {
    /// Input items inspected by merge and items consumed by the chunker.
    ///
    /// Passing a retained item from merge into the chunker counts both reads.
    pub item_reads: usize,
    /// Explicit ordered-key comparisons in the editor.
    pub comparisons: usize,
    /// Boundary decisions, pending-region checks, and completion frontier checks.
    pub frontier_checks: usize,
    /// Bytes in full-key and prefix-compressed item encoding outputs.
    pub item_bytes_encoded: usize,
    /// Bytes in canonical node encoding outputs, including framing and properties.
    pub node_bytes_encoded: usize,
    /// Actual item-hash preimage bytes; early boundary exits contribute zero.
    pub item_bytes_hashed: usize,
    /// Actual Node identity preimage bytes, including domain and zero separator.
    pub node_bytes_hashed: usize,
}

impl StreamWork {
    fn since(self, before: Self) -> Self {
        Self {
            item_reads: self.item_reads - before.item_reads,
            comparisons: self.comparisons - before.comparisons,
            frontier_checks: self.frontier_checks - before.frontier_checks,
            item_bytes_encoded: self.item_bytes_encoded - before.item_bytes_encoded,
            node_bytes_encoded: self.node_bytes_encoded - before.node_bytes_encoded,
            item_bytes_hashed: self.item_bytes_hashed - before.item_bytes_hashed,
            node_bytes_hashed: self.node_bytes_hashed - before.node_bytes_hashed,
        }
    }

    fn combine(&mut self, other: Self) {
        self.item_reads += other.item_reads;
        self.comparisons += other.comparisons;
        self.frontier_checks += other.frontier_checks;
        self.item_bytes_encoded += other.item_bytes_encoded;
        self.node_bytes_encoded += other.node_bytes_encoded;
        self.item_bytes_hashed += other.item_bytes_hashed;
        self.node_bytes_hashed += other.node_bytes_hashed;
    }
}

/// Identifies one connected canonical resynchronization stream at one level.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundaryRegion {
    /// Level of the stream: zero denotes leaf items.
    pub level: u8,
    /// Last key of the first old node whose boundary is invalidated.
    pub invalidated: Vec<u8>,
    /// Recovered old boundary, or `None` when processing reaches the stream tail.
    pub resynchronized: Option<Vec<u8>>,
    /// Last old-node key processed, including tails and deletion to empty.
    pub last: Vec<u8>,
    /// Actual canonical-stream operations performed in this region.
    pub work: StreamWork,
}

/// Records canonical processing of a newly created ancestor level to its tail.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewLevelWork {
    /// New ancestor level absent from the old tree.
    pub level: u8,
    /// First input child subtree's least key.
    pub first: Vec<u8>,
    /// Last input child subtree's greatest key; this stream ends at its tail.
    pub last: Vec<u8>,
    /// Actual canonical item and node operations at this new level.
    pub work: StreamWork,
}

/// Reports editing work separately from independent validation and seeks.
///
/// This pure Tree seam measures canonical-stream outputs and hash preimages;
/// it does not establish DRV-29 logical deltas or a complete index-maintenance
/// bound. Codec-internal validation is not a measured stream operation.
/// Construction uses its own private factory and is never added to an edit.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Work {
    /// Nodes inspected while seeking and rechunking the changed ranges.
    pub node_reads: usize,
    /// Search nodes inspected by ancestor and hard-link validation.
    pub validation_reads: usize,
    /// Items encoded for boundary decisions, including reset encodings.
    pub item_encodings: usize,
    /// Canonical nodes encoded, including the final root property map.
    pub node_encodings: usize,
    /// Total canonical work, partitioned exhaustively by the fields below.
    ///
    /// Equals existing `regions`, `new_levels`, `completion`, `root_properties`
    /// and `preparation` summed once. Adoption, seeks and validation are separate.
    pub stream: StreamWork,
    /// Canonical streams at levels newly created during root growth.
    pub new_levels: Vec<NewLevelWork>,
    /// Empty-root encoding and hierarchy completion/collapse frontier work.
    pub completion: StreamWork,
    /// Final root encoding when applying a distinct property map.
    pub root_properties: StreamWork,
    /// Canonical replacement-frontier comparisons before ancestor streams.
    pub preparation: StreamWork,
    /// Explicit key comparisons made while locating streams, outside regions.
    pub seek_comparisons: usize,
    /// Separate boundary certification work for attempted subtree adoption.
    pub adoption: StreamWork,
    /// Ordered traces of connected sparse-edit streams at all affected levels.
    pub regions: Vec<BoundaryRegion>,
}

impl Work {
    /// Adds every counter and appends region traces in execution order.
    ///
    /// Counts use ordinary `usize` arithmetic, like the original counters;
    /// they are not saturated or deduplicated. Callers must keep accumulated
    /// reports within the addressable operation count.
    ///
    /// # Panics
    /// Panics on counter overflow when overflow checks are enabled.
    pub fn combine(&mut self, other: Self) {
        self.node_reads += other.node_reads;
        self.validation_reads += other.validation_reads;
        self.item_encodings += other.item_encodings;
        self.node_encodings += other.node_encodings;
        self.stream.combine(other.stream);
        self.new_levels.extend(other.new_levels);
        self.completion.combine(other.completion);
        self.root_properties.combine(other.root_properties);
        self.preparation.combine(other.preparation);
        self.seek_comparisons += other.seek_comparisons;
        self.adoption.combine(other.adoption);
        self.regions.extend(other.regions);
    }
}

/// Contains an edited tree, its newly emitted nodes, and measured work.
#[derive(Clone, Debug)]
pub struct Mutation<'a> {
    /// Persistent result sharing unchanged nodes with its predecessor.
    pub tree: Tree<'a>,
    /// Newly encoded immutable objects, in children-before-parent order.
    ///
    /// A temporary root without properties may also be emitted before the
    /// final root is encoded; each object has its own canonical identity.
    pub emitted: Vec<Rc<StoredNode<'a>>>,
    /// Actual work performed by the edit.
    pub work: Work,
}

/// A persistent ordered map backed by immutable canonical prolly-tree nodes.
#[derive(Clone, Debug)]
pub struct Tree<'a> {
    root: Rc<StoredNode<'a>>,
    min_chunk_size: u64,
    usage: TreeUse,
    links: links::Links<'a>,
    members: links::Links<'a>,
}

impl<'a> Tree<'a> {
    /// Builds a tree from strictly sorted entries and optional root properties.
    ///
    /// Whole-tree ancestor, entry-use, and hard-link invariants are validated
    /// before construction. `None` and an explicitly empty property map retain
    /// their different canonical encodings.
    ///
    /// # Errors
    /// Rejects invalid entries, unsorted or duplicate keys, inconsistent
    /// ancestors or hard links, oversized items, and excessive tree depth.
    pub fn build(
        entries: Vec<LeafItem<'a>>,
        props: Option<Vec<Property<'a>>>,
        min_chunk_size: u64,
        usage: TreeUse,
    ) -> Result<Self, Error> {
        validate_tree_entries(&entries, usage)?;
        let links = links::build(&entries)?;
        let members = links::build_members(&entries);
        let mut factory = Factory::new(min_chunk_size, usage);
        let mut nodes = chunk::leaves(entries, &mut factory)?;
        let mut level = 0;

        while nodes.len() > 1 {
            level += 1;
            nodes = chunk::parents(nodes, level, &mut factory)?;
        }

        let root = nodes.pop().ok_or(Error::Node)?;
        let root = factory.root(root, props)?;
        Ok(Self {
            root,
            min_chunk_size,
            usage,
            links,
            members,
        })
    }

    /// Iterates a TREE-11 hard-link set's borrowed keys in ascending byte order.
    ///
    /// An absent identity yields an empty iterator. The auxiliary persistent
    /// index seeks in O(log n) time and visits only the returned members, so
    /// callers can relabel a surviving set without scanning unrelated entries.
    pub fn hardlink_members(&self, link_id: &[u8]) -> HardlinkMembers<'_, 'a> {
        HardlinkMembers::new(&self.members, link_id)
    }

    /// Returns the root identity, including the root's property map.
    pub fn root_identity(&self) -> Digest {
        self.root.identity
    }

    /// Returns the immutable root node.
    pub fn root(&self) -> &StoredNode<'a> {
        &self.root
    }

    /// Returns a shared handle to the immutable root node.
    pub fn root_rc(&self) -> Rc<StoredNode<'a>> {
        Rc::clone(&self.root)
    }

    /// Returns the root property map, preserving absent versus empty.
    pub fn props(&self) -> Option<&[Property<'a>]> {
        self.root.node.props.as_deref()
    }

    /// Returns the semantic context used to validate entries.
    pub fn usage(&self) -> TreeUse {
        self.usage
    }

    /// Reinterprets the same nodes in a different semantic context.
    ///
    /// Widening `Surface` to `Ordinary` or `OverlayLayer`, or `Ordinary` to
    /// `OverlayLayer`, shares the existing root without scanning entries.
    /// Narrowing or crossing the index/path boundary validates all entries.
    ///
    /// # Errors
    /// Rejects entries or keys that are invalid in the requested context.
    pub fn with_usage(&self, usage: TreeUse) -> Result<Self, Error> {
        let widening = matches!(
            (self.usage, usage),
            (TreeUse::Surface, TreeUse::Ordinary | TreeUse::OverlayLayer)
                | (TreeUse::Ordinary, TreeUse::OverlayLayer)
        );
        if self.usage != usage && !widening {
            validate_tree_entries(&self.iter().cloned().collect::<Vec<_>>(), usage)?;
        }
        let mut tree = self.clone();
        tree.usage = usage;
        Ok(tree)
    }

    /// Returns the chunk profile's minimum plaintext chunk size.
    pub fn min_chunk_size(&self) -> u64 {
        self.min_chunk_size
    }

    /// Returns the number of entries in the map.
    pub fn len(&self) -> u64 {
        self.root.count
    }

    /// Reports whether this tree contains direct unresolved conflict entries.
    pub fn has_conflicts(&self) -> bool {
        self.root.conflicts != 0
    }

    /// Reports whether the tree is the encoded empty leaf.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Finds a value by unsigned bytewise key order.
    pub fn get(&self, key: &[u8]) -> Option<&Entry<'a>> {
        let mut node = self.root.as_ref();
        loop {
            match &node.node.items {
                NodeItems::Leaf(items) => {
                    let index = items
                        .binary_search_by(|item| item.key.as_slice().cmp(key))
                        .ok()?;
                    return Some(&items[index].entry);
                }
                NodeItems::Internal(items) => {
                    let index = items.partition_point(|item| item.last_key.as_slice() < key);
                    node = node.children.get(index)?.as_ref();
                }
            }
        }
    }

    /// Iterates all leaf entries in ascending key order.
    pub fn iter(&self) -> Cursor<'_, 'a> {
        Cursor::new(self, &[])
    }

    /// Iterates entries at or after an unsigned bytewise key.
    pub fn cursor_from(&self, key: &[u8]) -> Cursor<'_, 'a> {
        Cursor::new(self, key)
    }

    /// Visits nodes in root-first depth-first order.
    pub fn nodes(&self) -> Nodes<'_, 'a> {
        Nodes::new(self.root())
    }

    /// Inserts or replaces an entry while sharing unaffected subtrees.
    ///
    /// # Errors
    /// Rejects invalid entries, missing ancestors, descendants below a
    /// nondirectory, inconsistent hard links, oversized nodes, or excessive
    /// depth. Hard-link changes additionally inspect the affected link sets.
    pub fn insert(&self, item: LeafItem<'a>) -> Result<Mutation<'a>, Error> {
        mutation::insert(self, item)
    }

    /// Removes an entry while sharing unaffected subtrees.
    ///
    /// Removing an absent key returns an unchanged tree with no emitted nodes.
    ///
    /// # Errors
    /// Rejects removal of an ancestor of retained entries or the first member
    /// of a retained hard-link set, and invalid resulting node encodings.
    pub fn remove(&self, key: &[u8]) -> Result<Mutation<'a>, Error> {
        mutation::remove(self, key)
    }

    /// Replaces a half-open key range with strictly sorted entries.
    ///
    /// `start` is inclusive and `end` is exclusive; `None` extends to the
    /// greatest key. An empty `start` addresses the beginning of the tree.
    /// Entries must lie within the range. One leaf-stream replacement and
    /// ancestor resynchronization share unaffected nodes. Ancestor lookups
    /// are memoized across entries instead of repeated per point mutation.
    /// Hard-link changes are validated and committed as complete set deltas.
    ///
    /// # Errors
    /// Rejects reversed bounds, unsorted or out-of-range entries, invalid
    /// entry forms or ancestors, inconsistent hard links, oversized items,
    /// and excessive depth. The original tree remains unchanged on error.
    pub fn replace_range(
        &self,
        start: &[u8],
        end: Option<&[u8]>,
        entries: Vec<LeafItem<'a>>,
    ) -> Result<Mutation<'a>, Error> {
        range::replace(self, start, end, entries)
    }

    /// Applies strictly sorted sparse entry changes as one atomic transaction.
    ///
    /// A missing entry value removes its key. Overlapping affected streams are
    /// processed together at leaves and every ancestor level. Distant regions
    /// seek past unaffected nodes after recovering a compatible canonical cut.
    /// Ancestors and complete hard-link deltas are validated on the final map.
    ///
    /// # Errors
    /// Rejects duplicate or unsorted keys, invalid final entries or ancestors,
    /// inconsistent hard links, oversized items, and excessive tree depth.
    pub fn edit_entries(
        &self,
        edits: &[(Vec<u8>, Option<Entry<'a>>)],
    ) -> Result<Mutation<'a>, Error> {
        match splice::apply_edits(self, &[], edits)? {
            SpliceOutcome::Applied(result) => Ok(result),
            SpliceOutcome::RechunkRequired(_) => Err(Error::Node),
        }
    }

    /// Atomically combines sparse entry changes with whole-subtree adoption.
    ///
    /// Sparse keys must be strictly sorted and outside every adopted range.
    /// Final-map validation permits complete hard-link sets to change across
    /// both kinds of edits. Canonical boundary compatibility and actual target
    /// sharing are checked after all changes. Failed adoption returns measured
    /// work in [`SpliceOutcome::RechunkRequired`] and leaves the map unchanged.
    ///
    /// # Errors
    /// Rejects invalid or overlapping patches, unsorted or overlapping sparse
    /// keys, invalid final entries or ancestors, inconsistent hard links, and
    /// resource-limit violations.
    pub fn edit_entries_with_subtrees(
        &self,
        edits: &[(Vec<u8>, Option<Entry<'a>>)],
        patches: &[SubtreeReplacement<'a>],
    ) -> Result<SpliceOutcome<'a>, Error> {
        splice::apply_edits(self, patches, edits)
    }

    /// Replaces disjoint aligned subtrees by their existing immutable nodes.
    ///
    /// Each target must have the same first key, last key, and level as its
    /// predecessor. Canonical cuts at both edges are certified at every
    /// descendant level before targets are adopted. The method returns
    /// [`SpliceOutcome::RechunkRequired`] when a changed edge invalidates a
    /// content boundary; callers can then descend into smaller subtrees.
    /// Root properties are preserved, and validation compares differing
    /// entry frontiers while skipping identical immutable nodes.
    ///
    /// # Errors
    /// Rejects unknown predecessor identities, overlapping ranges, changed
    /// range bounds or levels, nonroot properties, invalid entries or
    /// ancestors, inconsistent hard links, and resource-limit violations.
    pub fn splice_subtrees(
        &self,
        patches: &[SubtreeReplacement<'a>],
    ) -> Result<SpliceOutcome<'a>, Error> {
        splice::apply(self, patches)
    }

    /// Changes root properties without rewriting descendant nodes.
    ///
    /// # Errors
    /// Rejects invalid properties or properties that exceed the root limit.
    pub fn with_properties(&self, props: Option<Vec<Property<'a>>>) -> Result<Mutation<'a>, Error> {
        if self.root.node.props == props {
            return Ok(self.unchanged());
        }
        let mut factory = Factory::new(self.min_chunk_size, self.usage);
        let root = factory.root(Rc::clone(&self.root), props)?;
        Ok(self.finish(root, factory))
    }

    fn unchanged(&self) -> Mutation<'a> {
        Mutation {
            tree: self.clone(),
            emitted: Vec::new(),
            work: Work::default(),
        }
    }

    fn finish(&self, root: Rc<StoredNode<'a>>, factory: Factory<'a>) -> Mutation<'a> {
        Mutation {
            tree: Self {
                root,
                min_chunk_size: self.min_chunk_size,
                usage: self.usage,
                links: self.links.clone(),
                members: self.members.clone(),
            },
            emitted: factory.emitted,
            work: factory.work,
        }
    }
}

struct Factory<'a> {
    min_chunk_size: u64,
    usage: TreeUse,
    emitted: Vec<Rc<StoredNode<'a>>>,
    work: Work,
}

impl<'a> Factory<'a> {
    fn new(min_chunk_size: u64, usage: TreeUse) -> Self {
        Self {
            min_chunk_size,
            usage,
            emitted: Vec::new(),
            work: Work::default(),
        }
    }

    fn make(
        &mut self,
        node: Node<'a>,
        children: Vec<Rc<StoredNode<'a>>>,
        is_root: bool,
    ) -> Result<Rc<StoredNode<'a>>, Error> {
        let encoded = encode_node_for(&node, is_root, self.min_chunk_size, self.usage)?;
        self.work.stream.node_bytes_encoded += encoded.len();
        self.work.stream.node_bytes_hashed += encoded.len()
            + TERRANE_V1
                .domain(IdentityKind::Node)
                .map_err(|_| Error::Node)?
                .len()
            + 1;
        let identity = TERRANE_V1
            .calculate(IdentityKind::Node, &encoded)
            .map_err(|_| Error::Node)?
            .terrane_v1_digest()
            .map_err(|_| Error::Node)?;
        let mut count = 0_u64;
        let mut conflicts = 0_u64;
        let mut weight = encoded.len() as u64;

        match &node.items {
            NodeItems::Leaf(items) => {
                if node.level != 0 || !children.is_empty() {
                    return Err(Error::Node);
                }
                count = items.len() as u64;
                conflicts = items
                    .iter()
                    .filter(|item| {
                        matches!(
                            item.entry.kind,
                            crate::tree_format::EntryKind::Conflict { .. }
                        )
                    })
                    .count() as u64;
            }
            NodeItems::Internal(refs) => {
                if refs.len() != children.len() {
                    return Err(Error::Node);
                }
                for (reference, child) in refs.iter().zip(&children) {
                    if child.level().checked_add(1) != Some(node.level)
                        || child.node.props.is_some()
                        || child.reference()? != *reference
                    {
                        return Err(Error::Node);
                    }
                    count = count.checked_add(child.count).ok_or(Error::Limit)?;
                    conflicts = conflicts.checked_add(child.conflicts).ok_or(Error::Limit)?;
                    weight = weight.checked_add(child.weight).ok_or(Error::Limit)?;
                }
            }
        }

        let stored = Rc::new(StoredNode {
            node,
            encoded,
            identity,
            children,
            count,
            conflicts,
            weight,
        });
        self.work.node_encodings += 1;
        self.emitted.push(Rc::clone(&stored));
        Ok(stored)
    }

    fn root(
        &mut self,
        node: Rc<StoredNode<'a>>,
        props: Option<Vec<Property<'a>>>,
    ) -> Result<Rc<StoredNode<'a>>, Error> {
        if node.node.props == props {
            return Ok(node);
        }
        let mut decoded = node.node.clone();
        decoded.props = props;
        let before = self.work.stream;
        let root = self.make(decoded, node.children.clone(), true)?;
        self.work
            .root_properties
            .combine(self.work.stream.since(before));
        Ok(root)
    }
}
