//! SPDX-License-Identifier: MIT OR Apache-2.0
//! Implements sparse persistent ordered region trees with shared immutable nodes.
//!
//! Uniform zero and padding subtrees share children rather than expanding the
//! logical address space. A batch rebuilds each changed ancestor once; unchanged
//! content and snapshots retain their prior nodes. Node lifetime charges follow
//! the final shared reference, including references retained by older snapshots.

use crate::budget::Reservation;
use crate::{
    Geometry, MetadataBudget, NodeDigest, PageDigest, PageProof, RamError, RegionTreeDigest,
    empty_leaf_digest, inner_digest, leaf_digest, region_tree_digest,
};
use std::sync::Arc;

const ARC_OVERHEAD: usize = 2 * std::mem::size_of::<usize>();

#[derive(Debug)]
struct Node {
    digest: NodeDigest,
    kind: NodeKind,
    _charge: Reservation,
}

#[derive(Debug)]
enum NodeKind {
    Page(PageDigest),
    Empty,
    Inner(Arc<Node>, Arc<Node>),
}

impl Node {
    fn page(page: PageDigest, budget: &MetadataBudget) -> Result<Arc<Self>, RamError> {
        let charge = budget.reserve((std::mem::size_of::<Self>() + ARC_OVERHEAD) as u64)?;
        Ok(Arc::new(Self {
            digest: leaf_digest(page),
            kind: NodeKind::Page(page),
            _charge: charge,
        }))
    }

    fn empty(budget: &MetadataBudget) -> Result<Arc<Self>, RamError> {
        let charge = budget.reserve((std::mem::size_of::<Self>() + ARC_OVERHEAD) as u64)?;
        Ok(Arc::new(Self {
            digest: empty_leaf_digest(),
            kind: NodeKind::Empty,
            _charge: charge,
        }))
    }

    fn inner(
        height: u32,
        left: Arc<Self>,
        mut right: Arc<Self>,
        budget: &MetadataBudget,
    ) -> Result<Arc<Self>, RamError> {
        let digest = inner_digest(height, left.digest, right.digest)?;
        // Identical content at the same height can reuse a complete subtree.
        if left.digest == right.digest {
            right = left.clone();
        }
        let charge = budget.reserve((std::mem::size_of::<Self>() + ARC_OVERHEAD) as u64)?;
        Ok(Arc::new(Self {
            digest,
            kind: NodeKind::Inner(left, right),
            _charge: charge,
        }))
    }
}

/// A region's immutable ordered page identities and checked logical geometry.
#[derive(Clone, Debug)]
pub struct RegionTree {
    geometry: Geometry,
    root: Arc<Node>,
    budget: MetadataBudget,
}

impl RegionTree {
    /// Constructs sparse identity for a region proven to contain zero bytes.
    ///
    /// This is an explicit content declaration, not permission to interpret
    /// missing backing as zero RAM. Callers must establish the declared bytes.
    ///
    /// # Errors
    ///
    /// Returns [`RamError`] for zero length or insufficient metadata budget.
    pub fn zeroed(logical_length: u64, budget: &MetadataBudget) -> Result<Self, RamError> {
        let geometry = Geometry::new(logical_length)?;
        let mut uniform = UniformNodes::new(budget);
        let root = build_zero(0, geometry.height(), geometry, &mut uniform)?;
        Ok(Self {
            geometry,
            root,
            budget: budget.clone(),
        })
    }

    /// Constructs a checked ordered tree from one digest per real page.
    ///
    /// The caller must have hashed each page with its geometry's valid length.
    /// Digest construction does not prove availability of the underlying bytes.
    ///
    /// # Errors
    ///
    /// Returns [`RamError`] for a wrong page count, invalid geometry, or budget
    /// exhaustion. Failed construction releases all newly allocated nodes.
    pub fn from_page_digests(
        logical_length: u64,
        pages: &[PageDigest],
        budget: &MetadataBudget,
    ) -> Result<Self, RamError> {
        let geometry = Geometry::new(logical_length)?;
        if pages.len() as u64 != geometry.page_count() {
            return Err(RamError::InvalidLength);
        }
        let mut uniform = UniformNodes::new(budget);
        let root = build_digests(0, geometry.height(), pages, &mut uniform)?;
        Ok(Self {
            geometry,
            root,
            budget: budget.clone(),
        })
    }

    /// Returns the checked logical geometry.
    pub const fn geometry(&self) -> Geometry {
        self.geometry
    }

    /// Returns the canonical region commitment.
    pub fn digest(&self) -> RegionTreeDigest {
        region_tree_digest(self.geometry, self.root.digest)
    }

    /// Returns the reduced node commitment before its region wrapper.
    pub fn node_digest(&self) -> NodeDigest {
        self.root.digest
    }

    /// Returns the admitted metadata domain used by this tree.
    pub fn metadata_budget(&self) -> &MetadataBudget {
        &self.budget
    }

    /// Reports whether both views share the exact same immutable root allocation.
    pub fn shares_root_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.root, &other.root)
    }

    /// Retrieves a real page's content digest without reading guest RAM.
    ///
    /// # Errors
    ///
    /// Returns [`RamError::OutOfRange`] for absent/padding positions or an
    /// invariant error if the tree does not contain a page at that coordinate.
    pub fn page_digest(&self, page_index: u64) -> Result<PageDigest, RamError> {
        self.geometry.valid_length(page_index)?;
        let mut node = &self.root;
        let mut height = self.geometry.height();
        while height != 0 {
            match &node.kind {
                NodeKind::Inner(left, right) => {
                    height -= 1;
                    node = if (page_index >> height) & 1 == 0 {
                        left
                    } else {
                        right
                    };
                }
                _ => return Err(RamError::InvalidEncoding),
            }
        }
        match node.kind {
            NodeKind::Page(page) => Ok(page),
            _ => Err(RamError::InvalidEncoding),
        }
    }

    /// Returns an atomically rebuilt tree with a checked batch of changed pages.
    ///
    /// Updates may arrive unordered, but duplicate coordinates are rejected.
    /// Old snapshots remain immutable and failed batches leave them unchanged.
    /// Reverted or unchanged content reuses existing leaf/path allocations.
    ///
    /// # Errors
    ///
    /// Returns [`RamError`] for invalid/duplicate indices, allocation failure,
    /// or metadata exhaustion. New nodes and temporary reservations are released
    /// on failure; no partial tree is published.
    pub fn updated(&self, updates: &[(u64, PageDigest)]) -> Result<Self, RamError> {
        if updates.is_empty() {
            return Ok(self.clone());
        }
        if updates.len() as u64 > self.geometry.page_count() {
            return Err(RamError::OutOfRange);
        }
        let bytes = updates
            .len()
            .checked_mul(std::mem::size_of::<(u64, PageDigest)>())
            .ok_or(RamError::Overflow)?;
        let _work = self.budget.reserve(bytes as u64)?;
        let mut sorted = Vec::new();
        sorted
            .try_reserve_exact(updates.len())
            .map_err(|_| RamError::Allocation)?;
        sorted.extend_from_slice(updates);
        sorted.sort_unstable_by_key(|(index, _)| *index);
        let mut previous = None;
        for (index, _) in &sorted {
            self.geometry.valid_length(*index)?;
            if previous == Some(*index) {
                return Err(RamError::InvalidOrder);
            }
            previous = Some(*index);
        }
        let root = rebuild(&self.root, 0, self.geometry.height(), &sorted, &self.budget)?;
        Ok(Self {
            geometry: self.geometry,
            root,
            budget: self.budget.clone(),
        })
    }

    /// Builds a sibling path for a real page under its stable region owner.
    ///
    /// # Errors
    ///
    /// Returns [`RamError`] for an invalid region identifier or page coordinate.
    pub fn proof(&self, region_id: &str, page_index: u64) -> Result<PageProof, RamError> {
        let valid_length = self.geometry.valid_length(page_index)?;
        let mut siblings = Vec::new();
        siblings
            .try_reserve_exact(self.geometry.height() as usize)
            .map_err(|_| RamError::Allocation)?;
        let mut node = &self.root;
        let mut height = self.geometry.height();
        while height != 0 {
            match &node.kind {
                NodeKind::Inner(left, right) => {
                    height -= 1;
                    if (page_index >> height) & 1 == 0 {
                        siblings.push(right.digest);
                        node = left;
                    } else {
                        siblings.push(left.digest);
                        node = right;
                    }
                }
                _ => return Err(RamError::InvalidEncoding),
            }
        }
        siblings.reverse();
        PageProof::new(
            region_id,
            page_index,
            valid_length,
            self.page_digest(page_index)?,
            siblings,
        )
    }
}

struct UniformNodes<'a> {
    budget: &'a MetadataBudget,
    empty: [Option<Arc<Node>>; 53],
    zero: [Option<Arc<Node>>; 53],
}

impl<'a> UniformNodes<'a> {
    fn new(budget: &'a MetadataBudget) -> Self {
        Self {
            budget,
            empty: std::array::from_fn(|_| None),
            zero: std::array::from_fn(|_| None),
        }
    }

    fn subtree(&mut self, height: u32, zero: bool) -> Result<Arc<Node>, RamError> {
        let existing = if zero {
            &self.zero[height as usize]
        } else {
            &self.empty[height as usize]
        };
        if let Some(node) = existing {
            return Ok(node.clone());
        }
        let node = if height == 0 {
            if zero {
                Node::page(PageDigest::hash(&[0; 4096])?, self.budget)?
            } else {
                Node::empty(self.budget)?
            }
        } else {
            let child = self.subtree(height - 1, zero)?;
            Node::inner(height, child.clone(), child, self.budget)?
        };
        if zero {
            self.zero[height as usize] = Some(node.clone());
        } else {
            self.empty[height as usize] = Some(node.clone());
        }
        Ok(node)
    }
}

fn build_zero(
    start: u64,
    height: u32,
    geometry: Geometry,
    uniform: &mut UniformNodes<'_>,
) -> Result<Arc<Node>, RamError> {
    if start >= geometry.page_count() {
        return uniform.subtree(height, false);
    }
    let span = 1_u64 << height;
    let full_pages = geometry.logical_length() / 4096;
    if start + span <= full_pages {
        return uniform.subtree(height, true);
    }
    if height == 0 {
        let length = geometry.valid_length(start)? as usize;
        return Node::page(PageDigest::hash(&[0; 4096][..length])?, uniform.budget);
    }
    let half = span / 2;
    let left = build_zero(start, height - 1, geometry, uniform)?;
    let right = build_zero(start + half, height - 1, geometry, uniform)?;
    Node::inner(height, left, right, uniform.budget)
}

fn build_digests(
    start: u64,
    height: u32,
    pages: &[PageDigest],
    uniform: &mut UniformNodes<'_>,
) -> Result<Arc<Node>, RamError> {
    if start >= pages.len() as u64 {
        return uniform.subtree(height, false);
    }
    if height == 0 {
        return Node::page(pages[start as usize], uniform.budget);
    }
    let half = 1_u64 << (height - 1);
    let left = build_digests(start, height - 1, pages, uniform)?;
    let right = build_digests(start + half, height - 1, pages, uniform)?;
    Node::inner(height, left, right, uniform.budget)
}

fn rebuild(
    node: &Arc<Node>,
    start: u64,
    height: u32,
    updates: &[(u64, PageDigest)],
    budget: &MetadataBudget,
) -> Result<Arc<Node>, RamError> {
    if updates.is_empty() {
        return Ok(node.clone());
    }
    if height == 0 {
        return match node.kind {
            NodeKind::Page(page) if page == updates[0].1 => Ok(node.clone()),
            NodeKind::Page(_) => Node::page(updates[0].1, budget),
            _ => Err(RamError::OutOfRange),
        };
    }
    let midpoint = start + (1_u64 << (height - 1));
    let split = updates.partition_point(|(index, _)| *index < midpoint);
    match &node.kind {
        NodeKind::Inner(left, right) => {
            let new_left = rebuild(left, start, height - 1, &updates[..split], budget)?;
            let new_right = rebuild(right, midpoint, height - 1, &updates[split..], budget)?;
            if Arc::ptr_eq(left, &new_left) && Arc::ptr_eq(right, &new_right) {
                return Ok(node.clone());
            }
            Node::inner(height, new_left, new_right, budget)
        }
        _ => Err(RamError::InvalidEncoding),
    }
}
