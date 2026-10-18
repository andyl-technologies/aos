//! SPDX-License-Identifier: MIT OR Apache-2.0
//! Implements sparse persistent ordered region trees with shared immutable nodes.
//!
//! Uniform zero and padding subtrees share children rather than expanding the
//! logical address space. A batch rebuilds each changed ancestor once; unchanged
//! content and snapshots retain their prior nodes. Node lifetime charges follow
//! the final shared reference, including references retained by older snapshots.
//! Authenticated source commitments remain opaque until a verified path arrives;
//! hydration preserves every previously changed descendant.

use crate::budget::Reservation;
use crate::{
    Geometry, MetadataBudget, NodeDigest, PageDigest, PageProof, RamError, RamRootDigest,
    RegionTreeDigest, RootRecord, empty_leaf_digest, inner_digest, leaf_digest, region_tree_digest,
};
use std::sync::Arc;

const ARC_OVERHEAD: usize = 2 * std::mem::size_of::<usize>();

#[derive(Debug)]
struct Node {
    digest: NodeDigest,
    kind: NodeKind,
    _charge: Reservation,
    has_opaque: bool,
}

#[derive(Debug)]
enum NodeKind {
    Page(PageDigest),
    Empty,
    Inner(Arc<Node>, Arc<Node>),
    Opaque,
}

impl Node {
    fn opaque(digest: NodeDigest, budget: &MetadataBudget) -> Result<Arc<Self>, RamError> {
        let charge = budget.reserve((std::mem::size_of::<Self>() + ARC_OVERHEAD) as u64)?;
        Ok(Arc::new(Self {
            digest,
            kind: NodeKind::Opaque,
            _charge: charge,
            has_opaque: true,
        }))
    }

    fn page(page: PageDigest, budget: &MetadataBudget) -> Result<Arc<Self>, RamError> {
        let charge = budget.reserve((std::mem::size_of::<Self>() + ARC_OVERHEAD) as u64)?;
        Ok(Arc::new(Self {
            digest: leaf_digest(page),
            kind: NodeKind::Page(page),
            _charge: charge,
            has_opaque: false,
        }))
    }

    fn empty(budget: &MetadataBudget) -> Result<Arc<Self>, RamError> {
        let charge = budget.reserve((std::mem::size_of::<Self>() + ARC_OVERHEAD) as u64)?;
        Ok(Arc::new(Self {
            digest: empty_leaf_digest(),
            kind: NodeKind::Empty,
            _charge: charge,
            has_opaque: false,
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
        if left.digest == right.digest && !left.has_opaque && !right.has_opaque {
            right = left.clone();
        }
        let charge = budget.reserve((std::mem::size_of::<Self>() + ARC_OVERHEAD) as u64)?;
        Ok(Arc::new(Self {
            digest,
            has_opaque: left.has_opaque || right.has_opaque,
            kind: NodeKind::Inner(left, right),
            _charge: charge,
        }))
    }
}

/// A region's immutable ordered page identities and checked logical geometry.
#[derive(Clone, Debug)]
pub struct RegionTree {
    geometry: Geometry,
    root: Option<Arc<Node>>,
    origin_digest: RegionTreeDigest,
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
            origin_digest: region_tree_digest(geometry, root.digest),
            root: Some(root),
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
            origin_digest: region_tree_digest(geometry, root.digest),
            root: Some(root),
            budget: budget.clone(),
        })
    }

    /// Declares an authenticated region commitment without traversing its pages.
    ///
    /// The caller retains the matching immutable source separately. Unhydrated
    /// paths cannot supply page digests, proofs, or accept updates. Their scoped
    /// identity remains available without a page walk.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid logical geometry.
    pub fn from_region_digest(
        logical_length: u64,
        digest: RegionTreeDigest,
        budget: &MetadataBudget,
    ) -> Result<Self, RamError> {
        Ok(Self {
            geometry: Geometry::new(logical_length)?,
            root: None,
            origin_digest: digest,
            budget: budget.clone(),
        })
    }

    /// Hydrates one authenticated immutable source path while preserving changes.
    ///
    /// Source evidence always names the original region commitment, including
    /// after updates. Existing changed descendants remain authoritative; only
    /// unknown original subtrees are expanded. This operation never reads RAM.
    ///
    /// # Errors
    ///
    /// Returns an error for foreign source roots, invalid proofs or geometry,
    /// inconsistent opaque identities, or bounded metadata exhaustion. Failure
    /// leaves the original tree unchanged and releases new reservations.
    pub fn hydrated(
        &self,
        proof: &PageProof,
        source: &RootRecord,
        expected_source: RamRootDigest,
    ) -> Result<Self, RamError> {
        proof.verify_identity(source, expected_source)?;
        let region = source
            .topology()
            .region(proof.region_id())
            .ok_or(RamError::OutOfRange)?;
        if region.geometry() != self.geometry
            || source.region_root(proof.region_id()) != Some(self.origin_digest)
        {
            return Err(RamError::DigestMismatch);
        }
        let mut path = [empty_leaf_digest(); 53];
        path[0] = leaf_digest(proof.page_digest());
        for (level, sibling) in proof.siblings().iter().enumerate() {
            path[level + 1] = if (proof.page_index() >> level) & 1 == 0 {
                inner_digest(level as u32 + 1, path[level], *sibling)?
            } else {
                inner_digest(level as u32 + 1, *sibling, path[level])?
            };
        }
        let root = hydrate_path(
            self.root.as_ref(),
            self.geometry.height(),
            proof,
            &path,
            &self.budget,
        )?;
        Ok(Self {
            geometry: self.geometry,
            root: Some(root),
            origin_digest: self.origin_digest,
            budget: self.budget.clone(),
        })
    }

    /// Returns the checked logical geometry.
    pub const fn geometry(&self) -> Geometry {
        self.geometry
    }

    /// Returns the canonical region commitment.
    pub fn digest(&self) -> RegionTreeDigest {
        self.root.as_ref().map_or(self.origin_digest, |root| {
            region_tree_digest(self.geometry, root.digest)
        })
    }

    /// Returns the reduced node commitment once a source path has been hydrated.
    pub fn node_digest(&self) -> Option<NodeDigest> {
        self.root.as_ref().map(|root| root.digest)
    }

    /// Returns the admitted metadata domain used by this tree.
    pub fn metadata_budget(&self) -> &MetadataBudget {
        &self.budget
    }

    /// Reports whether both views share root structure or an opaque source identity.
    pub fn shares_root_with(&self, other: &Self) -> bool {
        match (&self.root, &other.root) {
            (Some(left), Some(right)) => Arc::ptr_eq(left, right),
            (None, None) => {
                self.geometry == other.geometry && self.origin_digest == other.origin_digest
            }
            _ => false,
        }
    }

    /// Retrieves a real page's content digest without reading guest RAM.
    ///
    /// # Errors
    ///
    /// Returns [`RamError::OutOfRange`] for absent/padding positions or an
    /// invariant error if the tree does not contain a page at that coordinate.
    /// Returns [`RamError::MissingProof`] if the requested path remains opaque.
    pub fn page_digest(&self, page_index: u64) -> Result<PageDigest, RamError> {
        self.geometry.valid_length(page_index)?;
        let mut node = self.root.as_ref().ok_or(RamError::MissingProof)?;
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
                NodeKind::Opaque => return Err(RamError::MissingProof),
                _ => return Err(RamError::InvalidEncoding),
            }
        }
        match node.kind {
            NodeKind::Page(page) => Ok(page),
            NodeKind::Opaque => Err(RamError::MissingProof),
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
    /// metadata exhaustion, or [`RamError::MissingProof`] for opaque targets.
    /// New nodes and temporary reservations are released
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
        let existing = self.root.as_ref().ok_or(RamError::MissingProof)?;
        let root = rebuild(existing, 0, self.geometry.height(), &sorted, &self.budget)?;
        Ok(Self {
            geometry: self.geometry,
            root: Some(root),
            origin_digest: self.origin_digest,
            budget: self.budget.clone(),
        })
    }

    /// Builds a sibling path for a real page under its stable region owner.
    ///
    /// # Errors
    ///
    /// Returns [`RamError`] for an invalid region identifier or page coordinate,
    /// allocation failure, or [`RamError::MissingProof`] for an opaque target.
    pub fn proof(&self, region_id: &str, page_index: u64) -> Result<PageProof, RamError> {
        let valid_length = self.geometry.valid_length(page_index)?;
        let mut siblings = Vec::new();
        siblings
            .try_reserve_exact(self.geometry.height() as usize)
            .map_err(|_| RamError::Allocation)?;
        let mut node = self.root.as_ref().ok_or(RamError::MissingProof)?;
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
                NodeKind::Opaque => return Err(RamError::MissingProof),
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
            NodeKind::Opaque => Err(RamError::MissingProof),
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
        NodeKind::Opaque => Err(RamError::MissingProof),
        _ => Err(RamError::InvalidEncoding),
    }
}

fn hydrate_path(
    existing: Option<&Arc<Node>>,
    height: u32,
    proof: &PageProof,
    path: &[NodeDigest; 53],
    budget: &MetadataBudget,
) -> Result<Arc<Node>, RamError> {
    if let Some(node) = existing {
        match &node.kind {
            NodeKind::Opaque if node.digest != path[height as usize] => {
                return Err(RamError::DigestMismatch);
            }
            NodeKind::Opaque => {}
            NodeKind::Page(_) if height == 0 => return Ok(node.clone()),
            NodeKind::Inner(left, right) if height != 0 => {
                let level = height - 1;
                let (new_left, new_right) = if (proof.page_index() >> level) & 1 == 0 {
                    (
                        hydrate_path(Some(left), level, proof, path, budget)?,
                        right.clone(),
                    )
                } else {
                    (
                        left.clone(),
                        hydrate_path(Some(right), level, proof, path, budget)?,
                    )
                };
                if Arc::ptr_eq(left, &new_left) && Arc::ptr_eq(right, &new_right) {
                    return Ok(node.clone());
                }
                return Node::inner(height, new_left, new_right, budget);
            }
            _ => return Err(RamError::InvalidEncoding),
        }
    }
    if height == 0 {
        return Node::page(proof.page_digest(), budget);
    }
    let level = height - 1;
    let child = hydrate_path(None, level, proof, path, budget)?;
    let sibling = Node::opaque(proof.siblings()[level as usize], budget)?;
    if (proof.page_index() >> level) & 1 == 0 {
        Node::inner(height, child, sibling, budget)
    } else {
        Node::inner(height, sibling, child, budget)
    }
}

/// Bounds the charged node allocation size of one fully distinct region tree.
pub(crate) fn maximum_node_metadata(geometry: Geometry) -> Result<u64, RamError> {
    let nodes = geometry
        .padded_leaf_count()
        .checked_mul(2)
        .and_then(|count| count.checked_sub(1))
        .ok_or(RamError::Overflow)?;
    nodes
        .checked_mul((std::mem::size_of::<Node>() + ARC_OVERHEAD) as u64)
        .ok_or(RamError::Overflow)
}
