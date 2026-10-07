//! Constructs and exhaustively checks immutable hierarchical index relationships.
//!
//! Inputs are a closed graph of canonical namespace trees, an ordinary recipe,
//! and an explicit carrier semantic context. Results contain owned Node bytes,
//! not producer evidence, current policy, lookup authority or a verified index.
//! Missing inline values remain represented even when no candidates exist.
//!
//! ```text
//! owner -> primary(value || object -> route)
//!                  index-gaps -> gaps(object -> missing-route)
//! route(local-file -> object, local-graft -> object + child-route)
//! ```

mod verification;

pub use verification::verify;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use core::fmt;

use super::carrier::{
    GapBinding, Role, SemanticContext, validate_namespace_attributes, validate_node, validate_row,
};
use super::{IndexEvaluationRecipe, IndexKey};
use crate::cbor;
use crate::chunking::CDC_1M_MIN;
use crate::derived::{AttributeName, AttributeValue};
use crate::identity::{Digest, IdentityKind, TERRANE_V1};
use crate::tree_builder::Tree;
use crate::tree_format::{
    Attribute, ContentRef, Entry, EntryKind, LeafItem, MAX_GRAFT_DEPTH, MAX_TREE_LEVEL, NodeItems,
    Property, TreeUse, decode_node_for,
};

/// A rejected immutable construction or relationship check.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// A source root is absent from the supplied closed graph.
    MissingSource,
    /// A referenced auxiliary Node is unavailable.
    MissingNode,
    /// A source has the wrong identity, profile or namespace interpretation.
    Source,
    /// Conditional conflict coverage is not implemented by this pure evaluator.
    Incomplete,
    /// Rows or relationships differ from the immutable source.
    Relationship,
    /// A cycle or depth/resource limit prevents traversal.
    Limit,
    /// A physical tree encoding is invalid.
    Tree(crate::tree_format::Error),
    /// A contextual carrier encoding is invalid.
    Carrier(super::Error),
    /// A registered derived attribute has an invalid value.
    Attribute(crate::derived::Error),
}

impl From<crate::tree_format::Error> for Error {
    fn from(value: crate::tree_format::Error) -> Self {
        Self::Tree(value)
    }
}

impl From<super::Error> for Error {
    fn from(value: super::Error) -> Self {
        Self::Carrier(value)
    }
}

impl From<crate::derived::Error> for Error {
    fn from(value: crate::derived::Error) -> Self {
        Self::Attribute(value)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSource => formatter.write_str("missing immutable source root"),
            Self::MissingNode => formatter.write_str("missing immutable index node"),
            Self::Source => formatter.write_str("invalid immutable source context"),
            Self::Incomplete => formatter.write_str("conditional source coverage is incomplete"),
            Self::Relationship => formatter.write_str("divergent immutable index relationship"),
            Self::Limit => formatter.write_str("immutable index traversal limit exceeded"),
            Self::Tree(error) => error.fmt(formatter),
            Self::Carrier(error) => error.fmt(formatter),
            Self::Attribute(error) => error.fmt(formatter),
        }
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Tree(error) => Some(error),
            Self::Carrier(error) => Some(error),
            Self::Attribute(error) => Some(error),
            _ => None,
        }
    }
}

/// Counts traversal, auxiliary Node and row events during construction or verification.
///
/// These counters do not measure total encoding, hashing, or canonical tree
/// rebuilding cost. They do not establish incremental maintenance cost bounds.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Work {
    /// Source root occurrences visited, including repeated graft occurrences.
    pub source_roots: usize,
    /// Source entries inspected across all predicate traversals.
    pub source_entries: usize,
    /// Physical auxiliary Nodes retained or visited, counting repeated visits.
    pub nodes: usize,
    /// Contextual auxiliary rows checked.
    pub rows: usize,
}

/// Owns a detached primary root and its complete auxiliary Node closure.
///
/// Public fields permit assembling untrusted verification inputs. Neither the
/// root digest nor a successful construction grants current authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexData {
    /// Primary candidate-tree Node identity.
    pub root: Digest,
    /// Canonical Node bytes indexed by their domain-separated identities.
    pub nodes: BTreeMap<Digest, Vec<u8>>,
    /// Traversal, auxiliary Node and row events during initial construction.
    pub work: Work,
}

/// Reports an exhaustive immutable relationship check without current evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Verification {
    /// Distinct present value/object pairs, independent of current visibility.
    pub candidates: usize,
    /// Distinct objects with at least one missing inline occurrence.
    pub missing_objects: usize,
    /// Verification event counts, collected independently of construction counts.
    pub work: Work,
    /// Actual supplied-byte checks and canonical reconstruction operations.
    pub physical_work: PhysicalWork,
}

/// Measures report-defined physical operations, excluding allocator and CPU instructions.
///
/// Repeated contextual checks remain repeated operations. Reconstruction retains
/// every editor phase rather than estimating work from final stored Node sizes.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PhysicalWork {
    /// Supplied Node decode calls, including the second root decode for properties.
    pub node_decodes: usize,
    /// Supplied bytes passed to Node decoding across all calls.
    pub node_bytes_decoded: usize,
    /// Actual supplied Node identity preimage bytes, including domain and NUL.
    pub node_bytes_hashed: usize,
    /// Canonical reconstructions in physical-tree visitation order.
    pub reconstructions: Vec<ReconstructionWork>,
}

/// Counts the actual initial empty frame before measured index reconstruction.
///
/// The existing persistent editor supplies subsequent insertion/property work.
/// This small report does not require incremental or streaming constructors.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct InitialFrameWork {
    /// Canonical bytes encoded for the initial empty physical frame.
    pub node_bytes_encoded: usize,
    /// Node-domain identity preimage bytes hashed for that frame.
    pub node_bytes_hashed: usize,
}

/// Separates the initial empty frame, full insertion, and final root properties.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconstructionWork {
    /// Supplied physical-tree root checked against this reconstruction.
    pub root: Digest,
    /// One initial empty Node encoding and identity hash; no item operations.
    pub initial: InitialFrameWork,
    /// Actual full-insertion work, including boundary short-circuit decisions.
    pub entries: crate::tree_builder::Work,
    /// Actual property replacement work; unchanged properties produce zero work.
    pub properties: crate::tree_builder::Work,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Predicate {
    object: Digest,
    value: Option<Vec<u8>>,
}

/// Borrows immutable namespace inputs for shared pure index checks.
pub(super) struct Source<'graph, 'value> {
    /// Independently keyed immutable namespace roots.
    pub(super) trees: &'graph BTreeMap<Digest, Tree<'value>>,
    /// Registered inline value attribute selected by the recipe.
    pub(super) attribute: &'graph str,
    /// Explicit content profile minimum used for physical Tree validation.
    pub(super) minimum: u64,
}

impl<'graph, 'value> Source<'graph, 'value> {
    /// Checks identity, physical context, conflicts and namespace-root placement.
    ///
    /// # Errors
    /// Rejects absent roots, wrong identities/profiles/uses, conflicts and gaps.
    pub(super) fn tree(&self, root: Digest) -> Result<&Tree<'value>, Error> {
        let tree = self.trees.get(&root).ok_or(Error::MissingSource)?;
        if self.minimum != CDC_1M_MIN as u64
            || tree.root_identity() != root
            || tree.usage() != TreeUse::Ordinary
            || tree.min_chunk_size() != self.minimum
        {
            return Err(Error::Source);
        }
        if tree.has_conflicts() {
            return Err(Error::Incomplete);
        }
        if tree.props().is_some_and(|properties| {
            properties
                .iter()
                .any(|property| property.name == "index-gaps")
        }) {
            return Err(Error::Source);
        }
        Ok(tree)
    }

    fn enter(&self, root: Digest, active: &mut Vec<Digest>, work: &mut Work) -> Result<(), Error> {
        if active.len() > MAX_GRAFT_DEPTH || active.contains(&root) {
            return Err(Error::Limit);
        }
        self.tree(root)?;
        active.push(root);
        work.source_roots = work.source_roots.checked_add(1).ok_or(Error::Limit)?;
        Ok(())
    }

    /// Checks namespace placement and the selected canonical inline value.
    ///
    /// # Errors
    /// Rejects structural namespace attributes and malformed registered values.
    pub(super) fn value(&self, entry: &Entry<'value>) -> Result<Option<&'value [u8]>, Error> {
        validate_namespace_attributes(2, entry)?;
        let Some(attribute) = entry
            .attrs
            .iter()
            .find(|attribute| attribute.name == self.attribute)
        else {
            return Ok(None);
        };
        validate_value(self.attribute, attribute.value)?;
        Ok(Some(attribute.value))
    }

    fn inventory(
        &self,
        root: Digest,
        active: &mut Vec<Digest>,
        predicates: &mut BTreeSet<Predicate>,
        work: &mut Work,
    ) -> Result<(), Error> {
        self.enter(root, active, work)?;
        for item in self.tree(root)?.iter() {
            work.source_entries = work.source_entries.checked_add(1).ok_or(Error::Limit)?;
            validate_namespace_attributes(2, &item.entry)?;
            match &item.entry.kind {
                EntryKind::File { content, .. } => {
                    predicates.insert(Predicate {
                        object: object(content),
                        value: self.value(&item.entry)?.map(<[u8]>::to_vec),
                    });
                }
                EntryKind::Tree { root: child, props } => {
                    if props.as_ref().is_some_and(|properties| {
                        properties
                            .iter()
                            .any(|property| matches!(property.name, "index-roots" | "index-gaps"))
                    }) {
                        return Err(Error::Source);
                    }
                    self.inventory(*child, active, predicates, work)?
                }
                EntryKind::Conflict { .. } => return Err(Error::Incomplete),
                _ => {}
            }
        }
        active.pop();
        Ok(())
    }
}

fn object(content: &ContentRef) -> Digest {
    match content {
        ContentRef::Inline(digest) | ContentRef::Manifest(digest) => *digest,
    }
}

/// Checks a registered value's type, canonical representation and key limit.
///
/// # Errors
/// Rejects invalid derived-value schemas or invalid/oversized canonical keys.
pub(super) fn validate_value(attribute: &str, value: &[u8]) -> Result<(), Error> {
    // Value registration does not invent schemas for arbitrary writer tags or
    // adapters. The registered per-object derived schemas do define types.
    if let Ok(name) = AttributeName::parse(attribute) {
        AttributeValue::decode(name, value)?;
    }
    IndexKey::new(value, [0; 32])?;
    Ok(())
}

struct OwnedRow {
    key: Vec<u8>,
    object: Digest,
    route: Option<Digest>,
}

fn pointer_bytes(route: Option<Digest>) -> Vec<u8> {
    let mut bytes = Vec::new();
    if let Some(route) = route {
        cbor::write_bytes(&mut bytes, &route);
    }
    bytes
}

fn entry<'a>(row: &OwnedRow, pointer: &'a [u8]) -> Entry<'a> {
    Entry {
        kind: EntryKind::Index {
            targets: alloc::vec![row.object],
        },
        attrs: if row.route.is_some() {
            alloc::vec![Attribute {
                name: "index.occurrences",
                value: pointer
            }]
        } else {
            Vec::new()
        },
        attrs_present: row.route.is_some(),
        xattrs: Vec::new(),
        xattrs_present: false,
        provenance: None,
    }
}

struct Builder {
    context: SemanticContext,
    minimum: u64,
    nodes: BTreeMap<Digest, Vec<u8>>,
    work: Work,
}

impl Builder {
    fn tree(
        &mut self,
        role: Role,
        rows: &[OwnedRow],
        gap: Option<Digest>,
    ) -> Result<Digest, Error> {
        let pointers: Vec<_> = rows.iter().map(|row| pointer_bytes(row.route)).collect();
        let entries = rows
            .iter()
            .zip(&pointers)
            .map(|(row, pointer)| LeafItem {
                key: row.key.clone(),
                entry: entry(row, pointer),
            })
            .collect();
        let binding = gap.map(|node| GapBinding::new(node).encode_binding());
        let properties = binding.as_ref().map(|value| {
            alloc::vec![Property {
                name: "index-gaps",
                value
            }]
        });
        let tree = Tree::build(entries, properties, self.minimum, TreeUse::Index)?;
        for node in tree.nodes() {
            validate_node(
                self.context,
                role,
                node.node(),
                node.identity() == tree.root_identity(),
            )?;
            self.work.nodes = self.work.nodes.checked_add(1).ok_or(Error::Limit)?;
            if let NodeItems::Leaf(items) = node.items() {
                self.work.rows = self
                    .work
                    .rows
                    .checked_add(items.len())
                    .ok_or(Error::Limit)?;
            }
            self.nodes.insert(node.identity(), node.encoded().to_vec());
        }
        Ok(tree.root_identity())
    }

    fn route(
        &mut self,
        source: &Source<'_, '_>,
        root: Digest,
        predicate: &Predicate,
        active: &mut Vec<Digest>,
    ) -> Result<Option<Digest>, Error> {
        source.enter(root, active, &mut self.work)?;
        let mut rows = Vec::new();
        for item in source.tree(root)?.iter() {
            self.work.source_entries = self
                .work
                .source_entries
                .checked_add(1)
                .ok_or(Error::Limit)?;
            match &item.entry.kind {
                EntryKind::File { content, .. } => {
                    if object(content) == predicate.object
                        && source.value(&item.entry)? == predicate.value.as_deref()
                    {
                        rows.push(OwnedRow {
                            key: item.key.clone(),
                            object: predicate.object,
                            route: None,
                        });
                    }
                }
                EntryKind::Tree { root: child, .. } => {
                    if let Some(route) = self.route(source, *child, predicate, active)? {
                        rows.push(OwnedRow {
                            key: item.key.clone(),
                            object: predicate.object,
                            route: Some(route),
                        });
                    }
                }
                _ => {}
            }
        }
        active.pop();
        if rows.is_empty() {
            return Ok(None);
        }
        let role = if predicate.value.is_some() {
            Role::PresentRoute
        } else {
            Role::MissingRoute
        };
        self.tree(role, &rows, None).map(Some)
    }
}

/// Constructs the exact closed-profile candidate, gap and hierarchical routes.
///
/// Every reached graft is loaded from the checked source-root graph. Matching
/// files retain their actual Chunk/Manifest identity; route pointers occupy
/// only structural metadata. Source properties and producer availability do
/// not select a different immutable result. Missing values are not exclusions.
///
/// # Errors
/// Rejects unavailable or mismatched source roots, incompatible chunk geometry,
/// nonnamespace trees, unsupported conflicts, cycles/depth limits, malformed
/// typed values and invalid contextual carrier encodings.
pub fn construct(
    recipe: &IndexEvaluationRecipe<'_>,
    trees: &BTreeMap<Digest, Tree<'_>>,
    minimum: u64,
    context: SemanticContext,
) -> Result<IndexData, Error> {
    let source = Source {
        trees,
        attribute: recipe.attribute(),
        minimum,
    };
    let mut builder = Builder {
        context,
        minimum,
        nodes: BTreeMap::new(),
        work: Work::default(),
    };
    let mut predicates = BTreeSet::new();
    source.inventory(
        recipe.owner(),
        &mut Vec::new(),
        &mut predicates,
        &mut builder.work,
    )?;

    let mut present = Vec::new();
    let mut missing = Vec::new();
    for predicate in predicates {
        let route = builder
            .route(&source, recipe.owner(), &predicate, &mut Vec::new())?
            .ok_or(Error::Relationship)?;
        let row = OwnedRow {
            key: match &predicate.value {
                Some(value) => IndexKey::new(value, predicate.object)?.encode(),
                None => predicate.object.to_vec(),
            },
            object: predicate.object,
            route: Some(route),
        };
        if predicate.value.is_some() {
            present.push(row);
        } else {
            missing.push(row);
        }
    }
    present.sort_by(|left, right| left.key.cmp(&right.key));
    missing.sort_by(|left, right| left.key.cmp(&right.key));
    let gap = if missing.is_empty() {
        None
    } else {
        Some(builder.tree(Role::Gap, &missing, None)?)
    };
    let root = builder.tree(Role::Primary, &present, gap)?;
    Ok(IndexData {
        root,
        nodes: builder.nodes,
        work: builder.work,
    })
}
