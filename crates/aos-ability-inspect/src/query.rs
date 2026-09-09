//! Bounded deterministic traversal over an [`InspectionView`](crate::InspectionView).
//!
//! Query documents are canonical portable JSON so a terminal, editor, or web
//! frontend can request the same finite neighborhood:
//!
//! ```json
//! {
//!   "schema": "aos.ability.inspection-query/v1",
//!   "required_features": [],
//!   "roots": [{ "kind": "package", "identity": "sha256:0000000000000000000000000000000000000000000000000000000000000000" }],
//!   "direction": "outgoing",
//!   "max_depth": 4,
//!   "max_nodes": 256
//! }
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};

use aos_ability_model::{ABILITY_LIMITS_V1, PlanId, RequiredFeature};
use aos_contract::limits::JsonLimits;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    InspectionEdge, InspectionNode, InspectionProjection, InspectionView, NodeKey, ProjectionKind,
    ViewAnchor,
};

/// Exact schema discriminator for a portable inspection graph query.
pub const INSPECTION_QUERY_SCHEMA: &str = "aos.ability.inspection-query/v1";

/// Maximum canonical bytes accepted for one portable graph query.
pub const INSPECTION_QUERY_MAX_BYTES: usize = ABILITY_LIMITS_V1.max_document_bytes as usize;

/// Maximum roots accepted for one portable graph query.
pub const INSPECTION_QUERY_MAX_ROOTS: usize = ABILITY_LIMITS_V1.max_graph_nodes as usize;

/// Maximum edge distance accepted for one portable graph query.
pub const INSPECTION_QUERY_MAX_DEPTH: usize = ABILITY_LIMITS_V1.max_structural_depth as usize;

/// Maximum retained nodes accepted for one portable graph query.
pub const INSPECTION_QUERY_MAX_NODES: usize = ABILITY_LIMITS_V1.max_graph_nodes as usize;

/// Exact schema discriminator for a portable inspection graph slice.
pub const INSPECTION_SLICE_SCHEMA: &str = "aos.ability.inspection-slice/v1";

/// Selects which endpoint direction a traversal follows.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Direction {
    /// Follows edges from their source to their destination.
    #[default]
    Outgoing,
    /// Follows edges from their destination to their source.
    Incoming,
    /// Follows both directions while retaining original edge orientation.
    Both,
}

/// Defines a bounded neighborhood query rooted at exact typed identities.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GraphQuery {
    schema: String,
    required_features: Vec<RequiredFeature>,
    roots: Vec<NodeKey>,
    direction: Direction,
    max_depth: usize,
    max_nodes: usize,
}

/// Owns the deterministic result of one bounded neighborhood query.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GraphSlice {
    schema: String,
    required_features: Vec<RequiredFeature>,
    anchor: ViewAnchor,
    plan: PlanId,
    binding_plan: PlanId,
    executable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    projection: Option<ProjectionKind>,
    roots: Vec<NodeKey>,
    direction: Direction,
    max_depth: usize,
    max_nodes: usize,
    truncated: bool,
    nodes: Vec<InspectionNode>,
    edges: Vec<InspectionEdge>,
}

/// Reports why a bounded graph query could not be evaluated.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum GraphQueryError {
    /// Bounded strict JSON decoding failed.
    #[error("inspection graph query decoding failed: {0}")]
    Decode(String),
    /// Canonical JSON encoding failed.
    #[error("inspection graph query encoding failed: {0}")]
    Encode(String),
    /// The encoded query exceeds the version-1 byte bound.
    #[error("inspection graph query exceeds its encoded byte limit")]
    EncodedSizeLimit,
    /// The bytes are valid JSON but are not their canonical representation.
    #[error("inspection graph query is not canonically encoded")]
    NoncanonicalEncoding,
    /// No traversal root was supplied.
    #[error("an inspection graph query requires at least one root")]
    EmptyRoots,
    /// The number of roots exceeds the version-1 graph bound.
    #[error("an inspection graph query has {actual} roots but permits only {limit}")]
    RootLimit {
        /// Counts supplied roots before graph allocation.
        actual: usize,
        /// Carries the version-1 root limit.
        limit: usize,
    },
    /// The node bound cannot retain even one root.
    #[error("an inspection graph query requires a positive node bound")]
    ZeroNodeLimit,
    /// The traversal depth exceeds the version-1 structural bound.
    #[error("an inspection graph query depth {actual} exceeds its limit {limit}")]
    DepthLimit {
        /// Carries the requested edge depth.
        actual: usize,
        /// Carries the version-1 depth limit.
        limit: usize,
    },
    /// The retained-node budget exceeds the version-1 graph bound.
    #[error("an inspection graph query node budget {actual} exceeds its limit {limit}")]
    NodeLimit {
        /// Carries the requested node budget.
        actual: usize,
        /// Carries the version-1 node limit.
        limit: usize,
    },
    /// More distinct roots were supplied than the node bound permits.
    #[error("the inspection graph query has {roots} roots but permits only {limit} nodes")]
    RootsExceedNodeLimit {
        /// Counts distinct roots.
        roots: usize,
        /// Carries the configured node limit.
        limit: usize,
    },
    /// A root does not exist in the checked view.
    #[error("an inspection graph query root does not exist in the checked view")]
    UnknownRoot(Box<NodeKey>),
    /// Roots are not in strict canonical typed-identity order.
    #[error("inspection graph query roots are not canonically ordered and unique")]
    NoncanonicalRoots,
    /// The query schema discriminator is unsupported.
    #[error("the inspection graph query has an unsupported schema discriminator")]
    UnsupportedSchema,
    /// Version 1 does not support optional query feature semantics.
    #[error("the inspection graph query requires unsupported feature semantics")]
    UnsupportedFeatures,
}

impl GraphQuery {
    /// Creates an outgoing query with explicit depth and node bounds.
    #[must_use]
    pub fn new(
        roots: impl IntoIterator<Item = NodeKey>,
        max_depth: usize,
        max_nodes: usize,
    ) -> Self {
        let roots = roots
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        Self {
            schema: INSPECTION_QUERY_SCHEMA.to_string(),
            required_features: Vec::new(),
            roots,
            direction: Direction::Outgoing,
            max_depth,
            max_nodes,
        }
    }

    /// Selects the traversal direction.
    #[must_use]
    pub const fn with_direction(mut self, direction: Direction) -> Self {
        self.direction = direction;
        self
    }

    /// Decodes one strictly bounded canonical query document.
    ///
    /// Structural JSON limits are checked before deserialization allocates the
    /// typed root collection. Semantic bounds are checked before any source
    /// graph index is built.
    ///
    /// # Errors
    ///
    /// Returns an error for oversized, malformed, noncanonical, unsupported,
    /// empty, unordered, or version-limit-exceeding input.
    pub fn decode(bytes: &[u8]) -> Result<Self, GraphQueryError> {
        if bytes.len() > INSPECTION_QUERY_MAX_BYTES {
            return Err(GraphQueryError::EncodedSizeLimit);
        }
        let query = query_limits()
            .decode::<Self>(bytes, INSPECTION_QUERY_SCHEMA)
            .map_err(|error| GraphQueryError::Decode(error.to_string()))?;
        query.validate_structure()?;
        if query.canonical_bytes()? != bytes {
            return Err(GraphQueryError::NoncanonicalEncoding);
        }
        Ok(query)
    }

    /// Encodes this query as bounded canonical JSON.
    ///
    /// # Errors
    ///
    /// Returns an error when the query is invalid, exceeds a version-1 bound,
    /// or cannot be encoded in the canonical AOS JSON dialect.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, GraphQueryError> {
        self.validate_structure()?;

        let mut writer = QueryBoundedWriter::new(INSPECTION_QUERY_MAX_BYTES);
        serde_json::to_writer(&mut writer, self).map_err(|error| {
            if writer.exceeded {
                GraphQueryError::EncodedSizeLimit
            } else {
                GraphQueryError::Encode(error.to_string())
            }
        })?;
        aos_contract::canonical::to_vec(self)
            .map_err(|error| GraphQueryError::Encode(error.to_string()))
    }

    /// Returns the exact traversal roots.
    #[must_use]
    pub fn roots(&self) -> &[NodeKey] {
        &self.roots
    }

    /// Returns the selected edge direction.
    #[must_use]
    pub const fn direction(&self) -> Direction {
        self.direction
    }

    /// Returns the maximum traversed edge distance from a root.
    #[must_use]
    pub const fn max_depth(&self) -> usize {
        self.max_depth
    }

    /// Returns the maximum number of retained nodes.
    #[must_use]
    pub const fn max_nodes(&self) -> usize {
        self.max_nodes
    }

    fn validate_structure(&self) -> Result<(), GraphQueryError> {
        if self.schema != INSPECTION_QUERY_SCHEMA {
            return Err(GraphQueryError::UnsupportedSchema);
        }
        if !self.required_features.is_empty() {
            return Err(GraphQueryError::UnsupportedFeatures);
        }
        if self.roots.is_empty() {
            return Err(GraphQueryError::EmptyRoots);
        }
        if self.roots.len() > INSPECTION_QUERY_MAX_ROOTS {
            return Err(GraphQueryError::RootLimit {
                actual: self.roots.len(),
                limit: INSPECTION_QUERY_MAX_ROOTS,
            });
        }
        if self.roots.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(GraphQueryError::NoncanonicalRoots);
        }
        if self.max_depth > INSPECTION_QUERY_MAX_DEPTH {
            return Err(GraphQueryError::DepthLimit {
                actual: self.max_depth,
                limit: INSPECTION_QUERY_MAX_DEPTH,
            });
        }
        if self.max_nodes == 0 {
            return Err(GraphQueryError::ZeroNodeLimit);
        }
        if self.max_nodes > INSPECTION_QUERY_MAX_NODES {
            return Err(GraphQueryError::NodeLimit {
                actual: self.max_nodes,
                limit: INSPECTION_QUERY_MAX_NODES,
            });
        }
        if self.roots.len() > self.max_nodes {
            return Err(GraphQueryError::RootsExceedNodeLimit {
                roots: self.roots.len(),
                limit: self.max_nodes,
            });
        }
        Ok(())
    }
}

impl GraphSlice {
    /// Returns the source and integrity status inherited from the checked view.
    #[must_use]
    pub const fn anchor(&self) -> &ViewAnchor {
        &self.anchor
    }

    /// Returns the exact checked effect-plan identity.
    #[must_use]
    pub const fn plan(&self) -> PlanId {
        self.plan
    }

    /// Returns the exact checked binding-plan identity.
    #[must_use]
    pub const fn binding_plan(&self) -> PlanId {
        self.binding_plan
    }

    /// Reports whether the complete source plan was executable.
    #[must_use]
    pub const fn is_executable(&self) -> bool {
        self.executable
    }

    /// Returns the semantic projection used for traversal, when one was selected.
    #[must_use]
    pub const fn projection(&self) -> Option<ProjectionKind> {
        self.projection
    }

    /// Reports whether a reachable node was omitted by a query bound.
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// Returns retained nodes in stable typed-identity order.
    #[must_use]
    pub fn nodes(&self) -> &[InspectionNode] {
        &self.nodes
    }

    /// Returns all source-view edges whose endpoints were both retained.
    #[must_use]
    pub fn edges(&self) -> &[InspectionEdge] {
        &self.edges
    }
}

impl InspectionView {
    /// Evaluates a bounded deterministic neighborhood query.
    ///
    /// The returned edges are the induced subgraph over retained nodes. Edge
    /// orientation is never rewritten for incoming or bidirectional queries.
    ///
    /// # Errors
    ///
    /// Returns an error for missing roots, a zero node limit, too many roots,
    /// noncanonical roots, a root absent from this checked view, an unsupported
    /// schema, or unsupported required feature semantics.
    pub fn query(&self, query: &GraphQuery) -> Result<GraphSlice, GraphQueryError> {
        evaluate_query(
            QuerySource {
                anchor: self.anchor(),
                plan: self.plan(),
                binding_plan: self.binding_plan(),
                executable: self.is_executable(),
                projection: None,
                nodes: self.nodes(),
                edges: self.edges(),
            },
            query,
        )
    }
}

impl InspectionProjection {
    /// Evaluates a bounded deterministic neighborhood within this projection.
    ///
    /// The slice retains the projection identity, original edge orientation,
    /// and only relationships admitted by the selected projection.
    ///
    /// # Errors
    ///
    /// Returns an error for missing roots, a zero node limit, too many roots,
    /// noncanonical roots, a root absent from this projection, an unsupported
    /// schema, or unsupported required feature semantics.
    pub fn query(&self, query: &GraphQuery) -> Result<GraphSlice, GraphQueryError> {
        evaluate_query(
            QuerySource {
                anchor: self.anchor(),
                plan: self.plan(),
                binding_plan: self.binding_plan(),
                executable: self.is_executable(),
                projection: Some(self.kind()),
                nodes: self.nodes(),
                edges: self.edges(),
            },
            query,
        )
    }
}

struct QuerySource<'a> {
    anchor: &'a ViewAnchor,
    plan: PlanId,
    binding_plan: PlanId,
    executable: bool,
    projection: Option<ProjectionKind>,
    nodes: &'a [InspectionNode],
    edges: &'a [InspectionEdge],
}

fn evaluate_query(
    source: QuerySource<'_>,
    query: &GraphQuery,
) -> Result<GraphSlice, GraphQueryError> {
    query.validate_structure()?;
    let roots: BTreeSet<_> = query.roots.iter().cloned().collect();
    let node_index: BTreeMap<_, _> = source.nodes.iter().map(|node| (node.key(), node)).collect();
    validate_roots(&roots, &node_index)?;

    let mut selected = roots.clone();
    let mut frontier = roots;
    let mut truncated = false;

    for depth in 0..=query.max_depth {
        let candidates = neighbors(source.edges, &frontier, query.direction)
            .difference(&selected)
            .cloned()
            .collect::<BTreeSet<_>>();
        if candidates.is_empty() {
            break;
        }
        if depth == query.max_depth {
            truncated = true;
            break;
        }

        let remaining = query.max_nodes.saturating_sub(selected.len());
        if candidates.len() > remaining {
            truncated = true;
        }
        frontier = candidates.into_iter().take(remaining).collect();
        selected.extend(frontier.iter().cloned());
        if frontier.is_empty() {
            break;
        }
    }

    let nodes = selected
        .iter()
        .filter_map(|key| node_index.get(key).map(|node| (*node).clone()))
        .collect();
    let edges = source
        .edges
        .iter()
        .filter(|edge| selected.contains(&edge.from) && selected.contains(&edge.to))
        .cloned()
        .collect();

    Ok(GraphSlice {
        schema: INSPECTION_SLICE_SCHEMA.to_string(),
        required_features: Vec::new(),
        anchor: source.anchor.clone(),
        plan: source.plan,
        binding_plan: source.binding_plan,
        executable: source.executable,
        projection: source.projection,
        roots: query.roots.clone(),
        direction: query.direction,
        max_depth: query.max_depth,
        max_nodes: query.max_nodes,
        truncated,
        nodes,
        edges,
    })
}

fn validate_roots(
    roots: &BTreeSet<NodeKey>,
    nodes: &BTreeMap<NodeKey, &InspectionNode>,
) -> Result<(), GraphQueryError> {
    if let Some(root) = roots.iter().find(|root| !nodes.contains_key(*root)) {
        return Err(GraphQueryError::UnknownRoot(Box::new(root.clone())));
    }
    Ok(())
}

struct QueryBoundedWriter {
    remaining: usize,
    exceeded: bool,
}

impl QueryBoundedWriter {
    const fn new(limit: usize) -> Self {
        Self {
            remaining: limit,
            exceeded: false,
        }
    }
}

impl Write for QueryBoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.remaining {
            self.exceeded = true;
            return Err(io::Error::other(
                "serialized inspection graph query exceeds its byte limit",
            ));
        }
        self.remaining -= bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn query_limits() -> JsonLimits {
    JsonLimits {
        max_bytes: INSPECTION_QUERY_MAX_BYTES,
        max_depth: ABILITY_LIMITS_V1.max_structural_depth as usize,
        max_items: ABILITY_LIMITS_V1.max_collection_items as usize,
        max_string_bytes: ABILITY_LIMITS_V1.max_string_bytes as usize,
    }
}

#[cfg(test)]
mod tests {
    use aos_contract::Sha256Digest;

    use super::*;

    #[test]
    fn root_limit_precedes_root_index_allocation() {
        let root = NodeKey::Package(Sha256Digest::of_bytes("query root"));
        let query = GraphQuery {
            schema: INSPECTION_QUERY_SCHEMA.to_string(),
            required_features: Vec::new(),
            roots: vec![root; INSPECTION_QUERY_MAX_ROOTS + 1],
            direction: Direction::Outgoing,
            max_depth: 1,
            max_nodes: INSPECTION_QUERY_MAX_NODES,
        };

        assert!(matches!(
            query.validate_structure(),
            Err(GraphQueryError::RootLimit {
                actual,
                limit: INSPECTION_QUERY_MAX_ROOTS,
            }) if actual == INSPECTION_QUERY_MAX_ROOTS + 1
        ));
    }
}

fn neighbors(
    edges: &[InspectionEdge],
    frontier: &BTreeSet<NodeKey>,
    direction: Direction,
) -> BTreeSet<NodeKey> {
    let mut result = BTreeSet::new();
    for edge in edges {
        if matches!(direction, Direction::Outgoing | Direction::Both)
            && frontier.contains(&edge.from)
        {
            result.insert(edge.to.clone());
        }
        if matches!(direction, Direction::Incoming | Direction::Both) && frontier.contains(&edge.to)
        {
            result.insert(edge.from.clone());
        }
    }
    result
}
