//! Bounded deterministic traversal over an [`InspectionView`](crate::InspectionView).

use std::collections::{BTreeMap, BTreeSet};

use aos_ability_model::{PlanId, RequiredFeature};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    InspectionEdge, InspectionNode, InspectionProjection, InspectionView, NodeKey, ProjectionKind,
    ViewAnchor,
};

/// Exact schema discriminator for a portable inspection graph query.
pub const INSPECTION_QUERY_SCHEMA: &str = "aos.ability.inspection-query/v1";

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
    /// No traversal root was supplied.
    #[error("an inspection graph query requires at least one root")]
    EmptyRoots,
    /// The node bound cannot retain even one root.
    #[error("an inspection graph query requires a positive node bound")]
    ZeroNodeLimit,
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
    let node_index: BTreeMap<_, _> = source.nodes.iter().map(|node| (node.key(), node)).collect();
    let roots: BTreeSet<_> = query.roots.iter().cloned().collect();
    validate_query(query, &roots, &node_index)?;

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

fn validate_query(
    query: &GraphQuery,
    roots: &BTreeSet<NodeKey>,
    nodes: &BTreeMap<NodeKey, &InspectionNode>,
) -> Result<(), GraphQueryError> {
    if query.schema != INSPECTION_QUERY_SCHEMA {
        return Err(GraphQueryError::UnsupportedSchema);
    }
    if !query.required_features.is_empty() {
        return Err(GraphQueryError::UnsupportedFeatures);
    }
    if roots.is_empty() {
        return Err(GraphQueryError::EmptyRoots);
    }
    if query.roots.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(GraphQueryError::NoncanonicalRoots);
    }
    if query.max_nodes == 0 {
        return Err(GraphQueryError::ZeroNodeLimit);
    }
    if roots.len() > query.max_nodes {
        return Err(GraphQueryError::RootsExceedNodeLimit {
            roots: roots.len(),
            limit: query.max_nodes,
        });
    }
    if let Some(root) = roots.iter().find(|root| !nodes.contains_key(*root)) {
        return Err(GraphQueryError::UnknownRoot(Box::new(root.clone())));
    }
    Ok(())
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
