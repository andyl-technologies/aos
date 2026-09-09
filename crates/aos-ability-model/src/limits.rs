//! Versioned resource limits for decoding, composition, and graph validation.

use serde::{Deserialize, Serialize};

/// Defines the bounded version-1 ability contract profile.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LimitProfile {
    /// Maximum canonical document size in bytes.
    pub max_document_bytes: u64,
    /// Maximum JSON or composition nesting depth.
    pub max_structural_depth: u32,
    /// Maximum total number of graph nodes or operations.
    pub max_graph_nodes: u32,
    /// Maximum total number of graph edges.
    pub max_graph_edges: u32,
    /// Maximum provider-resolution rounds.
    pub max_resolver_rounds: u32,
    /// Maximum candidates examined for one unresolved alias.
    pub max_candidates_per_alias: u32,
    /// Maximum total collection members in one document.
    pub max_collection_items: u64,
    /// Maximum UTF-8 byte length of one string or member name.
    pub max_string_bytes: u64,
    /// Maximum provider-search visits for one plan.
    pub max_provider_search_visits: u32,
}

/// Supplies the admission ceilings fixed by the RFC-0022 version-1 profile.
pub const ABILITY_LIMITS_V1: LimitProfile = LimitProfile {
    max_document_bytes: 32 * 1024 * 1024,
    max_structural_depth: 64,
    max_graph_nodes: 100_000,
    max_graph_edges: 1_000_000,
    max_resolver_rounds: 64,
    max_candidates_per_alias: 64,
    max_collection_items: 2_000_000,
    max_string_bytes: 1024 * 1024,
    max_provider_search_visits: 100_000,
};

impl LimitProfile {
    /// Reports whether every limit fits the version-1 admission ceiling.
    ///
    /// Required structural, graph, and search bounds must also be nonzero.
    #[must_use]
    pub fn is_admissible_v1(&self) -> bool {
        let ceiling = ABILITY_LIMITS_V1;
        self.max_document_bytes > 0
            && self.max_document_bytes <= ceiling.max_document_bytes
            && self.max_structural_depth > 0
            && self.max_structural_depth <= ceiling.max_structural_depth
            && self.max_graph_nodes > 0
            && self.max_graph_nodes <= ceiling.max_graph_nodes
            && self.max_graph_edges > 0
            && self.max_graph_edges <= ceiling.max_graph_edges
            && self.max_resolver_rounds > 0
            && self.max_resolver_rounds <= ceiling.max_resolver_rounds
            && self.max_candidates_per_alias > 0
            && self.max_candidates_per_alias <= ceiling.max_candidates_per_alias
            && self.max_collection_items > 0
            && self.max_collection_items <= ceiling.max_collection_items
            && self.max_string_bytes > 0
            && self.max_string_bytes <= ceiling.max_string_bytes
            && self.max_provider_search_visits > 0
            && self.max_provider_search_visits <= ceiling.max_provider_search_visits
    }
}
