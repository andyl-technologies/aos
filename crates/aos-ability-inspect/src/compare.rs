//! Stable structural comparison between checked inspection views.

use std::collections::{BTreeMap, BTreeSet};

use aos_ability_model::{PlanId, RequiredFeature};
use serde::{Deserialize, Serialize};

use crate::{InspectionEdge, InspectionNode, InspectionView, NodeKey};

/// Exact schema discriminator for a portable inspection comparison.
pub const INSPECTION_DIFF_SCHEMA: &str = "aos.ability.inspection-diff/v1";

/// Records a node whose stable identity remained while its details changed.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChangedNode {
    /// Identifies the node in both plans.
    pub key: NodeKey,
    /// Retains its complete earlier redacted representation.
    pub before: InspectionNode,
    /// Retains its complete later redacted representation.
    pub after: InspectionNode,
}

/// Describes deterministic structural changes between two checked views.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InspectionDiff {
    /// Carries [`INSPECTION_DIFF_SCHEMA`].
    pub schema: String,
    /// Names required optional semantics; version 1 always emits an empty set.
    pub required_features: Vec<RequiredFeature>,
    /// Identifies the earlier checked effect plan.
    pub before_plan: PlanId,
    /// Identifies the later checked effect plan.
    pub after_plan: PlanId,
    /// Reports any semantic plan-identity change, including redacted details.
    pub semantic_plan_changed: bool,
    /// Lists nodes present only in the later view.
    pub added_nodes: Vec<InspectionNode>,
    /// Lists nodes present only in the earlier view.
    pub removed_nodes: Vec<InspectionNode>,
    /// Lists nodes whose stable identities retained changed details.
    pub changed_nodes: Vec<ChangedNode>,
    /// Lists typed edges present only in the later view.
    pub added_edges: Vec<InspectionEdge>,
    /// Lists typed edges present only in the earlier view.
    pub removed_edges: Vec<InspectionEdge>,
}

impl InspectionDiff {
    /// Computes stable node and edge changes from `before` to `after`.
    #[must_use]
    pub fn between(before: &InspectionView, after: &InspectionView) -> Self {
        let before_nodes: BTreeMap<_, _> = before
            .nodes()
            .iter()
            .map(|node| (node.key(), node))
            .collect();
        let after_nodes: BTreeMap<_, _> = after
            .nodes()
            .iter()
            .map(|node| (node.key(), node))
            .collect();

        let added_nodes = after_nodes
            .iter()
            .filter(|(key, _)| !before_nodes.contains_key(*key))
            .map(|(_, node)| (*node).clone())
            .collect();
        let removed_nodes = before_nodes
            .iter()
            .filter(|(key, _)| !after_nodes.contains_key(*key))
            .map(|(_, node)| (*node).clone())
            .collect();
        let changed_nodes = before_nodes
            .iter()
            .filter_map(|(key, before_node)| {
                let after_node = after_nodes.get(key)?;
                (*before_node != *after_node).then(|| ChangedNode {
                    key: key.clone(),
                    before: (*before_node).clone(),
                    after: (*after_node).clone(),
                })
            })
            .collect();

        let before_edges: BTreeSet<_> = before.edges().iter().cloned().collect();
        let after_edges: BTreeSet<_> = after.edges().iter().cloned().collect();
        let added_edges = after_edges.difference(&before_edges).cloned().collect();
        let removed_edges = before_edges.difference(&after_edges).cloned().collect();

        Self {
            schema: INSPECTION_DIFF_SCHEMA.to_string(),
            required_features: Vec::new(),
            before_plan: before.plan(),
            after_plan: after.plan(),
            semantic_plan_changed: before.plan() != after.plan(),
            added_nodes,
            removed_nodes,
            changed_nodes,
            added_edges,
            removed_edges,
        }
    }

    /// Reports whether both views have the same nodes and typed edges.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        !self.semantic_plan_changed
            && self.added_nodes.is_empty()
            && self.removed_nodes.is_empty()
            && self.changed_nodes.is_empty()
            && self.added_edges.is_empty()
            && self.removed_edges.is_empty()
    }
}
