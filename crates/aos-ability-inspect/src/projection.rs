//! Selectable semantic projections over one complete checked-plan view.
//!
//! A projection filters the shared typed graph by relationship semantics. It
//! keeps original node identities and edge orientation, so frontends can change
//! layouts or switch projections without inventing another graph model.
//!
//! The portable format is a bounded JSON object. Canonical encoding removes
//! the whitespace shown here:
//!
//! ```json
//! {
//!   "schema": "aos.ability.inspection-projection/v1",
//!   "required_features": [],
//!   "kind": "retention",
//!   "anchor": { "kind": "locally-checked" },
//!   "plan": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
//!   "binding_plan": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
//!   "executable": true,
//!   "nodes": [],
//!   "edges": []
//! }
//! ```

use std::collections::BTreeSet;
use std::io::{self, Write};

use aos_ability_model::{PlanId, RequiredFeature};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    INSPECTION_VIEW_MAX_BYTES, INSPECTION_VIEW_MAX_ITEMS, InspectionEdge, InspectionNode,
    InspectionRelation, InspectionView, ViewAnchor,
};

/// Exact schema discriminator for a semantic inspection projection.
pub const INSPECTION_PROJECTION_SCHEMA: &str = "aos.ability.inspection-projection/v1";

/// Selects one RFC-defined view of the complete typed deployment graph.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProjectionKind {
    /// Shows package declarations, requests, interfaces, and composition aggregates.
    Composition,
    /// Shows selected providers, grants, implementation authority, and obligations.
    BindingAuthority,
    /// Shows operations, resource access, readiness, ordering, and communication.
    Activation,
    /// Shows consumers and exact artifacts retained by the checked plan.
    Retention,
}

/// Owns one deterministic semantic projection of a complete inspection view.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InspectionProjection {
    schema: String,
    required_features: Vec<RequiredFeature>,
    kind: ProjectionKind,
    anchor: ViewAnchor,
    plan: PlanId,
    binding_plan: PlanId,
    executable: bool,
    nodes: Vec<InspectionNode>,
    edges: Vec<InspectionEdge>,
}

/// Reports why a semantic graph projection cannot be represented safely.
#[derive(Debug, Error)]
pub enum InspectionProjectionError {
    /// Canonical projection encoding failed.
    #[error("inspection projection encoding failed: {0}")]
    Encoding(#[source] anyhow::Error),
    /// The projection exceeds the version-1 encoded byte bound.
    #[error("inspection projection exceeds its encoded byte limit")]
    EncodedSizeLimit,
    /// The projection exceeds the version-1 node or edge count bound.
    #[error("inspection projection exceeds its node or edge count limit")]
    ItemLimit,
    /// The schema discriminator is unsupported.
    #[error("inspection projection has an unsupported schema discriminator")]
    UnsupportedSchema,
    /// Version 1 does not support optional feature semantics.
    #[error("inspection projection requires unsupported feature semantics")]
    UnsupportedFeatures,
}

impl InspectionProjection {
    /// Derives a named projection while preserving stable identities and edge meaning.
    ///
    /// # Errors
    ///
    /// Returns an error if the projection exceeds its node, edge, or encoded
    /// byte bound, or if canonical encoding fails.
    pub fn from_view(
        view: &InspectionView,
        kind: ProjectionKind,
    ) -> Result<Self, InspectionProjectionError> {
        let edges: Vec<_> = view
            .edges()
            .iter()
            .filter(|edge| relation_is_visible(kind, edge.relation))
            .cloned()
            .collect();
        let endpoints: BTreeSet<_> = edges
            .iter()
            .flat_map(|edge| [&edge.from, &edge.to])
            .cloned()
            .collect();
        let nodes = view
            .nodes()
            .iter()
            .filter(|node| node_is_visible(kind, node) || endpoints.contains(&node.key()))
            .cloned()
            .collect();

        let projection = Self {
            schema: INSPECTION_PROJECTION_SCHEMA.to_string(),
            required_features: Vec::new(),
            kind,
            anchor: view.anchor().clone(),
            plan: view.plan(),
            binding_plan: view.binding_plan(),
            executable: view.is_executable(),
            nodes,
            edges,
        };
        projection.canonical_bytes()?;
        Ok(projection)
    }

    /// Encodes the complete projection as bounded canonical JSON.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported schema or feature, excessive graph
    /// size, excessive encoded size, or canonical serialization failure.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, InspectionProjectionError> {
        if self.schema != INSPECTION_PROJECTION_SCHEMA {
            return Err(InspectionProjectionError::UnsupportedSchema);
        }
        if !self.required_features.is_empty() {
            return Err(InspectionProjectionError::UnsupportedFeatures);
        }
        if self.nodes.len() > INSPECTION_VIEW_MAX_ITEMS
            || self.edges.len() > INSPECTION_VIEW_MAX_ITEMS
        {
            return Err(InspectionProjectionError::ItemLimit);
        }

        let mut writer = ProjectionBoundedWriter::new(INSPECTION_VIEW_MAX_BYTES);
        serde_json::to_writer(&mut writer, self).map_err(|error| {
            if writer.exceeded {
                InspectionProjectionError::EncodedSizeLimit
            } else {
                InspectionProjectionError::Encoding(error.into())
            }
        })?;
        aos_contract::canonical::to_vec(self).map_err(InspectionProjectionError::Encoding)
    }

    /// Returns the semantic projection kind.
    #[must_use]
    pub const fn kind(&self) -> ProjectionKind {
        self.kind
    }

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

    /// Reports whether every obligation in the complete source plan was discharged.
    #[must_use]
    pub const fn is_executable(&self) -> bool {
        self.executable
    }

    /// Returns retained nodes in stable typed-identity order.
    #[must_use]
    pub fn nodes(&self) -> &[InspectionNode] {
        &self.nodes
    }

    /// Returns retained edges in stable endpoint and relation order.
    #[must_use]
    pub fn edges(&self) -> &[InspectionEdge] {
        &self.edges
    }
}

impl InspectionView {
    /// Derives one RFC-defined semantic projection from this complete view.
    ///
    /// # Errors
    ///
    /// Returns an error if the projection exceeds its graph or encoded byte
    /// bound, or if canonical encoding fails.
    pub fn project(
        &self,
        kind: ProjectionKind,
    ) -> Result<InspectionProjection, InspectionProjectionError> {
        InspectionProjection::from_view(self, kind)
    }
}

fn node_is_visible(kind: ProjectionKind, node: &InspectionNode) -> bool {
    match kind {
        ProjectionKind::Composition => matches!(
            node,
            InspectionNode::Interface { .. }
                | InspectionNode::Package { .. }
                | InspectionNode::Request { .. }
                | InspectionNode::Provider { .. }
                | InspectionNode::Aggregate { .. }
        ),
        ProjectionKind::BindingAuthority => matches!(
            node,
            InspectionNode::Interface { .. }
                | InspectionNode::Package { .. }
                | InspectionNode::Request { .. }
                | InspectionNode::Binding { .. }
                | InspectionNode::Provider { .. }
                | InspectionNode::Operation { .. }
                | InspectionNode::Artifact { .. }
                | InspectionNode::Obligation { .. }
        ),
        ProjectionKind::Activation => matches!(
            node,
            InspectionNode::Interface { .. }
                | InspectionNode::Binding { .. }
                | InspectionNode::Provider { .. }
                | InspectionNode::Aggregate { .. }
                | InspectionNode::Operation { .. }
                | InspectionNode::Decision { .. }
                | InspectionNode::Merge { .. }
                | InspectionNode::Resource { .. }
                | InspectionNode::Obligation { .. }
        ),
        ProjectionKind::Retention => matches!(
            node,
            InspectionNode::Package { .. }
                | InspectionNode::Request { .. }
                | InspectionNode::Binding { .. }
                | InspectionNode::Provider { .. }
                | InspectionNode::Operation { .. }
                | InspectionNode::Artifact { .. }
                | InspectionNode::Resource { .. }
        ),
    }
}

fn relation_is_visible(kind: ProjectionKind, relation: InspectionRelation) -> bool {
    match kind {
        ProjectionKind::Composition => matches!(
            relation,
            InspectionRelation::ConsumesRequest
                | InspectionRelation::AcceptsInterface
                | InspectionRelation::SelectsBinding
                | InspectionRelation::SelectsProvider
                | InspectionRelation::SuppliesInterface
                | InspectionRelation::RunsPackage
                | InspectionRelation::ExportsInterface
                | InspectionRelation::RequiresInterface
                | InspectionRelation::BackedByPackage
                | InspectionRelation::ContributesToAggregate
                | InspectionRelation::OwnsAggregate
        ),
        ProjectionKind::BindingAuthority => matches!(
            relation,
            InspectionRelation::ConsumesRequest
                | InspectionRelation::AcceptsInterface
                | InspectionRelation::SelectsBinding
                | InspectionRelation::SelectsProvider
                | InspectionRelation::SuppliesInterface
                | InspectionRelation::BackedByPackage
                | InspectionRelation::UsesBinding
                | InspectionRelation::InvokesInterface
                | InspectionRelation::UsesImplementationArtifact
                | InspectionRelation::EstablishesProviderReadiness
                | InspectionRelation::HasObligation
        ),
        ProjectionKind::Activation => matches!(
            relation,
            InspectionRelation::SelectsProvider
                | InspectionRelation::UsesBinding
                | InspectionRelation::InvokesInterface
                | InspectionRelation::ReadsResource
                | InspectionRelation::SharedWritesResource
                | InspectionRelation::ExclusivelyWritesResource
                | InspectionRelation::ControlsResource
                | InspectionRelation::EstablishesProviderReadiness
                | InspectionRelation::HasObligation
                | InspectionRelation::Data
                | InspectionRelation::RequiredSuccess
                | InspectionRelation::OrderingOnly
                | InspectionRelation::Readiness
                | InspectionRelation::BranchGuard
                | InspectionRelation::BranchMerge
                | InspectionRelation::Communication
        ),
        ProjectionKind::Retention => matches!(
            relation,
            InspectionRelation::ConsumesRequest
                | InspectionRelation::SelectsBinding
                | InspectionRelation::SelectsProvider
                | InspectionRelation::BackedByPackage
                | InspectionRelation::RunsPackage
                | InspectionRelation::AuthenticatesArtifact
                | InspectionRelation::UsesImplementationArtifact
                | InspectionRelation::RetainsArtifact
                | InspectionRelation::Retention
        ),
    }
}

struct ProjectionBoundedWriter {
    remaining: usize,
    exceeded: bool,
}

impl ProjectionBoundedWriter {
    const fn new(limit: usize) -> Self {
        Self {
            remaining: limit,
            exceeded: false,
        }
    }
}

impl Write for ProjectionBoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.remaining {
            self.exceeded = true;
            return Err(io::Error::other(
                "inspection projection encoding exceeds its bound",
            ));
        }
        self.remaining -= bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
