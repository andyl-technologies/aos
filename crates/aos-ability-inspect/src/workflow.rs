//! Semantic comparison and removal previews for checked deployment views.
//!
//! The contracts in this module remain portable. They compare already checked
//! views and traverse their typed edges; native callers remain responsible for
//! authenticating live observations before attaching them to a workflow.

use std::collections::{BTreeSet, VecDeque};

use aos_ability_model::{PlanId, RequiredFeature};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    GenerationConvergence, InspectionDiff, InspectionEdge, InspectionNode, InspectionRelation,
    InspectionView, NodeKey, OperatorObservation,
};

/// Exact schema discriminator for a semantic deployment comparison.
pub const SEMANTIC_COMPARISON_SCHEMA: &str = "aos.ability.semantic-comparison/v1";

/// Exact schema discriminator for a bounded removal preview.
pub const REMOVAL_PREVIEW_SCHEMA: &str = "aos.ability.removal-preview/v1";

/// Classifies a change by the operator decision it can affect.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SemanticChangeKind {
    /// A selected provider or exact interface ABI changed.
    ProviderAbi,
    /// A credential-bearing request or operation changed.
    CredentialReference,
    /// A requested or supplied enforcement guarantee changed.
    EnforcementGuarantee,
    /// A provider-owned aggregate contribution or instance configuration changed.
    ConfigurationContribution,
    /// An immutable implementation or payload artifact changed.
    Artifact,
    /// An operation family, phase, recovery contract, or schedule changed.
    TransitionStrategy,
    /// A desired generation has not converged with authenticated observation.
    ObservedGeneration,
    /// A desired node is failed, stale, or unverified in the observation.
    ObservedState,
    /// Checked runtime semantics changed without a narrower visible classification.
    OtherRuntime,
}

/// Summarizes semantic changes between two checked deployment views.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticComparison {
    schema: String,
    required_features: Vec<RequiredFeature>,
    before_plan: PlanId,
    after_plan: PlanId,
    runtime_affecting: bool,
    classifications: Vec<SemanticChangeKind>,
    structural: InspectionDiff,
}

/// Reports why a semantic comparison cannot safely attach an observation.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SemanticComparisonError {
    /// The observation describes another checked plan.
    #[error("semantic comparison observation names another effect plan")]
    ObservationPlanMismatch,
    /// Canonical serialization failed.
    #[error("semantic comparison encoding failed: {0}")]
    Encoding(String),
}

impl SemanticComparison {
    /// Classifies structural and semantic changes between two checked views.
    ///
    /// An optional observation belongs to the later plan. Diverged or missing
    /// generation evidence is reported as an observed-generation difference.
    ///
    /// # Errors
    ///
    /// Returns an error when the observation names another effect plan.
    pub fn between(
        before: &InspectionView,
        after: &InspectionView,
        observation: Option<&OperatorObservation>,
    ) -> Result<Self, SemanticComparisonError> {
        let structural = InspectionDiff::between(before, after);
        let mut classifications = classify_diff(&structural);

        if let Some(observation) = observation {
            if observation.plan() != after.plan() {
                return Err(SemanticComparisonError::ObservationPlanMismatch);
            }
            if observation
                .generations()
                .iter()
                .any(|generation| generation.convergence() != GenerationConvergence::Converged)
            {
                classifications.insert(SemanticChangeKind::ObservedGeneration);
            }
            if observation
                .nodes()
                .iter()
                .any(|node| node.state != crate::ObservedNodeState::Available)
            {
                classifications.insert(SemanticChangeKind::ObservedState);
            }
        }

        if structural.semantic_plan_changed && classifications.is_empty() {
            classifications.insert(SemanticChangeKind::OtherRuntime);
        }

        Ok(Self {
            schema: SEMANTIC_COMPARISON_SCHEMA.to_string(),
            required_features: Vec::new(),
            before_plan: before.plan(),
            after_plan: after.plan(),
            runtime_affecting: !classifications.is_empty(),
            classifications: classifications.into_iter().collect(),
            structural,
        })
    }

    /// Returns the deterministic semantic classifications.
    #[must_use]
    pub fn classifications(&self) -> &[SemanticChangeKind] {
        &self.classifications
    }

    /// Reports whether deployment behavior or observed convergence changed.
    #[must_use]
    pub const fn is_runtime_affecting(&self) -> bool {
        self.runtime_affecting
    }

    /// Encodes the comparison as canonical JSON.
    ///
    /// # Errors
    ///
    /// Returns an error when canonical serialization fails.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, SemanticComparisonError> {
        aos_contract::canonical::to_vec(self)
            .map_err(|error| SemanticComparisonError::Encoding(error.to_string()))
    }
}

fn classify_diff(diff: &InspectionDiff) -> BTreeSet<SemanticChangeKind> {
    let mut kinds = BTreeSet::new();

    for node in diff.added_nodes.iter().chain(&diff.removed_nodes) {
        classify_node(node, &mut kinds);
    }
    for change in &diff.changed_nodes {
        classify_changed_node(&change.before, &change.after, &mut kinds);
    }
    for edge in diff.added_edges.iter().chain(&diff.removed_edges) {
        classify_edge(edge, &mut kinds);
    }
    kinds
}

fn classify_changed_node(
    before: &InspectionNode,
    after: &InspectionNode,
    kinds: &mut BTreeSet<SemanticChangeKind>,
) {
    match (before, after) {
        (
            InspectionNode::Binding {
                provider: before_provider,
                interface: before_interface,
                guarantees: before_guarantees,
                ..
            },
            InspectionNode::Binding {
                provider: after_provider,
                interface: after_interface,
                guarantees: after_guarantees,
                ..
            },
        ) => {
            let provider_changed =
                before_provider != after_provider || before_interface != after_interface;
            let guarantees_changed = before_guarantees != after_guarantees;
            if provider_changed {
                kinds.insert(SemanticChangeKind::ProviderAbi);
            }
            if guarantees_changed {
                kinds.insert(SemanticChangeKind::EnforcementGuarantee);
            }
            if before != after && !provider_changed && !guarantees_changed {
                kinds.insert(SemanticChangeKind::OtherRuntime);
            }
        }
        (
            InspectionNode::Request {
                guarantees: before_guarantees,
                ..
            },
            InspectionNode::Request {
                guarantees: after_guarantees,
                ..
            },
        ) => {
            if before_guarantees != after_guarantees {
                kinds.insert(SemanticChangeKind::EnforcementGuarantee);
            }
            if before != after {
                kinds.insert(SemanticChangeKind::OtherRuntime);
            }
        }
        (
            InspectionNode::Operation {
                family: before_family,
                ..
            },
            InspectionNode::Operation {
                family: after_family,
                ..
            },
        ) => {
            kinds.insert(SemanticChangeKind::TransitionStrategy);
            if matches!(
                before_family,
                aos_ability_model::OperationFamily::Credential { .. }
            ) || matches!(
                after_family,
                aos_ability_model::OperationFamily::Credential { .. }
            ) {
                kinds.insert(SemanticChangeKind::CredentialReference);
            }
        }
        _ => {
            classify_node(before, kinds);
            classify_node(after, kinds);
        }
    }
}

fn classify_node(node: &InspectionNode, kinds: &mut BTreeSet<SemanticChangeKind>) {
    match node {
        InspectionNode::Interface { .. } | InspectionNode::InterfaceReference { .. } => {
            kinds.insert(SemanticChangeKind::ProviderAbi);
        }
        InspectionNode::Request { guarantees, .. } => {
            if !guarantees.is_empty() {
                kinds.insert(SemanticChangeKind::EnforcementGuarantee);
            }
            kinds.insert(SemanticChangeKind::OtherRuntime);
        }
        InspectionNode::Binding { guarantees, .. } => {
            kinds.insert(SemanticChangeKind::ProviderAbi);
            if !guarantees.is_empty() {
                kinds.insert(SemanticChangeKind::EnforcementGuarantee);
            }
        }
        InspectionNode::Provider { configuration, .. } => {
            if configuration.is_some() {
                kinds.insert(SemanticChangeKind::ConfigurationContribution);
            }
            kinds.insert(SemanticChangeKind::OtherRuntime);
        }
        InspectionNode::Aggregate { .. } => {
            kinds.insert(SemanticChangeKind::ConfigurationContribution);
        }
        InspectionNode::Operation {
            interface, family, ..
        } => {
            kinds.insert(SemanticChangeKind::TransitionStrategy);
            let name = interface.name.as_str();
            if name.contains("credential")
                || matches!(
                    family,
                    aos_ability_model::OperationFamily::Credential { .. }
                )
            {
                kinds.insert(SemanticChangeKind::CredentialReference);
            }
        }
        InspectionNode::Decision { .. } | InspectionNode::Merge { .. } => {
            kinds.insert(SemanticChangeKind::TransitionStrategy);
        }
        InspectionNode::Artifact { .. } | InspectionNode::Package { .. } => {
            kinds.insert(SemanticChangeKind::Artifact);
        }
        InspectionNode::Resource { .. } | InspectionNode::Obligation { .. } => {
            kinds.insert(SemanticChangeKind::OtherRuntime);
        }
    }
}

fn classify_edge(edge: &InspectionEdge, kinds: &mut BTreeSet<SemanticChangeKind>) {
    match edge.relation {
        InspectionRelation::SelectsProvider | InspectionRelation::SuppliesInterface => {
            kinds.insert(SemanticChangeKind::ProviderAbi);
        }
        InspectionRelation::ContributesToAggregate | InspectionRelation::OwnsAggregate => {
            kinds.insert(SemanticChangeKind::ConfigurationContribution);
        }
        InspectionRelation::AuthenticatesArtifact
        | InspectionRelation::UsesImplementationArtifact
        | InspectionRelation::RetainsArtifact => {
            kinds.insert(SemanticChangeKind::Artifact);
        }
        InspectionRelation::UsesBinding
        | InspectionRelation::InvokesInterface
        | InspectionRelation::ReadsResource
        | InspectionRelation::SharedWritesResource
        | InspectionRelation::ExclusivelyWritesResource
        | InspectionRelation::ControlsResource
        | InspectionRelation::EstablishesProviderReadiness
        | InspectionRelation::Data
        | InspectionRelation::RequiredSuccess
        | InspectionRelation::OrderingOnly
        | InspectionRelation::Readiness
        | InspectionRelation::BranchGuard
        | InspectionRelation::BranchMerge => {
            kinds.insert(SemanticChangeKind::TransitionStrategy);
        }
        InspectionRelation::ConsumesRequest
        | InspectionRelation::AcceptsInterface
        | InspectionRelation::SelectsBinding
        | InspectionRelation::BackedByPackage
        | InspectionRelation::RunsPackage
        | InspectionRelation::ExportsInterface
        | InspectionRelation::RequiresInterface
        | InspectionRelation::HasObligation
        | InspectionRelation::Retention
        | InspectionRelation::Communication => {
            kinds.insert(SemanticChangeKind::OtherRuntime);
        }
    }
}

/// States how one reverse dependency affects a requested removal.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RemovalDisposition {
    /// A live consumer or binding prevents removal until it is changed.
    BlocksRemoval,
    /// A controller must plan an effect before the target can be retired.
    RequiresTransition,
    /// The relationship only retains data or an immutable artifact.
    RetentionOnly,
}

/// Describes one affected node and the edge that exposed the impact.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RemovalImpact {
    /// Identifies the affected node.
    pub node: NodeKey,
    /// Preserves the exact relationship to the removal closure.
    pub relation: InspectionRelation,
    /// States whether the relationship blocks, transitions, or only retains.
    pub disposition: RemovalDisposition,
}

/// Owns a bounded reverse-use preview for one exact removal target.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RemovalPreview {
    schema: String,
    required_features: Vec<RequiredFeature>,
    plan: PlanId,
    target: NodeKey,
    blocked: bool,
    truncated: bool,
    impacts: Vec<RemovalImpact>,
}

/// Reports why a removal preview cannot be produced.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RemovalPreviewError {
    /// The target does not exist in the checked view.
    #[error("removal target is absent from the checked view")]
    MissingTarget,
    /// The depth bound is zero or exceeds the shared structural limit.
    #[error("removal preview depth must be between 1 and the shared structural limit")]
    InvalidDepth,
    /// The node bound cannot retain the target.
    #[error("removal preview node bound must be positive and within the shared graph limit")]
    InvalidNodeLimit,
    /// Canonical serialization failed.
    #[error("removal preview encoding failed: {0}")]
    Encoding(String),
}

impl RemovalPreview {
    /// Traverses typed reverse dependencies from an exact removal target.
    ///
    /// Provider-owned aggregates and resources join the removal closure before
    /// reverse traversal, so aggregate consumers cannot be hidden behind the
    /// provider's outgoing ownership edge.
    ///
    /// # Errors
    ///
    /// Returns an error for an absent target or invalid traversal bounds.
    pub fn from_view(
        view: &InspectionView,
        target: NodeKey,
        max_depth: usize,
        max_nodes: usize,
    ) -> Result<Self, RemovalPreviewError> {
        if max_depth == 0
            || max_depth > aos_ability_model::ABILITY_LIMITS_V1.max_structural_depth as usize
        {
            return Err(RemovalPreviewError::InvalidDepth);
        }
        if max_nodes == 0
            || max_nodes > aos_ability_model::ABILITY_LIMITS_V1.max_graph_nodes as usize
        {
            return Err(RemovalPreviewError::InvalidNodeLimit);
        }
        if !view.nodes().iter().any(|node| node.key() == target) {
            return Err(RemovalPreviewError::MissingTarget);
        }

        let mut closure = BTreeSet::from([target.clone()]);
        let mut truncated = add_owned_nodes(view, &mut closure, max_nodes);
        let mut queue = closure
            .iter()
            .cloned()
            .map(|node| (node, 0usize))
            .collect::<VecDeque<_>>();
        let mut impacts = BTreeSet::new();

        while let Some((current, depth)) = queue.pop_front() {
            if depth >= max_depth {
                if view.edges().iter().any(|edge| edge.to == current) {
                    truncated = true;
                }
                continue;
            }

            for edge in view.edges().iter().filter(|edge| edge.to == current) {
                if closure.len() >= max_nodes && !closure.contains(&edge.from) {
                    truncated = true;
                    continue;
                }
                let impact = RemovalImpact {
                    node: edge.from.clone(),
                    relation: edge.relation,
                    disposition: removal_disposition(edge.relation),
                };
                if impacts.len() >= max_nodes && !impacts.contains(&impact) {
                    truncated = true;
                    continue;
                }
                impacts.insert(impact);
                if closure.insert(edge.from.clone()) {
                    queue.push_back((edge.from.clone(), depth + 1));
                }
            }
        }

        let impacts = impacts.into_iter().collect::<Vec<_>>();
        let blocked = truncated
            || impacts
                .iter()
                .any(|impact| impact.disposition == RemovalDisposition::BlocksRemoval);
        Ok(Self {
            schema: REMOVAL_PREVIEW_SCHEMA.to_string(),
            required_features: Vec::new(),
            plan: view.plan(),
            target,
            blocked,
            truncated,
            impacts,
        })
    }

    /// Reports whether consumers or incomplete traversal prevent safe removal.
    #[must_use]
    pub const fn is_blocked(&self) -> bool {
        self.blocked
    }

    /// Returns impacts in stable node, relation, and disposition order.
    #[must_use]
    pub fn impacts(&self) -> &[RemovalImpact] {
        &self.impacts
    }

    /// Encodes the preview as canonical JSON.
    ///
    /// # Errors
    ///
    /// Returns an error when canonical serialization fails.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, RemovalPreviewError> {
        aos_contract::canonical::to_vec(self)
            .map_err(|error| RemovalPreviewError::Encoding(error.to_string()))
    }
}

fn add_owned_nodes(
    view: &InspectionView,
    closure: &mut BTreeSet<NodeKey>,
    max_nodes: usize,
) -> bool {
    let mut truncated = false;
    loop {
        let additions = view
            .edges()
            .iter()
            .filter(|edge| {
                closure.contains(&edge.from)
                    && matches!(
                        edge.relation,
                        InspectionRelation::OwnsAggregate | InspectionRelation::ControlsResource
                    )
            })
            .map(|edge| edge.to.clone())
            .collect::<Vec<_>>();
        let before = closure.len();
        for addition in additions {
            if closure.len() >= max_nodes && !closure.contains(&addition) {
                truncated = true;
                continue;
            }
            closure.insert(addition);
        }
        if closure.len() == before {
            break;
        }
    }
    truncated
}

const fn removal_disposition(relation: InspectionRelation) -> RemovalDisposition {
    match relation {
        InspectionRelation::AuthenticatesArtifact
        | InspectionRelation::UsesImplementationArtifact
        | InspectionRelation::RetainsArtifact
        | InspectionRelation::Retention => RemovalDisposition::RetentionOnly,
        InspectionRelation::ReadsResource
        | InspectionRelation::SharedWritesResource
        | InspectionRelation::ExclusivelyWritesResource
        | InspectionRelation::ControlsResource
        | InspectionRelation::EstablishesProviderReadiness
        | InspectionRelation::Data
        | InspectionRelation::RequiredSuccess
        | InspectionRelation::OrderingOnly
        | InspectionRelation::Readiness
        | InspectionRelation::BranchGuard
        | InspectionRelation::BranchMerge => RemovalDisposition::RequiresTransition,
        InspectionRelation::ConsumesRequest
        | InspectionRelation::AcceptsInterface
        | InspectionRelation::SelectsBinding
        | InspectionRelation::SelectsProvider
        | InspectionRelation::SuppliesInterface
        | InspectionRelation::BackedByPackage
        | InspectionRelation::RunsPackage
        | InspectionRelation::ExportsInterface
        | InspectionRelation::RequiresInterface
        | InspectionRelation::ContributesToAggregate
        | InspectionRelation::OwnsAggregate
        | InspectionRelation::UsesBinding
        | InspectionRelation::InvokesInterface
        | InspectionRelation::HasObligation
        | InspectionRelation::Communication => RemovalDisposition::BlocksRemoval,
    }
}
