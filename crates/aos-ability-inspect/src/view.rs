//! Stable graph projection shared by terminal, web, and editor frontends.
//!
//! Views use one closed envelope with typed heterogeneous nodes and edges:
//!
//! ```json
//! {
//!   "schema": "aos.ability.inspection-view/v1",
//!   "required_features": [],
//!   "anchor": { "kind": "unanchored-bundle", "digest": "sha256:<digest>" },
//!   "plan": "sha256:<effect-plan-digest>",
//!   "binding_plan": "sha256:<binding-plan-digest>",
//!   "executable": true,
//!   "nodes": [],
//!   "edges": []
//! }
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};

use aos_ability_model::document::ProviderState;
use aos_ability_model::{
    AbilityActivationMode, AccessMode, AggregateId, ArtifactReference, AuthorityRole, BindingId,
    BindingSource, DependencyKind, InstanceId, InterfaceDescriptor, InterfaceKey, LocalKey,
    OperationFamily, OperationPhase, PlanId, PlanNodeKey, RecoveryContract, RequestId,
    RequiredFeature, ResourceId, ResourceLifetime, RevisionId, ScopedOperationKey, ValueExpression,
    ValueSchema, VersionedDocument,
};
use aos_ability_validate::CheckedEffectPlan;
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::bundle::CheckedInspectionBundle;

/// Exact schema discriminator for a portable checked-plan inspection view.
pub const INSPECTION_VIEW_SCHEMA: &str = "aos.ability.inspection-view/v1";

const INSPECTION_VIEW_COMPONENT_LIMIT: usize = 8;

/// Maximum encoded byte length accepted for one portable inspection view.
pub const INSPECTION_VIEW_MAX_BYTES: usize = (aos_ability_model::ABILITY_LIMITS_V1
    .max_document_bytes as usize)
    .saturating_mul(INSPECTION_VIEW_COMPONENT_LIMIT);

/// Maximum node or edge count accepted for one portable inspection view.
pub const INSPECTION_VIEW_MAX_ITEMS: usize = (aos_ability_model::ABILITY_LIMITS_V1
    .max_collection_items as usize)
    .saturating_mul(INSPECTION_VIEW_COMPONENT_LIMIT);

/// Reports why a checked plan cannot be projected into a bounded view.
#[derive(Debug, Error)]
pub enum InspectionViewError {
    /// A semantic commitment or canonical view could not be encoded.
    #[error("inspection view encoding failed: {0}")]
    Encoding(#[source] anyhow::Error),
    /// The view exceeds the version-1 encoded byte bound.
    #[error("inspection view exceeds its encoded byte limit")]
    EncodedSizeLimit,
    /// The view exceeds the version-1 node or edge count bound.
    #[error("inspection view exceeds its node or edge count limit")]
    ItemLimit,
    /// The schema discriminator is unsupported.
    #[error("inspection view has an unsupported schema discriminator")]
    UnsupportedSchema,
    /// Version 1 does not support optional feature semantics.
    #[error("inspection view requires unsupported feature semantics")]
    UnsupportedFeatures,
    /// A checked operation no longer resolves to its declared method schema.
    #[error("checked operation is missing its validated input schema")]
    MissingOperationInputSchema,
    /// A checked aggregate output no longer resolves to its declared output schema.
    #[error("checked aggregate output is missing its validated value schema")]
    MissingAggregateOutputSchema,
    /// A schema-typed literal artifact reference could not be decoded.
    #[error("checked literal artifact reference is invalid: {0}")]
    InvalidArtifactReference(#[source] serde_json::Error),
}

/// States what established the plan semantics and exact input identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ViewAnchor {
    /// A caller supplied an in-memory checked plan without a portable bundle.
    LocallyChecked,
    /// A self-contained bundle passed semantic validation but had no external commitment.
    UnanchoredBundle {
        /// Identifies the exact canonical bundle bytes.
        digest: Sha256Digest,
    },
    /// A self-contained bundle matched an independently supplied commitment.
    ExternallyAnchoredBundle {
        /// Identifies the exact canonical bundle bytes.
        digest: Sha256Digest,
    },
}

/// Identifies a node without requiring a frontend to parse its label.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", content = "identity", rename_all = "kebab-case")]
pub enum NodeKey {
    /// Names one exact public interface descriptor.
    Interface(InterfaceKey),
    /// Names one authenticated package manifest.
    Package(Sha256Digest),
    /// Names one consumer request.
    Request(RequestId),
    /// Names one plan-local provider binding.
    Binding(BindingId),
    /// Names one deployment provider or consumer instance.
    Provider(InstanceId),
    /// Names one provider-owned contribution aggregate.
    Aggregate(AggregateId),
    /// Names one effect operation.
    Operation(ScopedOperationKey),
    /// Names one conditional decision.
    Decision(ScopedOperationKey),
    /// Names one conditional merge.
    Merge(ScopedOperationKey),
    /// Names one exact immutable artifact and authenticated closure association.
    Artifact(Sha256Digest),
    /// Names one logical resource.
    Resource(ResourceId),
    /// Names one unresolved obligation within the plan.
    Obligation(LocalKey),
}

/// Describes provider state without inventing live evidence absent from the plan.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderAvailability {
    /// Authenticated metadata exists without a selected bootstrap.
    Declared,
    /// The checked graph contains a readiness path for this provider.
    Planned,
    /// The environment supplied a fresh live assignment.
    Available,
    /// Required provider evidence or resources were absent.
    Unavailable,
    /// Environment evidence existed but was no longer fresh.
    Stale,
    /// The provider was selected for pure composition and needs no runtime assignment.
    PureComposition,
    /// The checked plan did not retain enough evidence to classify the provider.
    Unknown,
}

/// Carries typed, redacted details for one stable inspection node.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum InspectionNode {
    /// Describes a caller-visible interface and its closed schemas.
    Interface {
        /// Identifies the exact interface descriptor.
        key: InterfaceKey,
        /// Retains the public interface contract.
        descriptor: InterfaceDescriptor,
    },
    /// Describes one exact package subject without embedding its payload.
    Package {
        /// Identifies the exact package document.
        digest: Sha256Digest,
        /// Names the package.
        name: LocalKey,
        /// Retains the authored package version.
        version: String,
        /// States whether the package may author structured effects.
        activation_mode: AbilityActivationMode,
    },
    /// Describes one typed consumer request.
    Request {
        /// Identifies the request and its consumer.
        id: RequestId,
        /// Lists accepted exact interfaces in policy order.
        accepted_interfaces: Vec<InterfaceKey>,
        /// Lists required methods in canonical order.
        methods: Vec<LocalKey>,
        /// Lists required guarantees in canonical order.
        guarantees: Vec<aos_ability_model::GuaranteeKey>,
        /// Bounds the requested resource lifetime.
        lifetime: ResourceLifetime,
        /// Commits to the complete request, including future redacted fields.
        semantic_digest: Sha256Digest,
    },
    /// Describes one checked provider choice without exposing private grant bodies.
    Binding {
        /// Names the binding within the checked plan.
        id: BindingId,
        /// Identifies the request satisfied by the binding.
        request: RequestId,
        /// Identifies the selected provider.
        provider: InstanceId,
        /// Identifies the exact selected interface.
        interface: InterfaceKey,
        /// Pins the provider package when package-backed.
        provider_package: Option<Sha256Digest>,
        /// Records the deterministic selection source.
        source: BindingSource,
        /// Lists guarantees actually supplied.
        guarantees: Vec<aos_ability_model::GuaranteeKey>,
        /// Bounds retained resource references.
        lifetime: ResourceLifetime,
        /// Reports whether separate provider mediation was admitted.
        mediation_allowed: bool,
        /// Commits to the exact implementation, policy revision, and grants.
        authority_digest: Sha256Digest,
    },
    /// Describes one provider or consumer instance and retained availability evidence.
    Provider {
        /// Identifies the stable deployment instance.
        id: InstanceId,
        /// Classifies only the evidence retained by the checked plan.
        availability: ProviderAvailability,
    },
    /// Describes one shared provider-owned aggregate.
    Aggregate {
        /// Identifies the provider and aggregation group.
        id: AggregateId,
    },
    /// Describes one finite external-effect operation with values redacted.
    Operation {
        /// Names the operation within its recursive scope.
        key: ScopedOperationKey,
        /// Selects the primary or provider implementation authority role.
        authority: AuthorityRole,
        /// Identifies the exact called interface.
        interface: InterfaceKey,
        /// Names the exact called method.
        method: LocalKey,
        /// Retains the high-level semantic family.
        family: OperationFamily,
        /// Places the operation in the durable transition phase.
        phase: OperationPhase,
        /// Retains the bounded recovery contract without request values.
        recovery: RecoveryContract,
        /// Commits to inputs, preconditions, access, deadlines, and branch context.
        semantic_digest: Sha256Digest,
    },
    /// Describes one durable conditional selector.
    Decision {
        /// Names the decision within its recursive scope.
        key: ScopedOperationKey,
        /// Lists all statically validated alternative names.
        alternatives: Vec<LocalKey>,
        /// Commits to the selector, predicates, and branch context.
        semantic_digest: Sha256Digest,
    },
    /// Describes one typed conditional result merge.
    Merge {
        /// Names the merge within its recursive scope.
        key: ScopedOperationKey,
        /// Names the decision whose alternatives it joins.
        decision: ScopedOperationKey,
        /// Lists the common output ports.
        outputs: Vec<LocalKey>,
        /// Commits to the complete typed merge definition.
        semantic_digest: Sha256Digest,
    },
    /// Describes one exact immutable artifact without embedding its contents.
    Artifact {
        /// Commits to the complete artifact reference, including its store identity.
        id: Sha256Digest,
        /// Retains the exact content, NAR, closure, and store-path reference.
        reference: ArtifactReference,
    },
    /// Describes one logical resource and checked desired/current revisions.
    Resource {
        /// Identifies the provider-owned logical resource.
        id: ResourceId,
        /// Retains the authenticated current revision, when known.
        current: Option<RevisionId>,
        /// Retains the desired semantic revision, when known.
        desired: Option<RevisionId>,
        /// Names the checked lifecycle controller, when one exists.
        controller: Option<AggregateId>,
    },
    /// Describes one unresolved deployment input.
    Obligation {
        /// Names the obligation within the plan.
        key: LocalKey,
        /// Classifies the missing input.
        obligation_kind: aos_ability_model::ObligationKind,
        /// Identifies the request that introduced it.
        request: RequestId,
        /// Identifies a related resource, when known.
        resource: Option<ResourceId>,
        /// Retains the bounded human-readable explanation.
        description: String,
    },
}

impl InspectionNode {
    /// Returns the stable typed identity of this node.
    #[must_use]
    pub fn key(&self) -> NodeKey {
        match self {
            Self::Interface { key, .. } => NodeKey::Interface(key.clone()),
            Self::Package { digest, .. } => NodeKey::Package(*digest),
            Self::Request { id, .. } => NodeKey::Request(id.clone()),
            Self::Binding { id, .. } => NodeKey::Binding(id.clone()),
            Self::Provider { id, .. } => NodeKey::Provider(id.clone()),
            Self::Aggregate { id } => NodeKey::Aggregate(id.clone()),
            Self::Operation { key, .. } => NodeKey::Operation(key.clone()),
            Self::Decision { key, .. } => NodeKey::Decision(key.clone()),
            Self::Merge { key, .. } => NodeKey::Merge(key.clone()),
            Self::Artifact { id, .. } => NodeKey::Artifact(*id),
            Self::Resource { id, .. } => NodeKey::Resource(id.clone()),
            Self::Obligation { key, .. } => NodeKey::Obligation(key.clone()),
        }
    }
}

/// Gives one inspection edge a stable machine-readable meaning.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum InspectionRelation {
    /// An instance declares and consumes a request.
    ConsumesRequest,
    /// A request accepts one exact public interface.
    AcceptsInterface,
    /// A request is satisfied by one checked binding.
    SelectsBinding,
    /// A binding selected a provider instance.
    SelectsProvider,
    /// A binding selected one exact public interface.
    SuppliesInterface,
    /// A provider selection is backed by an exact package manifest.
    BackedByPackage,
    /// A desired deployment instance runs one exact package manifest.
    RunsPackage,
    /// An authenticated package manifest exports one exact public interface.
    ExportsInterface,
    /// An authenticated package requirement accepts one exact public interface.
    RequiresInterface,
    /// An authenticated package manifest retains an exact artifact.
    AuthenticatesArtifact,
    /// A selected provider or binding uses an exact implementation artifact.
    UsesImplementationArtifact,
    /// A value expression or aggregate output retains an exact artifact.
    RetainsArtifact,
    /// A request contributed one authorized aggregate slot.
    ContributesToAggregate,
    /// A provider owns one shared aggregate.
    OwnsAggregate,
    /// An operation invokes authority from one binding.
    UsesBinding,
    /// An operation invokes one exact public interface.
    InvokesInterface,
    /// An operation only reads a logical resource.
    ReadsResource,
    /// An operation performs shared mutation of a logical resource.
    SharedWritesResource,
    /// An operation performs exclusive mutation of a logical resource.
    ExclusivelyWritesResource,
    /// An aggregate owns the lifecycle of a logical resource.
    ControlsResource,
    /// An operation establishes readiness for one planned binding.
    EstablishesProviderReadiness,
    /// A request remains blocked by one explicit deployment obligation.
    HasObligation,
    /// Carries a data dependency.
    Data,
    /// Carries a required-success scheduling dependency.
    RequiredSuccess,
    /// Carries ordering without requiring predecessor success.
    OrderingOnly,
    /// Carries provider-readiness ordering.
    Readiness,
    /// Guards a node by a selected branch.
    BranchGuard,
    /// Joins a selected branch into a merge.
    BranchMerge,
    /// Retains a referenced artifact or resource without startup ordering.
    Retention,
    /// Records allowed runtime communication without startup ordering.
    Communication,
}

/// Connects two stable nodes under one typed inspection relationship.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InspectionEdge {
    /// Names the relationship source.
    pub from: NodeKey,
    /// Names the relationship destination.
    pub to: NodeKey,
    /// Preserves the relationship's exact semantics.
    pub relation: InspectionRelation,
}

/// Owns a deterministic, redacted projection of one checked deployment plan.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InspectionView {
    schema: String,
    required_features: Vec<RequiredFeature>,
    anchor: ViewAnchor,
    plan: PlanId,
    binding_plan: PlanId,
    executable: bool,
    nodes: Vec<InspectionNode>,
    edges: Vec<InspectionEdge>,
}

impl InspectionView {
    /// Projects an in-memory checked plan into the shared portable view.
    ///
    /// # Errors
    ///
    /// Returns an error if a semantic commitment cannot be encoded or the
    /// resulting view exceeds its byte or item bound.
    pub fn from_checked(plan: &CheckedEffectPlan) -> Result<Self, InspectionViewError> {
        build_view(plan, ViewAnchor::LocallyChecked)
    }

    /// Projects a checked portable bundle and preserves its exact anchor status.
    ///
    /// # Errors
    ///
    /// Returns an error if a semantic commitment cannot be encoded or the
    /// resulting view exceeds its byte or item bound.
    pub fn from_bundle(bundle: &CheckedInspectionBundle) -> Result<Self, InspectionViewError> {
        let anchor = if bundle.is_externally_anchored() {
            ViewAnchor::ExternallyAnchoredBundle {
                digest: bundle.digest(),
            }
        } else {
            ViewAnchor::UnanchoredBundle {
                digest: bundle.digest(),
            }
        };
        build_view(bundle.plan(), anchor)
    }

    /// Encodes the complete view as bounded canonical JSON.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported schema, excessive node or edge
    /// count, excessive encoded size, or canonical serialization failure.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, InspectionViewError> {
        if self.schema != INSPECTION_VIEW_SCHEMA {
            return Err(InspectionViewError::UnsupportedSchema);
        }
        if !self.required_features.is_empty() {
            return Err(InspectionViewError::UnsupportedFeatures);
        }
        self.check_bounds()?;

        let mut writer = ViewBoundedWriter::new(INSPECTION_VIEW_MAX_BYTES);
        serde_json::to_writer(&mut writer, self).map_err(|error| {
            if writer.exceeded {
                InspectionViewError::EncodedSizeLimit
            } else {
                InspectionViewError::Encoding(error.into())
            }
        })?;
        aos_contract::canonical::to_vec(self).map_err(InspectionViewError::Encoding)
    }

    /// Returns the source and integrity status of the view.
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

    /// Reports whether all deployment obligations were discharged.
    #[must_use]
    pub const fn is_executable(&self) -> bool {
        self.executable
    }

    /// Returns nodes in stable typed-identity order.
    #[must_use]
    pub fn nodes(&self) -> &[InspectionNode] {
        &self.nodes
    }

    /// Returns edges in stable endpoint and relation order.
    #[must_use]
    pub fn edges(&self) -> &[InspectionEdge] {
        &self.edges
    }

    fn check_bounds(&self) -> Result<(), InspectionViewError> {
        if self.nodes.len() > INSPECTION_VIEW_MAX_ITEMS
            || self.edges.len() > INSPECTION_VIEW_MAX_ITEMS
        {
            return Err(InspectionViewError::ItemLimit);
        }
        Ok(())
    }
}

fn build_view(
    plan: &CheckedEffectPlan,
    anchor: ViewAnchor,
) -> Result<InspectionView, InspectionViewError> {
    let mut nodes = BTreeMap::new();
    let mut edges = BTreeSet::new();
    let binding_plan = plan.binding_plan();

    for (key, interface) in plan.interfaces() {
        insert_node(
            &mut nodes,
            InspectionNode::Interface {
                key: key.clone(),
                descriptor: interface.interface.clone(),
            },
        );
    }
    for package in binding_plan.packages() {
        let digest = package
            .content_digest()
            .map_err(|error| InspectionViewError::Encoding(error.into()))?;
        insert_node(
            &mut nodes,
            InspectionNode::Package {
                digest,
                name: package.package.name.clone(),
                version: package.package.version.clone(),
                activation_mode: package.activation_mode,
            },
        );
        for export in &package.exports {
            insert_edge(
                &mut edges,
                NodeKey::Package(digest),
                NodeKey::Interface(export.interface.clone()),
                InspectionRelation::ExportsInterface,
            );
        }
        for interface in package
            .requirements
            .iter()
            .flat_map(|requirement| &requirement.accepted_interfaces)
        {
            insert_edge(
                &mut edges,
                NodeKey::Package(digest),
                NodeKey::Interface(interface.clone()),
                InspectionRelation::RequiresInterface,
            );
        }
        insert_package_artifacts(&mut nodes, &mut edges, package, digest)?;
    }
    for instance in &binding_plan.desired_state().instances {
        insert_provider(&mut nodes, plan, &instance.instance);
        insert_edge(
            &mut edges,
            NodeKey::Provider(instance.instance.clone()),
            NodeKey::Package(instance.package),
            InspectionRelation::RunsPackage,
        );
    }
    for request in &binding_plan.document().requests {
        insert_provider(&mut nodes, plan, &request.id.consumer);
        insert_node(
            &mut nodes,
            InspectionNode::Request {
                id: request.id.clone(),
                accepted_interfaces: request.accepted_interfaces.clone(),
                methods: request.methods.clone(),
                guarantees: request.guarantees.clone(),
                lifetime: request.lifetime,
                semantic_digest: semantic_digest("request", request)?,
            },
        );
        insert_edge(
            &mut edges,
            NodeKey::Provider(request.id.consumer.clone()),
            NodeKey::Request(request.id.clone()),
            InspectionRelation::ConsumesRequest,
        );
        for interface in &request.accepted_interfaces {
            insert_edge(
                &mut edges,
                NodeKey::Request(request.id.clone()),
                NodeKey::Interface(interface.clone()),
                InspectionRelation::AcceptsInterface,
            );
        }
    }
    for binding in binding_plan.bindings() {
        insert_provider(&mut nodes, plan, &binding.provider);
        insert_node(
            &mut nodes,
            InspectionNode::Binding {
                id: binding.id.clone(),
                request: binding.request.clone(),
                provider: binding.provider.clone(),
                interface: binding.interface.clone(),
                provider_package: binding.provider_package,
                source: binding.source,
                guarantees: binding.guarantees.clone(),
                lifetime: binding.lifetime,
                mediation_allowed: binding.mediation_allowed,
                authority_digest: semantic_digest("binding-authority", binding)?,
            },
        );
        insert_edge(
            &mut edges,
            NodeKey::Request(binding.request.clone()),
            NodeKey::Binding(binding.id.clone()),
            InspectionRelation::SelectsBinding,
        );
        insert_edge(
            &mut edges,
            NodeKey::Binding(binding.id.clone()),
            NodeKey::Provider(binding.provider.clone()),
            InspectionRelation::SelectsProvider,
        );
        insert_edge(
            &mut edges,
            NodeKey::Binding(binding.id.clone()),
            NodeKey::Interface(binding.interface.clone()),
            InspectionRelation::SuppliesInterface,
        );
        if let Some(package) = binding.provider_package {
            insert_edge(
                &mut edges,
                NodeKey::Provider(binding.provider.clone()),
                NodeKey::Package(package),
                InspectionRelation::BackedByPackage,
            );
        }
        let artifact = insert_artifact(&mut nodes, &binding.implementation.artifact)?;
        insert_edge(
            &mut edges,
            NodeKey::Binding(binding.id.clone()),
            artifact,
            InspectionRelation::UsesImplementationArtifact,
        );
    }
    for provider in &binding_plan.environment().providers {
        insert_provider(&mut nodes, plan, &provider.provider);
        let artifact = insert_artifact(&mut nodes, &provider.implementation.artifact)?;
        insert_edge(
            &mut edges,
            NodeKey::Provider(provider.provider.clone()),
            artifact,
            InspectionRelation::UsesImplementationArtifact,
        );
    }
    for contribution in &binding_plan.desired_state().contributions {
        insert_provider(&mut nodes, plan, &contribution.aggregate.provider);
        insert_node(
            &mut nodes,
            InspectionNode::Aggregate {
                id: contribution.aggregate.clone(),
            },
        );
        insert_edge(
            &mut edges,
            NodeKey::Request(contribution.request.clone()),
            NodeKey::Aggregate(contribution.aggregate.clone()),
            InspectionRelation::ContributesToAggregate,
        );
        insert_edge(
            &mut edges,
            NodeKey::Provider(contribution.aggregate.provider.clone()),
            NodeKey::Aggregate(contribution.aggregate.clone()),
            InspectionRelation::OwnsAggregate,
        );
    }

    insert_plan_nodes(plan, &mut nodes, &mut edges)?;
    insert_resource_nodes(plan, &mut nodes, &mut edges);
    for artifact in &plan.document().artifacts {
        insert_artifact(&mut nodes, artifact)?;
    }
    for output in &binding_plan.desired_state().outputs {
        let schema = plan
            .interfaces()
            .get(&output.interface)
            .and_then(|interface| interface.interface.outputs.get(&output.port))
            .map(|output| &output.schema)
            .ok_or(InspectionViewError::MissingAggregateOutputSchema)?;
        insert_provider(&mut nodes, plan, &output.aggregate.provider);
        insert_node(
            &mut nodes,
            InspectionNode::Aggregate {
                id: output.aggregate.clone(),
            },
        );
        insert_expression_artifacts(
            &mut nodes,
            &mut edges,
            NodeKey::Aggregate(output.aggregate.clone()),
            schema,
            &output.value,
        )?;
    }

    for obligation in binding_plan
        .document()
        .obligations
        .iter()
        .chain(plan.document().obligations.iter())
    {
        insert_node(
            &mut nodes,
            InspectionNode::Obligation {
                key: obligation.key.clone(),
                obligation_kind: obligation.kind,
                request: obligation.request.clone(),
                resource: obligation.resource.clone(),
                description: obligation.description.clone(),
            },
        );
        insert_edge(
            &mut edges,
            NodeKey::Request(obligation.request.clone()),
            NodeKey::Obligation(obligation.key.clone()),
            InspectionRelation::HasObligation,
        );
    }

    let view = InspectionView {
        schema: INSPECTION_VIEW_SCHEMA.to_string(),
        required_features: Vec::new(),
        anchor,
        plan: plan.id(),
        binding_plan: binding_plan.id(),
        executable: plan.is_executable(),
        nodes: nodes.into_values().collect(),
        edges: edges.into_iter().collect(),
    };
    view.canonical_bytes()?;
    Ok(view)
}

fn insert_plan_nodes(
    plan: &CheckedEffectPlan,
    nodes: &mut BTreeMap<NodeKey, InspectionNode>,
    edges: &mut BTreeSet<InspectionEdge>,
) -> Result<(), InspectionViewError> {
    for operation in plan.operations() {
        let input_schema = plan
            .interfaces()
            .get(&operation.interface)
            .and_then(|interface| interface.interface.methods.get(&operation.method))
            .map(|method| &method.parameters)
            .ok_or(InspectionViewError::MissingOperationInputSchema)?;
        insert_node(
            nodes,
            InspectionNode::Operation {
                key: operation.key.clone(),
                authority: operation.authority,
                interface: operation.interface.clone(),
                method: operation.method.clone(),
                family: operation.family.clone(),
                phase: operation.phase,
                recovery: operation.recovery.clone(),
                semantic_digest: semantic_digest("operation", operation)?,
            },
        );
        insert_edge(
            edges,
            NodeKey::Operation(operation.key.clone()),
            NodeKey::Binding(operation.binding.clone()),
            InspectionRelation::UsesBinding,
        );
        insert_edge(
            edges,
            NodeKey::Operation(operation.key.clone()),
            NodeKey::Interface(operation.interface.clone()),
            InspectionRelation::InvokesInterface,
        );
        for access in &operation.accesses {
            insert_edge(
                edges,
                NodeKey::Operation(operation.key.clone()),
                NodeKey::Resource(access.resource.clone()),
                access_relation(access.mode),
            );
        }
        insert_expression_artifacts(
            nodes,
            edges,
            NodeKey::Operation(operation.key.clone()),
            input_schema,
            &operation.inputs,
        )?;
    }
    for decision in plan.decisions() {
        insert_node(
            nodes,
            InspectionNode::Decision {
                key: decision.key.clone(),
                alternatives: decision
                    .alternatives
                    .iter()
                    .map(|alternative| alternative.key.clone())
                    .collect(),
                semantic_digest: semantic_digest("decision", decision)?,
            },
        );
    }
    for merge in plan.merges() {
        insert_node(
            nodes,
            InspectionNode::Merge {
                key: merge.key.clone(),
                decision: merge.decision.clone(),
                outputs: merge.outputs.keys().cloned().collect(),
                semantic_digest: semantic_digest("merge", merge)?,
            },
        );
    }
    for edge in plan.edges() {
        insert_edge(
            edges,
            plan_node_key(&edge.from),
            plan_node_key(&edge.to),
            dependency_relation(edge.kind),
        );
    }
    for readiness in &plan.document().provider_readiness {
        insert_edge(
            edges,
            NodeKey::Operation(readiness.producer.clone()),
            NodeKey::Binding(readiness.binding.clone()),
            InspectionRelation::EstablishesProviderReadiness,
        );
    }
    Ok(())
}

fn insert_package_artifacts(
    nodes: &mut BTreeMap<NodeKey, InspectionNode>,
    edges: &mut BTreeSet<InspectionEdge>,
    package: &aos_ability_model::PackageDocument,
    package_digest: Sha256Digest,
) -> Result<(), InspectionViewError> {
    let artifacts = std::iter::once(&package.package.payload)
        .chain(std::iter::once(&package.package.source))
        .chain(package.artifacts.iter())
        .chain(package.module_entry_points.values())
        .chain(
            package
                .implementation
                .providers
                .iter()
                .map(|provider| &provider.artifact),
        )
        .chain(
            package
                .implementation
                .handlers
                .values()
                .map(|handler| &handler.artifact),
        );

    for artifact in artifacts {
        let artifact = insert_artifact(nodes, artifact)?;
        insert_edge(
            edges,
            NodeKey::Package(package_digest),
            artifact,
            InspectionRelation::AuthenticatesArtifact,
        );
    }
    Ok(())
}

fn insert_expression_artifacts(
    nodes: &mut BTreeMap<NodeKey, InspectionNode>,
    edges: &mut BTreeSet<InspectionEdge>,
    owner: NodeKey,
    schema: &ValueSchema,
    expression: &ValueExpression,
) -> Result<(), InspectionViewError> {
    let schema = unwrap_optional_schema(schema, expression);
    match expression {
        ValueExpression::Literal { value } => {
            insert_literal_artifacts(nodes, edges, &owner, schema, value.as_json())?;
        }
        ValueExpression::ArtifactReference { reference } => {
            insert_artifact_retention(nodes, edges, &owner, reference)?;
        }
        ValueExpression::List { items } => {
            if let ValueSchema::List { element, .. } = schema {
                for item in items {
                    insert_expression_artifacts(nodes, edges, owner.clone(), element, item)?;
                }
            }
        }
        ValueExpression::Object { fields } => match schema {
            ValueSchema::Map { value, .. } => {
                for field in fields.values() {
                    insert_expression_artifacts(nodes, edges, owner.clone(), value, field)?;
                }
            }
            ValueSchema::Record {
                fields: schemas, ..
            } => {
                for (name, field) in fields {
                    if let Some(field_schema) = schemas.get(name.as_str()) {
                        insert_expression_artifacts(
                            nodes,
                            edges,
                            owner.clone(),
                            field_schema,
                            field,
                        )?;
                    }
                }
            }
            ValueSchema::TaggedUnion { tag, variants } => {
                let selected = fields
                    .get(tag.as_str())
                    .and_then(|value| match value {
                        ValueExpression::Literal { value } => value.as_json().as_str(),
                        _ => None,
                    })
                    .and_then(|tag_value| {
                        variants
                            .iter()
                            .find(|(name, _)| name.as_str() == tag_value)
                            .map(|(_, schema)| schema)
                    });
                if let Some(selected) = selected {
                    insert_expression_artifacts(nodes, edges, owner, selected, expression)?;
                }
            }
            _ => {}
        },
        ValueExpression::ResourceReference { .. }
        | ValueExpression::AggregateOutput { .. }
        | ValueExpression::OperationResult { .. } => {}
    }
    Ok(())
}

fn insert_literal_artifacts(
    nodes: &mut BTreeMap<NodeKey, InspectionNode>,
    edges: &mut BTreeSet<InspectionEdge>,
    owner: &NodeKey,
    schema: &ValueSchema,
    value: &serde_json::Value,
) -> Result<(), InspectionViewError> {
    match (schema, value) {
        (ValueSchema::Optional { .. }, serde_json::Value::Null) => {}
        (ValueSchema::Optional { value: nested }, value) => {
            insert_literal_artifacts(nodes, edges, owner, nested, value)?;
        }
        (ValueSchema::ArtifactReference, value) => {
            let reference = serde_json::from_value::<ArtifactReference>(value.clone())
                .map_err(InspectionViewError::InvalidArtifactReference)?;
            insert_artifact_retention(nodes, edges, owner, &reference)?;
        }
        (ValueSchema::List { element, .. }, serde_json::Value::Array(items)) => {
            for item in items {
                insert_literal_artifacts(nodes, edges, owner, element, item)?;
            }
        }
        (ValueSchema::Map { value: nested, .. }, serde_json::Value::Object(fields)) => {
            for value in fields.values() {
                insert_literal_artifacts(nodes, edges, owner, nested, value)?;
            }
        }
        (
            ValueSchema::Record {
                fields: schemas, ..
            },
            serde_json::Value::Object(fields),
        ) => {
            for (name, value) in fields {
                if let Some(field_schema) = schemas.get(name.as_str()) {
                    insert_literal_artifacts(nodes, edges, owner, field_schema, value)?;
                }
            }
        }
        (ValueSchema::TaggedUnion { tag, variants }, serde_json::Value::Object(fields)) => {
            if let Some(variant) = fields
                .get(tag.as_str())
                .and_then(serde_json::Value::as_str)
                .and_then(|tag_value| {
                    variants
                        .iter()
                        .find(|(name, _)| name.as_str() == tag_value)
                        .map(|(_, schema)| schema)
                })
            {
                insert_literal_artifacts(nodes, edges, owner, variant, value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn insert_artifact_retention(
    nodes: &mut BTreeMap<NodeKey, InspectionNode>,
    edges: &mut BTreeSet<InspectionEdge>,
    owner: &NodeKey,
    reference: &ArtifactReference,
) -> Result<(), InspectionViewError> {
    let artifact = insert_artifact(nodes, reference)?;
    insert_edge(
        edges,
        owner.clone(),
        artifact,
        InspectionRelation::RetainsArtifact,
    );
    Ok(())
}

fn unwrap_optional_schema<'a>(
    mut schema: &'a ValueSchema,
    expression: &ValueExpression,
) -> &'a ValueSchema {
    while let ValueSchema::Optional { value } = schema {
        if matches!(expression, ValueExpression::Literal { value } if value.as_json().is_null()) {
            break;
        }
        schema = value;
    }
    schema
}

fn insert_artifact(
    nodes: &mut BTreeMap<NodeKey, InspectionNode>,
    reference: &ArtifactReference,
) -> Result<NodeKey, InspectionViewError> {
    let id = semantic_digest("artifact", reference)?;
    let node = InspectionNode::Artifact {
        id,
        reference: reference.clone(),
    };
    let key = node.key();
    insert_node(nodes, node);
    Ok(key)
}

fn insert_resource_nodes(
    plan: &CheckedEffectPlan,
    nodes: &mut BTreeMap<NodeKey, InspectionNode>,
    edges: &mut BTreeSet<InspectionEdge>,
) {
    let current: BTreeMap<_, _> = plan
        .document()
        .current_revisions
        .iter()
        .map(|revision| (revision.resource.clone(), revision.revision))
        .collect();
    let desired: BTreeMap<_, _> = plan
        .document()
        .desired_revisions
        .iter()
        .map(|revision| (revision.resource.clone(), revision.revision))
        .collect();
    let controllers: BTreeMap<_, _> = plan
        .document()
        .controllers
        .iter()
        .map(|assignment| (assignment.resource.clone(), assignment.controller.clone()))
        .collect();
    let resources: BTreeSet<_> = current
        .keys()
        .chain(desired.keys())
        .chain(controllers.keys())
        .chain(
            plan.operations()
                .iter()
                .flat_map(|operation| operation.accesses.iter().map(|access| &access.resource)),
        )
        .chain(
            plan.binding_plan()
                .document()
                .obligations
                .iter()
                .filter_map(|obligation| obligation.resource.as_ref()),
        )
        .chain(
            plan.document()
                .obligations
                .iter()
                .filter_map(|obligation| obligation.resource.as_ref()),
        )
        .cloned()
        .collect();

    for resource in resources {
        let controller = controllers.get(&resource).cloned();
        insert_provider(nodes, plan, &resource.provider);
        insert_node(
            nodes,
            InspectionNode::Resource {
                id: resource.clone(),
                current: current.get(&resource).copied(),
                desired: desired.get(&resource).copied(),
                controller: controller.clone(),
            },
        );
        if let Some(controller) = controller {
            insert_provider(nodes, plan, &controller.provider);
            insert_node(
                nodes,
                InspectionNode::Aggregate {
                    id: controller.clone(),
                },
            );
            insert_edge(
                edges,
                NodeKey::Aggregate(controller),
                NodeKey::Resource(resource),
                InspectionRelation::ControlsResource,
            );
        }
    }
}

fn insert_provider(
    nodes: &mut BTreeMap<NodeKey, InspectionNode>,
    plan: &CheckedEffectPlan,
    provider: &InstanceId,
) {
    let key = NodeKey::Provider(provider.clone());
    if nodes.contains_key(&key) {
        return;
    }
    let availability = plan
        .binding_plan()
        .environment()
        .providers
        .iter()
        .filter(|entry| &entry.provider == provider)
        .map(|entry| provider_availability(entry.state))
        .max_by_key(|availability| provider_availability_rank(*availability))
        .or_else(|| {
            plan.binding_plan()
                .planned_providers()
                .contains(provider)
                .then_some(ProviderAvailability::Planned)
        })
        .unwrap_or(ProviderAvailability::PureComposition);
    insert_node(
        nodes,
        InspectionNode::Provider {
            id: provider.clone(),
            availability,
        },
    );
}

fn insert_node(nodes: &mut BTreeMap<NodeKey, InspectionNode>, node: InspectionNode) {
    nodes.entry(node.key()).or_insert(node);
}

fn insert_edge(
    edges: &mut BTreeSet<InspectionEdge>,
    from: NodeKey,
    to: NodeKey,
    relation: InspectionRelation,
) {
    edges.insert(InspectionEdge { from, to, relation });
}

fn provider_availability(state: ProviderState) -> ProviderAvailability {
    match state {
        ProviderState::Declared => ProviderAvailability::Declared,
        ProviderState::Planned => ProviderAvailability::Planned,
        ProviderState::Available => ProviderAvailability::Available,
        ProviderState::Unavailable => ProviderAvailability::Unavailable,
        ProviderState::Stale => ProviderAvailability::Stale,
    }
}

fn provider_availability_rank(availability: ProviderAvailability) -> u8 {
    match availability {
        ProviderAvailability::Available => 6,
        ProviderAvailability::Planned => 5,
        ProviderAvailability::Declared => 4,
        ProviderAvailability::Stale => 3,
        ProviderAvailability::Unavailable => 2,
        ProviderAvailability::PureComposition => 1,
        ProviderAvailability::Unknown => 0,
    }
}

fn access_relation(mode: AccessMode) -> InspectionRelation {
    match mode {
        AccessMode::Read => InspectionRelation::ReadsResource,
        AccessMode::SharedWrite => InspectionRelation::SharedWritesResource,
        AccessMode::ExclusiveWrite => InspectionRelation::ExclusivelyWritesResource,
    }
}

fn dependency_relation(kind: DependencyKind) -> InspectionRelation {
    match kind {
        DependencyKind::Data => InspectionRelation::Data,
        DependencyKind::RequiredSuccess => InspectionRelation::RequiredSuccess,
        DependencyKind::OrderingOnly => InspectionRelation::OrderingOnly,
        DependencyKind::Readiness => InspectionRelation::Readiness,
        DependencyKind::BranchGuard => InspectionRelation::BranchGuard,
        DependencyKind::BranchMerge => InspectionRelation::BranchMerge,
        DependencyKind::Retention => InspectionRelation::Retention,
        DependencyKind::Communication => InspectionRelation::Communication,
    }
}

fn plan_node_key(key: &PlanNodeKey) -> NodeKey {
    match key {
        PlanNodeKey::Operation { key } => NodeKey::Operation(key.clone()),
        PlanNodeKey::Decision { key } => NodeKey::Decision(key.clone()),
        PlanNodeKey::Merge { key } => NodeKey::Merge(key.clone()),
    }
}

fn semantic_digest(
    kind: &str,
    value: &impl Serialize,
) -> Result<Sha256Digest, InspectionViewError> {
    Sha256Digest::of_canonical(&format!("{INSPECTION_VIEW_SCHEMA}\0{kind}"), value)
        .map_err(InspectionViewError::Encoding)
}

struct ViewBoundedWriter {
    remaining: usize,
    exceeded: bool,
}

impl ViewBoundedWriter {
    const fn new(limit: usize) -> Self {
        Self {
            remaining: limit,
            exceeded: false,
        }
    }
}

impl Write for ViewBoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.remaining {
            self.exceeded = true;
            return Err(io::Error::other(
                "serialized inspection view exceeds its byte limit",
            ));
        }
        self.remaining -= bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
