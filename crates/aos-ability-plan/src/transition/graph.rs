//! Provider fragment contracts, boundary lowering, and effect-graph assembly.
//!
//! Pure providers return a closed fragment shaped as follows:
//!
//! ```text
//! {"schema":"aos.ability.transition-fragment/v1","operations":[...],
//!  "decisions":[],"merges":[],"edges":[...],"exports":[...],
//!  "imports":[...],"links":[...],"provider_readiness":[],"obligations":[]}
//! ```

use std::collections::{BTreeMap, BTreeSet};

use aos_ability_model::{
    ABILITY_LIMITS_V1, AbilityActivationMode, ArtifactReference, AuthorityRole, Binding,
    ControllerAssignment, DecisionNode, DependencyEdge, DependencyKind, DeploymentObligation,
    EffectPlanDocument, InstanceId, LocalKey, MergeNode, Operation, OperationResultReference,
    PackageDocument, PlanNodeKey, ProviderAdoptionAuthorization, ProviderAdoptionEndpoint,
    ProviderImplementation, ProviderImplementationReference, ProviderReadiness, ResourceId,
    ResourceLifetime, ScopePath, ServiceAction, ValueExpression, VersionedDocument, compare_edges,
    compare_operation_keys,
};
use aos_ability_validate::{CheckedBindingPlan, CheckedTransitionAuthority};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use crate::{CompositionOutcome, VerifiedPlanningSnapshot};

use super::{TransitionError, TransitionLimits};

/// Exact schema discriminator returned by pure transition constructors.
pub const TRANSITION_FRAGMENT_SCHEMA: &str = "aos.ability.transition-fragment/v1";

/// Classifies one provider-authored synchronization boundary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TransitionExportKind {
    /// Allows an authorized upper provider to add prerequisites to this node.
    Entry,
    /// Allows an authorized upper provider to wait for this node and its results.
    Completion,
}

/// Publishes one provider-authored synchronization and typed-result boundary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransitionExport {
    /// Names this boundary within the exporting implementation.
    pub key: LocalKey,
    /// Selects whether the boundary admits predecessors or exposes completion.
    pub kind: TransitionExportKind,
    /// Names the internal node that accepts prerequisites or establishes completion.
    pub node: PlanNodeKey,
    /// Maps public output names to exact internal typed result producers.
    pub outputs: BTreeMap<LocalKey, OperationResultReference>,
}

/// Selects the direction of one lower-boundary relationship to a local node.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TransitionImportDirection {
    /// Makes the local node depend on lower-provider completion.
    AfterExport,
    /// Makes a lower-provider entry depend on the local node.
    BeforeExport,
}

/// Imports one exact lower-provider transition boundary through a checked binding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransitionImport {
    /// Identifies the author's checked outgoing lower-provider binding.
    pub binding: aos_ability_model::BindingId,
    /// Names the boundary exported by the selected lower implementation.
    pub export: LocalKey,
    /// Selects whether the local node precedes or follows the lower boundary.
    pub direction: TransitionImportDirection,
    /// Names exported output aliases consumed by the local node.
    pub outputs: Vec<LocalKey>,
    /// Names the local consumer or successor node.
    pub consumer: PlanNodeKey,
    /// Defines the typed relationship synthesized across the fragment boundary.
    pub kind: DependencyKind,
}

/// Connects completion and entry boundaries from two checked lower providers.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransitionLink {
    /// Identifies the outgoing binding that reaches the completing provider.
    pub from_binding: aos_ability_model::BindingId,
    /// Names a completion boundary exported by that provider.
    pub from_export: LocalKey,
    /// Identifies the outgoing binding that reaches the successor provider.
    pub to_binding: aos_ability_model::BindingId,
    /// Names an entry boundary exported by that provider.
    pub to_export: LocalKey,
    /// Defines the non-data relationship synthesized between both boundaries.
    pub kind: DependencyKind,
}

/// Orders exported boundaries across two exact implementations of one provider.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransitionHandoff {
    /// Identifies the predecessor implementation descriptor.
    pub from_implementation: Sha256Digest,
    /// Names its exported completion boundary.
    pub from_export: LocalKey,
    /// Identifies the successor implementation descriptor.
    pub to_implementation: Sha256Digest,
    /// Names its exported entry boundary.
    pub to_export: LocalKey,
    /// Defines the non-data relationship between both versions.
    pub kind: DependencyKind,
}

/// Carries one bounded provider-authored portion of an effect graph.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransitionFragment {
    /// Carries [`TRANSITION_FRAGMENT_SCHEMA`].
    pub schema: String,
    /// Lists effect operations in canonical scoped-key order.
    pub operations: Vec<Operation>,
    /// Lists conditional decisions in canonical scoped-key order.
    pub decisions: Vec<DecisionNode>,
    /// Lists conditional result merges in canonical scoped-key order.
    pub merges: Vec<MergeNode>,
    /// Lists typed graph dependencies in canonical order.
    pub edges: Vec<DependencyEdge>,
    /// Publishes explicit internal boundaries for checked upper providers.
    pub exports: Vec<TransitionExport>,
    /// Imports explicit boundaries through checked outgoing bindings.
    pub imports: Vec<TransitionImport>,
    /// Connects two exact lower-provider boundaries through checked bindings.
    pub links: Vec<TransitionLink>,
    /// Connects this provider's exact prior and desired implementation boundaries.
    pub handoffs: Vec<TransitionHandoff>,
    /// Declares readiness operations for planned child providers.
    pub provider_readiness: Vec<ProviderReadiness>,
    /// Carries explicit unresolved transition inputs that prohibit execution.
    pub obligations: Vec<DeploymentObligation>,
}

impl TransitionFragment {
    fn is_effect_free(&self) -> bool {
        self.operations.is_empty()
            && self.decisions.is_empty()
            && self.merges.is_empty()
            && self.edges.is_empty()
            && self.exports.is_empty()
            && self.imports.is_empty()
            && self.links.is_empty()
            && self.handoffs.is_empty()
            && self.provider_readiness.is_empty()
    }
}

#[derive(Clone)]
pub(super) struct TransitionGroup {
    pub(super) provider: InstanceId,
    pub(super) reference: ProviderImplementationReference,
    pub(super) package: Sha256Digest,
    pub(super) teardown: bool,
    pub(super) include_teardown: bool,
}

pub(super) struct AuthoredTransitionFragment {
    pub(super) provider: InstanceId,
    pub(super) implementation: ProviderImplementationReference,
    pub(super) operation_scope: ScopePath,
    pub(super) fragment: TransitionFragment,
}

pub(super) fn transition_groups(
    desired: &VerifiedPlanningSnapshot,
    current: Option<&VerifiedPlanningSnapshot>,
    authority: Option<&CheckedTransitionAuthority>,
) -> Result<BTreeMap<(InstanceId, Sha256Digest), TransitionGroup>, TransitionError> {
    let mut groups = transition_groups_for_outcome(desired.outcome())?;
    let Some(current) = current else {
        return Ok(groups);
    };

    for (key, mut prior) in transition_groups_for_outcome(current.outcome())? {
        if let Some(retained) = groups.get_mut(&key) {
            if retained.reference != prior.reference {
                return Err(TransitionError::MissingTeardownAuthority {
                    provider: prior.provider,
                });
            }

            let selects_group = authority_selects_group(authority, current, &prior);
            if retained.package != prior.package && !selects_group {
                return Err(TransitionError::MissingTeardownAuthority {
                    provider: prior.provider,
                });
            }

            // A retained parent may retire a child binding while its own incoming
            // selection remains unchanged, so fresh outgoing authority must expose
            // teardown state without authorizing a package replacement.
            if selects_group
                || authority_selects_outgoing_binding(authority, current, &prior.provider)
            {
                retained.include_teardown = true;
            }
            continue;
        }
        if authority_selects_group(authority, current, &prior) {
            prior.teardown = true;
            groups.insert(key.clone(), prior.clone());
        }
        let Some(retained) = groups.get(&key) else {
            return Err(TransitionError::MissingTeardownAuthority {
                provider: prior.provider,
            });
        };
        if retained.reference != prior.reference || retained.package != prior.package {
            return Err(TransitionError::MissingTeardownAuthority {
                provider: prior.provider,
            });
        }
    }

    Ok(groups)
}

fn authority_selects_group(
    authority: Option<&CheckedTransitionAuthority>,
    current: &VerifiedPlanningSnapshot,
    prior: &TransitionGroup,
) -> bool {
    let Some(authority) = authority else {
        return false;
    };
    authority.document().teardown_bindings.iter().any(|entry| {
        current
            .checked_binding()
            .binding(&entry.source_binding)
            .is_some_and(|source| {
                source.provider == prior.provider
                    && source.provider_package == Some(prior.package)
                    && source.implementation == prior.reference
            })
    }) || authority.document().teardown_providers.iter().any(|entry| {
        entry.provider == prior.provider
            && entry.implementation == prior.reference
            && entry.package == prior.package
    }) || authority
        .document()
        .provider_adoptions
        .iter()
        .any(|adoption| {
            adoption.source.provider == prior.provider
                && adoption.source.implementation == prior.reference
                && adoption.source.package == prior.package
        })
}

fn authority_selects_outgoing_binding(
    authority: Option<&CheckedTransitionAuthority>,
    current: &VerifiedPlanningSnapshot,
    provider: &InstanceId,
) -> bool {
    let Some(authority) = authority else {
        return false;
    };

    authority.document().teardown_bindings.iter().any(|entry| {
        current
            .checked_binding()
            .binding(&entry.source_binding)
            .is_some_and(|source| source.request.consumer == *provider)
    })
}

fn transition_groups_for_outcome(
    outcome: &CompositionOutcome,
) -> Result<BTreeMap<(InstanceId, Sha256Digest), TransitionGroup>, TransitionError> {
    let mut groups = BTreeMap::new();
    for binding in outcome.resolution.checked.bindings() {
        if binding.implementation.handler.is_some() {
            continue;
        }
        let package =
            binding
                .provider_package
                .ok_or_else(|| TransitionError::MissingImplementation {
                    provider: binding.provider.clone(),
                })?;
        insert_group(
            &mut groups,
            binding.provider.clone(),
            binding.implementation.clone(),
            package,
        )?;
    }
    for enabled in &outcome.resolution.policy.enabled_providers {
        if enabled.implementation.handler.is_some() {
            continue;
        }
        let package = outcome
            .desired_state
            .instances
            .iter()
            .find(|instance| instance.enabled && instance.instance == enabled.instance)
            .map(|instance| instance.package)
            .ok_or_else(|| TransitionError::MissingImplementation {
                provider: enabled.instance.clone(),
            })?;
        insert_group(
            &mut groups,
            enabled.instance.clone(),
            enabled.implementation.clone(),
            package,
        )?;
    }
    Ok(groups)
}

fn insert_group(
    groups: &mut BTreeMap<(InstanceId, Sha256Digest), TransitionGroup>,
    provider: InstanceId,
    reference: ProviderImplementationReference,
    package: Sha256Digest,
) -> Result<(), TransitionError> {
    let key = (provider.clone(), reference.descriptor);
    if let Some(existing) = groups.get(&key) {
        if existing.reference != reference || existing.package != package {
            return Err(TransitionError::InvalidFragment {
                provider,
                reason: "selected transition implementation has inconsistent exact provenance"
                    .to_string(),
            });
        }
        return Ok(());
    }
    groups.insert(
        key,
        TransitionGroup {
            provider,
            reference,
            package,
            teardown: false,
            include_teardown: false,
        },
    );
    Ok(())
}

pub(super) fn index_packages(
    packages: &[PackageDocument],
) -> Result<BTreeMap<Sha256Digest, &PackageDocument>, TransitionError> {
    let mut indexed = BTreeMap::new();
    for package in packages {
        let digest = package
            .content_digest()
            .map_err(|error| TransitionError::Encoding(error.to_string()))?;
        if indexed.insert(digest, package).is_some() {
            return Err(TransitionError::Encoding(
                "retained package set contains a duplicate canonical document".to_string(),
            ));
        }
    }
    Ok(indexed)
}

pub(super) fn package_for_group<'a>(
    group: &TransitionGroup,
    packages: &'a BTreeMap<Sha256Digest, &PackageDocument>,
) -> Result<&'a PackageDocument, TransitionError> {
    packages
        .get(&group.package)
        .copied()
        .ok_or_else(|| TransitionError::MissingImplementation {
            provider: group.provider.clone(),
        })
}

pub(super) fn pure_transition<'a>(
    group: &TransitionGroup,
    package: &'a PackageDocument,
) -> Result<Option<(&'a ProviderImplementation, &'a LocalKey)>, TransitionError> {
    let implementation = package
        .implementation
        .providers
        .iter()
        .find(|implementation| {
            implementation.artifact == group.reference.artifact
                && implementation
                    .descriptor_digest()
                    .is_ok_and(|digest| digest == group.reference.descriptor)
        })
        .ok_or_else(|| TransitionError::MissingImplementation {
            provider: group.provider.clone(),
        })?;
    match &implementation.implementation {
        aos_ability_model::ImplementationKind::PureComposition {
            transition_entry, ..
        } if group.reference.handler.is_none()
            && package.module_entry_points.get(transition_entry)
                == Some(&group.reference.artifact) =>
        {
            Ok(Some((implementation, transition_entry)))
        }
        aos_ability_model::ImplementationKind::TerminalHandler { .. } => Ok(None),
        aos_ability_model::ImplementationKind::PureComposition { .. } => {
            Err(TransitionError::MissingImplementation {
                provider: group.provider.clone(),
            })
        }
    }
}

pub(super) fn operation_scope(
    provider: &InstanceId,
    descriptor: Sha256Digest,
) -> Result<ScopePath, TransitionError> {
    ScopePath::new(vec![
        provider.key.clone(),
        LocalKey::new(descriptor.hex()).map_err(|error| TransitionError::InvalidFragment {
            provider: provider.clone(),
            reason: error.to_string(),
        })?,
    ])
    .map_err(|error| TransitionError::InvalidFragment {
        provider: provider.clone(),
        reason: error.to_string(),
    })
}

pub(super) fn validate_fragment(
    provider: &InstanceId,
    operation_scope: &ScopePath,
    implementation_descriptor: Sha256Digest,
    activation_mode: AbilityActivationMode,
    outgoing: &[&Binding],
    fragment: &TransitionFragment,
    limits: TransitionLimits,
) -> Result<(), TransitionError> {
    let invalid = |reason: &str| TransitionError::InvalidFragment {
        provider: provider.clone(),
        reason: reason.to_string(),
    };
    if fragment.schema != TRANSITION_FRAGMENT_SCHEMA {
        return Err(invalid("unsupported transition fragment schema"));
    }
    let node_count = fragment
        .operations
        .len()
        .saturating_add(fragment.decisions.len())
        .saturating_add(fragment.merges.len());
    if node_count > limits.max_graph_nodes as usize
        || fragment.edges.len() > limits.max_graph_edges as usize
        || fragment.exports.len() > limits.max_graph_nodes as usize
        || fragment.imports.len() > limits.max_graph_edges as usize
        || fragment.links.len() > limits.max_graph_edges as usize
        || fragment.handoffs.len() > limits.max_graph_edges as usize
        || fragment.provider_readiness.len() > limits.max_graph_nodes as usize
        || fragment.obligations.len() > limits.max_graph_nodes as usize
    {
        return Err(TransitionError::Limit {
            limit: "transition graph node or edge",
        });
    }
    if activation_mode == AbilityActivationMode::ContractsOnly && !fragment.is_effect_free() {
        return Err(invalid(
            "contracts-only provider authored transition effects through a lower implementation",
        ));
    }
    if fragment
        .operations
        .windows(2)
        .any(|pair| compare_operation_keys(&pair[0].key, &pair[1].key).is_ge())
        || fragment
            .decisions
            .windows(2)
            .any(|pair| compare_operation_keys(&pair[0].key, &pair[1].key).is_ge())
        || fragment
            .merges
            .windows(2)
            .any(|pair| compare_operation_keys(&pair[0].key, &pair[1].key).is_ge())
        || fragment
            .edges
            .windows(2)
            .any(|pair| compare_edges(&pair[0], &pair[1]).is_ge())
        || fragment
            .exports
            .windows(2)
            .any(|pair| pair[0].key >= pair[1].key)
        || fragment
            .imports
            .windows(2)
            .any(|pair| compare_transition_imports(&pair[0], &pair[1]).is_ge())
        || fragment
            .links
            .windows(2)
            .any(|pair| compare_transition_links(&pair[0], &pair[1]).is_ge())
        || fragment
            .handoffs
            .windows(2)
            .any(|pair| compare_transition_handoffs(&pair[0], &pair[1]).is_ge())
        || fragment
            .provider_readiness
            .windows(2)
            .any(|pair| pair[0].binding >= pair[1].binding)
        || fragment
            .obligations
            .windows(2)
            .any(|pair| pair[0].key >= pair[1].key)
    {
        return Err(invalid(
            "transition fragment collections are not in strict canonical order",
        ));
    }
    if fragment.operations.iter().any(|operation| {
        &operation.key.scope != operation_scope
            || operation
                .branch_context
                .iter()
                .any(|membership| &membership.decision.scope != operation_scope)
    }) || fragment.decisions.iter().any(|decision| {
        &decision.key.scope != operation_scope
            || decision
                .branch_context
                .iter()
                .any(|membership| &membership.decision.scope != operation_scope)
    }) || fragment.merges.iter().any(|merge| {
        &merge.key.scope != operation_scope
            || &merge.decision.scope != operation_scope
            || merge
                .branch_context
                .iter()
                .any(|membership| &membership.decision.scope != operation_scope)
    }) || fragment.edges.iter().any(|edge| {
        &edge.from.key().scope != operation_scope || &edge.to.key().scope != operation_scope
    }) {
        return Err(invalid(
            "transition node leaves its assigned provider implementation scope",
        ));
    }
    let outgoing: BTreeMap<_, _> = outgoing
        .iter()
        .map(|binding| (&binding.id, *binding))
        .collect();
    for operation in &fragment.operations {
        let Some(binding) = outgoing.get(&operation.binding) else {
            return Err(invalid(
                "transition operation does not use an outgoing checked provider binding",
            ));
        };
        validate_operation_grant(operation, binding, &invalid)?;
    }
    let local_nodes = fragment_node_keys(fragment);
    for export in &fragment.exports {
        if !local_nodes.contains(&export.node)
            || export.node.key().scope != *operation_scope
            || (export.kind == TransitionExportKind::Entry && !export.outputs.is_empty())
            || export.outputs.values().any(|output| {
                output.producer.key().scope != *operation_scope
                    || !local_nodes.contains(&result_producer_node(output))
            })
        {
            return Err(invalid(
                "transition export does not identify nodes in its provider scope",
            ));
        }
    }
    for import in &fragment.imports {
        if !outgoing.contains_key(&import.binding)
            || !local_nodes.contains(&import.consumer)
            || import.consumer.key().scope != *operation_scope
            || import.outputs.windows(2).any(|pair| pair[0] >= pair[1])
            || match import.direction {
                TransitionImportDirection::AfterExport => {
                    (import.kind == DependencyKind::Data) != !import.outputs.is_empty()
                }
                TransitionImportDirection::BeforeExport => {
                    import.kind == DependencyKind::Data || !import.outputs.is_empty()
                }
            }
        {
            return Err(invalid(
                "transition import is not a canonical checked lower-provider boundary",
            ));
        }
    }
    if fragment.links.iter().any(|link| {
        !outgoing.contains_key(&link.from_binding)
            || !outgoing.contains_key(&link.to_binding)
            || link.kind == DependencyKind::Data
    }) {
        return Err(invalid(
            "transition link is not a non-data relationship over outgoing bindings",
        ));
    }
    if fragment.handoffs.iter().any(|handoff| {
        handoff.kind == DependencyKind::Data
            || handoff.from_implementation == handoff.to_implementation
            || (handoff.from_implementation != implementation_descriptor
                && handoff.to_implementation != implementation_descriptor)
    }) {
        return Err(invalid(
            "transition handoff must join this exact implementation to another version with a non-data edge",
        ));
    }
    if fragment.provider_readiness.iter().any(|readiness| {
        !outgoing.contains_key(&readiness.binding) || readiness.producer.scope != *operation_scope
    }) {
        return Err(invalid(
            "transition readiness leaves its outgoing binding and operation scope",
        ));
    }
    if fragment.obligations.iter().any(|obligation| {
        obligation.request.consumer != *provider
            || !outgoing
                .values()
                .any(|binding| binding.request == obligation.request)
    }) {
        return Err(invalid(
            "transition obligation does not identify an outgoing provider request",
        ));
    }
    Ok(())
}

fn compare_transition_imports(
    left: &TransitionImport,
    right: &TransitionImport,
) -> std::cmp::Ordering {
    left.binding
        .cmp(&right.binding)
        .then_with(|| left.export.cmp(&right.export))
        .then_with(|| {
            transition_import_direction_rank(left.direction)
                .cmp(&transition_import_direction_rank(right.direction))
        })
        .then_with(|| left.consumer.cmp(&right.consumer))
        .then_with(|| left.kind.canonical_rank().cmp(&right.kind.canonical_rank()))
}

const fn transition_import_direction_rank(direction: TransitionImportDirection) -> u8 {
    match direction {
        TransitionImportDirection::AfterExport => 0,
        TransitionImportDirection::BeforeExport => 1,
    }
}

fn compare_transition_links(left: &TransitionLink, right: &TransitionLink) -> std::cmp::Ordering {
    left.from_binding
        .cmp(&right.from_binding)
        .then_with(|| left.from_export.cmp(&right.from_export))
        .then_with(|| left.to_binding.cmp(&right.to_binding))
        .then_with(|| left.to_export.cmp(&right.to_export))
        .then_with(|| left.kind.canonical_rank().cmp(&right.kind.canonical_rank()))
}

fn compare_transition_handoffs(
    left: &TransitionHandoff,
    right: &TransitionHandoff,
) -> std::cmp::Ordering {
    left.from_implementation
        .cmp(&right.from_implementation)
        .then_with(|| left.from_export.cmp(&right.from_export))
        .then_with(|| left.to_implementation.cmp(&right.to_implementation))
        .then_with(|| left.to_export.cmp(&right.to_export))
        .then_with(|| left.kind.canonical_rank().cmp(&right.kind.canonical_rank()))
}

fn fragment_node_keys(fragment: &TransitionFragment) -> BTreeSet<PlanNodeKey> {
    fragment
        .operations
        .iter()
        .map(|operation| PlanNodeKey::Operation {
            key: operation.key.clone(),
        })
        .chain(
            fragment
                .decisions
                .iter()
                .map(|decision| PlanNodeKey::Decision {
                    key: decision.key.clone(),
                }),
        )
        .chain(fragment.merges.iter().map(|merge| PlanNodeKey::Merge {
            key: merge.key.clone(),
        }))
        .collect()
}

fn result_producer_node(reference: &OperationResultReference) -> PlanNodeKey {
    match &reference.producer {
        aos_ability_model::ResultProducerKey::Operation { key } => {
            PlanNodeKey::Operation { key: key.clone() }
        }
        aos_ability_model::ResultProducerKey::Merge { key } => {
            PlanNodeKey::Merge { key: key.clone() }
        }
    }
}

fn validate_operation_grant(
    operation: &Operation,
    binding: &Binding,
    invalid: &impl Fn(&str) -> TransitionError,
) -> Result<(), TransitionError> {
    let grant = match operation.authority {
        AuthorityRole::Caller => &binding.caller_grant,
        AuthorityRole::Provider if binding.mediation_allowed => &binding.provider_grant,
        AuthorityRole::Provider => {
            return Err(invalid(
                "transition requests provider mediation absent from its checked binding",
            ));
        }
    };
    if !grant.methods.contains(&operation.method) {
        return Err(invalid(
            "transition operation method exceeds its exact checked grant",
        ));
    }
    if operation.accesses.iter().any(|access| {
        !grant.resources.iter().any(|permission| {
            permission.resource == access.resource && permission.access.permits(access.mode)
        })
    }) {
        return Err(invalid(
            "transition resource access exceeds its exact checked grant",
        ));
    }
    if operation.target.operations.iter().any(|requested| {
        !grant.resources.iter().any(|permission| {
            permission.resource == operation.target.resource
                && permission.operations.contains(requested)
        })
    }) {
        return Err(invalid(
            "transition target operation exceeds its exact checked grant",
        ));
    }
    Ok(())
}

fn foreign_results_by_consumer(
    authored: &AuthoredTransitionFragment,
) -> BTreeMap<PlanNodeKey, BTreeSet<OperationResultReference>> {
    let mut results = BTreeMap::new();
    for operation in &authored.fragment.operations {
        let consumer = PlanNodeKey::Operation {
            key: operation.key.clone(),
        };
        let mut references = BTreeSet::new();
        collect_expression_results(&operation.inputs, &mut references);
        retain_foreign_results(
            &mut results,
            consumer,
            references,
            &authored.operation_scope,
        );
    }
    for decision in &authored.fragment.decisions {
        retain_foreign_results(
            &mut results,
            PlanNodeKey::Decision {
                key: decision.key.clone(),
            },
            BTreeSet::from([decision.selector.result.clone()]),
            &authored.operation_scope,
        );
    }
    for merge in &authored.fragment.merges {
        let references = merge
            .outputs
            .values()
            .flat_map(|output| output.alternatives.values().cloned())
            .collect();
        retain_foreign_results(
            &mut results,
            PlanNodeKey::Merge {
                key: merge.key.clone(),
            },
            references,
            &authored.operation_scope,
        );
    }
    results
}

fn collect_expression_results(
    expression: &ValueExpression,
    references: &mut BTreeSet<OperationResultReference>,
) {
    let mut pending = vec![expression];
    while let Some(expression) = pending.pop() {
        match expression {
            ValueExpression::List { items } => pending.extend(items),
            ValueExpression::Object { fields } => pending.extend(fields.values()),
            ValueExpression::OperationResult { reference } => {
                references.insert(reference.clone());
            }
            ValueExpression::Literal { .. }
            | ValueExpression::ArtifactReference { .. }
            | ValueExpression::ResourceReference { .. }
            | ValueExpression::AggregateOutput { .. } => {}
        }
    }
}

fn retain_foreign_results(
    results: &mut BTreeMap<PlanNodeKey, BTreeSet<OperationResultReference>>,
    consumer: PlanNodeKey,
    mut references: BTreeSet<OperationResultReference>,
    operation_scope: &ScopePath,
) {
    references.retain(|reference| reference.producer.key().scope != *operation_scope);
    if !references.is_empty() {
        results.insert(consumer, references);
    }
}

pub(super) fn merge_fragments(
    binding_plan: &CheckedBindingPlan,
    provider_adoptions: &[ProviderAdoptionAuthorization],
    linked_healthy_adoptions: &BTreeSet<ResourceId>,
    controllers: Vec<ControllerAssignment>,
    fragments: Vec<AuthoredTransitionFragment>,
    packages: &BTreeMap<Sha256Digest, &PackageDocument>,
    evaluated_packages: &BTreeMap<Sha256Digest, InstanceId>,
    limits: TransitionLimits,
) -> Result<EffectPlanDocument, TransitionError> {
    let mut exported_boundaries = BTreeMap::new();
    for authored in &fragments {
        for export in &authored.fragment.exports {
            let key = (
                authored.provider.clone(),
                authored.implementation.descriptor,
                export.key.clone(),
            );
            if exported_boundaries.insert(key, export).is_some() {
                return Err(TransitionError::InvalidFragment {
                    provider: authored.provider.clone(),
                    reason: "transition fragment repeats an exported boundary".to_string(),
                });
            }
        }
    }

    let mut imported_edges = Vec::new();
    for authored in &fragments {
        let mut allowed_results: BTreeMap<PlanNodeKey, BTreeSet<OperationResultReference>> =
            BTreeMap::new();
        let foreign_results = foreign_results_by_consumer(authored);
        for import in &authored.fragment.imports {
            let binding = binding_plan.binding(&import.binding).ok_or_else(|| {
                TransitionError::InvalidFragment {
                    provider: authored.provider.clone(),
                    reason: "transition import names a missing checked binding".to_string(),
                }
            })?;
            if binding.request.consumer != authored.provider {
                return Err(TransitionError::InvalidFragment {
                    provider: authored.provider.clone(),
                    reason: "transition import does not use an outgoing checked binding"
                        .to_string(),
                });
            }
            let export_key = (
                binding.provider.clone(),
                binding.implementation.descriptor,
                import.export.clone(),
            );
            let export = exported_boundaries.get(&export_key).ok_or_else(|| {
                TransitionError::InvalidFragment {
                    provider: authored.provider.clone(),
                    reason: "transition import has no exact lower-provider export".to_string(),
                }
            })?;
            let expected_kind = match import.direction {
                TransitionImportDirection::AfterExport => TransitionExportKind::Completion,
                TransitionImportDirection::BeforeExport => TransitionExportKind::Entry,
            };
            if export.kind != expected_kind {
                return Err(TransitionError::InvalidFragment {
                    provider: authored.provider.clone(),
                    reason: "transition import uses an incompatible export boundary kind"
                        .to_string(),
                });
            }
            for output in &import.outputs {
                let reference =
                    export
                        .outputs
                        .get(output)
                        .ok_or_else(|| TransitionError::InvalidFragment {
                            provider: authored.provider.clone(),
                            reason: "transition import names an absent exported output".to_string(),
                        })?;
                allowed_results
                    .entry(import.consumer.clone())
                    .or_default()
                    .insert(reference.clone());
            }
            let (from, to) = match import.direction {
                TransitionImportDirection::AfterExport => {
                    (export.node.clone(), import.consumer.clone())
                }
                TransitionImportDirection::BeforeExport => {
                    (import.consumer.clone(), export.node.clone())
                }
            };
            imported_edges.push(DependencyEdge {
                from,
                to,
                kind: import.kind,
            });
        }
        for link in &authored.fragment.links {
            let from_binding = binding_plan.binding(&link.from_binding).ok_or_else(|| {
                TransitionError::InvalidFragment {
                    provider: authored.provider.clone(),
                    reason: "transition link names a missing source binding".to_string(),
                }
            })?;
            let to_binding = binding_plan.binding(&link.to_binding).ok_or_else(|| {
                TransitionError::InvalidFragment {
                    provider: authored.provider.clone(),
                    reason: "transition link names a missing target binding".to_string(),
                }
            })?;
            if from_binding.request.consumer != authored.provider
                || to_binding.request.consumer != authored.provider
            {
                return Err(TransitionError::InvalidFragment {
                    provider: authored.provider.clone(),
                    reason: "transition link leaves the author's outgoing checked bindings"
                        .to_string(),
                });
            }
            let from_key = (
                from_binding.provider.clone(),
                from_binding.implementation.descriptor,
                link.from_export.clone(),
            );
            let to_key = (
                to_binding.provider.clone(),
                to_binding.implementation.descriptor,
                link.to_export.clone(),
            );
            let from_export = exported_boundaries.get(&from_key).ok_or_else(|| {
                TransitionError::InvalidFragment {
                    provider: authored.provider.clone(),
                    reason: "transition link has no exact source export".to_string(),
                }
            })?;
            let to_export = exported_boundaries.get(&to_key).ok_or_else(|| {
                TransitionError::InvalidFragment {
                    provider: authored.provider.clone(),
                    reason: "transition link has no exact target export".to_string(),
                }
            })?;
            if from_export.kind != TransitionExportKind::Completion
                || to_export.kind != TransitionExportKind::Entry
            {
                return Err(TransitionError::InvalidFragment {
                    provider: authored.provider.clone(),
                    reason: "transition link must connect completion to entry boundaries"
                        .to_string(),
                });
            }
            imported_edges.push(DependencyEdge {
                from: from_export.node.clone(),
                to: to_export.node.clone(),
                kind: link.kind,
            });
        }
        for handoff in &authored.fragment.handoffs {
            let from_key = (
                authored.provider.clone(),
                handoff.from_implementation,
                handoff.from_export.clone(),
            );
            let to_key = (
                authored.provider.clone(),
                handoff.to_implementation,
                handoff.to_export.clone(),
            );
            let from_export = exported_boundaries.get(&from_key).ok_or_else(|| {
                TransitionError::InvalidFragment {
                    provider: authored.provider.clone(),
                    reason: "transition handoff has no exact predecessor export".to_string(),
                }
            })?;
            let to_export = exported_boundaries.get(&to_key).ok_or_else(|| {
                TransitionError::InvalidFragment {
                    provider: authored.provider.clone(),
                    reason: "transition handoff has no exact successor export".to_string(),
                }
            })?;
            if from_export.kind != TransitionExportKind::Completion
                || to_export.kind != TransitionExportKind::Entry
            {
                return Err(TransitionError::InvalidFragment {
                    provider: authored.provider.clone(),
                    reason: "transition handoff must connect completion to entry boundaries"
                        .to_string(),
                });
            }
            imported_edges.push(DependencyEdge {
                from: from_export.node.clone(),
                to: to_export.node.clone(),
                kind: handoff.kind,
            });
        }
        if foreign_results != allowed_results {
            return Err(TransitionError::InvalidFragment {
                provider: authored.provider.clone(),
                reason: "foreign transition results differ from explicit lower-provider imports"
                    .to_string(),
            });
        }
    }

    let mut operations = Vec::new();
    let mut decisions = Vec::new();
    let mut merges = Vec::new();
    let mut edges = Vec::new();
    let mut provider_readiness = Vec::new();
    let mut obligations = Vec::new();
    for authored in fragments {
        let fragment = authored.fragment;
        operations.extend(fragment.operations);
        decisions.extend(fragment.decisions);
        merges.extend(fragment.merges);
        edges.extend(fragment.edges);
        provider_readiness.extend(fragment.provider_readiness);
        obligations.extend(fragment.obligations);
    }
    edges.extend(imported_edges);
    edges.extend(provider_adoption_handoffs(
        binding_plan,
        &operations,
        provider_adoptions,
        linked_healthy_adoptions,
    )?);
    operations.sort_by(|left, right| compare_operation_keys(&left.key, &right.key));
    decisions.sort_by(|left, right| compare_operation_keys(&left.key, &right.key));
    merges.sort_by(|left, right| compare_operation_keys(&left.key, &right.key));
    edges.sort_by(compare_edges);
    provider_readiness.sort_by(|left, right| left.binding.cmp(&right.binding));
    obligations.sort_by(|left, right| left.key.cmp(&right.key));

    let artifacts = retained_transition_artifacts(binding_plan, packages, evaluated_packages)?;

    let node_count = operations
        .len()
        .saturating_add(decisions.len())
        .saturating_add(merges.len());
    if node_count > limits.max_graph_nodes as usize || edges.len() > limits.max_graph_edges as usize
    {
        return Err(TransitionError::Limit {
            limit: "merged transition graph",
        });
    }
    if provider_readiness.len() > limits.max_graph_nodes as usize
        || obligations.len() > limits.max_graph_nodes as usize
    {
        return Err(TransitionError::Limit {
            limit: "merged readiness or obligation collection",
        });
    }

    Ok(EffectPlanDocument {
        schema: EffectPlanDocument::SCHEMA.to_string(),
        required_features: Vec::new(),
        limits: ABILITY_LIMITS_V1,
        binding_plan: binding_plan.id().0,
        artifacts,
        current_revisions: binding_plan.environment().resources.clone(),
        desired_revisions: binding_plan.desired_state().resources.clone(),
        operations,
        decisions,
        merges,
        edges,
        provider_readiness,
        controllers,
        obligations,
    })
}

fn provider_adoption_handoffs(
    binding_plan: &CheckedBindingPlan,
    operations: &[Operation],
    adoptions: &[ProviderAdoptionAuthorization],
    linked_healthy_adoptions: &BTreeSet<ResourceId>,
) -> Result<Vec<DependencyEdge>, TransitionError> {
    let mut handoffs = Vec::with_capacity(adoptions.len());

    for adoption in adoptions {
        let source = operations
            .iter()
            .filter(|operation| {
                adoption_operation_matches(
                    binding_plan,
                    operation,
                    adoption,
                    &adoption.source,
                    false,
                ) && matches!(
                    operation.family,
                    aos_ability_model::OperationFamily::ServiceLifecycle {
                        action: ServiceAction::Stop
                    }
                )
            })
            .collect::<Vec<_>>();
        let candidate = operations
            .iter()
            .filter(|operation| {
                adoption_operation_matches(
                    binding_plan,
                    operation,
                    adoption,
                    &adoption.candidate,
                    true,
                ) && operation.method == adoption.candidate.handler_method
            })
            .collect::<Vec<_>>();
        let handoff = select_provider_adoption_handoff(
            &adoption.resource,
            operations,
            &source,
            &candidate,
            linked_healthy_adoptions,
        )
        .ok_or_else(|| TransitionError::InvalidFragment {
            provider: adoption.candidate.provider.clone(),
            reason: "provider adoption requires one exact source Stop and candidate acquisition operation"
                .to_string(),
        })?;
        let Some((source, candidate)) = handoff else {
            continue;
        };

        handoffs.push(DependencyEdge {
            from: PlanNodeKey::Operation {
                key: source.key.clone(),
            },
            to: PlanNodeKey::Operation {
                key: candidate.key.clone(),
            },
            kind: DependencyKind::RequiredSuccess,
        });
    }

    Ok(handoffs)
}

fn select_provider_adoption_handoff<'a>(
    resource: &ResourceId,
    operations: &'a [Operation],
    source: &[&'a Operation],
    candidate: &[&'a Operation],
    linked_healthy_adoptions: &BTreeSet<ResourceId>,
) -> Option<Option<(&'a Operation, &'a Operation)>> {
    if let ([source], [candidate]) = (source, candidate) {
        return Some(Some((source, candidate)));
    }

    let has_targeted_write = operations.iter().any(|operation| {
        operation
            .accesses
            .iter()
            .any(|access| access.resource == *resource && access.mode.is_write())
    });
    if linked_healthy_adoptions.contains(resource)
        && source.is_empty()
        && candidate.is_empty()
        && !has_targeted_write
    {
        return Some(None);
    }

    None
}

fn adoption_operation_matches(
    binding_plan: &CheckedBindingPlan,
    operation: &Operation,
    adoption: &ProviderAdoptionAuthorization,
    endpoint: &ProviderAdoptionEndpoint,
    desired: bool,
) -> bool {
    let Some(binding) = binding_plan.binding(&operation.binding) else {
        return false;
    };
    let Some(authority) = binding_plan.binding_authority(&operation.binding) else {
        return false;
    };
    let endpoint_binding_matches = match authority {
        aos_ability_validate::BindingAuthorityKind::Desired => {
            desired && operation.binding == endpoint.handler_binding
        }
        aos_ability_validate::BindingAuthorityKind::Teardown { source_binding, .. } => {
            !desired && *source_binding == endpoint.handler_binding
        }
    };

    // The endpoint method authenticates the ownership acquisition. A source
    // Stop is a teardown handoff on the sealed source binding, so its method
    // may differ while the exact implementation and resource still match.
    endpoint_binding_matches
        && (!desired || operation.method == endpoint.handler_method)
        && operation.target.resource == adoption.resource
        && operation.target.interface == adoption.resource_interface
        && operation.target.interface == endpoint.handler_interface
        && operation.target.lifetime == ResourceLifetime::Persistent
        && operation
            .accesses
            .iter()
            .any(|access| access.resource == adoption.resource && access.mode.is_write())
        && binding.request.consumer == endpoint.provider
        && binding.provider == endpoint.handler_provider
        && binding.interface == endpoint.handler_interface
        && binding.implementation == endpoint.handler_implementation
        && binding.provider_package == Some(endpoint.handler_package)
}

fn retained_transition_artifacts(
    binding_plan: &CheckedBindingPlan,
    packages: &BTreeMap<Sha256Digest, &PackageDocument>,
    evaluated_packages: &BTreeMap<Sha256Digest, InstanceId>,
) -> Result<Vec<ArtifactReference>, TransitionError> {
    let mut artifacts = BTreeMap::new();
    let mut retained_packages: BTreeSet<_> = evaluated_packages.keys().copied().collect();
    for binding in binding_plan.bindings() {
        insert_artifact(
            &mut artifacts,
            &binding.implementation.artifact,
            &binding.provider,
        )?;
        if let Some(package) = binding.provider_package {
            retained_packages.insert(package);
        }
    }
    for package_digest in &retained_packages {
        let package = packages.get(package_digest).copied().ok_or_else(|| {
            TransitionError::Encoding(
                "evaluated transition package is absent from the retained catalog".to_string(),
            )
        })?;
        let fallback_provider = binding_plan
            .bindings()
            .iter()
            .find(|binding| binding.provider_package == Some(*package_digest))
            .map(|binding| binding.provider.clone())
            .or_else(|| {
                binding_plan
                    .desired_state()
                    .instances
                    .iter()
                    .find(|instance| instance.package == *package_digest)
                    .map(|instance| instance.instance.clone())
            })
            .or_else(|| evaluated_packages.get(package_digest).cloned())
            .ok_or_else(|| {
                TransitionError::Encoding(
                    "evaluated package has no retained provider identity".to_string(),
                )
            })?;

        insert_artifact(&mut artifacts, &package.package.payload, &fallback_provider)?;
        insert_artifact(&mut artifacts, &package.package.source, &fallback_provider)?;
        for artifact in &package.artifacts {
            insert_artifact(&mut artifacts, artifact, &fallback_provider)?;
        }
        for artifact in package.module_entry_points.values() {
            insert_artifact(&mut artifacts, artifact, &fallback_provider)?;
        }
        for implementation in &package.implementation.providers {
            insert_artifact(&mut artifacts, &implementation.artifact, &fallback_provider)?;
        }
        for handler in package.implementation.handlers.values() {
            insert_artifact(&mut artifacts, &handler.artifact, &fallback_provider)?;
        }
    }
    Ok(artifacts.into_values().collect())
}

fn insert_artifact(
    artifacts: &mut BTreeMap<Sha256Digest, ArtifactReference>,
    artifact: &ArtifactReference,
    provider: &InstanceId,
) -> Result<(), TransitionError> {
    if let Some(existing) = artifacts.get(&artifact.content) {
        if existing != artifact {
            return Err(TransitionError::InvalidFragment {
                provider: provider.clone(),
                reason: "one artifact content identity has conflicting retained provenance"
                    .to_string(),
            });
        }
        return Ok(());
    }
    artifacts.insert(artifact.content, artifact.clone());
    Ok(())
}

#[cfg(test)]
mod tests {
    use aos_ability_model::{AccessMode, ProviderStateFormat};

    use super::*;

    fn operation_fixture() -> Operation {
        aos_ability_validate::test_support::checked_systemd_manager_effect_plan().operations()[0]
            .clone()
    }

    #[test]
    fn linked_healthy_adoption_allows_no_writes() {
        let mut observation = operation_fixture();
        observation.accesses[0].mode = AccessMode::Read;
        let resource = observation.target.resource.clone();
        let operations = vec![observation];
        let linked = BTreeSet::from([resource.clone()]);

        assert!(matches!(
            select_provider_adoption_handoff(&resource, &operations, &[], &[], &linked),
            Some(None)
        ));
    }

    #[test]
    fn linked_healthy_adoption_rejects_a_mismatched_write() {
        let mut operation = operation_fixture();
        let resource = operation.target.resource.clone();
        operation.target.resource.key =
            LocalKey::new("different-target").expect("static resource key must be valid");
        let operations = vec![operation];
        let linked = BTreeSet::from([resource.clone()]);

        assert!(
            select_provider_adoption_handoff(&resource, &operations, &[], &[], &linked).is_none()
        );
    }

    #[test]
    fn linked_healthy_adoption_rejects_a_partial_handoff() {
        let source = operation_fixture();
        let resource = source.target.resource.clone();
        let operations = vec![source];
        let source = [&operations[0]];
        let linked = BTreeSet::from([resource.clone()]);

        assert!(
            select_provider_adoption_handoff(&resource, &operations, &source, &[], &linked)
                .is_none()
        );
    }

    #[test]
    fn ordinary_adoption_still_requires_an_exact_handoff() {
        let source = operation_fixture();
        let candidate = operation_fixture();
        let resource = source.target.resource.clone();
        let operations = vec![source, candidate];
        let source = [&operations[0]];
        let candidate = [&operations[1]];

        assert!(
            select_provider_adoption_handoff(&resource, &operations, &[], &[], &BTreeSet::new())
                .is_none()
        );
        assert!(matches!(
            select_provider_adoption_handoff(
                &resource,
                &operations,
                &source,
                &candidate,
                &BTreeSet::new()
            ),
            Some(Some(_))
        ));
    }

    #[test]
    fn candidate_adoption_operation_requires_the_exact_sealed_handler_method() {
        let plan = aos_ability_validate::test_support::checked_stateful_owner_effect_plan();
        let operation = plan.operations()[0].clone();
        let binding = plan
            .binding_plan()
            .binding(&operation.binding)
            .expect("fixture operation must retain its checked binding");
        let assignment = plan
            .binding_plan()
            .environment()
            .providers
            .iter()
            .find(|assignment| {
                assignment.provider == binding.provider
                    && assignment.interface == binding.interface
                    && assignment.implementation == binding.implementation
            })
            .expect("fixture binding must retain its checked assignment");
        let endpoint = ProviderAdoptionEndpoint {
            provider: binding.request.consumer.clone(),
            package: binding
                .provider_package
                .expect("fixture binding must retain its package"),
            interface: binding.interface.clone(),
            implementation: binding.implementation.clone(),
            state_format: ProviderStateFormat {
                descriptor: Sha256Digest::of_bytes("unused owner state format"),
                artifact: binding.implementation.artifact.clone(),
            },
            handler_binding: binding.id.clone(),
            handler_method: operation.method.clone(),
            handler_provider: binding.provider.clone(),
            handler_incarnation: assignment
                .incarnation
                .clone()
                .expect("fixture assignment must be available"),
            handler_interface: binding.interface.clone(),
            handler_implementation: binding.implementation.clone(),
            handler_package: binding
                .provider_package
                .expect("fixture binding must retain its package"),
        };
        let adoption = ProviderAdoptionAuthorization {
            resource: operation.target.resource.clone(),
            resource_interface: operation.target.interface.clone(),
            source: endpoint.clone(),
            candidate: endpoint.clone(),
        };

        assert!(adoption_operation_matches(
            plan.binding_plan(),
            &operation,
            &adoption,
            &endpoint,
            true
        ));

        let mut wrong_method = endpoint;
        wrong_method.handler_method =
            LocalKey::new("wrong-stop-method").expect("static handler method must be valid");
        assert!(!adoption_operation_matches(
            plan.binding_plan(),
            &operation,
            &adoption,
            &wrong_method,
            true
        ));
    }
}
