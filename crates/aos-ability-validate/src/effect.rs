//! Effect-plan operation, reference, conditional, resource, and DAG validation.

mod operation;
mod resources;
mod schedule;
mod value_authority;

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use aos_ability_model::{
    compare_edges, compare_operation_keys, compare_plan_node_keys, compare_resource_ids,
    AccessMode, ArtifactReference, AuthorityGrant, AuthorityRole, Binding, BranchMembership,
    DecisionNode, DecisionPredicate, DependencyKind, Diagnostic, DiagnosticClass, DiagnosticCode,
    DiagnosticPhase, EffectPlanDocument, LocalKey, MergeNode, Operation, OperationFamily,
    OperationResultReference, OutputDescriptor, PlanId, PlanNodeKey, ResourceId, ResourceReference,
    ResultProducerKey, RetryPolicy, ScopedOperationKey, ValueExpression, ValueSchema,
    ValueVisibility, VersionedDocument,
};
use serde_json::Value;

use crate::authority::{authorize_invocation, required_target_access, ArtifactIndex};
use crate::error::push_diagnostic;
use crate::graph::{
    check_strict_order, diagnostic, BindingProviderState, CheckedBindingPlan, CheckedEffectPlan,
    ValidationContext,
};
use crate::schema::{validate_expression, SchemaPath};
use crate::ValidationErrors;
use operation::{
    build_result_owners, producer_node, result_descriptor, validate_operation, ResultOwnerMap,
};
use resources::validate_resources;
use schedule::{
    build_indices, build_node_contexts, scheduling_adjacency, topological_order,
    validate_branch_contexts, validate_edges, validate_exact_conditional_edges,
    validate_planned_provider_readiness, NodeContexts,
};

pub(crate) fn validate_effect_document(
    context: &ValidationContext,
    document: EffectPlanDocument,
    binding_plan: CheckedBindingPlan,
) -> Result<CheckedEffectPlan, ValidationErrors> {
    let mut diagnostics = Vec::new();
    let id = match document.content_digest() {
        Ok(digest) => PlanId(digest),
        Err(error) => {
            push_diagnostic(
                &mut diagnostics,
                diagnostic(
                    DiagnosticCode::UnsupportedSchema,
                    DiagnosticClass::InvalidContract,
                    DiagnosticPhase::Planning,
                    Vec::new(),
                    error.to_string(),
                ),
            );
            return Err(ValidationErrors::new(diagnostics));
        }
    };

    for feature in &document.required_features {
        if !context.supported_features().contains(feature) {
            push_diagnostic(
                &mut diagnostics,
                diagnostic(
                    DiagnosticCode::UnsupportedRequiredFeature,
                    DiagnosticClass::InvalidContract,
                    DiagnosticPhase::Planning,
                    vec!["required_features".to_string()],
                    format!("unsupported required feature '{}'", feature.as_str()),
                ),
            );
        }
    }
    if document.binding_plan != binding_plan.id().0 {
        push_diagnostic(
            &mut diagnostics,
            diagnostic(
                DiagnosticCode::BindingInterfaceMismatch,
                DiagnosticClass::InvalidContract,
                DiagnosticPhase::Planning,
                vec!["binding_plan".to_string()],
                "effect plan does not commit to the supplied checked binding plan".to_string(),
            ),
        );
    }

    validate_state_provenance(&document, &binding_plan, &mut diagnostics);

    validate_canonical_order(&document, &mut diagnostics);
    validate_plan_limits(&document, &mut diagnostics);
    let (operation_indices, decision_indices, merge_indices) =
        build_indices(&document, &mut diagnostics);
    let node_contexts = build_node_contexts(&document);
    let edge_set: BTreeSet<_> = document
        .edges
        .iter()
        .map(|edge| (edge.from.clone(), edge.to.clone(), edge.kind))
        .collect();
    let artifact_index: ArtifactIndex = document
        .artifacts
        .iter()
        .map(|artifact| (artifact.content, artifact.clone()))
        .collect();
    let resource_set: BTreeSet<_> = binding_plan
        .document()
        .resources
        .iter()
        .map(|revision| revision.resource.clone())
        .collect();

    validate_edges(
        &document,
        &operation_indices,
        &decision_indices,
        &merge_indices,
        &node_contexts,
        &mut diagnostics,
    );
    validate_branch_contexts(
        &document,
        &operation_indices,
        &decision_indices,
        &merge_indices,
        &node_contexts,
        &edge_set,
        &mut diagnostics,
    );
    validate_exact_conditional_edges(&document, &node_contexts, &edge_set, &mut diagnostics);
    let readiness_indices = validate_planned_provider_readiness(
        context,
        &document,
        &binding_plan,
        &operation_indices,
        &node_contexts,
        &edge_set,
        &mut diagnostics,
    );
    let adjacency = scheduling_adjacency(&document);
    let dispatch_order = topological_order(&document, &adjacency, &mut diagnostics);
    let result_owners = build_result_owners(
        context,
        &document,
        &binding_plan,
        &dispatch_order,
        &operation_indices,
        &merge_indices,
    );

    for (index, operation) in document.operations.iter().enumerate() {
        validate_operation(
            context,
            &document,
            &binding_plan,
            operation,
            index,
            &operation_indices,
            &merge_indices,
            &result_owners,
            &node_contexts,
            &edge_set,
            &artifact_index,
            &resource_set,
            &mut diagnostics,
        );
    }
    for (index, decision) in document.decisions.iter().enumerate() {
        validate_decision(
            context,
            &document,
            decision,
            index,
            &operation_indices,
            &merge_indices,
            &result_owners,
            &node_contexts,
            &edge_set,
            &mut diagnostics,
        );
    }
    for (index, merge) in document.merges.iter().enumerate() {
        validate_merge(
            context,
            &document,
            merge,
            index,
            &operation_indices,
            &decision_indices,
            &merge_indices,
            &result_owners,
            &node_contexts,
            &edge_set,
            &mut diagnostics,
        );
    }

    validate_resources(
        &document,
        &binding_plan,
        &adjacency,
        &dispatch_order,
        &node_contexts,
        &mut diagnostics,
    );

    if diagnostics.is_empty() {
        let executable =
            !binding_plan.has_unresolved_obligations() && document.obligations.is_empty();
        let required_runtime_artifacts = required_runtime_artifacts(&document, &binding_plan);
        Ok(CheckedEffectPlan {
            id,
            document,
            binding_plan,
            operation_indices,
            decision_indices,
            merge_indices,
            readiness_indices,
            dispatch_order,
            interfaces: context.shared_interfaces(),
            artifact_index,
            required_runtime_artifacts,
            executable,
        })
    } else {
        Err(ValidationErrors::new(diagnostics))
    }
}

fn validate_state_provenance(
    document: &EffectPlanDocument,
    binding_plan: &CheckedBindingPlan,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if document.current_revisions != binding_plan.environment().resources {
        push_diagnostic(
            diagnostics,
            planning_diagnostic(
                DiagnosticCode::BindingInterfaceMismatch,
                DiagnosticClass::InvalidContract,
                vec!["current_revisions".to_string()],
                "effect-plan current revisions do not exactly match the authenticated environment snapshot"
                    .to_string(),
            ),
        );
    }
    if document.desired_revisions != binding_plan.desired_state().resources {
        push_diagnostic(
            diagnostics,
            planning_diagnostic(
                DiagnosticCode::BindingInterfaceMismatch,
                DiagnosticClass::InvalidContract,
                vec!["desired_revisions".to_string()],
                "effect-plan desired revisions do not exactly match the committed desired state"
                    .to_string(),
            ),
        );
    }

    let mut expected_controllers: BTreeMap<_, _> = binding_plan
        .environment()
        .controllers
        .iter()
        .map(|assignment| (assignment.resource.clone(), assignment.clone()))
        .collect();
    expected_controllers.extend(
        binding_plan
            .desired_state()
            .controllers
            .iter()
            .map(|assignment| (assignment.resource.clone(), assignment.clone())),
    );
    let expected_controllers: Vec<_> = expected_controllers.into_values().collect();
    if document.controllers != expected_controllers {
        push_diagnostic(
            diagnostics,
            planning_diagnostic(
                DiagnosticCode::ConflictingController,
                DiagnosticClass::InvalidContract,
                vec!["controllers".to_string()],
                "effect-plan controllers do not exactly match the canonical current and desired controller union"
                    .to_string(),
            ),
        );
    }
}

fn required_runtime_artifacts(
    document: &EffectPlanDocument,
    binding_plan: &CheckedBindingPlan,
) -> Vec<ArtifactReference> {
    let mut artifacts = document.artifacts.clone();
    artifacts.extend(
        binding_plan
            .bindings()
            .iter()
            .map(|binding| binding.implementation.artifact.clone()),
    );
    artifacts.extend(
        binding_plan
            .environment()
            .providers
            .iter()
            .map(|provider| provider.implementation.artifact.clone()),
    );
    for package in binding_plan.packages() {
        artifacts.push(package.package.payload.clone());
        artifacts.push(package.package.source.clone());
        artifacts.extend(package.artifacts.iter().cloned());
        artifacts.extend(package.module_entry_points.values().cloned());
        artifacts.extend(
            package
                .implementation
                .providers
                .iter()
                .map(|provider| provider.artifact.clone()),
        );
        artifacts.extend(
            package
                .implementation
                .handlers
                .values()
                .map(|handler| handler.artifact.clone()),
        );
    }
    artifacts.sort_by(|left, right| {
        left.content
            .cmp(&right.content)
            .then_with(|| left.nar_hash.cmp(&right.nar_hash))
            .then_with(|| left.closure.cmp(&right.closure))
            .then_with(|| left.store_path.cmp(&right.store_path))
    });
    artifacts.dedup();
    artifacts
}

fn validate_canonical_order(document: &EffectPlanDocument, diagnostics: &mut Vec<Diagnostic>) {
    check_order_by(
        &document.operations,
        |left, right| compare_operation_keys(&left.key, &right.key),
        "operations",
        diagnostics,
    );
    check_order_by(
        &document.decisions,
        |left, right| compare_operation_keys(&left.key, &right.key),
        "decisions",
        diagnostics,
    );
    check_order_by(
        &document.merges,
        |left, right| compare_operation_keys(&left.key, &right.key),
        "merges",
        diagnostics,
    );
    check_order_by(&document.edges, compare_edges, "edges", diagnostics);
    check_order_by(
        &document.provider_readiness,
        |left, right| left.binding.cmp(&right.binding),
        "provider_readiness",
        diagnostics,
    );
    check_order_by(
        &document.current_revisions,
        |left, right| compare_resource_ids(&left.resource, &right.resource),
        "current_revisions",
        diagnostics,
    );
    check_order_by(
        &document.desired_revisions,
        |left, right| compare_resource_ids(&left.resource, &right.resource),
        "desired_revisions",
        diagnostics,
    );
    check_order_by(
        &document.controllers,
        |left, right| compare_resource_ids(&left.resource, &right.resource),
        "controllers",
        diagnostics,
    );
    check_order_by(
        &document.artifacts,
        |left, right| left.content.cmp(&right.content),
        "artifacts",
        diagnostics,
    );
    check_order_by(
        &document.obligations,
        |left, right| left.key.cmp(&right.key),
        "obligations",
        diagnostics,
    );
}

fn validate_plan_limits(document: &EffectPlanDocument, diagnostics: &mut Vec<Diagnostic>) {
    let node_count = document
        .operations
        .len()
        .saturating_add(document.decisions.len())
        .saturating_add(document.merges.len());
    if node_count > document.limits.max_graph_nodes as usize {
        push_diagnostic(
            diagnostics,
            planning_diagnostic(
                DiagnosticCode::LimitExceeded,
                DiagnosticClass::InvalidContract,
                vec!["operations".to_string()],
                "effect plan exceeds its graph-node limit".to_string(),
            ),
        );
    }
    if document.edges.len() > document.limits.max_graph_edges as usize {
        push_diagnostic(
            diagnostics,
            planning_diagnostic(
                DiagnosticCode::LimitExceeded,
                DiagnosticClass::InvalidContract,
                vec!["edges".to_string()],
                "effect plan exceeds its graph-edge limit".to_string(),
            ),
        );
    }
}

fn validate_decision(
    context: &ValidationContext,
    document: &EffectPlanDocument,
    decision: &DecisionNode,
    index: usize,
    operation_indices: &BTreeMap<ScopedOperationKey, usize>,
    merge_indices: &BTreeMap<ScopedOperationKey, usize>,
    result_owners: &ResultOwnerMap,
    node_contexts: &NodeContexts,
    edges: &BTreeSet<(PlanNodeKey, PlanNodeKey, DependencyKind)>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    check_order_by(
        &decision.alternatives,
        |left, right| left.key.cmp(&right.key),
        "alternatives",
        diagnostics,
    );
    let producer = producer_node(&decision.selector.result.producer);
    let consumer = PlanNodeKey::Decision {
        key: decision.key.clone(),
    };
    let Some(descriptor) = result_descriptor(
        context,
        document,
        &decision.selector.result.producer,
        &decision.selector.result.output,
        operation_indices,
        merge_indices,
    ) else {
        push_decision_diagnostic(
            decision,
            index,
            DiagnosticCode::MissingReference,
            "decision selector names an unknown result port".to_string(),
            diagnostics,
        );
        return;
    };
    if !edges.contains(&(producer, consumer, DependencyKind::Data)) {
        push_decision_diagnostic(
            decision,
            index,
            DiagnosticCode::MissingDataDependency,
            "decision selector lacks its exact typed data edge".to_string(),
            diagnostics,
        );
    }
    if node_contexts
        .get(&producer_node(&decision.selector.result.producer))
        .map(Vec::as_slice)
        .is_none_or(|producer| !context_is_prefix(producer, &decision.branch_context))
    {
        push_decision_diagnostic(
            decision,
            index,
            DiagnosticCode::MissingDataDependency,
            "decision selector escapes or crosses a conditional branch".to_string(),
            diagnostics,
        );
    }
    if descriptor.visibility == ValueVisibility::Private
        && result_owners
            .get(&(
                decision.selector.result.producer.clone(),
                decision.selector.result.output.clone(),
            ))
            .and_then(Clone::clone)
            .is_none()
    {
        push_decision_diagnostic(
            decision,
            index,
            DiagnosticCode::ResourceScopeEscape,
            "private decision selector has no single authenticated producing provider".to_string(),
            diagnostics,
        );
    }

    match (&decision.selector.tag_field, &descriptor.schema) {
        (None, ValueSchema::Boolean) => validate_boolean_alternatives(decision, index, diagnostics),
        (Some(tag_field), ValueSchema::TaggedUnion { tag, variants }) if tag_field == tag => {
            validate_tag_alternatives(decision, index, variants.keys(), diagnostics);
        }
        _ => push_decision_diagnostic(
            decision,
            index,
            DiagnosticCode::ValueTypeMismatch,
            "decision selector must be Boolean or name the exact tagged-union discriminator"
                .to_string(),
            diagnostics,
        ),
    }
}

fn validate_boolean_alternatives(
    decision: &DecisionNode,
    index: usize,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let predicates: BTreeSet<_> = decision
        .alternatives
        .iter()
        .filter_map(|alternative| match alternative.predicate {
            DecisionPredicate::Boolean { value } => Some(value),
            DecisionPredicate::Tag { .. } => None,
        })
        .collect();
    if decision.alternatives.len() != 2
        || predicates != BTreeSet::from([false, true])
        || decision
            .alternatives
            .iter()
            .any(|alternative| matches!(alternative.predicate, DecisionPredicate::Tag { .. }))
    {
        push_decision_diagnostic(
            decision,
            index,
            DiagnosticCode::ValueTypeMismatch,
            "Boolean decision alternatives must contain exactly false and true".to_string(),
            diagnostics,
        );
    }
}

fn validate_tag_alternatives<'a>(
    decision: &DecisionNode,
    index: usize,
    variants: impl Iterator<Item = &'a LocalKey>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let expected: BTreeSet<_> = variants.cloned().collect();
    let actual: BTreeSet<_> = decision
        .alternatives
        .iter()
        .filter_map(|alternative| match &alternative.predicate {
            DecisionPredicate::Tag { value } => Some(value.clone()),
            DecisionPredicate::Boolean { .. } => None,
        })
        .collect();
    if actual != expected
        || decision.alternatives.len() != expected.len()
        || decision
            .alternatives
            .iter()
            .any(|alternative| matches!(alternative.predicate, DecisionPredicate::Boolean { .. }))
    {
        push_decision_diagnostic(
            decision,
            index,
            DiagnosticCode::ValueTypeMismatch,
            "tagged decision alternatives must exactly cover every declared variant".to_string(),
            diagnostics,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_merge(
    context: &ValidationContext,
    document: &EffectPlanDocument,
    merge: &MergeNode,
    index: usize,
    operation_indices: &BTreeMap<ScopedOperationKey, usize>,
    decision_indices: &BTreeMap<ScopedOperationKey, usize>,
    merge_indices: &BTreeMap<ScopedOperationKey, usize>,
    result_owners: &ResultOwnerMap,
    node_contexts: &NodeContexts,
    edges: &BTreeSet<(PlanNodeKey, PlanNodeKey, DependencyKind)>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(decision_index) = decision_indices.get(&merge.decision) else {
        push_merge_diagnostic(
            merge,
            index,
            DiagnosticCode::MissingReference,
            "merge references an unknown decision".to_string(),
            diagnostics,
        );
        return;
    };
    let decision = &document.decisions[*decision_index];
    if merge.branch_context != decision.branch_context {
        push_merge_diagnostic(
            merge,
            index,
            DiagnosticCode::MissingDataDependency,
            "merge must return to the enclosing context of its decision".to_string(),
            diagnostics,
        );
    }
    let expected_alternatives: BTreeSet<_> = decision
        .alternatives
        .iter()
        .map(|alternative| alternative.key.clone())
        .collect();

    for (output_name, output) in &merge.outputs {
        let mut private_providers = BTreeSet::new();
        let actual_alternatives: BTreeSet<_> = output.alternatives.keys().cloned().collect();
        if actual_alternatives != expected_alternatives {
            push_merge_diagnostic(
                merge,
                index,
                DiagnosticCode::ValueTypeMismatch,
                format!(
                    "merge output '{}' must name one producer for every decision alternative",
                    output_name.as_str()
                ),
                diagnostics,
            );
        }
        for (alternative, reference) in &output.alternatives {
            let Some(descriptor) = result_descriptor(
                context,
                document,
                &reference.producer,
                &reference.output,
                operation_indices,
                merge_indices,
            ) else {
                push_merge_diagnostic(
                    merge,
                    index,
                    DiagnosticCode::MissingReference,
                    "merge output names an unknown producer port".to_string(),
                    diagnostics,
                );
                continue;
            };
            if descriptor != &output.descriptor {
                push_merge_diagnostic(
                    merge,
                    index,
                    DiagnosticCode::ValueTypeMismatch,
                    "all merge alternatives must have the exact common output descriptor"
                        .to_string(),
                    diagnostics,
                );
            }
            let membership = BranchMembership {
                decision: merge.decision.clone(),
                alternative: alternative.clone(),
            };
            let mut expected_context = decision.branch_context.clone();
            expected_context.push(membership);
            if node_contexts
                .get(&producer_node(&reference.producer))
                .map(Vec::as_slice)
                != Some(expected_context.as_slice())
            {
                push_merge_diagnostic(
                    merge,
                    index,
                    DiagnosticCode::MissingDataDependency,
                    "merge producer does not belong to its declared alternative".to_string(),
                    diagnostics,
                );
            }
            if output.descriptor.visibility == ValueVisibility::Private {
                if let Some(provider) = result_owners
                    .get(&(reference.producer.clone(), reference.output.clone()))
                    .and_then(Clone::clone)
                {
                    private_providers.insert(provider);
                }
            }
            let producer = producer_node(&reference.producer);
            let merge_node = PlanNodeKey::Merge {
                key: merge.key.clone(),
            };
            if !edges.contains(&(producer, merge_node, DependencyKind::BranchMerge)) {
                push_merge_diagnostic(
                    merge,
                    index,
                    DiagnosticCode::MissingDataDependency,
                    "merge alternative lacks an explicit branch-merge edge".to_string(),
                    diagnostics,
                );
            }
        }
        if output.descriptor.visibility == ValueVisibility::Private && private_providers.len() != 1
        {
            push_merge_diagnostic(
                merge,
                index,
                DiagnosticCode::ResourceScopeEscape,
                "private merge output does not retain one common producing provider".to_string(),
                diagnostics,
            );
        }
    }
}

fn all_nodes(document: &EffectPlanDocument) -> Vec<PlanNodeKey> {
    let mut nodes = Vec::with_capacity(
        document
            .operations
            .len()
            .saturating_add(document.decisions.len())
            .saturating_add(document.merges.len()),
    );
    nodes.extend(
        document
            .operations
            .iter()
            .map(|operation| PlanNodeKey::Operation {
                key: operation.key.clone(),
            }),
    );
    nodes.extend(
        document
            .decisions
            .iter()
            .map(|decision| PlanNodeKey::Decision {
                key: decision.key.clone(),
            }),
    );
    nodes.extend(document.merges.iter().map(|merge| PlanNodeKey::Merge {
        key: merge.key.clone(),
    }));
    nodes
}

fn context_is_prefix(prefix: &[BranchMembership], context: &[BranchMembership]) -> bool {
    context.starts_with(prefix)
}

fn push_branch_diagnostic(node: &PlanNodeKey, message: String, diagnostics: &mut Vec<Diagnostic>) {
    let mut item = planning_diagnostic(
        DiagnosticCode::MissingDataDependency,
        DiagnosticClass::InvalidContract,
        vec!["branch_context".to_string()],
        message,
    );
    item.operation = Some(node.key().clone());
    push_diagnostic(diagnostics, item);
}

fn push_operation_diagnostic(
    operation: &Operation,
    index: usize,
    code: DiagnosticCode,
    class: DiagnosticClass,
    message: String,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let mut item = planning_diagnostic(
        code,
        class,
        vec!["operations".to_string(), index.to_string()],
        message,
    );
    item.operation = Some(operation.key.clone());
    push_diagnostic(diagnostics, item);
}

fn push_operation_resource_diagnostic(
    operation: &Operation,
    index: usize,
    code: DiagnosticCode,
    message: String,
    resource: &ResourceId,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let mut item = planning_diagnostic(
        code,
        DiagnosticClass::ResourceConflict,
        vec!["operations".to_string(), index.to_string()],
        message,
    );
    item.operation = Some(operation.key.clone());
    item.resource = Some(resource.clone());
    push_diagnostic(diagnostics, item);
}

fn push_decision_diagnostic(
    decision: &DecisionNode,
    index: usize,
    code: DiagnosticCode,
    message: String,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let mut item = planning_diagnostic(
        code,
        DiagnosticClass::InvalidContract,
        vec!["decisions".to_string(), index.to_string()],
        message,
    );
    item.operation = Some(decision.key.clone());
    push_diagnostic(diagnostics, item);
}

fn push_merge_diagnostic(
    merge: &MergeNode,
    index: usize,
    code: DiagnosticCode,
    message: String,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let mut item = planning_diagnostic(
        code,
        DiagnosticClass::InvalidContract,
        vec!["merges".to_string(), index.to_string()],
        message,
    );
    item.operation = Some(merge.key.clone());
    push_diagnostic(diagnostics, item);
}

fn push_resource_diagnostic(
    code: DiagnosticCode,
    class: DiagnosticClass,
    resource: &ResourceId,
    message: String,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let mut item = planning_diagnostic(code, class, vec!["resources".to_string()], message);
    item.resource = Some(resource.clone());
    push_diagnostic(diagnostics, item);
}

fn planning_diagnostic(
    code: DiagnosticCode,
    class: DiagnosticClass,
    path: Vec<String>,
    message: String,
) -> Diagnostic {
    diagnostic(code, class, DiagnosticPhase::Planning, path, message)
}

fn check_order_by<T>(
    values: &[T],
    compare: impl Fn(&T, &T) -> Ordering,
    field: &str,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if !values
        .windows(2)
        .all(|pair| compare(&pair[0], &pair[1]) == Ordering::Less)
    {
        push_diagnostic(
            diagnostics,
            planning_diagnostic(
                DiagnosticCode::NonCanonicalOrder,
                DiagnosticClass::InvalidContract,
                vec![field.to_string()],
                "values must be strictly sorted without duplicate identities".to_string(),
            ),
        );
    }
}
