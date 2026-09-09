//! Effect-graph indexes, branch structure, readiness edges, and topological scheduling.

use super::*;

pub(super) type NodeIndices = (
    BTreeMap<ScopedOperationKey, usize>,
    BTreeMap<ScopedOperationKey, usize>,
    BTreeMap<ScopedOperationKey, usize>,
);

pub(super) type NodeContexts = BTreeMap<PlanNodeKey, Vec<BranchMembership>>;

pub(super) fn build_node_contexts(document: &EffectPlanDocument) -> NodeContexts {
    let mut contexts = BTreeMap::new();
    contexts.extend(document.operations.iter().map(|operation| {
        (
            PlanNodeKey::Operation {
                key: operation.key.clone(),
            },
            operation.branch_context.clone(),
        )
    }));
    contexts.extend(document.decisions.iter().map(|decision| {
        (
            PlanNodeKey::Decision {
                key: decision.key.clone(),
            },
            decision.branch_context.clone(),
        )
    }));
    contexts.extend(document.merges.iter().map(|merge| {
        (
            PlanNodeKey::Merge {
                key: merge.key.clone(),
            },
            merge.branch_context.clone(),
        )
    }));
    contexts
}

pub(super) fn build_indices(
    document: &EffectPlanDocument,
    diagnostics: &mut Vec<Diagnostic>,
) -> NodeIndices {
    let mut operations = BTreeMap::new();
    let mut decisions = BTreeMap::new();
    let mut merges = BTreeMap::new();
    for (index, operation) in document.operations.iter().enumerate() {
        if operations.insert(operation.key.clone(), index).is_some() {
            push_duplicate("operations", index, &operation.key, diagnostics);
        }
    }
    for (index, decision) in document.decisions.iter().enumerate() {
        if decisions.insert(decision.key.clone(), index).is_some() {
            push_duplicate("decisions", index, &decision.key, diagnostics);
        }
    }
    for (index, merge) in document.merges.iter().enumerate() {
        if merges.insert(merge.key.clone(), index).is_some() {
            push_duplicate("merges", index, &merge.key, diagnostics);
        }
    }
    (operations, decisions, merges)
}

fn push_duplicate(
    field: &str,
    index: usize,
    key: &ScopedOperationKey,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let mut item = planning_diagnostic(
        DiagnosticCode::DuplicateIdentity,
        DiagnosticClass::InvalidContract,
        vec![field.to_string(), index.to_string()],
        "duplicate scoped node identity within its node kind".to_string(),
    );
    item.operation = Some(key.clone());
    push_diagnostic(diagnostics, item);
}

pub(super) fn validate_edges(
    document: &EffectPlanDocument,
    operations: &BTreeMap<ScopedOperationKey, usize>,
    decisions: &BTreeMap<ScopedOperationKey, usize>,
    merges: &BTreeMap<ScopedOperationKey, usize>,
    node_contexts: &NodeContexts,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for (index, edge) in document.edges.iter().enumerate() {
        for (field, node) in [("from", &edge.from), ("to", &edge.to)] {
            if !node_exists(node, operations, decisions, merges) {
                push_diagnostic(
                    diagnostics,
                    planning_diagnostic(
                        DiagnosticCode::MissingReference,
                        DiagnosticClass::InvalidContract,
                        vec!["edges".to_string(), index.to_string(), field.to_string()],
                        "edge endpoint does not name a plan node".to_string(),
                    ),
                );
            }
        }

        if edge.kind == DependencyKind::BranchGuard
            && !matches!(edge.from, PlanNodeKey::Decision { .. })
        {
            push_diagnostic(
                diagnostics,
                planning_diagnostic(
                    DiagnosticCode::MethodContractMismatch,
                    DiagnosticClass::InvalidContract,
                    vec!["edges".to_string(), index.to_string()],
                    "branch-guard edge must originate at a decision".to_string(),
                ),
            );
        }
        if edge.kind == DependencyKind::BranchMerge && !matches!(edge.to, PlanNodeKey::Merge { .. })
        {
            push_diagnostic(
                diagnostics,
                planning_diagnostic(
                    DiagnosticCode::MethodContractMismatch,
                    DiagnosticClass::InvalidContract,
                    vec!["edges".to_string(), index.to_string()],
                    "branch-merge edge must terminate at a merge".to_string(),
                ),
            );
        }

        if !matches!(
            edge.kind,
            DependencyKind::BranchGuard | DependencyKind::BranchMerge
        ) {
            let from_context = node_contexts.get(&edge.from).map(Vec::as_slice);
            let to_context = node_contexts.get(&edge.to).map(Vec::as_slice);
            if let (Some(from), Some(to)) = (from_context, to_context) {
                if !context_is_prefix(from, to) {
                    push_diagnostic(
                        diagnostics,
                        planning_diagnostic(
                            DiagnosticCode::MissingDataDependency,
                            DiagnosticClass::InvalidContract,
                            vec!["edges".to_string(), index.to_string()],
                            "ordinary dependency escapes or crosses a conditional branch"
                                .to_string(),
                        ),
                    );
                }
            }
        }
    }
}

fn node_exists(
    node: &PlanNodeKey,
    operations: &BTreeMap<ScopedOperationKey, usize>,
    decisions: &BTreeMap<ScopedOperationKey, usize>,
    merges: &BTreeMap<ScopedOperationKey, usize>,
) -> bool {
    match node {
        PlanNodeKey::Operation { key } => operations.contains_key(key),
        PlanNodeKey::Decision { key } => decisions.contains_key(key),
        PlanNodeKey::Merge { key } => merges.contains_key(key),
    }
}

pub(super) fn validate_branch_contexts(
    document: &EffectPlanDocument,
    operations: &BTreeMap<ScopedOperationKey, usize>,
    decisions: &BTreeMap<ScopedOperationKey, usize>,
    merges: &BTreeMap<ScopedOperationKey, usize>,
    node_contexts: &NodeContexts,
    edges: &BTreeSet<(PlanNodeKey, PlanNodeKey, DependencyKind)>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let nodes = all_nodes(document);
    for node in nodes {
        let Some(context) = node_contexts.get(&node).map(Vec::as_slice) else {
            continue;
        };
        let mut seen = BTreeSet::new();
        for (depth, membership) in context.iter().enumerate() {
            if !seen.insert(membership.decision.clone()) {
                push_branch_diagnostic(
                    &node,
                    "branch context repeats a decision".to_string(),
                    diagnostics,
                );
                continue;
            }
            let Some(decision_index) = decisions.get(&membership.decision) else {
                push_branch_diagnostic(
                    &node,
                    "branch context names an unknown decision".to_string(),
                    diagnostics,
                );
                continue;
            };
            let decision = &document.decisions[*decision_index];
            if !decision
                .alternatives
                .iter()
                .any(|alternative| alternative.key == membership.alternative)
            {
                push_branch_diagnostic(
                    &node,
                    "branch context names an unknown decision alternative".to_string(),
                    diagnostics,
                );
            }
            if decision.branch_context != context[..depth] {
                push_branch_diagnostic(
                    &node,
                    "branch context does not follow the declared nesting order".to_string(),
                    diagnostics,
                );
            }
            let guard = (
                PlanNodeKey::Decision {
                    key: membership.decision.clone(),
                },
                node.clone(),
                DependencyKind::BranchGuard,
            );
            if !edges.contains(&guard) {
                push_branch_diagnostic(
                    &node,
                    "guarded node lacks an explicit branch-guard edge".to_string(),
                    diagnostics,
                );
            }
        }
    }

    // Keep parameters used in this comprehensive reference check explicit.
    let _ = (operations, merges);
}

pub(super) fn validate_exact_conditional_edges(
    document: &EffectPlanDocument,
    node_contexts: &NodeContexts,
    edges: &BTreeSet<(PlanNodeKey, PlanNodeKey, DependencyKind)>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let expected_guards: BTreeSet<_> = node_contexts
        .iter()
        .flat_map(|(node, context)| {
            context.iter().map(|membership| {
                (
                    PlanNodeKey::Decision {
                        key: membership.decision.clone(),
                    },
                    node.clone(),
                    DependencyKind::BranchGuard,
                )
            })
        })
        .collect();
    let expected_merges: BTreeSet<_> = document
        .merges
        .iter()
        .flat_map(|merge| {
            merge.outputs.values().flat_map(move |output| {
                output.alternatives.values().map(move |reference| {
                    (
                        producer_node(&reference.producer),
                        PlanNodeKey::Merge {
                            key: merge.key.clone(),
                        },
                        DependencyKind::BranchMerge,
                    )
                })
            })
        })
        .collect();
    let actual_guards: BTreeSet<_> = edges
        .iter()
        .filter(|(_, _, kind)| *kind == DependencyKind::BranchGuard)
        .cloned()
        .collect();
    let actual_merges: BTreeSet<_> = edges
        .iter()
        .filter(|(_, _, kind)| *kind == DependencyKind::BranchMerge)
        .cloned()
        .collect();

    if actual_guards != expected_guards {
        push_diagnostic(
            diagnostics,
            planning_diagnostic(
                DiagnosticCode::MissingDataDependency,
                DiagnosticClass::InvalidContract,
                vec!["edges".to_string()],
                "branch-guard edges must exactly match declared branch memberships".to_string(),
            ),
        );
    }
    if actual_merges != expected_merges {
        push_diagnostic(
            diagnostics,
            planning_diagnostic(
                DiagnosticCode::MissingDataDependency,
                DiagnosticClass::InvalidContract,
                vec!["edges".to_string()],
                "branch-merge edges must exactly match declared merge output producers".to_string(),
            ),
        );
    }
}

pub(super) fn validate_planned_provider_readiness(
    context: &ValidationContext,
    document: &EffectPlanDocument,
    binding_plan: &CheckedBindingPlan,
    operation_indices: &BTreeMap<ScopedOperationKey, usize>,
    node_contexts: &NodeContexts,
    edges: &BTreeSet<(PlanNodeKey, PlanNodeKey, DependencyKind)>,
    diagnostics: &mut Vec<Diagnostic>,
) -> BTreeMap<aos_ability_model::BindingId, usize> {
    let mut readiness_indices = BTreeMap::new();

    for (index, readiness) in document.provider_readiness.iter().enumerate() {
        if readiness_indices
            .insert(readiness.binding.clone(), index)
            .is_some()
        {
            push_diagnostic(
                diagnostics,
                planning_diagnostic(
                    DiagnosticCode::DuplicateIdentity,
                    DiagnosticClass::InvalidContract,
                    vec!["provider_readiness".to_string(), index.to_string()],
                    "duplicate readiness declaration for one planned binding".to_string(),
                ),
            );
        }

        let Some(binding) = binding_plan.binding(&readiness.binding) else {
            push_diagnostic(
                diagnostics,
                planning_diagnostic(
                    DiagnosticCode::MissingReference,
                    DiagnosticClass::InvalidContract,
                    vec!["provider_readiness".to_string(), index.to_string()],
                    "readiness declaration names an unknown binding".to_string(),
                ),
            );
            continue;
        };
        if binding_plan.provider_state(&readiness.binding) != Some(BindingProviderState::Planned) {
            push_diagnostic(
                diagnostics,
                planning_diagnostic(
                    DiagnosticCode::BindingInterfaceMismatch,
                    DiagnosticClass::InvalidContract,
                    vec!["provider_readiness".to_string(), index.to_string()],
                    "readiness declaration must name an exact planned provider binding".to_string(),
                ),
            );
        }

        let Some(producer_index) = operation_indices.get(&readiness.producer) else {
            push_diagnostic(
                diagnostics,
                planning_diagnostic(
                    DiagnosticCode::MissingReference,
                    DiagnosticClass::InvalidContract,
                    vec![
                        "provider_readiness".to_string(),
                        index.to_string(),
                        "producer".to_string(),
                    ],
                    "readiness declaration names an unknown producer operation".to_string(),
                ),
            );
            continue;
        };
        let producer = &document.operations[*producer_index];
        if !matches!(
            binding_plan.provider_state(&producer.binding),
            Some(BindingProviderState::Available | BindingProviderState::Planned)
        ) {
            push_operation_diagnostic(
                producer,
                *producer_index,
                DiagnosticCode::UnresolvedObligation,
                DiagnosticClass::UnavailableProvider,
                "readiness observation is not grounded in an available or planned terminal provider"
                    .to_string(),
                diagnostics,
            );
        }
        if producer.family != OperationFamily::ObserveReadiness {
            push_operation_diagnostic(
                producer,
                *producer_index,
                DiagnosticCode::MethodContractMismatch,
                DiagnosticClass::InvalidContract,
                "provider readiness must be produced by an observe-readiness operation".to_string(),
                diagnostics,
            );
        }
        let output = context
            .interface(&producer.interface)
            .and_then(|interface| interface.interface.methods.get(&producer.method))
            .and_then(|method| method.outputs.get(&readiness.output));
        if output.is_none_or(|output| {
            output.schema != ValueSchema::ProviderAssignment
                || output.phase != aos_ability_model::ValuePhase::Observation
                || output.visibility == ValueVisibility::Public
                || output.lifetime < binding.lifetime
        }) {
            push_operation_diagnostic(
                producer,
                *producer_index,
                DiagnosticCode::ValueTypeMismatch,
                DiagnosticClass::IncompatibleInterface,
                "readiness output must be a non-public observation-phase provider assignment with sufficient lifetime"
                    .to_string(),
                diagnostics,
            );
        }
    }

    let used_planned_bindings: BTreeSet<_> = document
        .operations
        .iter()
        .filter(|operation| {
            binding_plan.provider_state(&operation.binding) == Some(BindingProviderState::Planned)
        })
        .map(|operation| operation.binding.clone())
        .collect();
    let declared_bindings: BTreeSet<_> = document
        .provider_readiness
        .iter()
        .map(|readiness| readiness.binding.clone())
        .collect();
    if used_planned_bindings != declared_bindings {
        push_diagnostic(
            diagnostics,
            planning_diagnostic(
                DiagnosticCode::UnresolvedObligation,
                DiagnosticClass::UnavailableProvider,
                vec!["provider_readiness".to_string()],
                "readiness declarations must exactly cover planned bindings used by operations"
                    .to_string(),
            ),
        );
    }

    let mut expected_edges = BTreeSet::new();
    for (index, operation) in document.operations.iter().enumerate() {
        if binding_plan.provider_state(&operation.binding) != Some(BindingProviderState::Planned) {
            continue;
        }
        let Some(readiness_index) = readiness_indices.get(&operation.binding) else {
            continue;
        };
        let readiness = &document.provider_readiness[*readiness_index];
        let producer = PlanNodeKey::Operation {
            key: readiness.producer.clone(),
        };
        let consumer = PlanNodeKey::Operation {
            key: operation.key.clone(),
        };
        let readiness_edge = (
            producer.clone(),
            consumer.clone(),
            DependencyKind::Readiness,
        );
        expected_edges.insert(readiness_edge.clone());

        let source_context_applies = node_contexts
            .get(&producer)
            .zip(node_contexts.get(&consumer))
            .is_some_and(|(source, target)| context_is_prefix(source, target));
        if !edges.contains(&readiness_edge) || !source_context_applies {
            push_operation_diagnostic(
                operation,
                index,
                DiagnosticCode::UnresolvedObligation,
                DiagnosticClass::UnavailableProvider,
                "planned provider use lacks its exact declared assignment-readiness dependency"
                    .to_string(),
                diagnostics,
            );
        }
    }

    for (from, _, kind) in edges {
        if *kind != DependencyKind::Readiness {
            continue;
        }
        let source_is_observation = match from {
            PlanNodeKey::Operation { key } => operation_indices.get(key).is_some_and(|index| {
                document.operations[*index].family == OperationFamily::ObserveReadiness
            }),
            PlanNodeKey::Decision { .. } | PlanNodeKey::Merge { .. } => false,
        };
        if !source_is_observation {
            push_diagnostic(
                diagnostics,
                planning_diagnostic(
                    DiagnosticCode::MethodContractMismatch,
                    DiagnosticClass::InvalidContract,
                    vec!["edges".to_string()],
                    "ordinary readiness dependencies must originate at an observe-readiness operation with typed completion evidence"
                        .to_string(),
                ),
            );
        }
    }

    readiness_indices
}

pub(super) fn scheduling_adjacency(
    document: &EffectPlanDocument,
) -> BTreeMap<PlanNodeKey, BTreeSet<PlanNodeKey>> {
    let mut adjacency: BTreeMap<_, BTreeSet<_>> = all_nodes(document)
        .into_iter()
        .map(|node| (node, BTreeSet::new()))
        .collect();
    for edge in &document.edges {
        if edge.kind.is_scheduling() {
            adjacency
                .entry(edge.from.clone())
                .or_default()
                .insert(edge.to.clone());
        }
    }
    adjacency
}

pub(super) fn topological_order(
    document: &EffectPlanDocument,
    adjacency: &BTreeMap<PlanNodeKey, BTreeSet<PlanNodeKey>>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Vec<PlanNodeKey> {
    let mut indegree: BTreeMap<_, usize> = all_nodes(document)
        .into_iter()
        .map(|node| (node, 0))
        .collect();
    for destinations in adjacency.values() {
        for destination in destinations {
            if let Some(count) = indegree.get_mut(destination) {
                *count = count.saturating_add(1);
            }
        }
    }

    let mut ready: BTreeSet<_> = indegree
        .iter()
        .filter(|(_, count)| **count == 0)
        .map(|(node, _)| CanonicalNode(node.clone()))
        .collect();
    let mut order = Vec::with_capacity(indegree.len());
    while let Some(next) = ready.pop_first() {
        let node = next.0;
        order.push(node.clone());
        if let Some(destinations) = adjacency.get(&node) {
            for destination in destinations {
                if let Some(count) = indegree.get_mut(destination) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        ready.insert(CanonicalNode(destination.clone()));
                    }
                }
            }
        }
    }
    if order.len() != indegree.len() {
        push_diagnostic(
            diagnostics,
            planning_diagnostic(
                DiagnosticCode::SchedulingCycle,
                DiagnosticClass::InvalidContract,
                vec!["edges".to_string()],
                "scheduling dependencies contain a cycle".to_string(),
            ),
        );
    }
    order
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CanonicalNode(PlanNodeKey);

impl Ord for CanonicalNode {
    fn cmp(&self, other: &Self) -> Ordering {
        compare_plan_node_keys(&self.0, &other.0)
    }
}

impl PartialOrd for CanonicalNode {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
