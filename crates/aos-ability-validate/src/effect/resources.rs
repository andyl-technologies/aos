//! Resource coverage, conflict ordering, and bounded branch-aware reachability.

use super::schedule::NodeContexts;
use super::*;

pub(super) fn validate_resources(
    document: &EffectPlanDocument,
    binding_plan: &CheckedBindingPlan,
    adjacency: &BTreeMap<PlanNodeKey, BTreeSet<PlanNodeKey>>,
    dispatch_order: &[PlanNodeKey],
    node_contexts: &NodeContexts,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let current: BTreeMap<_, _> = document
        .current_revisions
        .iter()
        .map(|revision| (revision.resource.clone(), revision.revision))
        .collect();
    let desired: BTreeMap<_, _> = document
        .desired_revisions
        .iter()
        .map(|revision| (revision.resource.clone(), revision.revision))
        .collect();
    let revision_resources: BTreeSet<_> = current.keys().chain(desired.keys()).cloned().collect();
    let changed: BTreeSet<_> = revision_resources
        .into_iter()
        .filter(|resource| current.get(resource) != desired.get(resource))
        .collect();
    let controller_map: BTreeMap<_, _> = document
        .controllers
        .iter()
        .map(|assignment| (assignment.resource.clone(), assignment.controller.clone()))
        .collect();
    let plan_resources: BTreeSet<_> = binding_plan
        .document()
        .resources
        .iter()
        .map(|revision| revision.resource.clone())
        .collect();
    for resource in current.keys().chain(desired.keys()) {
        if !plan_resources.contains(resource) {
            push_resource_diagnostic(
                DiagnosticCode::ResourceScopeEscape,
                DiagnosticClass::Unauthorized,
                resource,
                "effect revision references a resource absent from the checked binding plan"
                    .to_string(),
                diagnostics,
            );
        }
    }
    for assignment in &document.controllers {
        if !plan_resources.contains(&assignment.resource)
            || assignment.controller.provider != assignment.resource.provider
        {
            push_resource_diagnostic(
                DiagnosticCode::ConflictingController,
                DiagnosticClass::ResourceConflict,
                &assignment.resource,
                "controller assignment is outside its provider-owned binding-plan resource"
                    .to_string(),
                diagnostics,
            );
        }
    }

    let mut accesses: BTreeMap<ResourceId, Vec<(usize, &Operation, AccessMode)>> = BTreeMap::new();
    for (operation_index, operation) in document.operations.iter().enumerate() {
        for access in &operation.accesses {
            accesses.entry(access.resource.clone()).or_default().push((
                operation_index,
                operation,
                access.mode,
            ));
        }
    }

    for (resource, users) in &accesses {
        if !plan_resources.contains(resource) {
            continue;
        }
        let controller = controller_map.get(resource);
        for (operation_index, operation, mode) in users {
            if mode.is_write() {
                if controller.is_none() {
                    push_operation_resource_diagnostic(
                        operation,
                        *operation_index,
                        DiagnosticCode::MissingController,
                        "mutating operation's resource has no lifecycle controller".to_string(),
                        resource,
                        diagnostics,
                    );
                } else if operation.controller.as_ref() != controller {
                    push_operation_resource_diagnostic(
                        operation,
                        *operation_index,
                        DiagnosticCode::ConflictingController,
                        "mutating operation does not use the resource's assigned controller"
                            .to_string(),
                        resource,
                        diagnostics,
                    );
                }
            }
        }
    }

    for resource in &changed {
        let controller = controller_map.get(resource);
        if controller.is_none() {
            push_resource_diagnostic(
                DiagnosticCode::MissingController,
                DiagnosticClass::ResourceConflict,
                resource,
                "changed resource has no lifecycle controller".to_string(),
                diagnostics,
            );
        } else if controller.is_some_and(|controller| controller.provider != resource.provider) {
            push_resource_diagnostic(
                DiagnosticCode::ConflictingController,
                DiagnosticClass::ResourceConflict,
                resource,
                "resource controller is owned by a different provider".to_string(),
                diagnostics,
            );
        }

        let writers: Vec<_> = accesses
            .get(resource)
            .into_iter()
            .flatten()
            .filter(|(_, _, mode)| mode.is_write())
            .collect();
        let covered_by_obligation = document
            .obligations
            .iter()
            .chain(&binding_plan.document().obligations)
            .any(|obligation| obligation.resource.as_ref() == Some(resource));
        if writers.is_empty() && !covered_by_obligation {
            push_resource_diagnostic(
                DiagnosticCode::UncoveredChange,
                DiagnosticClass::ResourceConflict,
                resource,
                "changed resource has neither a realizing write nor an explicit obligation"
                    .to_string(),
                diagnostics,
            );
        }
    }

    let positions: BTreeMap<_, _> = dispatch_order
        .iter()
        .enumerate()
        .map(|(index, node)| (node.clone(), index))
        .collect();
    let analysis_budget = u64::from(document.limits.max_graph_edges)
        .saturating_add(u64::from(document.limits.max_graph_nodes));
    let mut reachability = Reachability::new(adjacency, positions, node_contexts, analysis_budget);
    let mut remaining_pair_checks = analysis_budget;
    'resources: for (resource, users) in &accesses {
        if users.iter().all(|(_, _, mode)| !mode.is_write()) {
            continue;
        }
        for (left_index, (_, left, left_mode)) in users.iter().enumerate() {
            for (_, right, right_mode) in users.iter().skip(left_index + 1) {
                if remaining_pair_checks == 0 {
                    push_diagnostic(
                        diagnostics,
                        planning_diagnostic(
                            DiagnosticCode::LimitExceeded,
                            DiagnosticClass::InvalidContract,
                            vec!["operations".to_string(), "accesses".to_string()],
                            "resource-conflict analysis exceeds the bounded pair-check budget"
                                .to_string(),
                        ),
                    );
                    break 'resources;
                }
                remaining_pair_checks -= 1;
                if !accesses_conflict(*left_mode, *right_mode)
                    || mutually_exclusive(&left.branch_context, &right.branch_context)
                {
                    continue;
                }
                let left_node = PlanNodeKey::Operation {
                    key: left.key.clone(),
                };
                let right_node = PlanNodeKey::Operation {
                    key: right.key.clone(),
                };
                match reachability.ordered(&left_node, &right_node) {
                    Some(true) => {}
                    Some(false) => push_resource_diagnostic(
                        DiagnosticCode::ConflictingController,
                        DiagnosticClass::ResourceConflict,
                        resource,
                        "co-executable conflicting accesses lack a scheduling order".to_string(),
                        diagnostics,
                    ),
                    None => {
                        push_diagnostic(
                            diagnostics,
                            planning_diagnostic(
                                DiagnosticCode::LimitExceeded,
                                DiagnosticClass::InvalidContract,
                                vec!["operations".to_string(), "accesses".to_string()],
                                "resource-order analysis exceeds the bounded graph-visit budget"
                                    .to_string(),
                            ),
                        );
                        break 'resources;
                    }
                }
            }
        }
    }
}

fn accesses_conflict(left: AccessMode, right: AccessMode) -> bool {
    (left.is_write() && right.is_write())
        || left == AccessMode::ExclusiveWrite
        || right == AccessMode::ExclusiveWrite
}

fn mutually_exclusive(left: &[BranchMembership], right: &[BranchMembership]) -> bool {
    left.iter().any(|left_membership| {
        right.iter().any(|right_membership| {
            left_membership.decision == right_membership.decision
                && left_membership.alternative != right_membership.alternative
        })
    })
}

struct Reachability<'a> {
    adjacency: &'a BTreeMap<PlanNodeKey, BTreeSet<PlanNodeKey>>,
    positions: BTreeMap<PlanNodeKey, usize>,
    node_contexts: &'a NodeContexts,
    cache: BTreeMap<(PlanNodeKey, PlanNodeKey), bool>,
    remaining_visits: u64,
}

impl<'a> Reachability<'a> {
    fn new(
        adjacency: &'a BTreeMap<PlanNodeKey, BTreeSet<PlanNodeKey>>,
        positions: BTreeMap<PlanNodeKey, usize>,
        node_contexts: &'a NodeContexts,
        remaining_visits: u64,
    ) -> Self {
        Self {
            adjacency,
            positions,
            node_contexts,
            cache: BTreeMap::new(),
            remaining_visits,
        }
    }

    fn ordered(&mut self, left: &PlanNodeKey, right: &PlanNodeKey) -> Option<bool> {
        let left_position = self.positions.get(left)?;
        let right_position = self.positions.get(right)?;
        let active_branches = combined_branch_selection(
            self.node_contexts.get(left)?,
            self.node_contexts.get(right)?,
        )?;
        if left_position < right_position {
            self.reachable(left, right, &active_branches)
        } else {
            self.reachable(right, left, &active_branches)
        }
    }

    fn reachable(
        &mut self,
        from: &PlanNodeKey,
        to: &PlanNodeKey,
        active_branches: &BTreeMap<ScopedOperationKey, LocalKey>,
    ) -> Option<bool> {
        let key = (from.clone(), to.clone());
        if let Some(cached) = self.cache.get(&key) {
            return Some(*cached);
        }

        let mut seen = BTreeSet::new();
        let mut stack = vec![from.clone()];
        while let Some(node) = stack.pop() {
            if &node == to {
                self.cache.insert(key, true);
                return Some(true);
            }
            if !seen.insert(node.clone()) {
                continue;
            }
            if let Some(next) = self.adjacency.get(&node) {
                for candidate in next {
                    if self.remaining_visits == 0 {
                        return None;
                    }
                    self.remaining_visits -= 1;

                    let context_applies =
                        self.node_contexts.get(candidate).is_some_and(|context| {
                            context.iter().all(|membership| {
                                active_branches.get(&membership.decision)
                                    == Some(&membership.alternative)
                            })
                        });
                    if context_applies {
                        stack.push(candidate.clone());
                    }
                }
            }
        }
        self.cache.insert(key, false);
        Some(false)
    }
}

fn combined_branch_selection(
    left: &[BranchMembership],
    right: &[BranchMembership],
) -> Option<BTreeMap<ScopedOperationKey, LocalKey>> {
    let mut selected = BTreeMap::new();
    for membership in left.iter().chain(right) {
        if selected
            .insert(membership.decision.clone(), membership.alternative.clone())
            .is_some_and(|previous| previous != membership.alternative)
        {
            return None;
        }
    }
    Some(selected)
}
