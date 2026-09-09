//! Operation contracts, typed results, and nested invocation authority.

use super::value_authority::validate_nested_authority;
use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) fn validate_operation(
    context: &ValidationContext,
    document: &EffectPlanDocument,
    binding_plan: &CheckedBindingPlan,
    operation: &Operation,
    index: usize,
    operation_indices: &BTreeMap<ScopedOperationKey, usize>,
    merge_indices: &BTreeMap<ScopedOperationKey, usize>,
    result_owners: &ResultOwnerMap,
    node_contexts: &NodeContexts,
    edges: &BTreeSet<(PlanNodeKey, PlanNodeKey, DependencyKind)>,
    artifacts: &ArtifactIndex,
    resources: &BTreeSet<ResourceId>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(binding) = binding_plan.binding(&operation.binding) else {
        push_operation_diagnostic(
            operation,
            index,
            DiagnosticCode::MissingReference,
            DiagnosticClass::Unauthorized,
            "operation references an unknown binding".to_string(),
            diagnostics,
        );
        return;
    };
    if !matches!(
        binding_plan.provider_state(&operation.binding),
        Some(BindingProviderState::Available | BindingProviderState::Planned)
    ) || binding.implementation.handler.is_none()
    {
        push_operation_diagnostic(
            operation,
            index,
            DiagnosticCode::UnresolvedObligation,
            DiagnosticClass::UnavailableProvider,
            "final effect operation requires an available or planned terminal binding with an exact native handler"
                .to_string(),
            diagnostics,
        );
    }
    if artifacts.get(&binding.implementation.artifact.content)
        != Some(&binding.implementation.artifact)
    {
        push_operation_diagnostic(
            operation,
            index,
            DiagnosticCode::MissingReference,
            DiagnosticClass::Unauthorized,
            "selected implementation artifact is absent from the effect plan's retained roots"
                .to_string(),
            diagnostics,
        );
    }
    if operation.interface != binding.interface {
        push_operation_diagnostic(
            operation,
            index,
            DiagnosticCode::BindingInterfaceMismatch,
            DiagnosticClass::IncompatibleInterface,
            "operation interface differs from its exact binding descriptor".to_string(),
            diagnostics,
        );
        return;
    }
    let Some(interface) = context.interface(&operation.interface) else {
        push_operation_diagnostic(
            operation,
            index,
            DiagnosticCode::MissingReference,
            DiagnosticClass::IncompatibleInterface,
            "operation interface is absent from the validated catalog".to_string(),
            diagnostics,
        );
        return;
    };
    let Some(method) = interface.interface.methods.get(&operation.method) else {
        push_operation_diagnostic(
            operation,
            index,
            DiagnosticCode::MethodContractMismatch,
            DiagnosticClass::IncompatibleInterface,
            "operation calls a method absent from its exact descriptor".to_string(),
            diagnostics,
        );
        return;
    };

    if operation.family != method.operation_family
        || operation.target.interface != operation.interface
        || method.target_resource != operation.interface.name
    {
        push_operation_diagnostic(
            operation,
            index,
            DiagnosticCode::MethodContractMismatch,
            DiagnosticClass::IncompatibleInterface,
            "operation family or exact target interface disagrees with the method descriptor"
                .to_string(),
            diagnostics,
        );
    }
    if operation.target.resource.provider != binding.provider
        || !resources.contains(&operation.target.resource)
    {
        push_operation_resource_diagnostic(
            operation,
            index,
            DiagnosticCode::ResourceScopeEscape,
            "operation target is outside the selected provider's plan resources".to_string(),
            &operation.target.resource,
            diagnostics,
        );
    }
    if operation.target.lifetime > binding.lifetime {
        push_operation_resource_diagnostic(
            operation,
            index,
            DiagnosticCode::ResourceScopeEscape,
            "operation target lifetime exceeds its binding lifetime".to_string(),
            &operation.target.resource,
            diagnostics,
        );
    }
    check_strict_order(
        &operation.target.operations,
        &SchemaPath::root()
            .child("operations")
            .child(index.to_string())
            .child("target")
            .child("operations"),
        diagnostics,
    );
    check_order_by(
        &operation.preconditions,
        |left, right| compare_resource_ids(&left.resource, &right.resource),
        "operations.preconditions",
        diagnostics,
    );
    check_order_by(
        &operation.accesses,
        |left, right| compare_resource_ids(&left.resource, &right.resource),
        "operations.accesses",
        diagnostics,
    );
    let required_target_access = required_target_access(&operation.family);
    if !operation.accesses.iter().any(|access| {
        access.resource == operation.target.resource && access.mode.permits(required_target_access)
    }) {
        push_operation_resource_diagnostic(
            operation,
            index,
            DiagnosticCode::ResourceScopeEscape,
            "operation omits the target resource access required by its method family".to_string(),
            &operation.target.resource,
            diagnostics,
        );
    }
    for requested in &operation.target.operations {
        if !method.permitted_operations.contains(requested) {
            push_operation_resource_diagnostic(
                operation,
                index,
                DiagnosticCode::MethodContractMismatch,
                "target operation projection exceeds the method contract".to_string(),
                &operation.target.resource,
                diagnostics,
            );
        }
    }

    let grant = grant_for_operation(binding, operation, index, diagnostics);
    if let Some(grant) = grant {
        validate_operation_authority(operation, index, grant, diagnostics);
    }

    let consumer = PlanNodeKey::Operation {
        key: operation.key.clone(),
    };
    let result_validator = |expected: &ValueSchema,
                            reference: &OperationResultReference,
                            path: &SchemaPath,
                            found: &mut Vec<Diagnostic>| {
        validate_result_reference(
            context,
            document,
            binding_plan,
            operation,
            expected,
            reference,
            path,
            &consumer,
            operation_indices,
            merge_indices,
            result_owners,
            node_contexts,
            edges,
            found,
        );
    };
    validate_expression(
        &method.parameters,
        &operation.inputs,
        &SchemaPath::root()
            .child("operations")
            .child(index.to_string())
            .child("inputs"),
        diagnostics,
        Some(&result_validator),
        None,
    );
    validate_nested_authority(
        context,
        &method.parameters,
        &operation.inputs,
        operation,
        index,
        binding,
        grant,
        artifacts,
        resources,
        diagnostics,
    );

    for (purpose, method) in [
        ("reconcile", operation.recovery.reconcile.as_ref()),
        ("cancel", operation.recovery.cancel.as_ref()),
        ("compensate", operation.recovery.compensate.as_ref()),
    ] {
        let Some(method) = method else {
            continue;
        };
        if let Err(error) = authorize_invocation(context.interfaces(), binding, operation, method) {
            push_operation_diagnostic(
                operation,
                index,
                DiagnosticCode::MethodContractMismatch,
                DiagnosticClass::Unauthorized,
                format!("{purpose} method is not authorized: {error}"),
                diagnostics,
            );
        }
    }
    validate_recovery_contract(operation, interface, method, index, diagnostics);

    for access in &operation.accesses {
        if !resources.contains(&access.resource) {
            push_operation_resource_diagnostic(
                operation,
                index,
                DiagnosticCode::ResourceScopeEscape,
                "operation access references an unknown binding-plan resource".to_string(),
                &access.resource,
                diagnostics,
            );
        }
        if grant.is_none_or(|grant| !grant_permits(grant, &access.resource, access.mode, None)) {
            push_operation_resource_diagnostic(
                operation,
                index,
                DiagnosticCode::ResourceScopeEscape,
                "operation access exceeds its selected authority grant".to_string(),
                &access.resource,
                diagnostics,
            );
        }
    }
    for precondition in &operation.preconditions {
        if !operation
            .accesses
            .iter()
            .any(|access| access.resource == precondition.resource)
        {
            push_operation_resource_diagnostic(
                operation,
                index,
                DiagnosticCode::MissingReference,
                "precondition resource is absent from declared operation accesses".to_string(),
                &precondition.resource,
                diagnostics,
            );
        }
    }
}

fn validate_recovery_contract(
    operation: &Operation,
    interface: &aos_ability_model::InterfaceDocument,
    method: &aos_ability_model::MethodDescriptor,
    index: usize,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if operation.deadline.total_recovery_millis < operation.deadline.attempt_timeout_millis {
        push_operation_diagnostic(
            operation,
            index,
            DiagnosticCode::LimitExceeded,
            DiagnosticClass::InvalidContract,
            "total recovery deadline is shorter than one attempt deadline".to_string(),
            diagnostics,
        );
    }
    let retry_enabled = matches!(operation.recovery.retry, RetryPolicy::Bounded { .. });
    if retry_enabled && operation.recovery.reconcile.is_none() {
        push_operation_diagnostic(
            operation,
            index,
            DiagnosticCode::MethodContractMismatch,
            DiagnosticClass::InvalidContract,
            "bounded retry requires an explicit reconciliation method".to_string(),
            diagnostics,
        );
    }
    if method.outcome.indeterminate == aos_ability_model::IndeterminateSemantics::Reconcile
        && operation.recovery.reconcile.is_none()
    {
        push_operation_diagnostic(
            operation,
            index,
            DiagnosticCode::MethodContractMismatch,
            DiagnosticClass::InvalidContract,
            "reconcilable method outcome requires an explicit reconciliation method".to_string(),
            diagnostics,
        );
    }
    if method.outcome.indeterminate
        == aos_ability_model::IndeterminateSemantics::InterventionRequired
        && operation.recovery.reconcile.is_some()
    {
        push_operation_diagnostic(
            operation,
            index,
            DiagnosticCode::MethodContractMismatch,
            DiagnosticClass::InvalidContract,
            "intervention-required outcome semantics prohibit automatic reconciliation".to_string(),
            diagnostics,
        );
    }
    for recovery in [
        operation.recovery.reconcile.as_ref(),
        operation.recovery.cancel.as_ref(),
        operation.recovery.compensate.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        let recovery_descriptor = interface.interface.methods.get(&recovery.method);
        if recovery.interface != operation.interface || recovery_descriptor.is_none() {
            push_operation_diagnostic(
                operation,
                index,
                DiagnosticCode::MethodContractMismatch,
                DiagnosticClass::IncompatibleInterface,
                "recovery method must belong to the operation's exact interface".to_string(),
                diagnostics,
            );
            continue;
        }
        if recovery_descriptor.is_some_and(|recovery| {
            recovery.parameters != method.parameters
                || recovery.outputs != method.outputs
                || recovery.outcome.completion_evidence != method.outcome.completion_evidence
                || recovery.outcome.observation_evidence != method.outcome.observation_evidence
        }) {
            push_operation_diagnostic(
                operation,
                index,
                DiagnosticCode::MethodContractMismatch,
                DiagnosticClass::IncompatibleInterface,
                "recovery method must accept the retained primary request and return the same checked output and evidence schemas"
                    .to_string(),
                diagnostics,
            );
        }
    }
}

fn grant_for_operation<'a>(
    binding: &'a Binding,
    operation: &Operation,
    index: usize,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<&'a AuthorityGrant> {
    let grant = match operation.authority {
        AuthorityRole::Caller => &binding.caller_grant,
        AuthorityRole::Provider => {
            if !binding.mediation_allowed {
                push_operation_diagnostic(
                    operation,
                    index,
                    DiagnosticCode::MediationNotGranted,
                    DiagnosticClass::Unauthorized,
                    "provider authority requires explicit mediation permission".to_string(),
                    diagnostics,
                );
                return None;
            }
            &binding.provider_grant
        }
    };
    if !grant.methods.contains(&operation.method) {
        push_operation_diagnostic(
            operation,
            index,
            DiagnosticCode::MethodNotGranted,
            DiagnosticClass::Unauthorized,
            "selected authority grant does not permit the called method".to_string(),
            diagnostics,
        );
    }
    Some(grant)
}

fn validate_operation_authority(
    operation: &Operation,
    index: usize,
    grant: &AuthorityGrant,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if !grant_permits(grant, &operation.target.resource, AccessMode::Read, None) {
        push_operation_resource_diagnostic(
            operation,
            index,
            DiagnosticCode::ResourceScopeEscape,
            "operation target is absent from its selected authority grant".to_string(),
            &operation.target.resource,
            diagnostics,
        );
    }
    for projected in &operation.target.operations {
        if !grant_permits(
            grant,
            &operation.target.resource,
            AccessMode::Read,
            Some(projected),
        ) {
            push_operation_resource_diagnostic(
                operation,
                index,
                DiagnosticCode::ResourceScopeEscape,
                "target operation projection exceeds its selected authority grant".to_string(),
                &operation.target.resource,
                diagnostics,
            );
        }
    }
}

pub(super) fn grant_permits(
    grant: &AuthorityGrant,
    resource: &ResourceId,
    mode: AccessMode,
    operation: Option<&LocalKey>,
) -> bool {
    grant.resources.iter().any(|permission| {
        permission.resource == *resource
            && permission.access.permits(mode)
            && operation.is_none_or(|operation| permission.operations.contains(operation))
    })
}

fn validate_result_reference(
    context: &ValidationContext,
    document: &EffectPlanDocument,
    binding_plan: &CheckedBindingPlan,
    consumer_operation: &Operation,
    expected: &ValueSchema,
    reference: &OperationResultReference,
    path: &SchemaPath,
    consumer: &PlanNodeKey,
    operation_indices: &BTreeMap<ScopedOperationKey, usize>,
    merge_indices: &BTreeMap<ScopedOperationKey, usize>,
    result_owners: &ResultOwnerMap,
    node_contexts: &NodeContexts,
    edges: &BTreeSet<(PlanNodeKey, PlanNodeKey, DependencyKind)>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let producer = producer_node(&reference.producer);
    let Some(descriptor) = result_descriptor(
        context,
        document,
        &reference.producer,
        &reference.output,
        operation_indices,
        merge_indices,
    ) else {
        let mut item = planning_diagnostic(
            DiagnosticCode::MissingReference,
            DiagnosticClass::InvalidContract,
            path.components().to_vec(),
            "result reference names an unknown producer port".to_string(),
        );
        item.operation = Some(consumer_operation.key.clone());
        push_diagnostic(diagnostics, item);
        return;
    };

    if descriptor.schema != *expected {
        let mut item = planning_diagnostic(
            DiagnosticCode::ValueTypeMismatch,
            DiagnosticClass::IncompatibleInterface,
            path.components().to_vec(),
            "result port schema differs from the exact consuming schema".to_string(),
        );
        item.operation = Some(consumer_operation.key.clone());
        push_diagnostic(diagnostics, item);
    }
    if descriptor.phase > consumer_operation.input_phase {
        let mut item = planning_diagnostic(
            DiagnosticCode::ResultPhaseMismatch,
            DiagnosticClass::InvalidContract,
            path.components().to_vec(),
            "result is unavailable at the consumer's declared input phase".to_string(),
        );
        item.operation = Some(consumer_operation.key.clone());
        push_diagnostic(diagnostics, item);
    }
    if descriptor.visibility == ValueVisibility::Private
        && result_owners
            .get(&(reference.producer.clone(), reference.output.clone()))
            .and_then(Clone::clone)
            .zip(binding_plan.binding(&consumer_operation.binding))
            .is_none_or(|(producer, consumer)| producer != consumer.provider)
    {
        let mut item = planning_diagnostic(
            DiagnosticCode::ResourceScopeEscape,
            DiagnosticClass::Unauthorized,
            path.components().to_vec(),
            "private result escapes its producing provider".to_string(),
        );
        item.operation = Some(consumer_operation.key.clone());
        push_diagnostic(diagnostics, item);
    }

    if !edges.contains(&(producer.clone(), consumer.clone(), DependencyKind::Data)) {
        let mut item = planning_diagnostic(
            DiagnosticCode::MissingDataDependency,
            DiagnosticClass::InvalidContract,
            path.components().to_vec(),
            "result reference lacks its exact typed data edge".to_string(),
        );
        item.operation = Some(consumer_operation.key.clone());
        push_diagnostic(diagnostics, item);
    }
    if let (Some(from), Some(to)) = (
        node_contexts
            .get(&producer_node(&reference.producer))
            .map(Vec::as_slice),
        node_contexts.get(consumer).map(Vec::as_slice),
    ) {
        if !context_is_prefix(from, to) {
            let mut item = planning_diagnostic(
                DiagnosticCode::MissingDataDependency,
                DiagnosticClass::InvalidContract,
                path.components().to_vec(),
                "result reference escapes or crosses a conditional branch".to_string(),
            );
            item.operation = Some(consumer_operation.key.clone());
            push_diagnostic(diagnostics, item);
        }
    }
}

pub(super) fn result_descriptor<'a>(
    context: &'a ValidationContext,
    document: &'a EffectPlanDocument,
    producer: &ResultProducerKey,
    output: &LocalKey,
    operation_indices: &BTreeMap<ScopedOperationKey, usize>,
    merge_indices: &BTreeMap<ScopedOperationKey, usize>,
) -> Option<&'a OutputDescriptor> {
    match producer {
        ResultProducerKey::Operation { key } => {
            let operation = &document.operations[*operation_indices.get(key)?];
            let interface = context.interface(&operation.interface)?;
            interface
                .interface
                .methods
                .get(&operation.method)?
                .outputs
                .get(output)
        }
        ResultProducerKey::Merge { key } => document.merges[*merge_indices.get(key)?]
            .outputs
            .get(output)
            .map(|merged| &merged.descriptor),
    }
}

pub(super) type ResultOwnerMap =
    BTreeMap<(ResultProducerKey, LocalKey), Option<aos_ability_model::InstanceId>>;

pub(super) fn build_result_owners(
    context: &ValidationContext,
    document: &EffectPlanDocument,
    binding_plan: &CheckedBindingPlan,
    dispatch_order: &[PlanNodeKey],
    operation_indices: &BTreeMap<ScopedOperationKey, usize>,
    merge_indices: &BTreeMap<ScopedOperationKey, usize>,
) -> ResultOwnerMap {
    let mut owners = BTreeMap::new();
    for node in dispatch_order {
        match node {
            PlanNodeKey::Operation { key } => {
                let Some(operation) = operation_indices
                    .get(key)
                    .map(|index| &document.operations[*index])
                else {
                    continue;
                };
                let Some(provider) = binding_plan
                    .binding(&operation.binding)
                    .map(|binding| binding.provider.clone())
                else {
                    continue;
                };
                let Some(method) = context
                    .interface(&operation.interface)
                    .and_then(|interface| interface.interface.methods.get(&operation.method))
                else {
                    continue;
                };
                for output in method.outputs.keys() {
                    owners.insert(
                        (
                            ResultProducerKey::Operation { key: key.clone() },
                            output.clone(),
                        ),
                        Some(provider.clone()),
                    );
                }
            }
            PlanNodeKey::Merge { key } => {
                let Some(merge) = merge_indices.get(key).map(|index| &document.merges[*index])
                else {
                    continue;
                };
                for (output_name, output) in &merge.outputs {
                    let mut providers = output.alternatives.values().map(|reference| {
                        owners
                            .get(&(reference.producer.clone(), reference.output.clone()))
                            .and_then(Clone::clone)
                    });
                    let owner = providers.next().flatten().filter(|provider| {
                        providers.all(|candidate| candidate.as_ref() == Some(provider))
                    });
                    owners.insert(
                        (
                            ResultProducerKey::Merge { key: key.clone() },
                            output_name.clone(),
                        ),
                        owner,
                    );
                }
            }
            PlanNodeKey::Decision { .. } => {}
        }
    }
    owners
}

pub(super) fn producer_node(producer: &ResultProducerKey) -> PlanNodeKey {
    match producer {
        ResultProducerKey::Operation { key } => PlanNodeKey::Operation { key: key.clone() },
        ResultProducerKey::Merge { key } => PlanNodeKey::Merge { key: key.clone() },
    }
}
