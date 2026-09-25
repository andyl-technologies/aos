//! Request, provider-evidence, grant, and aggregate input validation.

use super::*;

pub(super) fn validate_request(
    request: &aos_ability_model::BindingRequest,
    index: usize,
    context: &ValidationContext,
    in_scope_instances: &BTreeSet<InstanceId>,
    request_authorities: &BTreeMap<InstanceId, aos_ability_model::DeclarationAuthority>,
    provider_authors: &BTreeMap<InstanceId, BTreeSet<LocalKey>>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    check_strict_order(
        &request.methods,
        &SchemaPath::root()
            .child("requests")
            .child(index.to_string())
            .child("methods"),
        diagnostics,
    );
    check_strict_order(
        &request.guarantees,
        &SchemaPath::root()
            .child("requests")
            .child(index.to_string())
            .child("guarantees"),
        diagnostics,
    );
    if request.accepted_interfaces.is_empty() {
        let mut item = diagnostic(
            DiagnosticCode::BindingInterfaceMismatch,
            DiagnosticClass::IncompatibleInterface,
            DiagnosticPhase::Binding,
            vec![
                "requests".to_string(),
                index.to_string(),
                "accepted_interfaces".to_string(),
            ],
            "request must name at least one exact accepted interface".to_string(),
        );
        item.request = Some(request.id.clone());
        push_diagnostic(diagnostics, item);
    }
    if !in_scope_instances.contains(&request.id.consumer) {
        let mut item = diagnostic(
            DiagnosticCode::BindingPrincipalMismatch,
            DiagnosticClass::Unauthorized,
            DiagnosticPhase::Binding,
            vec!["requests".to_string(), index.to_string(), "id".to_string()],
            "request consumer is outside the supplied environment and desired state".to_string(),
        );
        item.request = Some(request.id.clone());
        push_diagnostic(diagnostics, item);
    }
    let authenticated_provider_child = !request.id.scope.as_slice().is_empty()
        && request.authority.package().is_some_and(|package| {
            provider_authors
                .get(&request.id.consumer)
                .is_some_and(|authors| authors.contains(package))
        });
    match request_authorities.get(&request.id.consumer) {
        Some(authority) if authority == &request.authority => {}
        Some(_) if authenticated_provider_child => {}
        Some(authority) => {
            let mut item = diagnostic(
                DiagnosticCode::BindingPrincipalMismatch,
                DiagnosticClass::Unauthorized,
                DiagnosticPhase::Binding,
                vec![
                    "requests".to_string(),
                    index.to_string(),
                    "authority".to_string(),
                ],
                format!(
                    "request authority '{:?}' differs from consumer authority '{authority:?}'",
                    request.authority
                ),
            );
            item.request = Some(request.id.clone());
            push_diagnostic(diagnostics, item);
        }
        // Environment-only consumers have no desired declaration record to compare.
        // Their provenance was already injected by the authenticated environment.
        None => {}
    }
    for accepted in &request.accepted_interfaces {
        let Some(interface) = context.interface(accepted) else {
            let mut item = diagnostic(
                DiagnosticCode::MissingReference,
                DiagnosticClass::IncompatibleInterface,
                DiagnosticPhase::Binding,
                vec![
                    "requests".to_string(),
                    index.to_string(),
                    "accepted_interfaces".to_string(),
                ],
                "request names an interface absent from the validated catalog".to_string(),
            );
            item.request = Some(request.id.clone());
            push_diagnostic(diagnostics, item);
            continue;
        };

        let expression = ValueExpression::Literal {
            value: request.parameters.clone(),
        };
        if let Err(errors) = validate_value(&interface.interface.request, &expression) {
            for mut item in errors.into_diagnostics() {
                let mut prefixed = SchemaPath::root()
                    .child("requests")
                    .child(index.to_string())
                    .child("parameters")
                    .components()
                    .to_vec();
                prefixed.extend(item.path);
                item.path = prefixed;
                item.phase = DiagnosticPhase::Binding;
                item.request = Some(request.id.clone());
                push_diagnostic(diagnostics, item);
            }
        }
    }
}

pub(super) fn validate_binding(
    context: &ValidationContext,
    plan: &BindingPlanDocument,
    inputs: &BindingValidationInputs,
    input_index: &BindingInputIndex,
    binding: &Binding,
    request: &aos_ability_model::BindingRequest,
    resources: &BTreeSet<aos_ability_model::ResourceId>,
    index: usize,
    diagnostics: &mut Vec<Diagnostic>,
) -> BindingProviderState {
    let interface = context.interface(&binding.interface);
    if !request.accepted_interfaces.contains(&binding.interface) {
        push_diagnostic(
            diagnostics,
            binding_diagnostic(
                DiagnosticCode::BindingInterfaceMismatch,
                DiagnosticClass::IncompatibleInterface,
                index,
                "binding interface is not one of the request's exact descriptors".to_string(),
                binding,
            ),
        );
    }
    let Some(interface) = interface else {
        push_diagnostic(
            diagnostics,
            binding_diagnostic(
                DiagnosticCode::MissingReference,
                DiagnosticClass::IncompatibleInterface,
                index,
                "binding interface is absent from the validated catalog".to_string(),
                binding,
            ),
        );
        return BindingProviderState::Unavailable;
    };

    let planned_provider =
        validate_provider_evidence(binding, inputs, input_index, index, diagnostics);
    let aggregation = Some(&interface.interface.aggregation);

    if binding.policy_revision != plan.policy_revision {
        push_diagnostic(
            diagnostics,
            binding_diagnostic(
                DiagnosticCode::BindingPrincipalMismatch,
                DiagnosticClass::Unauthorized,
                index,
                "binding policy revision differs from the plan commitment".to_string(),
                binding,
            ),
        );
    }
    if binding.caller_grant.principal != request.id.consumer
        || binding.provider_grant.principal != binding.provider
    {
        push_diagnostic(
            diagnostics,
            binding_diagnostic(
                DiagnosticCode::BindingPrincipalMismatch,
                DiagnosticClass::Unauthorized,
                index,
                "caller/provider grant principals do not match the request and selected provider"
                    .to_string(),
                binding,
            ),
        );
    }
    if binding.lifetime < request.lifetime {
        push_diagnostic(
            diagnostics,
            binding_diagnostic(
                DiagnosticCode::BindingInterfaceMismatch,
                DiagnosticClass::IncompatibleInterface,
                index,
                "binding lifetime is shorter than the requested lifetime".to_string(),
                binding,
            ),
        );
    }

    check_strict_order(
        &binding.guarantees,
        &SchemaPath::root()
            .child("bindings")
            .child(index.to_string())
            .child("guarantees"),
        diagnostics,
    );
    for guarantee in &request.guarantees {
        if !binding.guarantees.contains(guarantee)
            || !interface.interface.guarantees.contains(guarantee)
        {
            push_diagnostic(
                diagnostics,
                binding_diagnostic(
                    DiagnosticCode::MissingGuarantee,
                    DiagnosticClass::IncompatibleInterface,
                    index,
                    "binding does not supply an exact requested interface guarantee".to_string(),
                    binding,
                ),
            );
        }
    }
    for guarantee in &binding.guarantees {
        if !interface.interface.guarantees.contains(guarantee) {
            push_diagnostic(
                diagnostics,
                binding_diagnostic(
                    DiagnosticCode::MissingGuarantee,
                    DiagnosticClass::IncompatibleInterface,
                    index,
                    "binding asserts a guarantee absent from its exact interface descriptor"
                        .to_string(),
                    binding,
                ),
            );
        }
    }
    for method in &request.methods {
        if !interface.interface.methods.contains_key(method)
            || !binding.caller_grant.methods.contains(method)
        {
            push_diagnostic(
                diagnostics,
                binding_diagnostic(
                    DiagnosticCode::MethodNotGranted,
                    DiagnosticClass::Unauthorized,
                    index,
                    "requested method is absent from the interface or caller grant".to_string(),
                    binding,
                ),
            );
        }
    }
    validate_grant_methods(
        &binding.caller_grant,
        binding,
        interface,
        index,
        "caller_grant",
        diagnostics,
    );
    validate_grant_methods(
        &binding.provider_grant,
        binding,
        interface,
        index,
        "provider_grant",
        diagnostics,
    );
    if !binding.mediation_allowed
        && (!binding.provider_grant.methods.is_empty()
            || !binding.provider_grant.aggregate_slots.is_empty()
            || !binding.provider_grant.resources.is_empty())
    {
        push_diagnostic(
            diagnostics,
            binding_diagnostic(
                DiagnosticCode::MediationNotGranted,
                DiagnosticClass::Unauthorized,
                index,
                "provider implementation authority requires explicit mediation permission"
                    .to_string(),
                binding,
            ),
        );
    }

    validate_grant(
        &binding.caller_grant,
        binding,
        context,
        plan,
        inputs,
        input_index,
        resources,
        aggregation,
        false,
        true,
        true,
        index,
        "caller_grant",
        diagnostics,
    );
    validate_grant(
        &binding.provider_grant,
        binding,
        context,
        plan,
        inputs,
        input_index,
        resources,
        aggregation,
        true,
        false,
        false,
        index,
        "provider_grant",
        diagnostics,
    );
    planned_provider
}

pub(super) fn validate_provider_evidence(
    binding: &Binding,
    inputs: &BindingValidationInputs,
    input_index: &BindingInputIndex,
    index: usize,
    diagnostics: &mut Vec<Diagnostic>,
) -> BindingProviderState {
    let mut exact_provider_found = false;
    let mut provider_state = BindingProviderState::Unavailable;
    let pinned_package_kind = binding.provider_package.and_then(|digest| {
        input_index.packages.get(&digest).and_then(|package_index| {
            package_supplies_binding(
                &inputs.packages[*package_index],
                &input_index.package_catalogs[*package_index],
                binding,
            )
        })
    });
    if binding.provider_package.is_some() && pinned_package_kind.is_none() {
        push_diagnostic(
            diagnostics,
            binding_diagnostic(
                DiagnosticCode::MissingReference,
                DiagnosticClass::UnavailableProvider,
                index,
                "binding's exact provider package does not supply its implementation and export"
                    .to_string(),
                binding,
            ),
        );
    }
    if pinned_package_kind == Some(PackageProviderKind::PureComposition) {
        exact_provider_found = true;
        provider_state = BindingProviderState::PureComposition;
    }
    if binding.provider_package.is_none() && binding.implementation.handler.is_none() {
        push_diagnostic(
            diagnostics,
            binding_diagnostic(
                DiagnosticCode::MissingReference,
                DiagnosticClass::UnavailableProvider,
                index,
                "pure composition binding requires an exact provider package pin".to_string(),
                binding,
            ),
        );
    }

    for inventory_index in input_index
        .inventory_by_instance
        .get(&binding.provider)
        .into_iter()
        .flatten()
    {
        let inventory = &inputs.environment.providers[*inventory_index];
        let reference_matches = inventory.interface == binding.interface
            && inventory.implementation == binding.implementation;
        let state_is_usable = matches!(
            inventory.state,
            ProviderState::Planned | ProviderState::Available
        );
        let package_evidence_valid = match binding.provider_package {
            Some(_) => pinned_package_kind.is_some(),
            None => binding.implementation.handler.is_some(),
        };
        if !reference_matches || !state_is_usable || !package_evidence_valid {
            continue;
        }

        exact_provider_found = true;
        provider_state = match inventory.state {
            ProviderState::Available => BindingProviderState::Available,
            ProviderState::Planned => BindingProviderState::Planned,
            ProviderState::Declared | ProviderState::Unavailable | ProviderState::Stale => {
                BindingProviderState::Unavailable
            }
        };
        for guarantee in &binding.guarantees {
            if !inventory.guarantees.contains(guarantee) {
                push_diagnostic(
                    diagnostics,
                    binding_diagnostic(
                        DiagnosticCode::MissingGuarantee,
                        DiagnosticClass::UnavailableProvider,
                        index,
                        "binding asserts a guarantee absent from the selected provider inventory"
                            .to_string(),
                        binding,
                    ),
                );
            }
        }
    }

    if !exact_provider_found {
        push_diagnostic(
            diagnostics,
            binding_diagnostic(
                DiagnosticCode::MissingReference,
                DiagnosticClass::UnavailableProvider,
                index,
                "binding has no exact usable environment inventory or desired-package provider evidence"
                    .to_string(),
                binding,
            ),
        );
    }
    provider_state
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum PackageProviderKind {
    PureComposition,
    TerminalHandler,
}

pub(super) fn package_supplies_binding(
    package: &PackageDocument,
    package_index: &PackageProviderIndex,
    binding: &Binding,
) -> Option<PackageProviderKind> {
    let provider_index = package_index
        .providers
        .get(&(binding.interface.clone(), binding.implementation.descriptor))?;
    let implementation = &package.implementation.providers[*provider_index];
    if implementation.artifact != binding.implementation.artifact {
        return None;
    }
    if !package_index
        .exports
        .contains(&(binding.interface.clone(), binding.implementation.descriptor))
    {
        return None;
    }

    match &binding.implementation.handler {
        Some(handler) => (implementation.handler.as_ref() == Some(handler)
            && package
                .implementation
                .handlers
                .get(handler)
                .is_some_and(|descriptor| descriptor.artifact == binding.implementation.artifact))
        .then_some(PackageProviderKind::TerminalHandler),
        None => implementation
            .provider_module
            .is_some()
            .then_some(PackageProviderKind::PureComposition),
    }
}

pub(super) fn validate_grant_methods(
    grant: &AuthorityGrant,
    binding: &Binding,
    interface: &aos_ability_model::InterfaceDocument,
    index: usize,
    field: &str,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for method in &grant.methods {
        if !interface.interface.methods.contains_key(method) {
            let mut item = binding_diagnostic(
                DiagnosticCode::MethodNotGranted,
                DiagnosticClass::Unauthorized,
                index,
                "grant names a method absent from the binding's exact interface descriptor"
                    .to_string(),
                binding,
            );
            item.path.push(field.to_string());
            item.path.push("methods".to_string());
            push_diagnostic(diagnostics, item);
        }
    }
}

pub(super) fn validate_grant(
    grant: &AuthorityGrant,
    binding: &Binding,
    context: &ValidationContext,
    plan: &BindingPlanDocument,
    inputs: &BindingValidationInputs,
    input_index: &BindingInputIndex,
    resources: &BTreeSet<aos_ability_model::ResourceId>,
    aggregation: Option<&aos_ability_model::AggregationContract>,
    permit_caller_observation: bool,
    permit_external_observation: bool,
    permit_stateful_owner_write: bool,
    index: usize,
    field: &str,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let root = SchemaPath::root()
        .child("bindings")
        .child(index.to_string())
        .child(field.to_string());
    check_strict_order(&grant.methods, &root.child("methods"), diagnostics);
    check_order_by(
        &grant.aggregate_slots,
        |left, right| {
            left.aggregate
                .cmp(&right.aggregate)
                .then_with(|| left.slot.cmp(&right.slot))
        },
        "aggregate_slots",
        diagnostics,
    );
    for permission in &grant.aggregate_slots {
        if permission.aggregate.provider != binding.provider
            || aggregation
                .is_none_or(|contract| contract.controller_group != permission.aggregate.group)
        {
            push_diagnostic(
                diagnostics,
                binding_diagnostic(
                    DiagnosticCode::ResourceScopeEscape,
                    DiagnosticClass::Unauthorized,
                    index,
                    "aggregate slot permission differs from the selected provider's authenticated aggregate"
                        .to_string(),
                    binding,
                ),
            );
        }
    }
    check_order_by(
        &grant.resources,
        |left, right| compare_resource_ids(&left.resource, &right.resource),
        field,
        diagnostics,
    );
    for (permission_index, permission) in grant.resources.iter().enumerate() {
        check_strict_order(
            &permission.operations,
            &root
                .child("resources")
                .child(permission_index.to_string())
                .child("operations"),
            diagnostics,
        );
        if !grant_resource_in_scope(
            permission,
            resources,
            &binding.provider,
            &binding.request.consumer,
            permit_caller_observation,
            permit_external_observation,
        ) && !(permit_stateful_owner_write
            && mediated_owner_write_in_scope(
                permission,
                binding,
                context,
                plan,
                inputs,
                input_index,
                resources,
            ))
        {
            let mut item = binding_diagnostic(
                DiagnosticCode::ResourceScopeEscape,
                DiagnosticClass::Unauthorized,
                index,
                    "grant resource is outside the selected provider's authenticated resources or read-only caller observation scope"
                        .to_string(),
                binding,
            );
            item.resource = Some(permission.resource.clone());
            push_diagnostic(diagnostics, item);
        }
    }
}

pub(super) fn mediated_owner_write_in_scope(
    permission: &aos_ability_model::ResourcePermission,
    binding: &Binding,
    context: &ValidationContext,
    plan: &BindingPlanDocument,
    inputs: &BindingValidationInputs,
    input_index: &BindingInputIndex,
    resources: &BTreeSet<aos_ability_model::ResourceId>,
) -> bool {
    if permission.resource.provider != binding.request.consumer
        || !permission.access.is_write()
        || !resources.contains(&permission.resource)
    {
        return false;
    }
    let request_matches_lifetime = plan
        .requests
        .iter()
        .any(|request| request.id == binding.request && request.lifetime == binding.lifetime);
    let binding_is_terminal = binding.provider_package.is_some_and(|digest| {
        input_index
            .packages
            .get(&digest)
            .is_some_and(|package_index| {
                package_supplies_binding(
                    &inputs.packages[*package_index],
                    &input_index.package_catalogs[*package_index],
                    binding,
                ) == Some(PackageProviderKind::TerminalHandler)
            })
    });
    if !request_matches_lifetime || !binding_is_terminal || permission.operations.is_empty() {
        return false;
    }

    permission.operations.iter().all(|operation| {
        binding.caller_grant.methods.contains(operation)
            && context
                .interface(&binding.interface)
                .and_then(|interface| interface.interface.methods.get(operation))
                .is_some()
    })
}

pub(super) fn grant_resource_in_scope(
    permission: &aos_ability_model::ResourcePermission,
    resources: &BTreeSet<aos_ability_model::ResourceId>,
    provider: &InstanceId,
    caller: &InstanceId,
    permit_caller_observation: bool,
    permit_external_observation: bool,
) -> bool {
    if !resources.contains(&permission.resource) {
        return false;
    }
    if permission.resource.provider == *provider {
        return true;
    }

    if permit_external_observation && permission.access == AccessMode::Read {
        return true;
    }

    permit_caller_observation
        && permission.resource.provider == *caller
        && permission.access == AccessMode::Read
}

pub(super) fn validate_aggregate_inputs(
    context: &ValidationContext,
    document: &BindingPlanDocument,
    inputs: &BindingValidationInputs,
    binding_indices: &BTreeMap<aos_ability_model::BindingId, usize>,
    resources: &BTreeSet<aos_ability_model::ResourceId>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let mut occupied_slots: BTreeMap<
        (AggregateId, LocalKey),
        Vec<(Sha256Digest, Option<Sha256Digest>)>,
    > = BTreeMap::new();
    let artifacts = retained_aggregate_input_artifacts(inputs);
    for (index, aggregate_input) in inputs.desired_state.aggregate_inputs.iter().enumerate() {
        let path = SchemaPath::root()
            .child("desired_state")
            .child("aggregate_inputs")
            .child(index.to_string());
        let Some(binding_index) = binding_indices.get(&aggregate_input.grant) else {
            let mut item = diagnostic(
                DiagnosticCode::MissingReference,
                DiagnosticClass::Unauthorized,
                DiagnosticPhase::Binding,
                path.child("grant").components().to_vec(),
                "aggregate input references no selected binding caller grant".to_string(),
            );
            item.request = Some(aggregate_input.request.clone());
            push_diagnostic(diagnostics, item);
            continue;
        };
        let binding = &document.bindings[*binding_index];
        let aggregation = context
            .interface(&binding.interface)
            .map(|document| &document.interface.aggregation);
        let authorized = binding
            .caller_grant
            .aggregate_slots
            .iter()
            .any(|permission| {
                permission.aggregate == aggregate_input.aggregate
                    && permission.slot == aggregate_input.slot
            });
        if binding.request != aggregate_input.request
            || aggregate_input.aggregate.provider != binding.provider
            || aggregation
                .is_none_or(|contract| contract.controller_group != aggregate_input.aggregate.group)
            || !authorized
        {
            let mut item = binding_diagnostic(
                DiagnosticCode::ResourceScopeEscape,
                DiagnosticClass::Unauthorized,
                *binding_index,
                "aggregate input request, aggregate, or slot exceeds its selected caller grant"
                    .to_string(),
                binding,
            );
            item.path = path.components().to_vec();
            push_diagnostic(diagnostics, item);
        }
        let peers = occupied_slots
            .entry((
                aggregate_input.aggregate.clone(),
                aggregate_input.slot.clone(),
            ))
            .or_default();
        let merge_contract = aggregation.and_then(|contract| contract.merge_contract);
        let same_implementation = peers
            .iter()
            .any(|(descriptor, _)| *descriptor == binding.implementation.descriptor);
        let incompatible_facets = peers.iter().any(|(descriptor, contract)| {
            *descriptor != binding.implementation.descriptor
                && (merge_contract.is_none() || *contract != merge_contract)
        });
        if (same_implementation
            && aggregation.is_none_or(|contract| contract.reject_slot_collisions))
            || incompatible_facets
        {
            let mut item = diagnostic(
                DiagnosticCode::DuplicateIdentity,
                DiagnosticClass::ResourceConflict,
                DiagnosticPhase::Binding,
                path.child("slot").components().to_vec(),
                "aggregate slot has duplicate or incompatible implementation inputs".to_string(),
            );
            item.request = Some(aggregate_input.request.clone());
            push_diagnostic(diagnostics, item);
        }
        peers.push((binding.implementation.descriptor, merge_contract));
        let Some(interface) = context.interface(&binding.interface) else {
            continue;
        };
        let expression = ValueExpression::Literal {
            value: aggregate_input.value.clone(),
        };
        if let Err(errors) = validate_value(&interface.interface.request, &expression) {
            for mut item in errors.into_diagnostics() {
                let mut prefixed = path.child("value").components().to_vec();
                prefixed.extend(item.path);
                item.path = prefixed;
                item.phase = DiagnosticPhase::Binding;
                item.request = Some(aggregate_input.request.clone());
                push_diagnostic(diagnostics, item);
            }
            continue;
        }

        if let Err(error) = authorize_materialized_references(
            context.interface_catalog(),
            binding,
            &binding.caller_grant,
            &interface.interface.request,
            &aggregate_input.value,
            &artifacts,
            resources,
            binding.lifetime,
            None,
        ) {
            let mut item = binding_diagnostic(
                DiagnosticCode::ResourceScopeEscape,
                DiagnosticClass::Unauthorized,
                *binding_index,
                format!("aggregate input value exceeds retained caller authority: {error}"),
                binding,
            );
            item.path = path.child("value").components().to_vec();
            push_diagnostic(diagnostics, item);
        }
    }
}

pub(super) fn retained_aggregate_input_artifacts(
    inputs: &BindingValidationInputs,
) -> ArtifactIndex {
    let mut artifacts = ArtifactIndex::new();
    for artifact in &inputs.environment.artifacts {
        insert_artifact(&mut artifacts, artifact);
    }
    for inventory in &inputs.environment.providers {
        insert_artifact(&mut artifacts, &inventory.implementation.artifact);
    }
    for package in &inputs.packages {
        insert_artifact(&mut artifacts, &package.package.payload);
        for artifact in &package.artifacts {
            insert_artifact(&mut artifacts, artifact);
        }
        if let Some(module) = &package.package_module {
            insert_artifact(&mut artifacts, &module.artifact);
        }
        for provider in &package.implementation.providers {
            insert_artifact(&mut artifacts, &provider.artifact);
            if let Some(module) = &provider.provider_module {
                insert_artifact(&mut artifacts, &module.artifact);
            }
            if let Some(state_format) = &provider.state_format {
                insert_artifact(&mut artifacts, &state_format.artifact);
            }
        }
        for handler in package.implementation.handlers.values() {
            insert_artifact(&mut artifacts, &handler.artifact);
        }
        for qualification in package.qualification.implementations.values() {
            insert_artifact(&mut artifacts, &qualification.observer.artifact);
        }
    }
    artifacts
}

pub(super) fn insert_artifact(
    index: &mut ArtifactIndex,
    artifact: &aos_ability_model::ArtifactReference,
) {
    index
        .entry(artifact.content)
        .or_insert_with(|| artifact.clone());
}

pub(super) fn check_order_by<T>(
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
            diagnostic(
                DiagnosticCode::NonCanonicalOrder,
                DiagnosticClass::InvalidContract,
                DiagnosticPhase::Binding,
                vec![field.to_string()],
                "values must be strictly sorted without duplicate identities".to_string(),
            ),
        );
    }
}

pub(super) fn binding_diagnostic(
    code: DiagnosticCode,
    class: DiagnosticClass,
    index: usize,
    message: String,
    binding: &Binding,
) -> Diagnostic {
    let mut item = diagnostic(
        code,
        class,
        DiagnosticPhase::Binding,
        vec!["bindings".to_string(), index.to_string()],
        message,
    );
    item.request = Some(binding.request.clone());
    item
}
