//! Binding-plan document identity and resource validation.

use super::*;

pub(crate) fn validate_binding_document(
    context: &ValidationContext,
    document: BindingPlanDocument,
    inputs: BindingValidationInputs,
) -> Result<CheckedBindingPlan, ValidationErrors> {
    let mut diagnostics = Vec::new();

    let id = match document.content_digest() {
        Ok(digest) => PlanId(digest),
        Err(error) => {
            push_diagnostic(
                &mut diagnostics,
                diagnostic(
                    DiagnosticCode::UnsupportedSchema,
                    DiagnosticClass::InvalidContract,
                    DiagnosticPhase::Binding,
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
                    DiagnosticPhase::Binding,
                    vec!["required_features".to_string()],
                    format!("unsupported required feature '{}'", feature.as_str()),
                ),
            );
        }
    }

    let Some(input_index) = validate_binding_inputs(context, &document, &inputs, &mut diagnostics)
    else {
        return Err(ValidationErrors::new(diagnostics));
    };

    check_order_by(
        &document.requests,
        |left, right| compare_request_ids(&left.id, &right.id),
        "requests",
        &mut diagnostics,
    );
    check_order_by(
        &document.resources,
        |left, right| compare_resource_ids(&left.resource, &right.resource),
        "resources",
        &mut diagnostics,
    );
    for (index, resource) in document.resources.iter().enumerate() {
        if !input_index
            .in_scope_instances
            .contains(&resource.resource.provider)
        {
            let mut item = diagnostic(
                DiagnosticCode::ResourceScopeEscape,
                DiagnosticClass::Unauthorized,
                DiagnosticPhase::Binding,
                vec!["resources".to_string(), index.to_string()],
                "plan resource provider is outside the supplied environment and desired state"
                    .to_string(),
            );
            item.resource = Some(resource.resource.clone());
            push_diagnostic(&mut diagnostics, item);
        }
    }
    check_order_by(
        &document.bindings,
        |left, right| left.id.cmp(&right.id),
        "bindings",
        &mut diagnostics,
    );
    check_order_by(
        &document.obligations,
        |left, right| left.key.cmp(&right.key),
        "obligations",
        &mut diagnostics,
    );

    let requests: BTreeMap<_, _> = document
        .requests
        .iter()
        .enumerate()
        .map(|(index, request)| (request.id.clone(), index))
        .collect();
    let resources: BTreeSet<_> = document
        .resources
        .iter()
        .map(|revision| revision.resource.clone())
        .collect();
    let mut request_bindings: BTreeMap<RequestId, usize> = BTreeMap::new();
    let mut request_obligations: BTreeMap<RequestId, usize> = BTreeMap::new();
    let mut binding_indices = BTreeMap::new();
    let mut provider_states = BTreeMap::new();
    let mut planned_providers = BTreeSet::new();

    for (index, binding) in document.bindings.iter().enumerate() {
        if binding_indices.insert(binding.id.clone(), index).is_some() {
            push_diagnostic(
                &mut diagnostics,
                binding_diagnostic(
                    DiagnosticCode::DuplicateIdentity,
                    DiagnosticClass::InvalidContract,
                    index,
                    "duplicate binding identity".to_string(),
                    binding,
                ),
            );
        }
        *request_bindings.entry(binding.request.clone()).or_default() += 1;

        let Some(request_index) = requests.get(&binding.request) else {
            push_diagnostic(
                &mut diagnostics,
                binding_diagnostic(
                    DiagnosticCode::MissingReference,
                    DiagnosticClass::InvalidContract,
                    index,
                    "binding references an unknown request".to_string(),
                    binding,
                ),
            );
            continue;
        };
        let request = &document.requests[*request_index];
        let provider_state = validate_binding(
            context,
            &document,
            &inputs,
            &input_index,
            binding,
            request,
            &resources,
            index,
            &mut diagnostics,
        );
        provider_states.insert(binding.id.clone(), provider_state);
        if provider_state == BindingProviderState::Planned {
            planned_providers.insert(binding.provider.clone());
        }
    }

    validate_desired_resource_realizations(context, &document, &inputs, &mut diagnostics);

    validate_contributions(
        context,
        &document,
        &inputs,
        &binding_indices,
        &resources,
        &mut diagnostics,
    );

    for (index, obligation) in document.obligations.iter().enumerate() {
        *request_obligations
            .entry(obligation.request.clone())
            .or_default() += 1;
        if !requests.contains_key(&obligation.request) {
            let mut item = diagnostic(
                DiagnosticCode::MissingReference,
                DiagnosticClass::InvalidContract,
                DiagnosticPhase::Binding,
                vec![
                    "obligations".to_string(),
                    index.to_string(),
                    "request".to_string(),
                ],
                "obligation references an unknown request".to_string(),
            );
            item.request = Some(obligation.request.clone());
            push_diagnostic(&mut diagnostics, item);
        }
        if obligation
            .resource
            .as_ref()
            .is_some_and(|resource| !resources.contains(resource))
        {
            let mut item = diagnostic(
                DiagnosticCode::MissingReference,
                DiagnosticClass::InvalidContract,
                DiagnosticPhase::Binding,
                vec![
                    "obligations".to_string(),
                    index.to_string(),
                    "resource".to_string(),
                ],
                "obligation references an unknown plan resource".to_string(),
            );
            item.request = Some(obligation.request.clone());
            item.resource = obligation.resource.clone();
            push_diagnostic(&mut diagnostics, item);
        }
    }

    for (index, request) in document.requests.iter().enumerate() {
        validate_request(
            request,
            index,
            context,
            &input_index.in_scope_instances,
            &input_index.request_authorities,
            &mut diagnostics,
        );
        let binding_count = request_bindings
            .get(&request.id)
            .copied()
            .unwrap_or_default();
        let obligation_count = request_obligations
            .get(&request.id)
            .copied()
            .unwrap_or_default();
        if binding_count > 1 || (binding_count == 1 && obligation_count != 0) {
            let mut item = diagnostic(
                DiagnosticCode::DuplicateIdentity,
                DiagnosticClass::AmbiguousBinding,
                DiagnosticPhase::Binding,
                vec!["requests".to_string(), index.to_string()],
                "request must have one binding or one or more unresolved obligations, never both"
                    .to_string(),
            );
            item.request = Some(request.id.clone());
            push_diagnostic(&mut diagnostics, item);
        } else if binding_count == 0 && obligation_count == 0 {
            let mut item = diagnostic(
                DiagnosticCode::MissingReference,
                DiagnosticClass::UnsatisfiedObligation,
                DiagnosticPhase::Binding,
                vec!["requests".to_string(), index.to_string()],
                "request has neither a binding nor an explicit deployment obligation".to_string(),
            );
            item.request = Some(request.id.clone());
            push_diagnostic(&mut diagnostics, item);
        }
    }

    if diagnostics.is_empty() {
        let executable = document.obligations.is_empty() && planned_providers.is_empty();
        let binding_authority = document
            .bindings
            .iter()
            .map(|binding| (binding.id.clone(), crate::BindingAuthorityKind::Desired))
            .collect();
        Ok(CheckedBindingPlan {
            id,
            document,
            inputs,
            binding_indices,
            binding_authority,
            provider_states,
            planned_providers,
            executable,
        })
    } else {
        Err(ValidationErrors::new(diagnostics))
    }
}

pub(super) fn validate_desired_resource_realizations(
    context: &ValidationContext,
    plan: &BindingPlanDocument,
    inputs: &BindingValidationInputs,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for (index, resource) in inputs.desired_state.resources.iter().enumerate() {
        let path = vec![
            "desired_state".to_string(),
            "resources".to_string(),
            index.to_string(),
            "realization".to_string(),
        ];
        let Some(controller) = inputs
            .desired_state
            .controllers
            .iter()
            .find(|assignment| assignment.resource == resource.resource)
        else {
            validate_published_resource(context, plan, inputs, resource, path, diagnostics);
            continue;
        };
        let controller_provider_bindings = plan
            .bindings
            .iter()
            .filter(|binding| binding.provider == controller.controller.provider)
            .collect::<Vec<_>>();
        if resource.realization.as_json().is_null()
            && controller_provider_bindings.iter().any(|binding| {
                binding.source == BindingSource::ExistingPin && binding.provider_package.is_none()
            })
            && controller_provider_bindings
                .iter()
                .all(|binding| binding.provider_package.is_none())
        {
            // An unchanged existing pin has no package-backed desired
            // realization to validate. Every newly selected controller carries
            // an authenticated provider package and follows the strict path.
            continue;
        }
        let mut controller_bindings = plan.bindings.iter().filter(|binding| {
            binding.provider == controller.controller.provider
                && context
                    .interface(&binding.interface)
                    .is_some_and(|interface| {
                        interface.interface.aggregation.controller_group
                            == controller.controller.group
                    })
        });
        let Some(binding) = controller_bindings.next() else {
            push_diagnostic(
                diagnostics,
                resource_realization_diagnostic(
                    DiagnosticCode::MissingReference,
                    path,
                    resource,
                    "desired resource controller has no selected implementation".to_string(),
                ),
            );
            continue;
        };
        if controller_bindings.any(|candidate| {
            candidate.provider_package != binding.provider_package
                || candidate.interface != binding.interface
                || candidate.implementation != binding.implementation
        }) {
            push_diagnostic(
                diagnostics,
                resource_realization_diagnostic(
                    DiagnosticCode::DuplicateIdentity,
                    path,
                    resource,
                    "desired resource controller resolves to conflicting selected implementations"
                        .to_string(),
                ),
            );
            continue;
        }
        let Some(implementation) = exact_bound_implementation(inputs, binding) else {
            push_diagnostic(
                diagnostics,
                resource_realization_diagnostic(
                    DiagnosticCode::MissingReference,
                    path,
                    resource,
                    "desired resource controller implementation is absent from the authenticated package catalog"
                        .to_string(),
                ),
            );
            continue;
        };
        let Some(selected_interface) = context.interface(&binding.interface) else {
            push_diagnostic(
                diagnostics,
                resource_realization_diagnostic(
                    DiagnosticCode::MissingReference,
                    path,
                    resource,
                    "desired resource controller interface is unavailable".to_string(),
                ),
            );
            continue;
        };
        let authorized_write_methods = binding
            .caller_grant
            .methods
            .iter()
            .filter(|method_name| {
                selected_interface
                    .interface
                    .methods
                    .get(*method_name)
                    .is_some_and(|method| {
                        method.target_resource == resource.kind
                            && method.semantics.required_target_access.is_write()
                    })
            })
            .collect::<Vec<_>>();
        let resource_write_granted = binding.caller_grant.resources.iter().any(|permission| {
            permission.resource == resource.resource
                && permission.access.is_write()
                && authorized_write_methods
                    .iter()
                    .any(|method| permission.operations.contains(method))
        });
        if authorized_write_methods.is_empty() || !resource_write_granted {
            push_diagnostic(
                diagnostics,
                resource_realization_diagnostic(
                    DiagnosticCode::ResourceScopeEscape,
                    path.clone(),
                    resource,
                    "desired resource lacks an exact selected write method and resource grant"
                        .to_string(),
                ),
            );
        }
        let Some(schema) = implementation.desired_schema.as_ref() else {
            push_diagnostic(
                diagnostics,
                resource_realization_diagnostic(
                    DiagnosticCode::UnsupportedRequiredFeature,
                    path,
                    resource,
                    "selected controller implementation does not declare a desired realization schema"
                        .to_string(),
                ),
            );
            continue;
        };
        if let Err(errors) = validate_materialized_value(schema, &resource.realization) {
            for error in errors.into_diagnostics() {
                let mut item = resource_realization_diagnostic(
                    error.code,
                    path.clone(),
                    resource,
                    error.message,
                );
                item.class = error.class;
                push_diagnostic(diagnostics, item);
            }
        }
    }
}

pub(super) fn validate_published_resource(
    context: &ValidationContext,
    plan: &BindingPlanDocument,
    inputs: &BindingValidationInputs,
    resource: &aos_ability_model::ResourceRevision,
    path: Vec<String>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(reference) = published_resource_reference(&resource.value) else {
        // Existing read-only observations may retain provider-neutral values.
        // The stricter publication contract applies when a provider publishes
        // an explicit ResourceReference into the final catalog.
        return;
    };
    if reference.resource != resource.resource
        || reference.interface.name != resource.kind
        || reference.lifetime != resource.lifetime
    {
        push_diagnostic(
            diagnostics,
            resource_realization_diagnostic(
                DiagnosticCode::BindingInterfaceMismatch,
                path.clone(),
                resource,
                "published ResourceReference does not match its catalog identity, interface, and lifetime"
                    .to_string(),
            ),
        );
        return;
    }
    let Some(interface) = context.interface(&reference.interface) else {
        push_diagnostic(
            diagnostics,
            resource_realization_diagnostic(
                DiagnosticCode::MissingReference,
                path.clone(),
                resource,
                "published ResourceReference names an unavailable interface".to_string(),
            ),
        );
        return;
    };
    if reference.operations.is_empty()
        || reference
            .operations
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || reference.operations.iter().any(|method| {
            interface
                .interface
                .methods
                .get(method)
                .is_none_or(|method| method.semantics.required_target_access != AccessMode::Read)
        })
    {
        push_diagnostic(
            diagnostics,
            resource_realization_diagnostic(
                DiagnosticCode::ResourceScopeEscape,
                path.clone(),
                resource,
                "a resource without a write controller may publish only read methods".to_string(),
            ),
        );
        return;
    }
    let bindings = plan
        .bindings
        .iter()
        .filter(|binding| {
            binding.provider == reference.resource.provider
                && binding.interface == reference.interface
        })
        .collect::<Vec<_>>();
    let [binding] = bindings.as_slice() else {
        let (code, message) = if bindings.is_empty() {
            (
                DiagnosticCode::MissingReference,
                "published ResourceReference has no exact selected provider binding",
            )
        } else {
            (
                DiagnosticCode::DuplicateIdentity,
                "published ResourceReference has multiple candidate provider bindings",
            )
        };
        push_diagnostic(
            diagnostics,
            resource_realization_diagnostic(code, path.clone(), resource, message.to_string()),
        );
        return;
    };
    let request_authorizes_publication = plan
        .requests
        .iter()
        .find(|request| request.id == binding.request)
        .is_some_and(|request| {
            request.accepted_interfaces.contains(&reference.interface)
                && reference
                    .operations
                    .iter()
                    .all(|method| request.methods.contains(method))
        });
    let binding_authorizes_publication = reference
        .operations
        .iter()
        .all(|method| binding.caller_grant.methods.contains(method));
    let exact_read_grant = binding.caller_grant.resources.iter().any(|permission| {
        permission.resource == reference.resource
            && permission.access == AccessMode::Read
            && reference
                .operations
                .iter()
                .all(|method| permission.operations.contains(method))
    });
    if !request_authorizes_publication || !binding_authorizes_publication || !exact_read_grant {
        push_diagnostic(
            diagnostics,
            resource_realization_diagnostic(
                DiagnosticCode::ResourceScopeEscape,
                path.clone(),
                resource,
                "published ResourceReference lacks an exact request, method, and read resource grant"
                    .to_string(),
            ),
        );
    }
    if exact_bound_implementation(inputs, binding).is_none() {
        push_diagnostic(
            diagnostics,
            resource_realization_diagnostic(
                DiagnosticCode::MissingReference,
                path.clone(),
                resource,
                "published ResourceReference binding has no authenticated implementation"
                    .to_string(),
            ),
        );
    }
    if !resource.realization.as_json().is_null() {
        push_diagnostic(
            diagnostics,
            resource_realization_diagnostic(
                DiagnosticCode::ValueTypeMismatch,
                path,
                resource,
                "published read-only resource must not carry a desired backend realization"
                    .to_string(),
            ),
        );
    }
}

pub(super) fn published_resource_reference(
    value: &aos_ability_model::AbilityValue,
) -> Option<ResourceReference> {
    let mut object = value.as_json().as_object()?.clone();
    if object.len() != 5
        || object
            .remove("_type")
            .and_then(|value| value.as_str().map(str::to_owned))
            .as_deref()
            != Some("aos-resource-reference")
    {
        return None;
    }

    serde_json::from_value(serde_json::Value::Object(object)).ok()
}

pub(super) fn exact_bound_implementation<'a>(
    inputs: &'a BindingValidationInputs,
    binding: &aos_ability_model::Binding,
) -> Option<&'a ProviderImplementation> {
    let package_digest = binding.provider_package?;
    let mut packages = inputs.packages.iter().filter(|package| {
        package
            .content_digest()
            .is_ok_and(|digest| digest == package_digest)
    });
    let package = packages.next()?;
    if packages.next().is_some() {
        return None;
    }

    let mut implementations = package
        .implementation
        .providers
        .iter()
        .filter(|implementation| {
            implementation.interface == binding.interface
                && implementation.artifact == binding.implementation.artifact
                && implementation
                    .descriptor_digest()
                    .is_ok_and(|descriptor| descriptor == binding.implementation.descriptor)
        });
    let implementation = implementations.next()?;
    implementations.next().is_none().then_some(implementation)
}

pub(super) fn resource_realization_diagnostic(
    code: DiagnosticCode,
    path: Vec<String>,
    resource: &aos_ability_model::ResourceRevision,
    message: String,
) -> Diagnostic {
    let mut item = diagnostic(
        code,
        DiagnosticClass::InvalidContract,
        DiagnosticPhase::Binding,
        path,
        message,
    );
    item.resource = Some(resource.resource.clone());
    item
}

pub(super) fn validate_binding_inputs(
    context: &ValidationContext,
    plan: &BindingPlanDocument,
    inputs: &BindingValidationInputs,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<BindingInputIndex> {
    let environment_digest =
        validate_input_document(context, &inputs.environment, "environment", diagnostics)?;
    let desired_digest =
        validate_input_document(context, &inputs.desired_state, "desired_state", diagnostics)?;
    let limits = aos_ability_model::ABILITY_LIMITS_V1;
    if inputs.packages.len() > limits.max_graph_nodes as usize {
        push_diagnostic(
            diagnostics,
            diagnostic(
                DiagnosticCode::LimitExceeded,
                DiagnosticClass::InvalidContract,
                DiagnosticPhase::Binding,
                vec!["packages".to_string()],
                "package input catalog exceeds the version-1 entry limit".to_string(),
            ),
        );
        return None;
    }

    let mut package_digests = Vec::with_capacity(inputs.packages.len());
    let mut aggregate_package_bytes = 0_u64;
    for package in &inputs.packages {
        let digest = validate_input_document(context, package, "packages", diagnostics)?;
        let encoded_len = match aos_ability_model::encode_canonical(package) {
            Ok(bytes) => bytes.len() as u64,
            Err(_) => return None,
        };
        aggregate_package_bytes = aggregate_package_bytes.saturating_add(encoded_len);
        if aggregate_package_bytes > limits.max_document_bytes {
            push_diagnostic(
                diagnostics,
                diagnostic(
                    DiagnosticCode::LimitExceeded,
                    DiagnosticClass::InvalidContract,
                    DiagnosticPhase::Binding,
                    vec!["packages".to_string()],
                    "package input catalog exceeds the version-1 aggregate byte limit".to_string(),
                ),
            );
            return None;
        }
        package_digests.push(digest);
    }

    let mut input_index = BindingInputIndex {
        package_catalogs: (0..inputs.packages.len())
            .map(|_| PackageProviderIndex::default())
            .collect(),
        ..BindingInputIndex::default()
    };
    for (provider_index, provider) in inputs.environment.providers.iter().enumerate() {
        input_index
            .inventory_by_instance
            .entry(provider.provider.clone())
            .or_default()
            .push(provider_index);
        if provider.provider.environment == inputs.environment.environment {
            input_index
                .in_scope_instances
                .insert(provider.provider.clone());
        }
    }
    for (desired_index, desired) in inputs.desired_state.instances.iter().enumerate() {
        if !desired.enabled {
            continue;
        }
        input_index
            .enabled_desired_by_instance
            .entry(desired.instance.clone())
            .or_default()
            .push(desired_index);
        if desired.instance.environment == inputs.environment.environment {
            input_index
                .in_scope_instances
                .insert(desired.instance.clone());
        }
    }
    for (request_index, request) in inputs.desired_state.child_requests.iter().enumerate() {
        input_index
            .requests
            .entry(request.id.clone())
            .or_insert(request_index);
    }

    if environment_digest != plan.environment {
        push_diagnostic(
            diagnostics,
            diagnostic(
                DiagnosticCode::BindingInterfaceMismatch,
                DiagnosticClass::InvalidContract,
                DiagnosticPhase::Binding,
                vec!["environment".to_string()],
                "binding plan environment digest does not match the supplied document".to_string(),
            ),
        );
    }
    if desired_digest != plan.desired_state {
        push_diagnostic(
            diagnostics,
            diagnostic(
                DiagnosticCode::BindingInterfaceMismatch,
                DiagnosticClass::InvalidContract,
                DiagnosticPhase::Binding,
                vec!["desired_state".to_string()],
                "binding plan desired-state digest does not match the supplied document"
                    .to_string(),
            ),
        );
    }
    if plan.requests != inputs.desired_state.child_requests {
        push_diagnostic(
            diagnostics,
            diagnostic(
                DiagnosticCode::BindingPrincipalMismatch,
                DiagnosticClass::InvalidContract,
                DiagnosticPhase::Binding,
                vec!["requests".to_string()],
                "binding-plan requests do not exactly match the committed desired-state requests"
                    .to_string(),
            ),
        );
    }
    let expected_resources = merged_resource_revisions(
        &inputs.environment.resources,
        &inputs.desired_state.resources,
    );
    if plan.resources != expected_resources {
        push_diagnostic(
            diagnostics,
            diagnostic(
                DiagnosticCode::ResourceScopeEscape,
                DiagnosticClass::InvalidContract,
                DiagnosticPhase::Binding,
                vec!["resources".to_string()],
                "binding-plan resources do not exactly match the canonical current and desired resource union"
                    .to_string(),
            ),
        );
    }
    if inputs.desired_state.environment != environment_digest
        || inputs.environment.policy_revision != plan.policy_revision
    {
        push_diagnostic(
            diagnostics,
            diagnostic(
                DiagnosticCode::BindingPrincipalMismatch,
                DiagnosticClass::Unauthorized,
                DiagnosticPhase::Binding,
                vec!["policy_revision".to_string()],
                "desired environment or policy commitment is inconsistent with binding inputs"
                    .to_string(),
            ),
        );
    }

    check_order_by(
        &inputs.environment.providers,
        |left, right| {
            compare_instance_ids(&left.provider, &right.provider)
                .then_with(|| left.interface.cmp(&right.interface))
        },
        "environment.providers",
        diagnostics,
    );
    check_order_by(
        &inputs.environment.resources,
        |left, right| compare_resource_ids(&left.resource, &right.resource),
        "environment.resources",
        diagnostics,
    );
    check_order_by(
        &inputs.environment.controllers,
        |left, right| compare_resource_ids(&left.resource, &right.resource),
        "environment.controllers",
        diagnostics,
    );
    for (index, provider) in inputs.environment.providers.iter().enumerate() {
        if provider.provider.environment != inputs.environment.environment {
            push_diagnostic(
                diagnostics,
                diagnostic(
                    DiagnosticCode::BindingPrincipalMismatch,
                    DiagnosticClass::Unauthorized,
                    DiagnosticPhase::Binding,
                    vec![
                        "environment".to_string(),
                        "providers".to_string(),
                        index.to_string(),
                    ],
                    "provider inventory entry belongs to a different environment".to_string(),
                ),
            );
        }
        if context.interface(&provider.interface).is_none() {
            push_diagnostic(
                diagnostics,
                diagnostic(
                    DiagnosticCode::MissingReference,
                    DiagnosticClass::IncompatibleInterface,
                    DiagnosticPhase::Binding,
                    vec![
                        "environment".to_string(),
                        "providers".to_string(),
                        index.to_string(),
                    ],
                    "provider inventory names an interface absent from the validated catalog"
                        .to_string(),
                ),
            );
        }
        let incarnation_is_valid = match provider.state {
            ProviderState::Available => provider.incarnation.is_some(),
            ProviderState::Declared
            | ProviderState::Planned
            | ProviderState::Unavailable
            | ProviderState::Stale => provider.incarnation.is_none(),
        };
        if !incarnation_is_valid {
            push_diagnostic(
                diagnostics,
                diagnostic(
                    DiagnosticCode::ValueTypeMismatch,
                    DiagnosticClass::InvalidContract,
                    DiagnosticPhase::Binding,
                    vec![
                        "environment".to_string(),
                        "providers".to_string(),
                        index.to_string(),
                        "incarnation".to_string(),
                    ],
                    "exactly available provider inventory must carry a live incarnation"
                        .to_string(),
                ),
            );
        }
        check_strict_order(
            &provider.guarantees,
            &SchemaPath::root()
                .child("environment")
                .child("providers")
                .child(index.to_string())
                .child("guarantees"),
            diagnostics,
        );
    }

    check_order_by(
        &inputs.desired_state.instances,
        |left, right| compare_instance_ids(&left.instance, &right.instance),
        "desired_state.instances",
        diagnostics,
    );
    check_order_by(
        &inputs.desired_state.child_requests,
        |left, right| compare_request_ids(&left.id, &right.id),
        "desired_state.child_requests",
        diagnostics,
    );
    check_order_by(
        &inputs.desired_state.resources,
        |left, right| compare_resource_ids(&left.resource, &right.resource),
        "desired_state.resources",
        diagnostics,
    );
    check_order_by(
        &inputs.desired_state.outputs,
        |left, right| {
            left.aggregate
                .cmp(&right.aggregate)
                .then_with(|| left.interface.cmp(&right.interface))
                .then_with(|| left.port.cmp(&right.port))
        },
        "desired_state.outputs",
        diagnostics,
    );
    check_order_by(
        &inputs.desired_state.controllers,
        |left, right| compare_resource_ids(&left.resource, &right.resource),
        "desired_state.controllers",
        diagnostics,
    );
    validate_controller_continuity(inputs, diagnostics);
    for (index, desired) in inputs.desired_state.instances.iter().enumerate() {
        if desired.instance.environment != inputs.environment.environment {
            push_diagnostic(
                diagnostics,
                diagnostic(
                    DiagnosticCode::BindingPrincipalMismatch,
                    DiagnosticClass::Unauthorized,
                    DiagnosticPhase::Binding,
                    vec![
                        "desired_state".to_string(),
                        "instances".to_string(),
                        index.to_string(),
                    ],
                    "desired instance belongs to a different environment".to_string(),
                ),
            );
        }
    }

    for (index, (package, digest)) in inputs
        .packages
        .iter()
        .zip(package_digests.iter().copied())
        .enumerate()
    {
        if input_index.packages.insert(digest, index).is_some() {
            push_diagnostic(
                diagnostics,
                diagnostic(
                    DiagnosticCode::DuplicateIdentity,
                    DiagnosticClass::InvalidContract,
                    DiagnosticPhase::Binding,
                    vec!["packages".to_string(), index.to_string()],
                    "duplicate exact package document".to_string(),
                ),
            );
        }
        // A package manifest may describe requirements for other configurations.
        // Only concrete requests in this desired state need exact interfaces.
        input_index.package_catalogs[index] =
            validate_package_document(context, package, index, true, diagnostics);
    }
    check_strict_order(
        &package_digests,
        &SchemaPath::root().child("packages"),
        diagnostics,
    );
    for (index, desired) in inputs.desired_state.instances.iter().enumerate() {
        input_index
            .request_authorities
            .insert(desired.instance.clone(), desired.authority.clone());

        let Some(package_digest) = desired.package else {
            continue;
        };
        if !input_index.packages.contains_key(&package_digest) {
            push_diagnostic(
                diagnostics,
                diagnostic(
                    DiagnosticCode::MissingReference,
                    DiagnosticClass::InvalidContract,
                    DiagnosticPhase::Binding,
                    vec![
                        "desired_state".to_string(),
                        "instances".to_string(),
                        index.to_string(),
                    ],
                    "desired instance references a package absent from the exact input catalog"
                        .to_string(),
                ),
            );
            continue;
        }
    }
    Some(input_index)
}

pub(super) fn validate_controller_continuity(
    inputs: &BindingValidationInputs,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let current_resources: BTreeSet<_> = inputs
        .environment
        .resources
        .iter()
        .map(|revision| &revision.resource)
        .collect();
    let desired_resources: BTreeSet<_> = inputs
        .desired_state
        .resources
        .iter()
        .map(|revision| &revision.resource)
        .collect();
    let current_controllers: BTreeMap<_, _> = inputs
        .environment
        .controllers
        .iter()
        .map(|assignment| (&assignment.resource, &assignment.controller))
        .collect();

    for assignment in &inputs.desired_state.controllers {
        if current_resources.contains(&assignment.resource)
            && desired_resources.contains(&assignment.resource)
            && current_controllers
                .get(&assignment.resource)
                .is_some_and(|current| *current != &assignment.controller)
        {
            let mut item = diagnostic(
                DiagnosticCode::ConflictingController,
                DiagnosticClass::ResourceConflict,
                DiagnosticPhase::Binding,
                vec!["desired_state".to_string(), "controllers".to_string()],
                "retained resource changes lifecycle controller without an explicit transfer contract"
                    .to_string(),
            );
            item.resource = Some(assignment.resource.clone());
            push_diagnostic(diagnostics, item);
        }
    }
}

pub(super) fn merged_resource_revisions(
    current: &[aos_ability_model::ResourceRevision],
    desired: &[aos_ability_model::ResourceRevision],
) -> Vec<aos_ability_model::ResourceRevision> {
    let mut revisions: BTreeMap<_, _> = current
        .iter()
        .map(|revision| (revision.resource.clone(), revision.clone()))
        .collect();
    revisions.extend(
        desired
            .iter()
            .map(|revision| (revision.resource.clone(), revision.clone())),
    );
    revisions.into_values().collect()
}

pub(super) fn validate_input_document<T: VersionedDocument>(
    context: &ValidationContext,
    document: &T,
    field: &str,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<Sha256Digest> {
    for feature in document.required_features() {
        if !context.supported_features().contains(feature) {
            push_diagnostic(
                diagnostics,
                diagnostic(
                    DiagnosticCode::UnsupportedRequiredFeature,
                    DiagnosticClass::InvalidContract,
                    DiagnosticPhase::Binding,
                    vec![field.to_string(), "required_features".to_string()],
                    format!("unsupported required feature '{}'", feature.as_str()),
                ),
            );
        }
    }
    match document.content_digest() {
        Ok(digest) => Some(digest),
        Err(error) => {
            push_diagnostic(
                diagnostics,
                diagnostic(
                    DiagnosticCode::UnsupportedSchema,
                    DiagnosticClass::InvalidContract,
                    DiagnosticPhase::Binding,
                    vec![field.to_string()],
                    error.to_string(),
                ),
            );
            None
        }
    }
}
