//! Package manifests, required root requests, and provider implementation catalogs.

use super::*;

pub(super) fn validate_declared_root_requests(
    desired: &aos_ability_model::document::DesiredInstance,
    package: &PackageDocument,
    requests: &[aos_ability_model::BindingRequest],
    request_indices: &BTreeMap<RequestId, usize>,
    desired_index: usize,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if !desired.enabled {
        return;
    }
    for requirement in package
        .requirements
        .iter()
        .filter(|requirement| requirement.strength == RequirementStrength::Required)
    {
        let request_id = RequestId {
            consumer: desired.instance.clone(),
            scope: aos_ability_model::ScopePath::root(),
            key: requirement.alias.clone(),
        };
        let supplied = request_indices
            .get(&request_id)
            .map(|index| &requests[*index])
            .is_some_and(|request| {
                request.accepted_interfaces == requirement.accepted_interfaces
                    && request.methods == requirement.methods
                    && request.guarantees == requirement.guarantees
            });
        if !supplied {
            let mut item = diagnostic(
                DiagnosticCode::MissingReference,
                DiagnosticClass::UnsatisfiedObligation,
                DiagnosticPhase::Binding,
                vec![
                    "desired_state".to_string(),
                    "instances".to_string(),
                    desired_index.to_string(),
                ],
                "enabled package omits a required root ability request from desired state"
                    .to_string(),
            );
            item.request = Some(request_id);
            push_diagnostic(diagnostics, item);
        }
    }
}

pub(super) fn validate_package_document(
    context: &ValidationContext,
    package: &PackageDocument,
    index: usize,
    diagnostics: &mut Vec<Diagnostic>,
) -> PackageProviderIndex {
    let mut package_index = PackageProviderIndex::default();
    let root = SchemaPath::root()
        .child("packages")
        .child(index.to_string());
    check_order_by(
        &package.artifacts,
        |left, right| left.content.cmp(&right.content),
        "packages.artifacts",
        diagnostics,
    );
    check_order_by(
        &package.exports,
        |left, right| left.name.cmp(&right.name),
        "packages.exports",
        diagnostics,
    );
    check_order_by(
        &package.requirements,
        |left, right| left.alias.cmp(&right.alias),
        "packages.requirements",
        diagnostics,
    );
    check_order_by(
        &package.implementation.providers,
        |left, right| left.interface.cmp(&right.interface),
        "packages.implementation.providers",
        diagnostics,
    );
    check_strict_order(&package.ownership, &root.child("ownership"), diagnostics);

    let mut implementations = BTreeSet::new();
    for (provider_index, provider) in package.implementation.providers.iter().enumerate() {
        let provider_root = root
            .child("implementation")
            .child("providers")
            .child(provider_index.to_string());
        if context.interface(&provider.interface).is_none() {
            push_diagnostic(
                diagnostics,
                diagnostic(
                    DiagnosticCode::MissingReference,
                    DiagnosticClass::IncompatibleInterface,
                    DiagnosticPhase::Binding,
                    provider_root.components().to_vec(),
                    "package provider interface is absent from the validated catalog".to_string(),
                ),
            );
        }
        check_order_by(
            &provider.requirements,
            |left, right| left.alias.cmp(&right.alias),
            "packages.implementation.providers.requirements",
            diagnostics,
        );
        for (requirement_index, requirement) in provider.requirements.iter().enumerate() {
            validate_requirement(
                context,
                requirement,
                &provider_root
                    .child("requirements")
                    .child(requirement_index.to_string()),
                diagnostics,
            );
        }
        check_strict_order(
            &provider.owns_resource_kinds,
            &provider_root.child("owns_resource_kinds"),
            diagnostics,
        );
        match provider.descriptor_digest() {
            Ok(descriptor) => {
                if !implementations.insert(descriptor) {
                    push_diagnostic(
                        diagnostics,
                        diagnostic(
                            DiagnosticCode::DuplicateIdentity,
                            DiagnosticClass::InvalidContract,
                            DiagnosticPhase::Binding,
                            provider_root.components().to_vec(),
                            "package contains duplicate provider implementation descriptors"
                                .to_string(),
                        ),
                    );
                }
                package_index
                    .providers
                    .entry((provider.interface.clone(), descriptor))
                    .or_insert(provider_index);
            }
            Err(error) => push_diagnostic(
                diagnostics,
                diagnostic(
                    DiagnosticCode::LimitExceeded,
                    DiagnosticClass::InvalidContract,
                    DiagnosticPhase::Binding,
                    provider_root.components().to_vec(),
                    error.to_string(),
                ),
            ),
        }
    }
    for (requirement_index, requirement) in package.requirements.iter().enumerate() {
        validate_requirement(
            context,
            requirement,
            &root
                .child("requirements")
                .child(requirement_index.to_string()),
            diagnostics,
        );
    }
    for (export_index, export) in package.exports.iter().enumerate() {
        if context.interface(&export.interface).is_none()
            || !package_index
                .providers
                .contains_key(&(export.interface.clone(), export.implementation))
        {
            push_diagnostic(
                diagnostics,
                diagnostic(
                    DiagnosticCode::MissingReference,
                    DiagnosticClass::IncompatibleInterface,
                    DiagnosticPhase::Binding,
                    root.child("exports")
                        .child(export_index.to_string())
                        .components()
                        .to_vec(),
                    "package export lacks a matching exact interface implementation".to_string(),
                ),
            );
        }
        package_index
            .exports
            .insert((export.interface.clone(), export.implementation));
    }
    package_index
}

fn validate_requirement(
    context: &ValidationContext,
    requirement: &RequirementDeclaration,
    path: &SchemaPath,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if requirement.accepted_interfaces.is_empty() {
        push_diagnostic(
            diagnostics,
            diagnostic(
                DiagnosticCode::BindingInterfaceMismatch,
                DiagnosticClass::IncompatibleInterface,
                DiagnosticPhase::Binding,
                path.child("accepted_interfaces").components().to_vec(),
                "package requirement must name at least one exact accepted interface".to_string(),
            ),
        );
    }
    check_strict_order(
        &requirement.accepted_interfaces,
        &path.child("accepted_interfaces"),
        diagnostics,
    );
    check_strict_order(&requirement.methods, &path.child("methods"), diagnostics);
    check_strict_order(
        &requirement.guarantees,
        &path.child("guarantees"),
        diagnostics,
    );
    for interface in &requirement.accepted_interfaces {
        if context.interface(interface).is_none() {
            push_diagnostic(
                diagnostics,
                diagnostic(
                    DiagnosticCode::MissingReference,
                    DiagnosticClass::IncompatibleInterface,
                    DiagnosticPhase::Binding,
                    path.child("accepted_interfaces").components().to_vec(),
                    "package requirement interface is absent from the validated catalog"
                        .to_string(),
                ),
            );
        }
    }
    let fallback_is_valid = matches!(requirement.strength, RequirementStrength::Advisory)
        == requirement.fallback.is_some();
    if !fallback_is_valid {
        push_diagnostic(
            diagnostics,
            diagnostic(
                DiagnosticCode::BindingInterfaceMismatch,
                DiagnosticClass::InvalidContract,
                DiagnosticPhase::Binding,
                path.child("fallback").components().to_vec(),
                "exactly advisory requirements must declare fallback behavior".to_string(),
            ),
        );
    }
    if let Some(fallback) = &requirement.fallback {
        validate_requirement_fallback(context, requirement, fallback, path, diagnostics);
    }
}

fn validate_requirement_fallback(
    context: &ValidationContext,
    requirement: &RequirementDeclaration,
    fallback: &aos_ability_model::RequirementFallback,
    path: &SchemaPath,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for interface_key in &requirement.accepted_interfaces {
        let Some(interface) = context.interface(interface_key) else {
            continue;
        };
        if fallback.outputs.len() != interface.interface.outputs.len()
            || fallback
                .outputs
                .keys()
                .any(|output| !interface.interface.outputs.contains_key(output))
        {
            push_diagnostic(
                diagnostics,
                diagnostic(
                    DiagnosticCode::ValueTypeMismatch,
                    DiagnosticClass::IncompatibleInterface,
                    DiagnosticPhase::Binding,
                    path.child("fallback")
                        .child("outputs")
                        .components()
                        .to_vec(),
                    "advisory fallback must supply every exact accepted-interface output"
                        .to_string(),
                ),
            );
            continue;
        }
        for (output, value) in &fallback.outputs {
            let Some(descriptor) = interface.interface.outputs.get(output) else {
                continue;
            };
            if descriptor.visibility != aos_ability_model::ValueVisibility::Public
                || schema_requires_authority(&descriptor.schema)
            {
                push_diagnostic(
                    diagnostics,
                    diagnostic(
                        DiagnosticCode::ResourceScopeEscape,
                        DiagnosticClass::Unauthorized,
                        DiagnosticPhase::Binding,
                        path.child("fallback")
                            .child("outputs")
                            .child(output.as_str())
                            .components()
                            .to_vec(),
                        "literal advisory fallback cannot synthesize protected or authority-bearing output"
                            .to_string(),
                    ),
                );
                continue;
            }
            let expression = aos_ability_model::ValueExpression::Literal {
                value: value.clone(),
            };
            if let Err(errors) = crate::schema::validate_value(&descriptor.schema, &expression) {
                for mut item in errors.into_diagnostics() {
                    let mut prefixed = path
                        .child("fallback")
                        .child("outputs")
                        .child(output.as_str())
                        .components()
                        .to_vec();
                    prefixed.extend(item.path);
                    item.path = prefixed;
                    item.phase = DiagnosticPhase::Binding;
                    push_diagnostic(diagnostics, item);
                }
            }
        }
    }
}

fn schema_requires_authority(schema: &aos_ability_model::ValueSchema) -> bool {
    let mut stack = vec![schema];
    while let Some(schema) = stack.pop() {
        match schema {
            aos_ability_model::ValueSchema::ArtifactReference
            | aos_ability_model::ValueSchema::ResourceReference
            | aos_ability_model::ValueSchema::ProviderAssignment
            | aos_ability_model::ValueSchema::OperationResultReference => return true,
            aos_ability_model::ValueSchema::List { element, .. }
            | aos_ability_model::ValueSchema::Map { value: element, .. }
            | aos_ability_model::ValueSchema::Optional { value: element } => stack.push(element),
            aos_ability_model::ValueSchema::Record { fields, .. } => stack.extend(fields.values()),
            aos_ability_model::ValueSchema::TaggedUnion { variants, .. } => {
                stack.extend(variants.values())
            }
            aos_ability_model::ValueSchema::Boolean
            | aos_ability_model::ValueSchema::Integer { .. }
            | aos_ability_model::ValueSchema::String { .. }
            | aos_ability_model::ValueSchema::StringEnum { .. } => {}
        }
    }
    false
}
