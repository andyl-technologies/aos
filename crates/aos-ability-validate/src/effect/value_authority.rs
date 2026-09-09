//! Static nested artifact and resource authority validation.

use super::operation::grant_permits;
use super::*;

pub(super) fn validate_nested_authority(
    context: &ValidationContext,
    schema: &ValueSchema,
    expression: &ValueExpression,
    operation: &Operation,
    operation_index: usize,
    binding: &Binding,
    grant: Option<&AuthorityGrant>,
    artifacts: &ArtifactIndex,
    resources: &BTreeSet<ResourceId>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let schema = unwrap_optional(schema, expression);
    match expression {
        ValueExpression::Literal { value } => validate_literal_authority(
            context,
            schema,
            value.as_json(),
            operation,
            operation_index,
            binding,
            grant,
            artifacts,
            resources,
            diagnostics,
        ),
        ValueExpression::ArtifactReference { reference } => {
            validate_artifact_reference(
                reference,
                operation,
                operation_index,
                artifacts,
                diagnostics,
            );
        }
        ValueExpression::ResourceReference { reference } => validate_resource_reference(
            context,
            reference,
            operation,
            operation_index,
            binding,
            grant,
            resources,
            diagnostics,
        ),
        ValueExpression::OperationResult { .. } => {}
        ValueExpression::List { items } => {
            if let ValueSchema::List { element, .. } = schema {
                for item in items {
                    validate_nested_authority(
                        context,
                        element,
                        item,
                        operation,
                        operation_index,
                        binding,
                        grant,
                        artifacts,
                        resources,
                        diagnostics,
                    );
                }
            }
        }
        ValueExpression::Object { fields } => match schema {
            ValueSchema::Map { value, .. } => {
                for field in fields.values() {
                    validate_nested_authority(
                        context,
                        value,
                        field,
                        operation,
                        operation_index,
                        binding,
                        grant,
                        artifacts,
                        resources,
                        diagnostics,
                    );
                }
            }
            ValueSchema::Record {
                fields: schemas, ..
            } => {
                for (name, field) in fields {
                    if let Some(field_schema) = schemas.get(name.as_str()) {
                        validate_nested_authority(
                            context,
                            field_schema,
                            field,
                            operation,
                            operation_index,
                            binding,
                            grant,
                            artifacts,
                            resources,
                            diagnostics,
                        );
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
                    validate_nested_authority(
                        context,
                        selected,
                        expression,
                        operation,
                        operation_index,
                        binding,
                        grant,
                        artifacts,
                        resources,
                        diagnostics,
                    );
                }
            }
            _ => {}
        },
    }
}

fn unwrap_optional<'a>(
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
fn validate_literal_authority(
    context: &ValidationContext,
    schema: &ValueSchema,
    value: &Value,
    operation: &Operation,
    operation_index: usize,
    binding: &Binding,
    grant: Option<&AuthorityGrant>,
    artifacts: &ArtifactIndex,
    resources: &BTreeSet<ResourceId>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    match (schema, value) {
        (ValueSchema::Optional { .. }, Value::Null) => {}
        (ValueSchema::Optional { value: nested }, value) => validate_literal_authority(
            context,
            nested,
            value,
            operation,
            operation_index,
            binding,
            grant,
            artifacts,
            resources,
            diagnostics,
        ),
        (ValueSchema::ArtifactReference, value) => {
            if let Ok(reference) = serde_json::from_value::<ArtifactReference>(value.clone()) {
                validate_artifact_reference(
                    &reference,
                    operation,
                    operation_index,
                    artifacts,
                    diagnostics,
                );
            }
        }
        (ValueSchema::ResourceReference, value) => {
            if let Ok(reference) = serde_json::from_value::<ResourceReference>(value.clone()) {
                validate_resource_reference(
                    context,
                    &reference,
                    operation,
                    operation_index,
                    binding,
                    grant,
                    resources,
                    diagnostics,
                );
            }
        }
        (ValueSchema::List { element, .. }, Value::Array(items)) => {
            for item in items {
                validate_literal_authority(
                    context,
                    element,
                    item,
                    operation,
                    operation_index,
                    binding,
                    grant,
                    artifacts,
                    resources,
                    diagnostics,
                );
            }
        }
        (ValueSchema::Map { value: nested, .. }, Value::Object(fields)) => {
            for value in fields.values() {
                validate_literal_authority(
                    context,
                    nested,
                    value,
                    operation,
                    operation_index,
                    binding,
                    grant,
                    artifacts,
                    resources,
                    diagnostics,
                );
            }
        }
        (
            ValueSchema::Record {
                fields: schemas, ..
            },
            Value::Object(fields),
        ) => {
            for (name, value) in fields {
                if let Some(field_schema) = schemas.get(name.as_str()) {
                    validate_literal_authority(
                        context,
                        field_schema,
                        value,
                        operation,
                        operation_index,
                        binding,
                        grant,
                        artifacts,
                        resources,
                        diagnostics,
                    );
                }
            }
        }
        (ValueSchema::TaggedUnion { tag, variants }, Value::Object(fields)) => {
            if let Some(tag_value) = fields.get(tag.as_str()).and_then(Value::as_str) {
                if let Some(variant) = variants.get(tag_value) {
                    validate_literal_authority(
                        context,
                        variant,
                        value,
                        operation,
                        operation_index,
                        binding,
                        grant,
                        artifacts,
                        resources,
                        diagnostics,
                    );
                }
            }
        }
        _ => {}
    }
}

fn validate_artifact_reference(
    reference: &ArtifactReference,
    operation: &Operation,
    index: usize,
    artifacts: &ArtifactIndex,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if artifacts.get(&reference.content) != Some(reference) {
        push_operation_diagnostic(
            operation,
            index,
            DiagnosticCode::MissingReference,
            DiagnosticClass::Unauthorized,
            "artifact reference is absent from the effect plan's retained catalog".to_string(),
            diagnostics,
        );
    }
}

fn validate_resource_reference(
    context: &ValidationContext,
    reference: &ResourceReference,
    operation: &Operation,
    index: usize,
    binding: &Binding,
    grant: Option<&AuthorityGrant>,
    resources: &BTreeSet<ResourceId>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if context.interface(&reference.interface).is_none()
        || !resources.contains(&reference.resource)
        || reference.resource.provider != binding.provider
        || reference.lifetime > binding.lifetime
        || grant.is_none_or(|grant| {
            !grant_permits(grant, &reference.resource, AccessMode::Read, None)
                || reference.operations.iter().any(|requested| {
                    !grant_permits(
                        grant,
                        &reference.resource,
                        AccessMode::Read,
                        Some(requested),
                    )
                })
        })
    {
        push_operation_resource_diagnostic(
            operation,
            index,
            DiagnosticCode::ResourceScopeEscape,
            "nested resource reference is not authenticated by the catalog, plan, and grant"
                .to_string(),
            &reference.resource,
            diagnostics,
        );
    }
}
