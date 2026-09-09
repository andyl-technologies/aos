//! Typed aggregate-output and nested-reference validation for pure composition.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};

use aos_ability_model::{
    AccessMode, AggregateOutput, AggregateOutputReference, ArtifactReference, AuthorityGrant,
    Binding, Diagnostic, DiagnosticClass, DiagnosticCode, DiagnosticPhase, InstanceId, ResourceId,
    ResourceReference, ResourceRevision, ValueExpression, ValueSchema, ValueVisibility,
};
use serde::Serialize;
use serde_json::Value;

use crate::ValidationErrors;
use crate::authority::grant_permits;
use crate::graph::{ValidationContext, diagnostic};
use crate::schema::{SchemaPath, validate_composition_value};

pub(crate) fn validate_composed_output(
    context: &ValidationContext,
    provider: &InstanceId,
    output: &AggregateOutput,
    outputs: &[AggregateOutput],
    bindings: &[Binding],
    resources: &[ResourceRevision],
    artifacts: &[ArtifactReference],
    root_authority: Option<(&AuthorityGrant, aos_ability_model::ResourceLifetime)>,
) -> Result<(), ValidationErrors> {
    preflight_projection_inputs(output, outputs, bindings, resources, artifacts).map_err(
        |message| {
            single_diagnostic(
                DiagnosticCode::LimitExceeded,
                DiagnosticClass::InvalidContract,
                message,
            )
        },
    )?;
    if !outputs.iter().any(|candidate| candidate == output) {
        return Err(single_diagnostic(
            DiagnosticCode::ResourceScopeEscape,
            DiagnosticClass::Unauthorized,
            "validated aggregate output differs from its exact desired output entry",
        ));
    }
    if output.aggregate.provider != *provider {
        return Err(single_diagnostic(
            DiagnosticCode::ResourceScopeEscape,
            DiagnosticClass::Unauthorized,
            "aggregate output belongs to a different provider instance",
        ));
    }
    let Some(interface) = context.interface(&output.interface) else {
        return Err(single_diagnostic(
            DiagnosticCode::MissingReference,
            DiagnosticClass::IncompatibleInterface,
            "aggregate output interface is absent from the validated catalog",
        ));
    };
    if !interface.interface.outputs.contains_key(&output.port) {
        return Err(single_diagnostic(
            DiagnosticCode::MissingReference,
            DiagnosticClass::IncompatibleInterface,
            "aggregate output port is absent from its exact interface",
        ));
    }

    let resources: BTreeSet<_> = resources
        .iter()
        .map(|revision| revision.resource.clone())
        .collect();
    let artifact_index: BTreeMap<_, _> = artifacts
        .iter()
        .map(|artifact| (artifact.content, artifact))
        .collect();
    validate_projection_graph(
        context,
        provider,
        output,
        outputs,
        bindings,
        &resources,
        &artifact_index,
        root_authority,
    )
    .map_err(|message| {
        single_diagnostic(
            DiagnosticCode::ResourceScopeEscape,
            DiagnosticClass::Unauthorized,
            message,
        )
    })
}

#[allow(clippy::too_many_arguments)]
fn validate_projection_graph(
    context: &ValidationContext,
    recipient: &InstanceId,
    root: &AggregateOutput,
    outputs: &[AggregateOutput],
    bindings: &[Binding],
    resources: &BTreeSet<ResourceId>,
    artifacts: &BTreeMap<aos_contract::Sha256Digest, &ArtifactReference>,
    root_authority: Option<(&AuthorityGrant, aos_ability_model::ResourceLifetime)>,
) -> Result<(), &'static str> {
    let output_index: BTreeMap<_, _> = outputs
        .iter()
        .enumerate()
        .map(|(index, output)| {
            (
                (
                    output.aggregate.clone(),
                    output.interface.clone(),
                    output.port.clone(),
                ),
                index,
            )
        })
        .collect();
    if output_index.len() != outputs.len() {
        return Err("desired aggregate outputs contain a duplicate qualified identity");
    }
    let root_key = (
        root.aggregate.clone(),
        root.interface.clone(),
        root.port.clone(),
    );
    let Some(root_index) = output_index.get(&root_key).copied() else {
        return Err("validated aggregate output is absent from its desired output set");
    };
    if outputs[root_index] != *root {
        return Err("validated aggregate output differs from its exact desired output entry");
    }
    let recipient_lifetime = context
        .interface(&root.interface)
        .and_then(|interface| interface.interface.outputs.get(&root.port))
        .map(|descriptor| descriptor.lifetime)
        .ok_or("validated aggregate output names an unknown interface port")?;

    enum Visit {
        Enter(usize),
        Exit(usize),
    }
    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    let mut stack = vec![Visit::Enter(root_index)];
    let mut traversed_edges = 0_u32;
    while let Some(visit) = stack.pop() {
        let index = match visit {
            Visit::Exit(index) => {
                visiting.remove(&index);
                visited.insert(index);
                continue;
            }
            Visit::Enter(index) => index,
        };
        if visited.contains(&index) {
            continue;
        }
        if !visiting.insert(index) {
            return Err("aggregate output projection graph contains a cycle");
        }
        if visited.len().saturating_add(visiting.len())
            > aos_ability_model::ABILITY_LIMITS_V1.max_graph_nodes as usize
        {
            return Err("aggregate output projection graph exceeds the node limit");
        }
        stack.push(Visit::Exit(index));

        let output = &outputs[index];
        let descriptor = context
            .interface(&output.interface)
            .and_then(|interface| interface.interface.outputs.get(&output.port))
            .ok_or("aggregate output projection names an unknown interface port")?;
        let references = RefCell::new(Vec::new());
        let collect = |expected: &ValueSchema,
                       reference: &AggregateOutputReference,
                       _path: &SchemaPath,
                       _diagnostics: &mut Vec<Diagnostic>| {
            references
                .borrow_mut()
                .push((expected.clone(), reference.clone()));
        };
        validate_composition_value(&descriptor.schema, &output.value, &collect)
            .map_err(|_| "aggregate output projection violates its declared schema")?;
        let references = references.into_inner();
        authorize_expression(
            context,
            recipient,
            bindings,
            &descriptor.schema,
            &output.value,
            resources,
            artifacts,
            recipient_lifetime,
            root_authority,
        )?;

        traversed_edges = traversed_edges.saturating_add(references.len() as u32);
        if traversed_edges > aos_ability_model::ABILITY_LIMITS_V1.max_graph_edges {
            return Err("aggregate output projection graph exceeds the edge limit");
        }
        for (expected, reference) in references.into_iter().rev() {
            let key = (
                reference.aggregate.clone(),
                reference.interface.clone(),
                reference.port.clone(),
            );
            let target_index = output_index
                .get(&key)
                .copied()
                .ok_or("aggregate output reference names no exact desired output")?;
            let target = &outputs[target_index];
            let target_descriptor = context
                .interface(&target.interface)
                .and_then(|interface| interface.interface.outputs.get(&target.port))
                .ok_or("aggregate output reference names an unknown interface port")?;
            let routed = target.aggregate.provider == output.aggregate.provider
                || bindings.iter().any(|binding| {
                    binding.caller_grant.principal == output.aggregate.provider
                        && binding.provider == target.aggregate.provider
                        && binding.interface == target.interface
                });
            if !routed
                || target_descriptor.schema != expected
                || target_descriptor.phase > descriptor.phase
                || target_descriptor.lifetime < descriptor.lifetime
                || (target_descriptor.visibility == ValueVisibility::Private
                    && target.aggregate.provider != output.aggregate.provider)
            {
                return Err(
                    "aggregate output reference exceeds its selected lower binding, schema, phase, lifetime, or visibility",
                );
            }
            stack.push(Visit::Enter(target_index));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn authorize_expression(
    context: &ValidationContext,
    principal: &InstanceId,
    bindings: &[Binding],
    schema: &ValueSchema,
    expression: &ValueExpression,
    resources: &BTreeSet<ResourceId>,
    artifacts: &BTreeMap<aos_contract::Sha256Digest, &ArtifactReference>,
    maximum_lifetime: aos_ability_model::ResourceLifetime,
    root_authority: Option<(&AuthorityGrant, aos_ability_model::ResourceLifetime)>,
) -> Result<(), &'static str> {
    let schema = unwrap_optional(schema, expression);
    match expression {
        ValueExpression::Literal { value } => authorize_literal(
            context,
            principal,
            bindings,
            schema,
            value.as_json(),
            resources,
            artifacts,
            maximum_lifetime,
            root_authority,
        ),
        ValueExpression::ArtifactReference { reference } => {
            authorize_artifact(reference, artifacts)
        }
        ValueExpression::ResourceReference { reference } => authorize_resource(
            context,
            principal,
            bindings,
            reference,
            resources,
            maximum_lifetime,
            root_authority,
        ),
        ValueExpression::AggregateOutput { .. } => Ok(()),
        ValueExpression::OperationResult { .. } => {
            Err("runtime operation result cannot appear in a pure aggregate output")
        }
        ValueExpression::List { items } => {
            let ValueSchema::List { element, .. } = schema else {
                return Ok(());
            };
            for item in items {
                authorize_expression(
                    context,
                    principal,
                    bindings,
                    element,
                    item,
                    resources,
                    artifacts,
                    maximum_lifetime,
                    root_authority,
                )?;
            }
            Ok(())
        }
        ValueExpression::Object { fields } => match schema {
            ValueSchema::Map { value, .. } => {
                for field in fields.values() {
                    authorize_expression(
                        context,
                        principal,
                        bindings,
                        value,
                        field,
                        resources,
                        artifacts,
                        maximum_lifetime,
                        root_authority,
                    )?;
                }
                Ok(())
            }
            ValueSchema::Record {
                fields: schemas, ..
            } => {
                for (name, field) in fields {
                    if let Some(field_schema) = schemas.get(name.as_str()) {
                        authorize_expression(
                            context,
                            principal,
                            bindings,
                            field_schema,
                            field,
                            resources,
                            artifacts,
                            maximum_lifetime,
                            root_authority,
                        )?;
                    }
                }
                Ok(())
            }
            ValueSchema::TaggedUnion { tag, variants } => {
                let selected = fields
                    .get(tag.as_str())
                    .and_then(|value| match value {
                        ValueExpression::Literal { value } => value.as_json().as_str(),
                        _ => None,
                    })
                    .and_then(|tag_value| variants.get(tag_value));
                if let Some(selected) = selected {
                    authorize_expression(
                        context,
                        principal,
                        bindings,
                        selected,
                        expression,
                        resources,
                        artifacts,
                        maximum_lifetime,
                        root_authority,
                    )?;
                }
                Ok(())
            }
            _ => Ok(()),
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn authorize_literal(
    context: &ValidationContext,
    principal: &InstanceId,
    bindings: &[Binding],
    schema: &ValueSchema,
    value: &Value,
    resources: &BTreeSet<ResourceId>,
    artifacts: &BTreeMap<aos_contract::Sha256Digest, &ArtifactReference>,
    maximum_lifetime: aos_ability_model::ResourceLifetime,
    root_authority: Option<(&AuthorityGrant, aos_ability_model::ResourceLifetime)>,
) -> Result<(), &'static str> {
    match (schema, value) {
        (ValueSchema::Optional { .. }, Value::Null) => Ok(()),
        (ValueSchema::Optional { value: nested }, value) => authorize_literal(
            context,
            principal,
            bindings,
            nested,
            value,
            resources,
            artifacts,
            maximum_lifetime,
            root_authority,
        ),
        (ValueSchema::ArtifactReference, value) => {
            let reference = serde_json::from_value::<ArtifactReference>(value.clone())
                .map_err(|_| "typed artifact reference is malformed")?;
            authorize_artifact(&reference, artifacts)
        }
        (ValueSchema::ResourceReference, value) => {
            let reference = serde_json::from_value::<ResourceReference>(value.clone())
                .map_err(|_| "typed resource reference is malformed")?;
            authorize_resource(
                context,
                principal,
                bindings,
                &reference,
                resources,
                maximum_lifetime,
                root_authority,
            )
        }
        (ValueSchema::List { element, .. }, Value::Array(items)) => {
            for item in items {
                authorize_literal(
                    context,
                    principal,
                    bindings,
                    element,
                    item,
                    resources,
                    artifacts,
                    maximum_lifetime,
                    root_authority,
                )?;
            }
            Ok(())
        }
        (ValueSchema::Map { value: nested, .. }, Value::Object(fields)) => {
            for value in fields.values() {
                authorize_literal(
                    context,
                    principal,
                    bindings,
                    nested,
                    value,
                    resources,
                    artifacts,
                    maximum_lifetime,
                    root_authority,
                )?;
            }
            Ok(())
        }
        (
            ValueSchema::Record {
                fields: schemas, ..
            },
            Value::Object(fields),
        ) => {
            for (name, value) in fields {
                if let Some(field_schema) = schemas.get(name.as_str()) {
                    authorize_literal(
                        context,
                        principal,
                        bindings,
                        field_schema,
                        value,
                        resources,
                        artifacts,
                        maximum_lifetime,
                        root_authority,
                    )?;
                }
            }
            Ok(())
        }
        (ValueSchema::TaggedUnion { tag, variants }, Value::Object(fields)) => {
            let selected = fields
                .get(tag.as_str())
                .and_then(Value::as_str)
                .and_then(|tag_value| variants.get(tag_value));
            if let Some(selected) = selected {
                authorize_literal(
                    context,
                    principal,
                    bindings,
                    selected,
                    value,
                    resources,
                    artifacts,
                    maximum_lifetime,
                    root_authority,
                )?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn authorize_artifact(
    reference: &ArtifactReference,
    artifacts: &BTreeMap<aos_contract::Sha256Digest, &ArtifactReference>,
) -> Result<(), &'static str> {
    if artifacts.get(&reference.content).copied() == Some(reference) {
        Ok(())
    } else {
        Err("aggregate output artifact is absent from its retained provider and binding catalog")
    }
}

fn authorize_resource(
    context: &ValidationContext,
    principal: &InstanceId,
    bindings: &[Binding],
    reference: &ResourceReference,
    resources: &BTreeSet<ResourceId>,
    maximum_lifetime: aos_ability_model::ResourceLifetime,
    root_authority: Option<(&AuthorityGrant, aos_ability_model::ResourceLifetime)>,
) -> Result<(), &'static str> {
    if !resources.contains(&reference.resource) || context.interface(&reference.interface).is_none()
    {
        return Err(
            "aggregate output resource is absent from the checked catalog or desired state",
        );
    }
    if reference.lifetime < maximum_lifetime {
        return Err("aggregate output outlives its referenced resource");
    }
    let binding_authorized = bindings.iter().any(|binding| {
        let grant = selected_projection_grant(binding, principal, reference);
        grant.is_some_and(|grant| {
            maximum_lifetime <= binding.lifetime
                && reference.lifetime <= binding.lifetime
                && grant_permits(grant, &reference.resource, AccessMode::Read, None)
                && reference.operations.iter().all(|operation| {
                    grant_permits(
                        grant,
                        &reference.resource,
                        AccessMode::Read,
                        Some(operation),
                    )
                })
        })
    });
    let root_authorized = root_authority.is_some_and(|(grant, lifetime)| {
        grant.principal == *principal
            && reference.resource.provider == *principal
            && maximum_lifetime <= lifetime
            && reference.lifetime <= lifetime
            && grant_permits(grant, &reference.resource, AccessMode::Read, None)
            && reference.operations.iter().all(|operation| {
                grant_permits(
                    grant,
                    &reference.resource,
                    AccessMode::Read,
                    Some(operation),
                )
            })
    });
    if binding_authorized || root_authorized {
        Ok(())
    } else {
        Err("aggregate output resource exceeds its selected lower-binding authority")
    }
}

#[derive(Serialize)]
struct BorrowedProjectionInputs<'a> {
    root: &'a AggregateOutput,
    outputs: &'a [AggregateOutput],
    bindings: &'a [Binding],
    resources: &'a [ResourceRevision],
    artifacts: &'a [ArtifactReference],
}

fn preflight_projection_inputs(
    root: &AggregateOutput,
    outputs: &[AggregateOutput],
    bindings: &[Binding],
    resources: &[ResourceRevision],
    artifacts: &[ArtifactReference],
) -> Result<(), &'static str> {
    let limits = aos_ability_model::ABILITY_LIMITS_V1;
    if [
        outputs.len(),
        bindings.len(),
        resources.len(),
        artifacts.len(),
    ]
    .into_iter()
    .any(|count| count > limits.max_graph_nodes as usize)
    {
        return Err("aggregate output validation input exceeds the graph entry limit");
    }
    let collection_items = outputs
        .len()
        .saturating_add(bindings.len())
        .saturating_add(resources.len())
        .saturating_add(artifacts.len());
    if collection_items as u64 > limits.max_collection_items {
        return Err("aggregate output validation input exceeds the collection item limit");
    }
    preflight_projection_expressions(root, outputs, collection_items as u64)?;

    let input = BorrowedProjectionInputs {
        root,
        outputs,
        bindings,
        resources,
        artifacts,
    };
    let mut writer = ProjectionSizeWriter::new(limits.max_document_bytes);
    serde_json::to_writer(&mut writer, &input).map_err(|_| {
        if writer.exceeded {
            "aggregate output validation input exceeds the encoded byte limit"
        } else {
            "aggregate output validation input cannot be encoded"
        }
    })
}

fn preflight_projection_expressions(
    root: &AggregateOutput,
    outputs: &[AggregateOutput],
    initial_items: u64,
) -> Result<(), &'static str> {
    let limits = aos_ability_model::ABILITY_LIMITS_V1;
    let mut item_count = initial_items;
    let mut stack = Vec::with_capacity(outputs.len().saturating_add(1));
    stack.push((&root.value, 1_u32));
    stack.extend(outputs.iter().map(|output| (&output.value, 1_u32)));
    while let Some((expression, depth)) = stack.pop() {
        if depth > limits.max_structural_depth {
            return Err("aggregate output validation input exceeds the structural depth limit");
        }
        let child_depth = depth.saturating_add(1);
        match expression {
            ValueExpression::List { items } => {
                item_count = item_count.saturating_add(items.len() as u64);
                if item_count > limits.max_collection_items {
                    return Err(
                        "aggregate output validation input exceeds the collection item limit",
                    );
                }
                stack.extend(items.iter().map(|item| (item, child_depth)));
            }
            ValueExpression::Object { fields } => {
                item_count = item_count.saturating_add(fields.len() as u64);
                if item_count > limits.max_collection_items {
                    return Err(
                        "aggregate output validation input exceeds the collection item limit",
                    );
                }
                stack.extend(fields.values().map(|field| (field, child_depth)));
            }
            ValueExpression::Literal { .. }
            | ValueExpression::ArtifactReference { .. }
            | ValueExpression::ResourceReference { .. }
            | ValueExpression::AggregateOutput { .. }
            | ValueExpression::OperationResult { .. } => {}
        }
    }
    Ok(())
}

struct ProjectionSizeWriter {
    remaining: u64,
    exceeded: bool,
}

impl ProjectionSizeWriter {
    const fn new(limit: u64) -> Self {
        Self {
            remaining: limit,
            exceeded: false,
        }
    }
}

impl Write for ProjectionSizeWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() as u64 > self.remaining {
            self.exceeded = true;
            return Err(io::Error::other(
                "projection input exceeds its encoded byte limit",
            ));
        }
        self.remaining -= bytes.len() as u64;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn selected_projection_grant<'a>(
    binding: &'a Binding,
    principal: &InstanceId,
    reference: &ResourceReference,
) -> Option<&'a AuthorityGrant> {
    if binding.interface != reference.interface || binding.provider != reference.resource.provider {
        return None;
    }
    if binding.caller_grant.principal == *principal {
        Some(&binding.caller_grant)
    } else if binding.provider == *principal
        && binding.mediation_allowed
        && binding.provider_grant.principal == *principal
    {
        Some(&binding.provider_grant)
    } else {
        None
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

fn single_diagnostic(
    code: DiagnosticCode,
    class: DiagnosticClass,
    message: impl Into<String>,
) -> ValidationErrors {
    ValidationErrors::new(vec![diagnostic(
        code,
        class,
        DiagnosticPhase::Binding,
        vec!["outputs".to_string()],
        message.into(),
    )])
}
