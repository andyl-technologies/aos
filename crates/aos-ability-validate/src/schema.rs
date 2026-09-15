//! Pure validation of schema definitions and literal or symbolic values.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use aos_ability_model::{
    ABILITY_LIMITS_V1, ArtifactReference, Diagnostic, DiagnosticClass, DiagnosticCode,
    DiagnosticPhase, InterfaceName, JsonValueKind, LocalKey, OperationResultReference,
    ProviderAssignment, ResourceReference, StringSyntax, ValueExpression, ValueSchema,
};
use serde::Serialize;
use serde_json::Value;

use crate::ValidationErrors;
use crate::error::push_diagnostic;
use aos_contract::limits::BoundedWriter;

/// Identifies one position inside a method parameter or output schema.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SchemaPath(Vec<String>);

impl SchemaPath {
    /// Constructs the root schema path.
    #[must_use]
    pub const fn root() -> Self {
        Self(Vec::new())
    }

    /// Returns a child path without modifying the current path.
    #[must_use]
    pub fn child(&self, component: impl Into<String>) -> Self {
        let mut components = self.0.clone();
        components.push(component.into());
        Self(components)
    }

    /// Returns the path components in traversal order.
    #[must_use]
    pub fn components(&self) -> &[String] {
        &self.0
    }
}

impl fmt::Display for SchemaPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            return formatter.write_str("/");
        }
        for component in &self.0 {
            formatter.write_str("/")?;
            formatter.write_str(&component.replace('~', "~0").replace('/', "~1"))?;
        }
        Ok(())
    }
}

/// Validates one explicit literal or symbolic expression against a closed schema.
///
/// Operation-result expressions require an effect-graph context and are
/// rejected by this standalone entry point. [`crate::ValidationContext`]
/// resolves them against exact producer ports while checking an effect plan.
///
/// # Errors
///
/// Returns structured diagnostics when the expression does not satisfy the
/// schema or contains a result reference without a graph context.
pub fn validate_value(
    schema: &ValueSchema,
    expression: &ValueExpression,
) -> Result<(), ValidationErrors> {
    validate_value_with_literal_source(schema, expression, LiteralSource::Authored, None)
}

pub(crate) fn validate_materialized_value(
    schema: &ValueSchema,
    value: &aos_ability_model::AbilityValue,
) -> Result<(), ValidationErrors> {
    validate_value_with_literal_source(
        schema,
        &ValueExpression::Literal {
            value: value.clone(),
        },
        LiteralSource::Materialized,
        None,
    )
}

pub(crate) fn validate_composition_value(
    schema: &ValueSchema,
    expression: &ValueExpression,
    aggregate_validator: &AggregateReferenceValidator<'_>,
) -> Result<(), ValidationErrors> {
    validate_value_with_literal_source(
        schema,
        expression,
        LiteralSource::Authored,
        Some(aggregate_validator),
    )
}

fn validate_value_with_literal_source(
    schema: &ValueSchema,
    expression: &ValueExpression,
    literal_source: LiteralSource,
    aggregate_validator: Option<&AggregateReferenceValidator<'_>>,
) -> Result<(), ValidationErrors> {
    let mut diagnostics = Vec::new();
    if !schema.is_within_limits(
        ABILITY_LIMITS_V1.max_structural_depth,
        ABILITY_LIMITS_V1.max_collection_items,
    ) {
        push_diagnostic(
            &mut diagnostics,
            schema_diagnostic(
                DiagnosticCode::LimitExceeded,
                &SchemaPath::root(),
                "schema exceeds the version-1 structural limits".to_string(),
            ),
        );
        return Err(ValidationErrors::new(diagnostics));
    }
    if !expression.is_within_limits(
        ABILITY_LIMITS_V1.max_structural_depth,
        ABILITY_LIMITS_V1.max_collection_items,
    ) {
        push_diagnostic(
            &mut diagnostics,
            schema_diagnostic(
                DiagnosticCode::LimitExceeded,
                &SchemaPath::root(),
                "expression exceeds the version-1 structural limits".to_string(),
            ),
        );
        return Err(ValidationErrors::new(diagnostics));
    }
    if let Err(message) = validate_standalone_size_and_strings(schema, expression) {
        push_diagnostic(
            &mut diagnostics,
            schema_diagnostic(DiagnosticCode::LimitExceeded, &SchemaPath::root(), message),
        );
        return Err(ValidationErrors::new(diagnostics));
    }

    validate_schema_definition(
        schema,
        &SchemaPath::root(),
        1,
        ABILITY_LIMITS_V1.max_structural_depth,
        ABILITY_LIMITS_V1.max_string_bytes,
        ABILITY_LIMITS_V1.max_collection_items,
        &mut diagnostics,
    );
    validate_expression_with_literal_source(
        schema,
        expression,
        &SchemaPath::root(),
        &mut diagnostics,
        None,
        aggregate_validator,
        literal_source,
    );
    if diagnostics.is_empty() {
        Ok(())
    } else {
        Err(ValidationErrors::new(diagnostics))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LiteralSource {
    Authored,
    Materialized,
}

#[path = "schema_definition.rs"]
mod definition;
pub(crate) use definition::validate_schema_definition;

pub(crate) type ResultReferenceValidator<'a> = dyn Fn(
        &ValueSchema,
        &aos_ability_model::OperationResultReference,
        &SchemaPath,
        &mut Vec<Diagnostic>,
    ) + 'a;

pub(crate) type AggregateReferenceValidator<'a> = dyn Fn(
        &ValueSchema,
        &aos_ability_model::AggregateOutputReference,
        &SchemaPath,
        &mut Vec<Diagnostic>,
    ) + 'a;

pub(crate) fn validate_expression(
    schema: &ValueSchema,
    expression: &ValueExpression,
    path: &SchemaPath,
    diagnostics: &mut Vec<Diagnostic>,
    result_validator: Option<&ResultReferenceValidator<'_>>,
    aggregate_validator: Option<&AggregateReferenceValidator<'_>>,
) {
    validate_expression_with_literal_source(
        schema,
        expression,
        path,
        diagnostics,
        result_validator,
        aggregate_validator,
        LiteralSource::Authored,
    );
}

fn validate_expression_with_literal_source(
    schema: &ValueSchema,
    expression: &ValueExpression,
    path: &SchemaPath,
    diagnostics: &mut Vec<Diagnostic>,
    result_validator: Option<&ResultReferenceValidator<'_>>,
    aggregate_validator: Option<&AggregateReferenceValidator<'_>>,
    literal_source: LiteralSource,
) {
    if let ValueExpression::OperationResult { reference } = expression {
        if let Some(validate_result) = result_validator {
            validate_result(schema, reference, path, diagnostics);
        } else {
            push_diagnostic(
                diagnostics,
                schema_diagnostic(
                    DiagnosticCode::MissingReference,
                    path,
                    "operation result requires an effect-graph validation context".to_string(),
                ),
            );
        }
        return;
    }
    if let ValueExpression::AggregateOutput { reference } = expression {
        if let Some(validate_aggregate) = aggregate_validator {
            validate_aggregate(schema, reference, path, diagnostics);
        } else {
            push_diagnostic(
                diagnostics,
                schema_diagnostic(
                    DiagnosticCode::MissingReference,
                    path,
                    "aggregate output requires a composition validation context".to_string(),
                ),
            );
        }
        return;
    }

    if let ValueSchema::Optional { value } = schema {
        if matches!(expression, ValueExpression::Literal { value } if value.as_json().is_null()) {
            return;
        }
        validate_expression_with_literal_source(
            value,
            expression,
            path,
            diagnostics,
            result_validator,
            aggregate_validator,
            literal_source,
        );
        return;
    }
    if let ValueSchema::DisjointUnion { variants } = schema {
        let kind = expression_json_kind(expression);
        let variant = kind.and_then(|kind| {
            variants
                .iter()
                .find(|variant| variant.top_level_json_kind() == Some(kind))
        });
        if let Some(variant) = variant {
            validate_expression_with_literal_source(
                variant,
                expression,
                path,
                diagnostics,
                result_validator,
                aggregate_validator,
                literal_source,
            );
        } else {
            push_type_mismatch(path, expression_kind(expression), schema, diagnostics);
        }
        return;
    }

    match expression {
        ValueExpression::Literal { value } => {
            validate_literal(schema, value.as_json(), path, diagnostics, literal_source);
        }
        ValueExpression::List { items } => {
            let ValueSchema::List {
                element, max_items, ..
            } = schema
            else {
                push_type_mismatch(path, "list expression", schema, diagnostics);
                return;
            };
            if items.len() as u64 > *max_items {
                push_diagnostic(
                    diagnostics,
                    schema_diagnostic(
                        DiagnosticCode::LimitExceeded,
                        path,
                        format!("list contains more than {max_items} items"),
                    ),
                );
            }
            for (index, item) in items.iter().enumerate() {
                validate_expression_with_literal_source(
                    element,
                    item,
                    &path.child(index.to_string()),
                    diagnostics,
                    result_validator,
                    aggregate_validator,
                    literal_source,
                );
            }
        }
        ValueExpression::Object { fields } => {
            validate_expression_object(
                schema,
                fields,
                path,
                diagnostics,
                result_validator,
                aggregate_validator,
                literal_source,
            );
        }
        ValueExpression::PathWithin { base, .. } => {
            if !matches!(
                schema,
                ValueSchema::String {
                    syntax: Some(StringSyntax::ExecutionPathV1),
                    ..
                }
            ) {
                push_type_mismatch(path, "path-within expression", schema, diagnostics);
                return;
            }
            validate_expression_with_literal_source(
                schema,
                base,
                &path.child("base"),
                diagnostics,
                result_validator,
                aggregate_validator,
                literal_source,
            );
        }
        ValueExpression::ArtifactReference { .. } => {
            if !matches!(schema, ValueSchema::ArtifactReference) {
                push_type_mismatch(path, "artifact reference", schema, diagnostics);
            }
        }
        ValueExpression::ResourceReference { reference } => {
            if !matches!(schema, ValueSchema::ResourceReference) {
                push_type_mismatch(path, "resource reference", schema, diagnostics);
            }
            check_sorted_unique(&reference.operations, path, diagnostics);
        }
        ValueExpression::AggregateOutput { .. } => {}
        ValueExpression::OperationResult { .. } => {}
    }
}

fn validate_literal(
    schema: &ValueSchema,
    value: &Value,
    path: &SchemaPath,
    diagnostics: &mut Vec<Diagnostic>,
    literal_source: LiteralSource,
) {
    match (schema, value) {
        (ValueSchema::Boolean, Value::Bool(_)) => {}
        (ValueSchema::Integer { minimum, maximum }, Value::Number(number)) => {
            if number
                .as_i64()
                .is_none_or(|integer| integer < *minimum || integer > *maximum)
            {
                push_diagnostic(
                    diagnostics,
                    schema_diagnostic(
                        DiagnosticCode::ValueTypeMismatch,
                        path,
                        format!("integer is outside [{minimum}, {maximum}]"),
                    ),
                );
            }
        }
        (ValueSchema::String { max_length, syntax }, Value::String(text)) => {
            validate_string(text, *max_length, *syntax, path, diagnostics);
        }
        (ValueSchema::StringEnum { values }, Value::String(text)) => {
            if values.binary_search(text).is_err() {
                push_diagnostic(
                    diagnostics,
                    schema_diagnostic(
                        DiagnosticCode::ValueTypeMismatch,
                        path,
                        "string is not a declared enumeration value".to_string(),
                    ),
                );
            }
        }
        (
            ValueSchema::List {
                element,
                max_items,
                unique,
                canonical_order,
            },
            Value::Array(items),
        ) => {
            if items.len() as u64 > *max_items {
                push_diagnostic(
                    diagnostics,
                    schema_diagnostic(
                        DiagnosticCode::LimitExceeded,
                        path,
                        format!("list contains more than {max_items} items"),
                    ),
                );
            }
            validate_list_constraints(items, *unique, *canonical_order, path, diagnostics);
            for (index, item) in items.iter().enumerate() {
                validate_json_literal(
                    element,
                    item,
                    &path.child(index.to_string()),
                    diagnostics,
                    literal_source,
                );
            }
        }
        (
            ValueSchema::Map {
                key,
                value,
                max_entries,
            },
            Value::Object(entries),
        ) => {
            validate_literal_map(
                key,
                value,
                *max_entries,
                entries,
                path,
                diagnostics,
                literal_source,
            );
        }
        (
            ValueSchema::Record {
                fields,
                optional_fields,
            },
            Value::Object(values),
        ) => validate_literal_record(
            fields,
            optional_fields,
            values,
            path,
            diagnostics,
            literal_source,
        ),
        (
            ValueSchema::DocumentRecord {
                fields,
                optional_fields,
                ..
            },
            Value::Object(values),
        ) => validate_literal_document_record(
            fields,
            optional_fields,
            values,
            path,
            diagnostics,
            literal_source,
        ),
        (ValueSchema::TaggedUnion { tag, variants }, Value::Object(values)) => {
            validate_literal_tagged_union(tag, variants, values, path, diagnostics, literal_source);
        }
        (ValueSchema::DisjointUnion { variants }, value) => {
            let kind = json_value_kind(value);
            let variant = kind.and_then(|kind| {
                variants
                    .iter()
                    .find(|variant| variant.top_level_json_kind() == Some(kind))
            });
            if let Some(variant) = variant {
                validate_json_literal(variant, value, path, diagnostics, literal_source);
            } else {
                push_type_mismatch(path, json_kind(value), schema, diagnostics);
            }
        }
        (ValueSchema::Optional { .. }, Value::Null) => {}
        (ValueSchema::Optional { value }, other) => {
            validate_json_literal(value, other, path, diagnostics, literal_source);
        }
        (ValueSchema::ArtifactReference, value) => {
            let _ = validate_typed_reference::<ArtifactReference>(
                value,
                "artifact reference",
                path,
                diagnostics,
            );
        }
        (ValueSchema::ResourceReference, value) => {
            if let Some(reference) = validate_typed_reference::<ResourceReference>(
                value,
                "resource reference",
                path,
                diagnostics,
            ) {
                check_sorted_unique(&reference.operations, path, diagnostics);
            }
        }
        (ValueSchema::ProviderAssignment, value) => {
            if literal_source == LiteralSource::Authored {
                push_diagnostic(
                    diagnostics,
                    schema_diagnostic(
                        DiagnosticCode::MissingReference,
                        path,
                        "provider assignment must originate from an observed operation output"
                            .to_string(),
                    ),
                );
            } else {
                let _ = validate_typed_reference::<ProviderAssignment>(
                    value,
                    "provider assignment",
                    path,
                    diagnostics,
                );
            }
        }
        (ValueSchema::OperationResultReference, value) => {
            let _ = validate_typed_reference::<OperationResultReference>(
                value,
                "operation result reference",
                path,
                diagnostics,
            );
        }
        _ => push_type_mismatch(path, json_kind(value), schema, diagnostics),
    }
}

fn validate_list_constraints(
    items: &[Value],
    unique: bool,
    canonical_order: bool,
    path: &SchemaPath,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if !unique && !canonical_order {
        return;
    }
    let encodings = items
        .iter()
        .map(aos_contract::canonical::to_vec)
        .collect::<Result<Vec<_>, _>>();
    let Ok(encodings) = encodings else {
        push_diagnostic(
            diagnostics,
            schema_diagnostic(
                DiagnosticCode::ValueTypeMismatch,
                path,
                "list elements cannot be canonically encoded".to_string(),
            ),
        );
        return;
    };
    if unique {
        let distinct = encodings.iter().collect::<std::collections::BTreeSet<_>>();
        if distinct.len() != encodings.len() {
            push_diagnostic(
                diagnostics,
                schema_diagnostic(
                    DiagnosticCode::ValueTypeMismatch,
                    path,
                    "list elements must be unique".to_string(),
                ),
            );
        }
    }
    if canonical_order && !encodings.windows(2).all(|pair| pair[0] < pair[1]) {
        push_diagnostic(
            diagnostics,
            schema_diagnostic(
                DiagnosticCode::ValueTypeMismatch,
                path,
                "list elements must be in strict canonical order".to_string(),
            ),
        );
    }
}

fn validate_typed_reference<T>(
    value: &Value,
    name: &str,
    path: &SchemaPath,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<T>
where
    T: serde::de::DeserializeOwned,
{
    match T::deserialize(value) {
        Ok(reference) => Some(reference),
        Err(_) => {
            push_diagnostic(
                diagnostics,
                schema_diagnostic(
                    DiagnosticCode::ValueTypeMismatch,
                    path,
                    format!("value is not an exact closed {name}"),
                ),
            );
            None
        }
    }
}

fn validate_standalone_size_and_strings(
    schema: &ValueSchema,
    expression: &ValueExpression,
) -> Result<(), String> {
    validate_encoded_size(schema, "schema")?;
    validate_encoded_size(expression, "expression")?;

    let mut stack = vec![expression];
    while let Some(current) = stack.pop() {
        match current {
            ValueExpression::List { items } => stack.extend(items),
            ValueExpression::Object { fields } => {
                if fields
                    .keys()
                    .any(|name| name.len() as u64 > ABILITY_LIMITS_V1.max_string_bytes)
                {
                    return Err(
                        "expression object member exceeds the version-1 string byte limit"
                            .to_string(),
                    );
                }
                stack.extend(fields.values());
            }
            ValueExpression::PathWithin { base, .. } => stack.push(base),
            ValueExpression::ArtifactReference { reference } => {
                if reference.store_path.len() as u64 > ABILITY_LIMITS_V1.max_string_bytes {
                    return Err(
                        "artifact store path exceeds the version-1 string byte limit".to_string(),
                    );
                }
            }
            ValueExpression::Literal { .. }
            | ValueExpression::ResourceReference { .. }
            | ValueExpression::AggregateOutput { .. }
            | ValueExpression::OperationResult { .. } => {}
        }
    }

    Ok(())
}

fn validate_encoded_size(value: &impl Serialize, name: &str) -> Result<(), String> {
    let mut writer = BoundedWriter::new(
        ABILITY_LIMITS_V1.max_document_bytes,
        "encoded value exceeds its configured bound",
    );
    serde_json::to_writer(&mut writer, value).map_err(|_| {
        if writer.exceeded() {
            format!("{name} exceeds the version-1 encoded byte limit")
        } else {
            format!("{name} cannot be encoded for bounded validation")
        }
    })
}

fn validate_json_literal(
    schema: &ValueSchema,
    value: &Value,
    path: &SchemaPath,
    diagnostics: &mut Vec<Diagnostic>,
    literal_source: LiteralSource,
) {
    validate_literal(schema, value, path, diagnostics, literal_source);
}

fn validate_expression_object(
    schema: &ValueSchema,
    fields: &std::collections::BTreeMap<String, ValueExpression>,
    path: &SchemaPath,
    diagnostics: &mut Vec<Diagnostic>,
    result_validator: Option<&ResultReferenceValidator<'_>>,
    aggregate_validator: Option<&AggregateReferenceValidator<'_>>,
    literal_source: LiteralSource,
) {
    match schema {
        ValueSchema::Map {
            key,
            value,
            max_entries,
        } => {
            if fields.len() as u64 > *max_entries {
                push_diagnostic(
                    diagnostics,
                    schema_diagnostic(
                        DiagnosticCode::LimitExceeded,
                        path,
                        format!("map contains more than {max_entries} entries"),
                    ),
                );
            }
            for (name, field_value) in fields {
                if !name.is_ascii() {
                    push_diagnostic(
                        diagnostics,
                        schema_diagnostic(
                            DiagnosticCode::ValueTypeMismatch,
                            &path.child(name),
                            "object member name is outside the canonical ASCII key dialect"
                                .to_string(),
                        ),
                    );
                }
                validate_string(name, key.max_length, key.syntax, path, diagnostics);
                validate_expression_with_literal_source(
                    value,
                    field_value,
                    &path.child(name),
                    diagnostics,
                    result_validator,
                    aggregate_validator,
                    literal_source,
                );
            }
        }
        ValueSchema::Record {
            fields: schema_fields,
            optional_fields,
        } => {
            validate_expression_record(
                schema_fields,
                optional_fields,
                fields,
                path,
                diagnostics,
                result_validator,
                aggregate_validator,
                literal_source,
            );
        }
        ValueSchema::DocumentRecord {
            fields: schema_fields,
            optional_fields,
            ..
        } => {
            validate_expression_document_record(
                schema_fields,
                optional_fields,
                fields,
                path,
                diagnostics,
                result_validator,
                aggregate_validator,
                literal_source,
            );
        }
        ValueSchema::TaggedUnion { tag, variants } => {
            let Some(ValueExpression::Literal { value }) = fields.get(tag.as_str()) else {
                push_diagnostic(
                    diagnostics,
                    schema_diagnostic(
                        DiagnosticCode::ValueTypeMismatch,
                        &path.child(tag.as_str()),
                        "tagged union discriminator must be a literal string".to_string(),
                    ),
                );
                return;
            };
            let Some(tag_value) = value.as_json().as_str() else {
                push_type_mismatch(
                    &path.child(tag.as_str()),
                    json_kind(value.as_json()),
                    schema,
                    diagnostics,
                );
                return;
            };
            let Some(variant) = variants.get(tag_value) else {
                push_diagnostic(
                    diagnostics,
                    schema_diagnostic(
                        DiagnosticCode::ValueTypeMismatch,
                        &path.child(tag.as_str()),
                        "tag does not select a declared variant".to_string(),
                    ),
                );
                return;
            };
            validate_expression_object(
                variant,
                fields,
                path,
                diagnostics,
                result_validator,
                aggregate_validator,
                literal_source,
            );
        }
        _ => push_type_mismatch(path, "object expression", schema, diagnostics),
    }
}

fn validate_expression_record(
    schema_fields: &BTreeMap<LocalKey, ValueSchema>,
    optional_fields: &[LocalKey],
    values: &std::collections::BTreeMap<String, ValueExpression>,
    path: &SchemaPath,
    diagnostics: &mut Vec<Diagnostic>,
    result_validator: Option<&ResultReferenceValidator<'_>>,
    aggregate_validator: Option<&AggregateReferenceValidator<'_>>,
    literal_source: LiteralSource,
) {
    let optional: BTreeSet<&str> = optional_fields.iter().map(LocalKey::as_str).collect();
    let declared: BTreeSet<&str> = schema_fields.keys().map(LocalKey::as_str).collect();

    for (name, field_schema) in schema_fields {
        let value = values.get(name.as_str());
        if let Some(value) = value {
            validate_expression_with_literal_source(
                field_schema,
                value,
                &path.child(name.as_str()),
                diagnostics,
                result_validator,
                aggregate_validator,
                literal_source,
            );
        } else if !optional.contains(name.as_str()) {
            push_diagnostic(
                diagnostics,
                schema_diagnostic(
                    DiagnosticCode::ValueTypeMismatch,
                    &path.child(name.as_str()),
                    "required record field is missing".to_string(),
                ),
            );
        }
    }
    for name in values.keys() {
        if !declared.contains(name.as_str()) {
            push_diagnostic(
                diagnostics,
                schema_diagnostic(
                    DiagnosticCode::ValueTypeMismatch,
                    &path.child(name),
                    "record contains an unsupported field".to_string(),
                ),
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_expression_document_record(
    schema_fields: &BTreeMap<String, ValueSchema>,
    optional_fields: &[String],
    values: &BTreeMap<String, ValueExpression>,
    path: &SchemaPath,
    diagnostics: &mut Vec<Diagnostic>,
    result_validator: Option<&ResultReferenceValidator<'_>>,
    aggregate_validator: Option<&AggregateReferenceValidator<'_>>,
    literal_source: LiteralSource,
) {
    let optional: BTreeSet<&str> = optional_fields.iter().map(String::as_str).collect();

    for (name, field_schema) in schema_fields {
        if let Some(value) = values.get(name) {
            validate_expression_with_literal_source(
                field_schema,
                value,
                &path.child(name),
                diagnostics,
                result_validator,
                aggregate_validator,
                literal_source,
            );
        } else if !optional.contains(name.as_str()) {
            push_diagnostic(
                diagnostics,
                schema_diagnostic(
                    DiagnosticCode::ValueTypeMismatch,
                    &path.child(name),
                    "required document field is missing".to_string(),
                ),
            );
        }
    }
    for name in values.keys() {
        if !schema_fields.contains_key(name) {
            push_diagnostic(
                diagnostics,
                schema_diagnostic(
                    DiagnosticCode::ValueTypeMismatch,
                    &path.child(name),
                    "document contains an unsupported field".to_string(),
                ),
            );
        }
    }
}

fn validate_literal_map(
    key: &aos_ability_model::StringConstraint,
    value_schema: &ValueSchema,
    max_entries: u64,
    entries: &serde_json::Map<String, Value>,
    path: &SchemaPath,
    diagnostics: &mut Vec<Diagnostic>,
    literal_source: LiteralSource,
) {
    if entries.len() as u64 > max_entries {
        push_diagnostic(
            diagnostics,
            schema_diagnostic(
                DiagnosticCode::LimitExceeded,
                path,
                format!("map contains more than {max_entries} entries"),
            ),
        );
    }
    for (name, value) in entries {
        validate_string(name, key.max_length, key.syntax, path, diagnostics);
        validate_json_literal(
            value_schema,
            value,
            &path.child(name),
            diagnostics,
            literal_source,
        );
    }
}

fn validate_literal_record(
    fields: &BTreeMap<LocalKey, ValueSchema>,
    optional_fields: &[LocalKey],
    values: &serde_json::Map<String, Value>,
    path: &SchemaPath,
    diagnostics: &mut Vec<Diagnostic>,
    literal_source: LiteralSource,
) {
    let optional: BTreeSet<&str> = optional_fields.iter().map(LocalKey::as_str).collect();
    let declared: BTreeSet<&str> = fields.keys().map(LocalKey::as_str).collect();

    for (name, field_schema) in fields {
        if let Some(value) = values.get(name.as_str()) {
            validate_json_literal(
                field_schema,
                value,
                &path.child(name.as_str()),
                diagnostics,
                literal_source,
            );
        } else if !optional.contains(name.as_str()) {
            push_diagnostic(
                diagnostics,
                schema_diagnostic(
                    DiagnosticCode::ValueTypeMismatch,
                    &path.child(name.as_str()),
                    "required record field is missing".to_string(),
                ),
            );
        }
    }
    for name in values.keys() {
        if !declared.contains(name.as_str()) {
            push_diagnostic(
                diagnostics,
                schema_diagnostic(
                    DiagnosticCode::ValueTypeMismatch,
                    &path.child(name),
                    "record contains an unsupported field".to_string(),
                ),
            );
        }
    }
}

fn validate_literal_document_record(
    fields: &BTreeMap<String, ValueSchema>,
    optional_fields: &[String],
    values: &serde_json::Map<String, Value>,
    path: &SchemaPath,
    diagnostics: &mut Vec<Diagnostic>,
    literal_source: LiteralSource,
) {
    let optional: BTreeSet<&str> = optional_fields.iter().map(String::as_str).collect();

    for (name, field_schema) in fields {
        if let Some(value) = values.get(name) {
            validate_json_literal(
                field_schema,
                value,
                &path.child(name),
                diagnostics,
                literal_source,
            );
        } else if !optional.contains(name.as_str()) {
            push_diagnostic(
                diagnostics,
                schema_diagnostic(
                    DiagnosticCode::ValueTypeMismatch,
                    &path.child(name),
                    "required document field is missing".to_string(),
                ),
            );
        }
    }
    for name in values.keys() {
        if !fields.contains_key(name) {
            push_diagnostic(
                diagnostics,
                schema_diagnostic(
                    DiagnosticCode::ValueTypeMismatch,
                    &path.child(name),
                    "document contains an unsupported field".to_string(),
                ),
            );
        }
    }
}

fn validate_document_key(
    name: &str,
    max_length: u64,
    path: &SchemaPath,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if name.is_empty()
        || name.len() as u64 > max_length
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ')
    {
        push_diagnostic(
            diagnostics,
            schema_diagnostic(
                DiagnosticCode::ValueTypeMismatch,
                &path.child("fields").child(name),
                "document field name must be a non-empty bounded printable ASCII string"
                    .to_string(),
            ),
        );
    }
}

fn validate_literal_tagged_union(
    tag: &LocalKey,
    variants: &std::collections::BTreeMap<LocalKey, ValueSchema>,
    values: &serde_json::Map<String, Value>,
    path: &SchemaPath,
    diagnostics: &mut Vec<Diagnostic>,
    literal_source: LiteralSource,
) {
    let Some(Value::String(tag_value)) = values.get(tag.as_str()) else {
        push_diagnostic(
            diagnostics,
            schema_diagnostic(
                DiagnosticCode::ValueTypeMismatch,
                &path.child(tag.as_str()),
                "tagged union discriminator must be a string".to_string(),
            ),
        );
        return;
    };
    let Some(variant) = variants.get(tag_value.as_str()) else {
        push_diagnostic(
            diagnostics,
            schema_diagnostic(
                DiagnosticCode::ValueTypeMismatch,
                &path.child(tag.as_str()),
                "tag does not select a declared variant".to_string(),
            ),
        );
        return;
    };
    let ValueSchema::Record {
        fields,
        optional_fields,
    } = variant
    else {
        push_type_mismatch(path, "tagged-union variant", variant, diagnostics);
        return;
    };
    validate_literal_record(
        fields,
        optional_fields,
        values,
        path,
        diagnostics,
        literal_source,
    );
}

fn validate_tagged_variant(
    tag: &LocalKey,
    variant_name: &LocalKey,
    variant: &ValueSchema,
    path: &SchemaPath,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let ValueSchema::Record {
        fields,
        optional_fields,
    } = variant
    else {
        push_diagnostic(
            diagnostics,
            schema_diagnostic(
                DiagnosticCode::ValueTypeMismatch,
                &path.child("variants").child(variant_name.as_str()),
                "tagged-union variant must be a closed record".to_string(),
            ),
        );
        return;
    };
    let Some((_, ValueSchema::StringEnum { values })) =
        fields.iter().find(|(name, _)| *name == tag)
    else {
        push_diagnostic(
            diagnostics,
            schema_diagnostic(
                DiagnosticCode::MissingReference,
                &path.child("variants").child(variant_name.as_str()),
                "variant record must declare the discriminator as a string enumeration".to_string(),
            ),
        );
        return;
    };
    if optional_fields.contains(tag)
        || values.len() != 1
        || values
            .first()
            .is_none_or(|value| value != variant_name.as_str())
    {
        push_diagnostic(
            diagnostics,
            schema_diagnostic(
                DiagnosticCode::ValueTypeMismatch,
                &path.child("variants").child(variant_name.as_str()),
                "variant discriminator must be required and equal its variant name".to_string(),
            ),
        );
    }
}

fn validate_string(
    value: &str,
    max_length: u64,
    syntax: Option<StringSyntax>,
    path: &SchemaPath,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if value.len() as u64 > max_length {
        push_diagnostic(
            diagnostics,
            schema_diagnostic(
                DiagnosticCode::LimitExceeded,
                path,
                format!("string exceeds the {max_length} byte schema limit"),
            ),
        );
    }
    let syntax_matches = match syntax {
        None => true,
        Some(StringSyntax::LocalKeyV1) => LocalKey::new(value).is_ok(),
        Some(StringSyntax::QualifiedNameV1) => InterfaceName::new(value).is_ok(),
        Some(StringSyntax::ExecutionPathV1) => is_execution_path(value),
    };
    if !syntax_matches {
        push_diagnostic(
            diagnostics,
            schema_diagnostic(
                DiagnosticCode::ValueTypeMismatch,
                path,
                "string does not satisfy its named syntax profile".to_string(),
            ),
        );
    }
}

fn is_execution_path(path: &str) -> bool {
    path.starts_with('/')
        && !path.contains('\0')
        && (path == "/"
            || path[1..]
                .split('/')
                .all(|component| !component.is_empty() && component != "." && component != ".."))
}

fn validate_declared_string_bound(
    value: u64,
    maximum: u64,
    path: &SchemaPath,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if value == 0 || value > maximum {
        push_diagnostic(
            diagnostics,
            schema_diagnostic(
                DiagnosticCode::LimitExceeded,
                path,
                format!("declared string bound must be in 1..={maximum}"),
            ),
        );
    }
}

fn validate_declared_collection_bound(
    value: u64,
    maximum: u64,
    path: &SchemaPath,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if value > maximum {
        push_diagnostic(
            diagnostics,
            schema_diagnostic(
                DiagnosticCode::LimitExceeded,
                path,
                format!("declared collection bound must be in 0..={maximum}"),
            ),
        );
    }
}

fn check_sorted_unique<T>(values: &[T], path: &SchemaPath, diagnostics: &mut Vec<Diagnostic>)
where
    T: Ord,
{
    if !values.windows(2).all(|pair| pair[0] < pair[1]) {
        push_diagnostic(
            diagnostics,
            schema_diagnostic(
                DiagnosticCode::NonCanonicalOrder,
                path,
                "values must be strictly sorted without duplicates".to_string(),
            ),
        );
    }
}

fn push_type_mismatch(
    path: &SchemaPath,
    actual: &str,
    schema: &ValueSchema,
    diagnostics: &mut Vec<Diagnostic>,
) {
    push_diagnostic(
        diagnostics,
        schema_diagnostic(
            DiagnosticCode::ValueTypeMismatch,
            path,
            format!(
                "{actual} does not satisfy the {} schema",
                schema_kind(schema)
            ),
        ),
    );
}

fn schema_diagnostic(code: DiagnosticCode, path: &SchemaPath, message: String) -> Diagnostic {
    Diagnostic {
        code,
        class: DiagnosticClass::InvalidContract,
        phase: DiagnosticPhase::Schema,
        path: path.components().to_vec(),
        message,
        request: None,
        operation: None,
        resource: None,
        live_effect_may_have_occurred: false,
    }
}

fn json_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "Boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn json_value_kind(value: &Value) -> Option<JsonValueKind> {
    JsonValueKind::of_json(value)
}

fn expression_json_kind(expression: &ValueExpression) -> Option<JsonValueKind> {
    expression.top_level_json_kind()
}

fn expression_kind(expression: &ValueExpression) -> &'static str {
    match expression {
        ValueExpression::Literal { value } => json_kind(value.as_json()),
        ValueExpression::List { .. } => "array",
        ValueExpression::PathWithin { .. } => "string",
        ValueExpression::Object { .. }
        | ValueExpression::ArtifactReference { .. }
        | ValueExpression::ResourceReference { .. } => "object",
        ValueExpression::AggregateOutput { .. } => "aggregate output",
        ValueExpression::OperationResult { .. } => "operation result",
    }
}

fn schema_kind(schema: &ValueSchema) -> &'static str {
    match schema {
        ValueSchema::Boolean => "Boolean",
        ValueSchema::Integer { .. } => "integer",
        ValueSchema::String { .. } => "string",
        ValueSchema::StringEnum { .. } => "string-enum",
        ValueSchema::List { .. } => "list",
        ValueSchema::Map { .. } => "map",
        ValueSchema::Record { .. } => "record",
        ValueSchema::DocumentRecord { .. } => "document-record",
        ValueSchema::TaggedUnion { .. } => "tagged-union",
        ValueSchema::DisjointUnion { .. } => "disjoint-union",
        ValueSchema::Optional { .. } => "optional",
        ValueSchema::ArtifactReference => "artifact-reference",
        ValueSchema::ResourceReference => "resource-reference",
        ValueSchema::ProviderAssignment => "provider-assignment",
        ValueSchema::OperationResultReference => "operation-result-reference",
    }
}

#[cfg(test)]
#[path = "schema_tests.rs"]
mod tests;
