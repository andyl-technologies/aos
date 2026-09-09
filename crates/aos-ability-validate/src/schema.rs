//! Pure validation of schema definitions and literal or symbolic values.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{self, Write};

use aos_ability_model::{
    ABILITY_LIMITS_V1, ArtifactReference, Diagnostic, DiagnosticClass, DiagnosticCode,
    DiagnosticPhase, InterfaceName, LocalKey, OperationResultReference, ProviderAssignment,
    ResourceReference, StringSyntax, ValueExpression, ValueSchema,
};
use serde::Serialize;
use serde_json::Value;

use crate::ValidationErrors;
use crate::error::push_diagnostic;

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

pub(crate) fn validate_schema_definition(
    schema: &ValueSchema,
    path: &SchemaPath,
    depth: u32,
    max_depth: u32,
    max_string_bytes: u64,
    max_collection_items: u64,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if depth > max_depth {
        push_diagnostic(
            diagnostics,
            schema_diagnostic(
                DiagnosticCode::LimitExceeded,
                path,
                format!("schema exceeds the structural depth limit of {max_depth}"),
            ),
        );
        return;
    }

    match schema {
        ValueSchema::Boolean
        | ValueSchema::ArtifactReference
        | ValueSchema::ResourceReference
        | ValueSchema::ProviderAssignment
        | ValueSchema::OperationResultReference => {}
        ValueSchema::Integer { minimum, maximum } => {
            const MAX_EXACT_INTEGER: i64 = 9_007_199_254_740_991;
            if minimum > maximum || *minimum < -MAX_EXACT_INTEGER || *maximum > MAX_EXACT_INTEGER {
                push_diagnostic(
                    diagnostics,
                    schema_diagnostic(
                        DiagnosticCode::ValueTypeMismatch,
                        path,
                        "integer bounds must be ordered and within the exact I-JSON range"
                            .to_string(),
                    ),
                );
            }
        }
        ValueSchema::String { max_length, .. } => {
            validate_declared_string_bound(*max_length, max_string_bytes, path, diagnostics);
        }
        ValueSchema::StringEnum { values } => {
            validate_declared_collection_bound(
                values.len() as u64,
                max_collection_items,
                path,
                diagnostics,
            );
            if values.is_empty() {
                push_diagnostic(
                    diagnostics,
                    schema_diagnostic(
                        DiagnosticCode::ValueTypeMismatch,
                        path,
                        "string enumeration must contain at least one value".to_string(),
                    ),
                );
            }
            check_sorted_unique(values, path, diagnostics);
            for (index, value) in values.iter().enumerate() {
                if value.len() as u64 > max_string_bytes {
                    push_diagnostic(
                        diagnostics,
                        schema_diagnostic(
                            DiagnosticCode::LimitExceeded,
                            &path.child(index.to_string()),
                            "enumeration value exceeds the string byte limit".to_string(),
                        ),
                    );
                }
            }
        }
        ValueSchema::List { element, max_items } => {
            validate_declared_collection_bound(*max_items, max_collection_items, path, diagnostics);
            validate_schema_definition(
                element,
                &path.child("element"),
                depth.saturating_add(1),
                max_depth,
                max_string_bytes,
                max_collection_items,
                diagnostics,
            );
        }
        ValueSchema::Map {
            key,
            value,
            max_entries,
        } => {
            validate_declared_collection_bound(
                *max_entries,
                max_collection_items,
                path,
                diagnostics,
            );
            validate_declared_string_bound(
                key.max_length,
                max_string_bytes,
                &path.child("key"),
                diagnostics,
            );
            validate_schema_definition(
                value,
                &path.child("value"),
                depth.saturating_add(1),
                max_depth,
                max_string_bytes,
                max_collection_items,
                diagnostics,
            );
        }
        ValueSchema::Record {
            fields,
            optional_fields,
        } => {
            validate_declared_collection_bound(
                fields.len().saturating_add(optional_fields.len()) as u64,
                max_collection_items,
                path,
                diagnostics,
            );
            check_sorted_unique(optional_fields, &path.child("optional_fields"), diagnostics);
            for optional in optional_fields {
                if !fields.contains_key(optional) {
                    push_diagnostic(
                        diagnostics,
                        schema_diagnostic(
                            DiagnosticCode::MissingReference,
                            &path.child("optional_fields").child(optional.as_str()),
                            "optional field is not declared in fields".to_string(),
                        ),
                    );
                }
            }
            for (name, field) in fields {
                validate_schema_definition(
                    field,
                    &path.child("fields").child(name.as_str()),
                    depth.saturating_add(1),
                    max_depth,
                    max_string_bytes,
                    max_collection_items,
                    diagnostics,
                );
            }
        }
        ValueSchema::TaggedUnion { tag, variants } => {
            validate_declared_collection_bound(
                variants.len() as u64,
                max_collection_items,
                path,
                diagnostics,
            );
            if variants.is_empty() {
                push_diagnostic(
                    diagnostics,
                    schema_diagnostic(
                        DiagnosticCode::ValueTypeMismatch,
                        path,
                        "tagged union must contain at least one variant".to_string(),
                    ),
                );
            }
            for (variant_name, variant) in variants {
                validate_tagged_variant(tag, variant_name, variant, path, diagnostics);
                validate_schema_definition(
                    variant,
                    &path.child("variants").child(variant_name.as_str()),
                    depth.saturating_add(1),
                    max_depth,
                    max_string_bytes,
                    max_collection_items,
                    diagnostics,
                );
            }
        }
        ValueSchema::Optional { value } => validate_schema_definition(
            value,
            &path.child("value"),
            depth.saturating_add(1),
            max_depth,
            max_string_bytes,
            max_collection_items,
            diagnostics,
        ),
    }
}

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

    match expression {
        ValueExpression::Literal { value } => {
            validate_literal(schema, value.as_json(), path, diagnostics, literal_source);
        }
        ValueExpression::List { items } => {
            let ValueSchema::List { element, max_items } = schema else {
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
        (ValueSchema::List { element, max_items }, Value::Array(items)) => {
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
        (ValueSchema::TaggedUnion { tag, variants }, Value::Object(values)) => {
            validate_literal_tagged_union(tag, variants, values, path, diagnostics, literal_source);
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
    let mut writer = CountingWriter::new(ABILITY_LIMITS_V1.max_document_bytes);
    serde_json::to_writer(&mut writer, value).map_err(|_| {
        if writer.exceeded {
            format!("{name} exceeds the version-1 encoded byte limit")
        } else {
            format!("{name} cannot be encoded for bounded validation")
        }
    })
}

struct CountingWriter {
    remaining: u64,
    exceeded: bool,
}

impl CountingWriter {
    const fn new(limit: u64) -> Self {
        Self {
            remaining: limit,
            exceeded: false,
        }
    }
}

impl Write for CountingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() as u64 > self.remaining {
            self.exceeded = true;
            return Err(io::Error::other(
                "encoded value exceeds its configured bound",
            ));
        }
        self.remaining -= bytes.len() as u64;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
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
    if value == 0 || value > maximum {
        push_diagnostic(
            diagnostics,
            schema_diagnostic(
                DiagnosticCode::LimitExceeded,
                path,
                format!("declared collection bound must be in 1..={maximum}"),
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

fn schema_kind(schema: &ValueSchema) -> &'static str {
    match schema {
        ValueSchema::Boolean => "Boolean",
        ValueSchema::Integer { .. } => "integer",
        ValueSchema::String { .. } => "string",
        ValueSchema::StringEnum { .. } => "string-enum",
        ValueSchema::List { .. } => "list",
        ValueSchema::Map { .. } => "map",
        ValueSchema::Record { .. } => "record",
        ValueSchema::TaggedUnion { .. } => "tagged-union",
        ValueSchema::Optional { .. } => "optional",
        ValueSchema::ArtifactReference => "artifact-reference",
        ValueSchema::ResourceReference => "resource-reference",
        ValueSchema::ProviderAssignment => "provider-assignment",
        ValueSchema::OperationResultReference => "operation-result-reference",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use aos_ability_model::AbilityValue;

    use super::*;

    fn literal(value: Value) -> ValueExpression {
        ValueExpression::Literal {
            value: AbilityValue::new(value).expect("valid canonical test value"),
        }
    }

    #[test]
    fn validates_nested_record_and_named_string_syntax() {
        let key = LocalKey::new("name").expect("valid test key");
        let schema = ValueSchema::Record {
            fields: BTreeMap::from([(
                key,
                ValueSchema::String {
                    max_length: 32,
                    syntax: Some(StringSyntax::QualifiedNameV1),
                },
            )]),
            optional_fields: Vec::new(),
        };
        let value = literal(serde_json::json!({"name": "nginx.virtual-host"}));

        assert!(validate_value(&schema, &value).is_ok());
    }

    #[test]
    fn rejects_missing_optional_encoding_and_unknown_record_fields() {
        let required = LocalKey::new("required").expect("valid test key");
        let schema = ValueSchema::Record {
            fields: BTreeMap::from([(required, ValueSchema::Boolean)]),
            optional_fields: Vec::new(),
        };
        let value = literal(serde_json::json!({"extra": true}));

        let errors = validate_value(&schema, &value).expect_err("invalid record must fail");
        assert_eq!(errors.diagnostics().len(), 2);
    }

    #[test]
    fn result_reference_is_never_inferred_from_literal_shape() {
        let schema = ValueSchema::Record {
            fields: BTreeMap::from([
                (
                    LocalKey::new("operation").expect("valid test key"),
                    ValueSchema::String {
                        max_length: 16,
                        syntax: None,
                    },
                ),
                (
                    LocalKey::new("output").expect("valid test key"),
                    ValueSchema::String {
                        max_length: 16,
                        syntax: None,
                    },
                ),
            ]),
            optional_fields: Vec::new(),
        };
        let value = literal(serde_json::json!({"operation": "prepare", "output": "path"}));

        assert!(validate_value(&schema, &value).is_ok());
    }

    #[test]
    fn optional_schema_accepts_an_explicit_null_literal() {
        let schema = ValueSchema::Optional {
            value: Box::new(ValueSchema::Boolean),
        };

        assert!(validate_value(&schema, &literal(Value::Null)).is_ok());
    }

    #[test]
    fn literal_resource_reference_rejects_noncanonical_operation_order() {
        let digest = format!("sha256:{}", "00".repeat(32));
        let value = literal(serde_json::json!({
            "interface": {
                "name": "test.resource",
                "abi": 1,
                "descriptor": digest,
            },
            "resource": {
                "provider": {
                    "environment": {
                        "authority": "test",
                        "key": "host",
                        "stage": "host",
                    },
                    "key": "provider",
                },
                "key": "resource",
            },
            "operations": ["write", "read"],
            "lifetime": "transaction",
        }));

        let errors = validate_value(&ValueSchema::ResourceReference, &value)
            .expect_err("unsorted typed reference operations must fail");
        assert!(
            errors
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == DiagnosticCode::NonCanonicalOrder)
        );
    }

    #[test]
    fn authored_provider_assignment_is_rejected_but_materialized_evidence_is_accepted() {
        let digest = format!("sha256:{}", "00".repeat(32));
        let assignment = AbilityValue::new(serde_json::json!({
            "provider": {
                "environment": {
                    "authority": "test",
                    "key": "host",
                    "stage": "host",
                },
                "key": "provider",
            },
            "interface": {
                "name": "test.provider",
                "abi": 1,
                "descriptor": digest,
            },
            "implementation": {
                "descriptor": digest,
                "artifact": {
                    "content": digest,
                    "store_path": "/nix/store/provider",
                    "nar_hash": digest,
                    "closure": digest,
                },
                "handler": "activate",
            },
            "incarnation": "fresh-incarnation",
        }))
        .expect("valid canonical provider assignment");
        let authored = ValueExpression::Literal {
            value: assignment.clone(),
        };

        let errors = validate_value(&ValueSchema::ProviderAssignment, &authored)
            .expect_err("authored assignment evidence must be rejected");
        assert!(
            errors
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == DiagnosticCode::MissingReference)
        );
        assert!(validate_materialized_value(&ValueSchema::ProviderAssignment, &assignment).is_ok());
    }
}
