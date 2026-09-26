//! Validation of authored schema definitions.

use super::*;

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
        | ValueSchema::TransactionBlobReference
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
        ValueSchema::List {
            element,
            max_items,
            unique,
            canonical_order,
        } => {
            validate_declared_collection_bound(*max_items, max_collection_items, path, diagnostics);
            if *canonical_order && !*unique {
                push_diagnostic(
                    diagnostics,
                    schema_diagnostic(
                        DiagnosticCode::ValueTypeMismatch,
                        path,
                        "canonical list ordering requires unique elements".to_string(),
                    ),
                );
            }
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
        ValueSchema::DocumentRecord {
            key_max_length,
            fields,
            optional_fields,
        } => {
            validate_declared_string_bound(
                *key_max_length,
                max_string_bytes,
                &path.child("key_max_length"),
                diagnostics,
            );
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
                            &path.child("optional_fields").child(optional),
                            "optional document field is not declared in fields".to_string(),
                        ),
                    );
                }
            }
            for (name, field) in fields {
                validate_document_key(name, *key_max_length, path, diagnostics);
                validate_schema_definition(
                    field,
                    &path.child("fields").child(name),
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
        ValueSchema::DisjointUnion { variants } => {
            validate_declared_collection_bound(
                variants.len() as u64,
                max_collection_items,
                path,
                diagnostics,
            );
            if variants.len() < 2 {
                push_diagnostic(
                    diagnostics,
                    schema_diagnostic(
                        DiagnosticCode::ValueTypeMismatch,
                        path,
                        "disjoint union must contain at least two variants".to_string(),
                    ),
                );
            }

            let mut previous_kind = None;
            for (index, variant) in variants.iter().enumerate() {
                let variant_path = path.child("variants").child(index.to_string());
                let kind = variant.top_level_json_kind();
                if kind.is_none() {
                    push_diagnostic(
                        diagnostics,
                        schema_diagnostic(
                            DiagnosticCode::ValueTypeMismatch,
                            &variant_path,
                            "disjoint-union variants must admit one top-level JSON kind"
                                .to_string(),
                        ),
                    );
                } else if previous_kind.is_some_and(|previous| Some(previous) >= kind) {
                    push_diagnostic(
                        diagnostics,
                        schema_diagnostic(
                            DiagnosticCode::ValueTypeMismatch,
                            &variant_path,
                            "disjoint-union variants must have distinct canonical JSON-kind order"
                                .to_string(),
                        ),
                    );
                }
                previous_kind = kind;

                validate_schema_definition(
                    variant,
                    &variant_path,
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
        ValueSchema::Refined { value, constraints } => {
            if constraints.is_empty() {
                push_diagnostic(
                    diagnostics,
                    schema_diagnostic(
                        DiagnosticCode::ValueTypeMismatch,
                        &path.child("constraints"),
                        "refined schema must contain at least one constraint".to_string(),
                    ),
                );
            }
            validate_declared_collection_bound(
                constraints.len() as u64,
                max_collection_items,
                &path.child("constraints"),
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
            for (index, constraint) in constraints.iter().enumerate() {
                validate_constraint_definition(
                    constraint,
                    value,
                    &path.child("constraints").child(index.to_string()),
                    max_string_bytes,
                    max_collection_items,
                    diagnostics,
                );
            }
        }
    }
}

fn validate_constraint_definition(
    constraint: &ValueConstraint,
    base_schema: &ValueSchema,
    path: &SchemaPath,
    max_string_bytes: u64,
    max_collection_items: u64,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let base_schema = refined_base(base_schema);
    let incompatible = |expected: &str, diagnostics: &mut Vec<Diagnostic>| {
        push_diagnostic(
            diagnostics,
            schema_diagnostic(
                DiagnosticCode::ValueTypeMismatch,
                path,
                format!("refinement is incompatible with its base schema; expected {expected}"),
            ),
        );
    };
    match constraint {
        ValueConstraint::StringPattern { pattern } => {
            validate_declared_string_bound(
                pattern.len() as u64,
                max_string_bytes,
                path,
                diagnostics,
            );
            if !aos_ability_model::portable_pattern_is_valid(pattern, max_string_bytes) {
                push_diagnostic(
                    diagnostics,
                    schema_diagnostic(
                        DiagnosticCode::ValueTypeMismatch,
                        path,
                        "refinement pattern is not a valid portable regular expression".to_string(),
                    ),
                );
            }
            if !is_string_schema(base_schema) {
                incompatible("a string", diagnostics);
            }
        }
        ValueConstraint::MapKeysPattern { pattern } => {
            validate_declared_string_bound(
                pattern.len() as u64,
                max_string_bytes,
                path,
                diagnostics,
            );
            if !aos_ability_model::portable_pattern_is_valid(pattern, max_string_bytes) {
                push_diagnostic(
                    diagnostics,
                    schema_diagnostic(
                        DiagnosticCode::ValueTypeMismatch,
                        path,
                        "refinement pattern is not a valid portable regular expression".to_string(),
                    ),
                );
            }
            if !matches!(base_schema, ValueSchema::Map { .. }) {
                incompatible("a map", diagnostics);
            }
        }
        ValueConstraint::StringExcludes { classes } => {
            validate_declared_collection_bound(
                classes.len() as u64,
                max_collection_items,
                path,
                diagnostics,
            );
            if classes.is_empty() || classes.windows(2).any(|pair| pair[0] >= pair[1]) {
                push_diagnostic(
                    diagnostics,
                    schema_diagnostic(
                        DiagnosticCode::ValueTypeMismatch,
                        path,
                        "string-excludes classes must be non-empty, sorted, and unique".to_string(),
                    ),
                );
            }
            if !is_string_schema(base_schema) {
                incompatible("a string", diagnostics);
            }
        }
        ValueConstraint::MinimumSize { minimum } => {
            let maximum = maximum_cardinality(base_schema);
            if maximum.is_none() {
                incompatible("a string or bounded collection", diagnostics);
            } else if maximum.is_some_and(|maximum| *minimum > maximum) {
                push_diagnostic(
                    diagnostics,
                    schema_diagnostic(
                        DiagnosticCode::ValueTypeMismatch,
                        path,
                        "minimum-size exceeds the base schema's maximum size".to_string(),
                    ),
                );
            }
            validate_declared_collection_bound(*minimum, max_collection_items, path, diagnostics);
        }
        ValueConstraint::IntegerSet { values } => {
            validate_declared_collection_bound(
                values.len() as u64,
                max_collection_items,
                path,
                diagnostics,
            );
            if values.is_empty() || !values.windows(2).all(|pair| pair[0] < pair[1]) {
                push_diagnostic(
                    diagnostics,
                    schema_diagnostic(
                        DiagnosticCode::ValueTypeMismatch,
                        path,
                        "integer-set values must be non-empty, sorted, and unique".to_string(),
                    ),
                );
            }
            match base_schema {
                ValueSchema::Integer { minimum, maximum } => {
                    if values
                        .iter()
                        .any(|value| value < minimum || value > maximum)
                    {
                        push_diagnostic(
                            diagnostics,
                            schema_diagnostic(
                                DiagnosticCode::ValueTypeMismatch,
                                path,
                                "integer-set contains a value outside the base schema bounds"
                                    .to_string(),
                            ),
                        );
                    }
                }
                _ => incompatible("an integer", diagnostics),
            }
        }
        ValueConstraint::AtMostOneNonNull { fields } => {
            validate_declared_collection_bound(
                fields.len() as u64,
                max_collection_items,
                path,
                diagnostics,
            );
            check_sorted_unique(fields, path, diagnostics);
            if fields.is_empty() {
                push_diagnostic(
                    diagnostics,
                    schema_diagnostic(
                        DiagnosticCode::ValueTypeMismatch,
                        path,
                        "at-most-one-non-null must name at least one field".to_string(),
                    ),
                );
            }
            let missing = match base_schema {
                ValueSchema::Record {
                    fields: declared, ..
                } => fields
                    .iter()
                    .filter(|field| !declared.contains_key(*field))
                    .collect::<Vec<_>>(),
                ValueSchema::DocumentRecord {
                    fields: declared, ..
                } => fields
                    .iter()
                    .filter(|field| !declared.contains_key(field.as_str()))
                    .collect::<Vec<_>>(),
                _ => {
                    incompatible("a record", diagnostics);
                    Vec::new()
                }
            };
            if !missing.is_empty() {
                push_diagnostic(
                    diagnostics,
                    schema_diagnostic(
                        DiagnosticCode::MissingReference,
                        path,
                        "at-most-one-non-null names a field absent from the base schema"
                            .to_string(),
                    ),
                );
            }
        }
        ValueConstraint::UniqueAt { path: value_path } => {
            validate_value_path(value_path, path, diagnostics);
            validate_list_path(base_schema, value_path, path, diagnostics);
        }
        ValueConstraint::DisjointAt { left, right } => {
            validate_value_path(left, &path.child("left"), diagnostics);
            validate_value_path(right, &path.child("right"), diagnostics);
            validate_compatible_list_paths(base_schema, left, right, path, diagnostics);
        }
        ValueConstraint::SubsetUnless {
            subset,
            superset,
            unless_path,
            ..
        } => {
            validate_value_path(subset, &path.child("subset"), diagnostics);
            validate_value_path(superset, &path.child("superset"), diagnostics);
            validate_value_path(unless_path, &path.child("unless_path"), diagnostics);
            validate_compatible_list_paths(base_schema, subset, superset, path, diagnostics);
            let unless_schemas = schemas_at_path(base_schema, unless_path);
            if unless_schemas.is_none() {
                push_missing_path(path, "unless_path", diagnostics);
            } else if !constraint.is_compatible_with(base_schema) {
                push_diagnostic(
                    diagnostics,
                    schema_diagnostic(
                        DiagnosticCode::ValueTypeMismatch,
                        path,
                        "subset-unless bypass value is not admitted by unless_path".to_string(),
                    ),
                );
            }
        }
        ValueConstraint::StructuredDocument {
            format_field,
            document_field,
        } => {
            if !matches!(
                base_schema,
                ValueSchema::Record { .. } | ValueSchema::DocumentRecord { .. }
            ) {
                incompatible("a record", diagnostics);
                return;
            }
            let format_path = [format_field.clone()];
            let document_path = [document_field.clone()];
            let format_schemas = schemas_at_path(base_schema, &format_path);
            let document_schemas = schemas_at_path(base_schema, &document_path);
            if !format_schemas.as_ref().is_some_and(|schemas| {
                schemas
                    .iter()
                    .all(|schema| is_string_schema(refined_base(schema)))
            }) {
                push_diagnostic(
                    diagnostics,
                    schema_diagnostic(
                        DiagnosticCode::ValueTypeMismatch,
                        path,
                        "structured-document format field must be a declared string".to_string(),
                    ),
                );
            }
            if !document_schemas.as_ref().is_some_and(|schemas| {
                schemas
                    .iter()
                    .all(|schema| matches!(refined_base(schema), ValueSchema::List { .. }))
            }) {
                push_diagnostic(
                    diagnostics,
                    schema_diagnostic(
                        DiagnosticCode::ValueTypeMismatch,
                        path,
                        "structured-document document field must be a declared list".to_string(),
                    ),
                );
            }
        }
    }
}

fn refined_base(mut schema: &ValueSchema) -> &ValueSchema {
    while let ValueSchema::Refined { value, .. } = schema {
        schema = value;
    }
    schema
}

fn is_string_schema(schema: &ValueSchema) -> bool {
    matches!(
        schema,
        ValueSchema::String { .. } | ValueSchema::StringEnum { .. }
    )
}

fn maximum_cardinality(schema: &ValueSchema) -> Option<u64> {
    match refined_base(schema) {
        ValueSchema::String { max_length, .. } => Some(*max_length),
        ValueSchema::StringEnum { values } => values
            .iter()
            .map(|value| value.len() as u64)
            .max()
            .or(Some(0)),
        ValueSchema::List { max_items, .. } => Some(*max_items),
        ValueSchema::Map { max_entries, .. } => Some(*max_entries),
        ValueSchema::Record { fields, .. } => Some(fields.len() as u64),
        ValueSchema::DocumentRecord { fields, .. } => Some(fields.len() as u64),
        _ => None,
    }
}

fn schemas_at_path<'a>(
    schema: &'a ValueSchema,
    value_path: &[aos_ability_model::LocalKey],
) -> Option<Vec<&'a ValueSchema>> {
    if value_path.is_empty() {
        return Some(vec![refined_base(schema)]);
    }
    let schema = refined_base(schema);
    let field = &value_path[0];
    let remaining = &value_path[1..];
    match schema {
        ValueSchema::Record { fields, .. } => schemas_at_path(fields.get(field)?, remaining),
        ValueSchema::DocumentRecord { fields, .. } => {
            schemas_at_path(fields.get(field.as_str())?, remaining)
        }
        ValueSchema::TaggedUnion { variants, .. } => variants
            .values()
            .map(|variant| schemas_at_path(variant, value_path))
            .collect::<Option<Vec<_>>>()
            .map(|paths| paths.into_iter().flatten().collect()),
        ValueSchema::DisjointUnion { variants } => variants
            .iter()
            .map(|variant| schemas_at_path(variant, value_path))
            .collect::<Option<Vec<_>>>()
            .map(|paths| paths.into_iter().flatten().collect()),
        _ => None,
    }
}

fn validate_list_path(
    base_schema: &ValueSchema,
    value_path: &[aos_ability_model::LocalKey],
    path: &SchemaPath,
    diagnostics: &mut Vec<Diagnostic>,
) {
    match schemas_at_path(base_schema, value_path) {
        Some(schemas)
            if schemas
                .iter()
                .all(|schema| matches!(refined_base(schema), ValueSchema::List { .. })) => {}
        Some(_) => push_diagnostic(
            diagnostics,
            schema_diagnostic(
                DiagnosticCode::ValueTypeMismatch,
                path,
                "refinement path must name a list".to_string(),
            ),
        ),
        None => push_missing_path(path, "path", diagnostics),
    }
}

fn validate_compatible_list_paths(
    base_schema: &ValueSchema,
    left: &[aos_ability_model::LocalKey],
    right: &[aos_ability_model::LocalKey],
    path: &SchemaPath,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let left_schemas = schemas_at_path(base_schema, left);
    let right_schemas = schemas_at_path(base_schema, right);
    let left_elements = list_element_schemas(left_schemas.as_deref());
    let right_elements = list_element_schemas(right_schemas.as_deref());
    match (left_elements, right_elements) {
        (Some(left), Some(right))
            if left.iter().all(|schema| right.contains(schema))
                && right.iter().all(|schema| left.contains(schema)) => {}
        (Some(_), Some(_)) => push_diagnostic(
            diagnostics,
            schema_diagnostic(
                DiagnosticCode::ValueTypeMismatch,
                path,
                "refinement list paths use incompatible element schemas".to_string(),
            ),
        ),
        _ => push_diagnostic(
            diagnostics,
            schema_diagnostic(
                DiagnosticCode::ValueTypeMismatch,
                path,
                "refinement paths must name lists present in every base-schema variant".to_string(),
            ),
        ),
    }
}

fn list_element_schemas<'a>(schemas: Option<&[&'a ValueSchema]>) -> Option<Vec<&'a ValueSchema>> {
    schemas?
        .iter()
        .map(|schema| match refined_base(schema) {
            ValueSchema::List { element, .. } => Some(element.as_ref()),
            _ => None,
        })
        .collect()
}

fn push_missing_path(path: &SchemaPath, label: &str, diagnostics: &mut Vec<Diagnostic>) {
    push_diagnostic(
        diagnostics,
        schema_diagnostic(
            DiagnosticCode::MissingReference,
            path,
            format!("refinement {label} does not exist in every base-schema variant"),
        ),
    );
}

fn validate_value_path(
    value_path: &[aos_ability_model::LocalKey],
    path: &SchemaPath,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if value_path.is_empty() {
        push_diagnostic(
            diagnostics,
            schema_diagnostic(
                DiagnosticCode::ValueTypeMismatch,
                path,
                "refinement path must contain at least one field".to_string(),
            ),
        );
    }
}
