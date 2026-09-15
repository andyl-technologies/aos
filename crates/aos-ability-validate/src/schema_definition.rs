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
    }
}
