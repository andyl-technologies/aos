//! Tests for value schema validation.

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
fn validates_empty_record() {
    let schema = ValueSchema::Record {
        fields: BTreeMap::new(),
        optional_fields: Vec::new(),
    };
    let value = literal(serde_json::json!({}));

    assert!(validate_value(&schema, &value).is_ok());
}

#[test]
fn validates_zero_capacity_list_and_map() {
    let list_schema = ValueSchema::List {
        element: Box::new(ValueSchema::Boolean),
        max_items: 0,
        unique: false,
        canonical_order: false,
    };
    let map_schema = ValueSchema::Map {
        key: aos_ability_model::StringConstraint {
            max_length: 32,
            syntax: None,
        },
        value: Box::new(ValueSchema::Boolean),
        max_entries: 0,
    };

    assert!(validate_value(&list_schema, &literal(serde_json::json!([]))).is_ok());
    assert!(validate_value(&map_schema, &literal(serde_json::json!({}))).is_ok());
}

#[test]
fn constrained_list_rejects_duplicates_and_noncanonical_order() {
    let schema = ValueSchema::List {
        element: Box::new(ValueSchema::String {
            max_length: 8,
            syntax: None,
        }),
        max_items: 4,
        unique: true,
        canonical_order: true,
    };

    assert!(validate_value(&schema, &literal(serde_json::json!(["a", "b"]))).is_ok());
    assert!(validate_value(&schema, &literal(serde_json::json!(["a", "a"]))).is_err());
    assert!(validate_value(&schema, &literal(serde_json::json!(["b", "a"]))).is_err());
}

#[test]
fn canonical_order_requires_unique_elements() {
    let schema = ValueSchema::List {
        element: Box::new(ValueSchema::Boolean),
        max_items: 4,
        unique: false,
        canonical_order: true,
    };

    assert!(validate_value(&schema, &literal(serde_json::json!([false, true]))).is_err());
}

#[test]
fn disjoint_union_accepts_raw_boolean_integer_and_string_values() {
    let schema = ValueSchema::DisjointUnion {
        variants: vec![
            ValueSchema::Boolean,
            ValueSchema::Integer {
                minimum: 0,
                maximum: 8,
            },
            ValueSchema::String {
                max_length: 8,
                syntax: None,
            },
        ],
    };

    assert!(validate_value(&schema, &literal(serde_json::json!(true))).is_ok());
    assert!(validate_value(&schema, &literal(serde_json::json!(4))).is_ok());
    assert!(validate_value(&schema, &literal(serde_json::json!("raw"))).is_ok());
    assert!(validate_value(&schema, &literal(serde_json::json!([]))).is_err());
}

#[test]
fn disjoint_union_rejects_ambiguous_or_reordered_variants() {
    let ambiguous = ValueSchema::DisjointUnion {
        variants: vec![
            ValueSchema::String {
                max_length: 8,
                syntax: None,
            },
            ValueSchema::StringEnum {
                values: vec!["value".to_string()],
            },
        ],
    };
    let reordered = ValueSchema::DisjointUnion {
        variants: vec![
            ValueSchema::String {
                max_length: 8,
                syntax: None,
            },
            ValueSchema::Boolean,
        ],
    };

    assert!(validate_value(&ambiguous, &literal(serde_json::json!("value"))).is_err());
    assert!(validate_value(&reordered, &literal(serde_json::json!(true))).is_err());
}

#[test]
fn document_record_preserves_application_keys_and_rejects_unknown_fields() {
    let schema = ValueSchema::DocumentRecord {
        key_max_length: 32,
        fields: BTreeMap::from([
            (
                "@type".to_string(),
                ValueSchema::String {
                    max_length: 64,
                    syntax: None,
                },
            ),
            ("enabled".to_string(), ValueSchema::Boolean),
        ]),
        optional_fields: vec!["enabled".to_string()],
    };

    assert!(
        validate_value(
            &schema,
            &literal(serde_json::json!({"@type": "type.googleapis.com/example"})),
        )
        .is_ok()
    );
    assert!(
        validate_value(
            &schema,
            &literal(serde_json::json!({"@type": "example", "unknown": true})),
        )
        .is_err()
    );
}

#[test]
fn document_record_rejects_invalid_declared_keys_and_optional_order() {
    let invalid_key = ValueSchema::DocumentRecord {
        key_max_length: 8,
        fields: BTreeMap::from([("bad\nkey".to_string(), ValueSchema::Boolean)]),
        optional_fields: Vec::new(),
    };
    let invalid_optional_order = ValueSchema::DocumentRecord {
        key_max_length: 8,
        fields: BTreeMap::from([
            ("alpha".to_string(), ValueSchema::Boolean),
            ("beta".to_string(), ValueSchema::Boolean),
        ]),
        optional_fields: vec!["beta".to_string(), "alpha".to_string()],
    };

    assert!(validate_value(&invalid_key, &literal(serde_json::json!({}))).is_err());
    assert!(
        validate_value(
            &invalid_optional_order,
            &literal(serde_json::json!({"alpha": true, "beta": true})),
        )
        .is_err()
    );
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
fn path_within_requires_an_execution_path_schema_and_base() {
    let schema = ValueSchema::String {
        max_length: 4096,
        syntax: Some(StringSyntax::ExecutionPathV1),
    };
    let path = ValueExpression::PathWithin {
        base: Box::new(literal(Value::String("/run/krb5".to_string()))),
        relative_path: aos_ability_model::RelativePath::new("service.pid").expect("relative path"),
    };

    assert!(validate_value(&schema, &path).is_ok());

    let untyped_schema = ValueSchema::String {
        max_length: 4096,
        syntax: None,
    };
    assert!(validate_value(&untyped_schema, &path).is_err());

    let relative_base = ValueExpression::PathWithin {
        base: Box::new(literal(Value::String("run/krb5".to_string()))),
        relative_path: aos_ability_model::RelativePath::new("service.pid").expect("relative path"),
    };
    assert!(validate_value(&schema, &relative_base).is_err());
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

#[test]
fn authored_transaction_blob_is_rejected_but_materialized_reference_is_accepted() {
    let digest = format!("sha256:{}", "00".repeat(32));
    let reference = AbilityValue::new(serde_json::json!({
        "_type": TRANSACTION_BLOB_REFERENCE_TYPE,
        "transaction": "transaction-1",
        "handle": "blob-content",
        "content_sha256": digest,
        "size_bytes": 4096,
    }))
    .expect("valid canonical transaction blob reference");
    let authored = ValueExpression::Literal {
        value: reference.clone(),
    };

    let errors = validate_value(&ValueSchema::TransactionBlobReference, &authored)
        .expect_err("authored transaction blob references must be rejected");
    assert!(
        errors
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == DiagnosticCode::MissingReference)
    );
    assert!(
        validate_materialized_value(&ValueSchema::TransactionBlobReference, &reference).is_ok()
    );

    let oversized = AbilityValue::new(serde_json::json!({
        "_type": TRANSACTION_BLOB_REFERENCE_TYPE,
        "transaction": "transaction-1",
        "handle": "blob-content",
        "content_sha256": digest,
        "size_bytes": MAX_TRANSACTION_BLOB_BYTES + 1,
    }))
    .expect("canonical oversized reference");
    assert!(
        validate_materialized_value(&ValueSchema::TransactionBlobReference, &oversized).is_err()
    );
}
