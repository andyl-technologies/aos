//! Exact private capture, strict scalar decoding, and hostile pairing regressions.

use super::*;

fn classifier() -> SnapshotClassifier {
    let shapes = contract()
        .unwrap()
        .into_iter()
        .map(|(name, table)| SnapshotTableShape {
            name,
            columns: table
                .columns
                .into_iter()
                .map(|column| column.name)
                .collect(),
        })
        .collect::<Vec<_>>();
    let digests = MIGRATIONS
        .iter()
        .map(|script| hex::encode(Sha256::digest(script.as_bytes())))
        .collect::<Vec<_>>();
    SnapshotClassifier::new(SCHEMA_IDENTITY, MIGRATIONS.len(), &digests, &shapes).unwrap()
}

fn source_row(table: &str, overrides: &[(&str, Value)]) -> Row {
    let contracts = contract().unwrap();
    let values = contracts[table]
        .columns
        .iter()
        .map(|column| {
            overrides
                .iter()
                .find(|(name, _)| *name == column.name)
                .map(|(_, value)| value.clone())
                .unwrap_or_else(|| {
                    if column.nullable {
                        Value::Null
                    } else {
                        match column.storage.as_str() {
                            "integer" => Value::Int(1),
                            "bytes" => Value::Bytes(vec![0, 255]),
                            _ if column.rule == "secret_reference" => {
                                Value::Text("native://test/credential/v1".into())
                            }
                            _ if column.rule == "fingerprint" => Value::Text("a".repeat(64)),
                            _ if column.rule == "idp_locator" => {
                                Value::Text("https://idp.example.invalid".into())
                            }
                            _ => Value::Text("value".into()),
                        }
                    }
                })
        })
        .collect();
    Row::new(values)
}

fn user(id: i64, secret: &str) -> Row {
    source_row(
        "users",
        &[
            ("id", Value::Int(id)),
            ("password_hash", Value::Text(secret.into())),
        ],
    )
}

fn retained(capture: &CapturedSnapshotRow) -> &ClassifiedSnapshotRow {
    match capture.classified() {
        SnapshotRowDisposition::Retained(row) => row,
        _ => panic!("expected retained row"),
    }
}

fn round_trip(classifier: &SnapshotClassifier, table: &str, source: &Row) -> CapturedSnapshotRow {
    let capture = classifier.capture_private_row(table, source).unwrap();
    let originals = capture
        .private_cells()
        .iter()
        .map(copy_original)
        .collect::<Vec<_>>();
    let reconstructed = classifier
        .reconstruct_private_row(retained(&capture), &originals)
        .unwrap();
    reconstructed.with_private_row(|row| assert_eq!(row, source));
    assert!(!format!("{reconstructed:?}").contains("PRIVATE"));
    capture
}

fn copy_original(original: &PrivateSnapshotCell) -> PrivateSnapshotCell {
    let mut bytes = Vec::new();
    original.write_private_scalar_json(&mut bytes).unwrap();
    PrivateSnapshotCell::from_private_scalar_json(original.dependency().clone(), &bytes).unwrap()
}

fn dependency(value: &Value) -> SnapshotPrivateDependency {
    SnapshotPrivateDependency {
        table: "users".into(),
        primary_key_digest: "a".repeat(64),
        column: "password_hash".into(),
        cell_digest: cell_digest(value),
        payload_bytes: payload_len(value),
        reason: PrivateDependencyReason::Secret,
    }
}

fn private(value: &Value) -> PrivateSnapshotCell {
    let bytes = serde_json::to_vec(&serde_json::json!({
        "version": 1, "scalar": scalar(value).unwrap()
    }))
    .unwrap();
    PrivateSnapshotCell::from_private_scalar_json(dependency(value), &bytes).unwrap()
}

fn alter_locator(
    original: &PrivateSnapshotCell,
    alter: impl FnOnce(&mut SnapshotPrivateDependency),
) -> PrivateSnapshotCell {
    let mut locator = original.dependency().clone();
    alter(&mut locator);
    let mut bytes = Vec::new();
    original.write_private_scalar_json(&mut bytes).unwrap();
    PrivateSnapshotCell::from_private_scalar_json(locator, &bytes).unwrap()
}

#[tokio::test]
async fn actual_production_sqlite_rows_round_trip_secrets_and_extreme_integers() {
    use crate::backend::{Backend, SqlxBackend};
    use crate::db::Database;

    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let _database = Database::with_backend(Box::new(SqlxBackend::Sqlite(pool.clone())))
        .await
        .unwrap();
    let backend = SqlxBackend::Sqlite(pool);
    let classifier = classifier();

    for (id, label) in [(i64::MIN, "min"), (i64::MAX, "max")] {
        backend
            .execute(
                "INSERT INTO users (id, email, display_name, created_at, deleted_at, password_hash) VALUES (?, ?, NULL, ?, NULL, ?)",
                &[Value::Int(id), Value::Text(label.into()), Value::Int(i64::MAX), Value::Text("PRIVATE-HASH\0EXACT".into())],
            )
            .await
            .unwrap();
        let source = backend
            .query("SELECT id,email,display_name,created_at,deleted_at,password_hash,principal_incarnation FROM users WHERE id=?", &[Value::Int(id)])
            .await
            .unwrap()
            .pop()
            .unwrap();
        let capture = round_trip(&classifier, "users", &source);
        assert_eq!(capture.private_cells().len(), 1);
        assert!(!serde_json::to_string(capture.classified())
            .unwrap()
            .contains("PRIVATE-HASH"));
    }
}

#[test]
fn opaque_history_original_json_and_multiple_private_cells_are_exact() {
    let original = " { \"client_secret_enc\" : \"PRIVATE-HISTORY\", \"ordinary\": [1,2] }\n";
    let updated = "{\"version\":\"ordinary-package-version\",\"context\":\"PRIVATE-NEXT\"}";
    let row = source_row(
        "change_request_revisions",
        &[
            ("old_json", Value::Text(original.into())),
            ("new_json", Value::Text(updated.into())),
        ],
    );
    let capture = round_trip(&classifier(), "change_request_revisions", &row);

    assert_eq!(capture.private_cells().len(), 2);
    capture.private_cells()[0]
        .with_private_value(|value| assert_eq!(value, &Value::Text(original.into())));
    let debug = format!("{capture:?} {:?}", capture.private_cells());
    assert!(!debug.contains("PRIVATE"));
    assert!(!serde_json::to_string(capture.classified())
        .unwrap()
        .contains("PRIVATE"));
}

#[test]
fn composite_primary_key_binds_private_originals_to_every_key_component() {
    let classifier = classifier();
    let make = |binding_id, purpose: &str, generation| {
        source_row(
            "binding_credential_revisions",
            &[
                ("binding_id", Value::Int(binding_id)),
                ("purpose", Value::Text(purpose.into())),
                ("generation", Value::Int(generation)),
                (
                    "validation_error",
                    Value::Text("PRIVATE-PROVIDER-ERROR".into()),
                ),
            ],
        )
    };
    let first = round_trip(
        &classifier,
        "binding_credential_revisions",
        &make(1, "read", 1),
    );
    for other in [make(2, "read", 1), make(1, "write", 1), make(1, "read", 2)] {
        let other = classifier
            .capture_private_row("binding_credential_revisions", &other)
            .unwrap();
        assert!(classifier
            .reconstruct_private_row(retained(&first), other.private_cells())
            .is_err());
    }
}

#[test]
fn retained_binary_empty_null_and_negative_integer_values_round_trip() {
    let classifier = classifier();
    let row = source_row(
        "endpoints",
        &[
            ("ipv4_bytes", Value::Bytes(vec![0, 128, 255, 1])),
            ("ipv6_bytes", Value::Bytes(Vec::new())),
            ("created_at", Value::Int(i64::MIN)),
        ],
    );
    let capture = round_trip(&classifier, "endpoints", &row);
    assert!(capture.private_cells().is_empty());
    round_trip(&classifier, "users", &source_row("users", &[]));
}

#[test]
fn strict_private_codec_preserves_all_scalar_types_and_signed_zero() {
    for value in [
        Value::Int(i64::MIN),
        Value::Int(i64::MAX),
        Value::Int(0),
        Value::Real(-0.0),
        Value::Real(0.0),
        Value::Real(f64::MIN),
        Value::Real(f64::MAX),
        Value::Real(f64::from_bits(1)),
        Value::Text("PRIVATE\0\n\"\\雪".into()),
        Value::Text(String::new()),
        Value::Bytes(vec![0, 255, 128]),
        Value::Bytes(Vec::new()),
        Value::Null,
    ] {
        let original = private(&value);
        let decoded = copy_original(&original);
        decoded.with_private_value(|decoded| {
            assert_eq!(cell_digest(decoded), cell_digest(&value));
            if let (Value::Real(a), Value::Real(b)) = (decoded, &value) {
                assert_eq!(a.to_bits(), b.to_bits());
            }
        });
        assert!(!format!("{decoded:?}").contains("PRIVATE"));
    }
}

#[test]
fn finite_real_codec_does_not_admit_real_into_current_production_rows() {
    let classifier = classifier();
    let source = user(1, "PRIVATE");
    let capture = classifier.capture_private_row("users", &source).unwrap();
    let mut classified = retained(&capture).clone();
    classified.cells.insert(
        "created_at".into(),
        ClassifiedCell::Scalar(SnapshotScalar::RealBits("8000000000000000".into())),
    );
    assert!(classifier
        .reconstruct_private_row(&classified, capture.private_cells())
        .is_err());
    assert!(classifier
        .capture_private_row("users", &source_row("users", &[("id", Value::Real(1.0))]))
        .is_err());
}

#[test]
fn missing_duplicate_extra_reordered_and_cross_row_originals_reject() {
    let classifier = classifier();
    let source = source_row(
        "change_request_revisions",
        &[
            (
                "old_json",
                Value::Text("{\"private\":\"PRIVATE-A\"}".into()),
            ),
            (
                "new_json",
                Value::Text("{\"private\":\"PRIVATE-B\"}".into()),
            ),
        ],
    );
    let capture = classifier
        .capture_private_row("change_request_revisions", &source)
        .unwrap();
    let original = capture.private_cells();
    let cases = [
        vec![],
        vec![copy_original(&original[0])],
        vec![copy_original(&original[0]), copy_original(&original[0])],
        vec![copy_original(&original[1]), copy_original(&original[0])],
        vec![
            copy_original(&original[0]),
            copy_original(&original[1]),
            copy_original(&original[1]),
        ],
    ];
    for originals in cases {
        assert!(classifier
            .reconstruct_private_row(retained(&capture), &originals)
            .is_err());
    }
    let a = classifier
        .capture_private_row("users", &user(1, "PRIVATE-SAME"))
        .unwrap();
    let b = classifier
        .capture_private_row("users", &user(2, "PRIVATE-SAME"))
        .unwrap();
    assert!(classifier
        .reconstruct_private_row(retained(&a), b.private_cells())
        .is_err());
}

#[test]
fn dependency_table_column_key_reason_digest_and_length_tampering_rejects() {
    let classifier = classifier();
    let capture = classifier
        .capture_private_row("users", &user(1, "PRIVATE-SECRET"))
        .unwrap();
    let original = &capture.private_cells()[0];
    for modified in [
        alter_locator(original, |d| d.table = "orgs".into()),
        alter_locator(original, |d| d.column = "display_name".into()),
        alter_locator(original, |d| d.primary_key_digest = "b".repeat(64)),
        alter_locator(original, |d| d.reason = PrivateDependencyReason::OpaqueJson),
    ] {
        assert!(classifier
            .reconstruct_private_row(retained(&capture), &[modified])
            .is_err());
    }
    let mut bytes = Vec::new();
    original.write_private_scalar_json(&mut bytes).unwrap();
    let mut locator = original.dependency().clone();
    locator.payload_bytes += 1;
    assert!(PrivateSnapshotCell::from_private_scalar_json(locator, &bytes).is_err());
    let mut digest = original.dependency().clone();
    digest.cell_digest = "b".repeat(64);
    assert!(PrivateSnapshotCell::from_private_scalar_json(digest, &bytes).is_err());
}

#[test]
fn caller_metadata_cannot_reclassify_private_originals_as_public_scalars() {
    let classifier = classifier();
    let capture = classifier
        .capture_private_row("users", &user(1, "PRIVATE-HASH"))
        .unwrap();
    let mut metadata = retained(&capture).clone();
    metadata.cells.insert(
        "password_hash".into(),
        ClassifiedCell::Scalar(SnapshotScalar::Text("PRIVATE-HASH".into())),
    );
    metadata.private_dependencies.clear();
    assert!(classifier.reconstruct_private_row(&metadata, &[]).is_err());

    let mut metadata = retained(&capture).clone();
    metadata.cells.insert(
        "unregistered".into(),
        ClassifiedCell::Scalar(SnapshotScalar::Null),
    );
    assert!(classifier
        .reconstruct_private_row(&metadata, capture.private_cells())
        .is_err());
    let mut metadata = retained(&capture).clone();
    metadata
        .private_dependencies
        .push(metadata.private_dependencies[0].clone());
    assert!(classifier
        .reconstruct_private_row(&metadata, capture.private_cells())
        .is_err());
}

#[test]
fn scalar_type_identity_rejects_same_payload_bytes_with_different_types() {
    let value = Value::Text("PRIVATE".into());
    let locator = dependency(&value);
    let encoded = br#"{"version":1,"scalar":{"kind":"bytes_hex","value":"50524956415445"}}"#;
    assert!(PrivateSnapshotCell::from_private_scalar_json(locator, encoded).is_err());
}

#[test]
fn malformed_scalar_documents_and_versions_reject_without_payload_detail() {
    let marker = "PRIVATE-MALFORMED-SECRET";
    let locator = dependency(&Value::Text(marker.into()));
    let cases = [
        "{",
        "[]",
        "null",
        r#"{"version":2,"scalar":{"kind":"text","value":"PRIVATE-MALFORMED-SECRET"}}"#,
        r#"{"version":"1","scalar":{"kind":"text","value":"PRIVATE-MALFORMED-SECRET"}}"#,
        r#"{"version":1.0,"scalar":{"kind":"text","value":"PRIVATE-MALFORMED-SECRET"}}"#,
        r#"{"version":1,"version":1,"scalar":{"kind":"text","value":"PRIVATE-MALFORMED-SECRET"}}"#,
        r#"{"version":1,"scalar":{"kind":"text","value":"PRIVATE-MALFORMED-SECRET"},"PRIVATE-MALFORMED-SECRET":0}"#,
        r#"{"version":1,"scalar":{"kind":"text","value":"PRIVATE-MALFORMED-SECRET","extra":0}}"#,
        r#"{"version":1,"scalar":{"kind":"text","value":17}}"#,
        r#"{"version":1,"scalar":{"kind":"future","value":"PRIVATE-MALFORMED-SECRET"}}"#,
        r#"{"version":1,"scalar":{"kind":"null","value":null}}"#,
        r#"{"version":1,"scalar":{"kind":"text","kind":"text","value":"PRIVATE-MALFORMED-SECRET"}}"#,
        r#"{"version":1,"scalar":{"kind":"text","value":"PRIVATE-MALFORMED-SECRET"}} trailing"#,
    ];
    for bytes in cases {
        let error =
            PrivateSnapshotCell::from_private_scalar_json(locator.clone(), bytes.as_bytes())
                .unwrap_err();
        assert!(!format!("{error:#} {error:?}").contains(marker));
    }
}

#[test]
fn noncanonical_integer_hex_and_nonfinite_real_encodings_reject() {
    let cases = [
        ("integer", "+1"),
        ("integer", "01"),
        ("integer", "-0"),
        ("integer", " 1"),
        ("integer", "1 "),
        ("integer", "1.0"),
        ("integer", "9223372036854775808"),
        ("integer", "-9223372036854775809"),
        ("bytes_hex", "A0"),
        ("bytes_hex", "a"),
        ("bytes_hex", "gg"),
        ("real_bits", "800000000000000"),
        ("real_bits", "80000000000000000"),
        ("real_bits", "3FF0000000000000"),
        ("real_bits", "7ff0000000000000"),
        ("real_bits", "fff0000000000000"),
        ("real_bits", "7ff8000000000001"),
    ];
    for (kind, value) in cases {
        let bytes = serde_json::to_vec(
            &serde_json::json!({"version":1,"scalar":{"kind":kind,"value":value}}),
        )
        .unwrap();
        let error = PrivateSnapshotCell::from_private_scalar_json(dependency(&Value::Null), &bytes)
            .unwrap_err();
        assert!(matches!(
            error.to_string().as_str(),
            "snapshot integer scalar is invalid"
                | "snapshot bytes scalar is invalid"
                | "snapshot real scalar is invalid"
                | "snapshot real value is not finite"
        ));
    }
}

#[test]
fn maximum_original_text_and_blob_allow_escaping_without_larger_payloads() {
    for value in [
        Value::Text("\0".repeat(MAX_CELL_BYTES)),
        Value::Bytes(vec![255; MAX_CELL_BYTES]),
    ] {
        let original = private(&value);
        let mut bytes = Vec::new();
        original.write_private_scalar_json(&mut bytes).unwrap();
        assert!(bytes.len() > MAX_CELL_BYTES);
        let decoded =
            PrivateSnapshotCell::from_private_scalar_json(dependency(&value), &bytes).unwrap();
        decoded.with_private_value(|decoded| assert_eq!(cell_digest(decoded), cell_digest(&value)));
    }
    for value in [
        Value::Text("x".repeat(MAX_CELL_BYTES + 1)),
        Value::Bytes(vec![0; MAX_CELL_BYTES + 1]),
    ] {
        let bytes =
            serde_json::to_vec(&serde_json::json!({"version":1,"scalar":scalar(&value).unwrap()}))
                .unwrap();
        assert!(PrivateSnapshotCell::from_private_scalar_json(dependency(&value), &bytes).is_err());
    }
    let oversized = vec![b' '; 6 * MAX_CELL_BYTES + 129];
    assert!(
        PrivateSnapshotCell::from_private_scalar_json(dependency(&Value::Null), &oversized)
            .is_err()
    );
}

#[test]
fn row_limits_are_enforced_before_capture_or_reconstruction_clones() {
    let classifier = classifier();
    let source = source_row(
        "users",
        &[("password_hash", Value::Text("x".repeat(MAX_CELL_BYTES + 1)))],
    );
    assert!(classifier.capture_private_row("users", &source).is_err());

    let input = source_row("registries", &[("trust_keys", Value::Text("[]".into()))]);
    let mut oversized = Vec::new();
    for (index, column) in contract().unwrap()["registries"].columns.iter().enumerate() {
        oversized.push(if column.storage == "text" {
            Value::Text("x".repeat(MAX_CELL_BYTES))
        } else {
            input.value(index).unwrap().clone()
        });
    }
    assert!(classifier
        .capture_private_row("registries", &Row::new(oversized))
        .is_err());
    let valid_registry = classifier
        .capture_private_row("registries", &input)
        .unwrap();
    let mut metadata = retained(&valid_registry).clone();
    for column in &contract().unwrap()["registries"].columns {
        if column.storage == "text" && column.rule == "retain" {
            metadata.cells.insert(
                column.name.clone(),
                ClassifiedCell::Scalar(SnapshotScalar::Text("x".repeat(MAX_CELL_BYTES))),
            );
        }
    }
    assert!(classifier
        .reconstruct_private_row(&metadata, valid_registry.private_cells())
        .is_err());

    let capture = classifier
        .capture_private_row("users", &user(1, "PRIVATE"))
        .unwrap();
    let originals = (0..20)
        .map(|_| copy_original(&capture.private_cells()[0]))
        .collect::<Vec<_>>();
    assert!(classifier
        .reconstruct_private_row(retained(&capture), &originals)
        .is_err());
}

#[test]
fn omitted_authentication_and_source_metadata_capture_no_private_originals() {
    let classifier = classifier();
    for table in ["sessions", "hub_schema_identity"] {
        let capture = classifier
            .capture_private_row(table, &source_row(table, &[]))
            .unwrap();
        assert!(capture.private_cells().is_empty());
        assert!(!matches!(
            capture.classified(),
            SnapshotRowDisposition::Retained(_)
        ));
    }
}

#[test]
fn private_writer_failure_does_not_leak_writer_error_context() {
    struct Refuse;
    impl std::io::Write for Refuse {
        fn write(&mut self, _bytes: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("PRIVATE-WRITER-CONTEXT"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let original = private(&Value::Text("PRIVATE-CELL".into()));
    let error = original.write_private_scalar_json(Refuse).unwrap_err();
    assert!(!format!("{error:#} {error:?}").contains("PRIVATE"));
}

#[test]
fn immutable_secret_bearing_plan_bytes_and_confirmation_hash_are_unchanged() {
    let input = serde_json::json!({
        "org_id":1,"org_slug":"test","issuer":"https://idp.test",
        "authorization_endpoint":"https://idp.test/auth","token_endpoint":"https://idp.test/token",
        "jwks_uri":"https://idp.test/keys","client_id":"hub",
        "client_secret_enc":"PRIVATE-ORIGINAL-SEALED-IDP","client_secret_action":"replace",
        "scopes":"openid","groups_claim":null,"role_map_json":"{}",
        "allow_jit":true,"enforce_sso":false,"default_role":"viewer",
        "baseline_resource_version":null,"baseline_incarnation_id":null,
        "incarnation_id":"idp-incarnation-0001"
    });
    let text = format!(" \n{}\n", serde_json::to_string_pretty(&input).unwrap());
    let source = source_row(
        "topology_plans",
        &[
            ("plan_kind", Value::Text("set_identity_provider".into())),
            ("input_versions_json", Value::Text(text.clone())),
            ("effects_json", Value::Text("[]".into())),
            ("warnings_json", Value::Text("[]".into())),
            (
                "confirmation_hash",
                Value::Text("exact-immutable-confirmation-hash".into()),
            ),
        ],
    );
    let capture = round_trip(&classifier(), "topology_plans", &source);
    let original = capture
        .private_cells()
        .iter()
        .find(|original| original.dependency().column == "input_versions_json")
        .unwrap();
    original.with_private_value(|value| assert_eq!(value, &Value::Text(text)));
    assert_eq!(
        retained(&capture).cells["confirmation_hash"],
        ClassifiedCell::Scalar(SnapshotScalar::Text(
            "exact-immutable-confirmation-hash".into()
        ))
    );
}

#[test]
fn capture_and_reconstruction_errors_exclude_private_parser_context() {
    let classifier = classifier();
    let marker = "PRIVATE-CAPTURE-PARSER-CONTEXT";
    let source = source_row(
        "change_request_revisions",
        &[("old_json", Value::Text(format!("{{{marker}")))],
    );
    let error = classifier
        .capture_private_row("change_request_revisions", &source)
        .unwrap_err();
    assert!(!format!("{error:#} {error:?}").contains(marker));

    let capture = classifier
        .capture_private_row("users", &user(1, marker))
        .unwrap();
    let mut metadata = retained(&capture).clone();
    metadata.cells.insert(
        "created_at".into(),
        ClassifiedCell::Scalar(SnapshotScalar::Integer(marker.into())),
    );
    let error = classifier
        .reconstruct_private_row(&metadata, capture.private_cells())
        .unwrap_err();
    assert!(!format!("{error:#} {error:?}").contains(marker));
}

#[test]
fn hostile_structured_scalar_payloads_and_unknown_fields_reject_directly() {
    // The cap bounds encoded input, while the direct scalar visitor rejects an
    // array without constructing an unbounded-by-row generic JSON value tree.
    let array = format!(
        "{{\"version\":1,\"scalar\":{{\"kind\":\"text\",\"value\":[{}0]}}}}",
        "0,".repeat(500_000)
    );
    let error =
        PrivateSnapshotCell::from_private_scalar_json(dependency(&Value::Null), array.as_bytes())
            .unwrap_err();
    assert_eq!(error.to_string(), "snapshot private scalar JSON is invalid");
    let unknown = format!(
        "{{\"version\":1,\"scalar\":{{\"kind\":\"null\",\"PRIVATE-UNKNOWN-FIELD\":[{}0]}}}}",
        "0,".repeat(500_000)
    );
    let error =
        PrivateSnapshotCell::from_private_scalar_json(dependency(&Value::Null), unknown.as_bytes())
            .unwrap_err();
    assert_eq!(error.to_string(), "snapshot private scalar JSON is invalid");
}
