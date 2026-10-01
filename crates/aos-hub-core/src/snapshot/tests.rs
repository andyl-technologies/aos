//! Focused schema coverage, secret omission, and closed-value qualification.

use super::*;

mod channels;
mod direct;
mod direct_oci;
mod direct_receipts;
mod lifetimes;
mod mirror;
mod privacy;

#[test]
fn historical_contract_keeps_exact_digests_and_refuses_mixed_generations() {
    let historical = SnapshotClassifier::for_supported_generation(3).unwrap();
    let generation4 = SnapshotClassifier::for_supported_generation(4).unwrap();
    let generation5 = SnapshotClassifier::for_supported_generation(5).unwrap();
    let generation6 = SnapshotClassifier::for_supported_generation(6).unwrap();
    let current = SnapshotClassifier::for_supported_generation(7).unwrap();

    assert_eq!(historical.tables.len(), 267);
    assert_eq!(generation4.tables.len(), 275);
    assert_eq!(generation5.tables.len(), 276);
    assert_eq!(generation6.tables.len(), 276);
    assert_eq!(current.tables.len(), 278);
    assert_eq!(generation6.manifest().migration_digests, digests()[..6]);
    assert_eq!(
        generation6.manifest().classification_digest,
        hex::encode(Sha256::digest(GENERATION6_CONTRACT))
    );
    assert!(!generation6.tables.contains_key("surface_object_usage"));
    assert!(!generation6
        .tables
        .contains_key("binding_identity_reservations"));
    assert_eq!(current.tables["surface_object_usage"].columns.len(), 5);
    assert_eq!(
        current.tables["binding_identity_reservations"]
            .columns
            .len(),
        3
    );
    assert_eq!(generation5.manifest().migration_digests, digests()[..5]);
    assert_eq!(
        generation5.manifest().classification_digest,
        hex::encode(Sha256::digest(GENERATION5_CONTRACT))
    );
    assert_eq!(generation5.tables["mirror_import_objects"].columns.len(), 9);
    assert_eq!(
        generation6.tables["mirror_import_objects"].columns.len(),
        12
    );
    assert_eq!(current.tables["mirror_import_objects"].columns.len(), 13);
    assert!(!historical.tables.contains_key("direct_upload_sessions"));
    assert_eq!(historical.manifest().migration_digests, digests()[..3]);
    assert_eq!(generation4.manifest().migration_digests, digests()[..4]);
    assert!(!generation4.tables.contains_key("mirror_import_objects"));
    assert!(current.tables.contains_key("mirror_import_objects"));
    assert_eq!(
        historical.manifest().classification_digest,
        hex::encode(Sha256::digest(LEGACY_CONTRACT))
    );
    assert_eq!(
        generation4.manifest().classification_digest,
        hex::encode(Sha256::digest(GENERATION4_CONTRACT))
    );

    assert!(SnapshotClassifier::new(SCHEMA_IDENTITY, 3, &digests(), &shapes()).is_err());
    assert!(SnapshotClassifier::new(SCHEMA_IDENTITY, 4, &digests()[..3], &shapes()).is_err());
    assert!(SnapshotClassifier::new(SCHEMA_IDENTITY, 5, &digests()[..4], &shapes()).is_err());
    for version in [0, 1, 2, 9, usize::MAX] {
        assert!(SnapshotClassifier::for_supported_generation(version).is_err());
    }
}

fn shapes() -> Vec<SnapshotTableShape> {
    contract()
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
        .collect()
}

fn digests() -> Vec<String> {
    MIGRATIONS
        .iter()
        .map(|script| hex::encode(Sha256::digest(script.as_bytes())))
        .collect()
}

fn classifier() -> SnapshotClassifier {
    SnapshotClassifier::new(SCHEMA_IDENTITY, MIGRATIONS.len(), &digests(), &shapes()).unwrap()
}

fn row(table: &str, overrides: &[(&str, Value)]) -> Row {
    let contracts = contract().unwrap();
    let columns = &contracts[table].columns;
    let mut values = Vec::new();
    for column in columns {
        let value = overrides
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
                        _ if column.rule == "fingerprint" => Value::Text("4".repeat(64)),
                        _ if column.rule == "idp_locator" => {
                            Value::Text("https://idp.example.invalid".into())
                        }
                        _ if table == "binding_identity_reservations"
                            && column.name == "reservation_id" =>
                        {
                            Value::Text("11111111-1111-4111-8111-111111111111".into())
                        }
                        _ => Value::Text(
                            if column.rule == "private_json" {
                                if matches!(
                                    column.name.as_str(),
                                    "permissions"
                                        | "trust_keys"
                                        | "events"
                                        | "effects_json"
                                        | "warnings_json"
                                        | "platform_os_features_json"
                                        | "os_features_json"
                                        | "path_json"
                                ) {
                                    "[]"
                                } else {
                                    "{}"
                                }
                            } else {
                                "value"
                            }
                            .into(),
                        ),
                    }
                }
            });
        values.push(value);
    }
    Row::new(values)
}

fn retained(disposition: SnapshotRowDisposition) -> ClassifiedSnapshotRow {
    match disposition {
        SnapshotRowDisposition::Retained(row) => row,
        _ => panic!("expected retained row"),
    }
}

fn idp() -> serde_json::Value {
    serde_json::json!({
        "org_id": 1, "org_slug": "test", "issuer": "https://idp.test",
        "authorization_endpoint": "https://idp.test/auth", "token_endpoint": "https://idp.test/token",
        "jwks_uri": "https://idp.test/keys", "client_id": "hub", "client_secret_enc": "PRIVATE-SEALED-IDP",
        "client_secret_action": "replace", "scopes": "openid", "groups_claim": null,
        "role_map_json": "{\"engineers\":\"developer\"}", "allow_jit": true, "enforce_sso": false,
        "default_role": "viewer", "baseline_resource_version": null, "baseline_incarnation_id": null,
        "incarnation_id": "idp-incarnation-0001"
    })
}

fn idp_plan(input: &str) -> Row {
    row(
        "topology_plans",
        &[
            ("plan_kind", Value::Text("set_identity_provider".into())),
            ("input_versions_json", Value::Text(input.into())),
            ("effects_json", Value::Text("[]".into())),
            ("warnings_json", Value::Text("[]".into())),
            (
                "confirmation_hash",
                Value::Text("original-confirmation-hash".into()),
            ),
        ],
    )
}

#[tokio::test]
async fn contract_covers_the_actual_production_initializer() {
    use crate::backend::SqlxBackend;
    use crate::db::Database;
    use sqlx::Row as _;

    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let database = Database::with_backend(Box::new(SqlxBackend::Sqlite(pool.clone())))
        .await
        .unwrap();
    let tables = sqlx::query("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
        .fetch_all(&pool).await.unwrap();
    let contracts = contract().unwrap();
    assert_eq!(contracts.len(), 279);
    assert_eq!(
        contracts
            .values()
            .map(|table| table.columns.len())
            .sum::<usize>(),
        2725
    );
    assert_eq!(tables.len(), contracts.len());

    for source_table in tables {
        let name: String = source_table.get(0);
        let source_columns = sqlx::query(&format!("PRAGMA table_info(\"{name}\")"))
            .fetch_all(&pool)
            .await
            .unwrap();
        let columns = &contracts[&name].columns;
        assert_eq!(source_columns.len(), columns.len(), "{name}");
        if contracts[&name].disposition == "retain" {
            let references = sqlx::query(&format!("PRAGMA foreign_key_list(\"{name}\")"))
                .fetch_all(&pool)
                .await
                .unwrap();
            for reference in references {
                let target: String = reference.get(2);
                assert_eq!(
                    contracts[&target].disposition, "retain",
                    "retained {name} refers to excluded {target}"
                );
            }
        }
        for (source, column) in source_columns.iter().zip(columns) {
            let column_name: String = source.get(1);
            let declared_type: String = source.get(2);
            let not_null: i64 = source.get(3);
            let primary_key: i64 = source.get(5);
            let storage = match declared_type.as_str() {
                "INTEGER" | "BIGINT" => "integer",
                "BLOB" => "bytes",
                _ => "text",
            };
            assert_eq!(column.name, column_name, "{name}");
            assert_eq!(column.storage, storage, "{name}.{column_name}");
            assert_eq!(
                column.nullable,
                not_null == 0 && primary_key == 0,
                "{name}.{column_name}"
            );
            assert_eq!(
                column.primary_key_ordinal, primary_key as usize,
                "{name}.{column_name}"
            );
        }
    }
    drop(database);
    pool.close().await;
}

#[test]
fn unknown_lineage_hashes_tables_columns_and_order_reject_before_rows() {
    let valid = shapes();
    assert!(SnapshotClassifier::new("foreign", MIGRATIONS.len(), &digests(), &valid).is_err());
    assert!(
        SnapshotClassifier::new(SCHEMA_IDENTITY, MIGRATIONS.len() + 1, &digests(), &valid).is_err()
    );
    let mut hashes = digests();
    hashes[0] = "0".repeat(64);
    assert!(SnapshotClassifier::new(SCHEMA_IDENTITY, MIGRATIONS.len(), &hashes, &valid).is_err());

    let mut variants = Vec::new();
    let mut missing = valid.clone();
    missing.pop();
    variants.push(missing);
    let mut duplicate = valid.clone();
    duplicate[0] = duplicate[1].clone();
    variants.push(duplicate);
    let mut unknown = valid.clone();
    unknown[0].name = "new_private_table".into();
    variants.push(unknown);
    let mut column = valid.clone();
    column[0].columns[0] = "secret_future_column".into();
    variants.push(column);
    let mut order = valid;
    order[0].columns.swap(0, 1);
    variants.push(order);
    for variant in variants {
        assert!(
            SnapshotClassifier::new(SCHEMA_IDENTITY, MIGRATIONS.len(), &digests(), &variant)
                .is_err()
        );
    }
}

#[test]
fn durable_password_and_token_hashes_never_enter_archive_or_debug() {
    for (table, column) in [
        ("users", "password_hash"),
        ("tokens", "hash"),
        ("invitations", "secret_enc"),
        ("org_idp_configs", "client_secret_enc"),
    ] {
        let input = row(
            table,
            &[(column, Value::Text("PRIVATE-CREDENTIAL-BYTES".into()))],
        );
        let classified = retained(classifier().classify(table, &input).unwrap());
        let serialized = serde_json::to_string(&classified).unwrap();
        assert!(!serialized.contains("PRIVATE-CREDENTIAL-BYTES"));
        assert!(!format!("{classified:?}").contains("PRIVATE-CREDENTIAL-BYTES"));
        let dependency = classified
            .private_dependencies
            .iter()
            .find(|dependency| dependency.column == column)
            .unwrap();
        assert_eq!(dependency.reason, PrivateDependencyReason::Secret);
        assert_eq!(dependency.payload_bytes, 24);
        assert_eq!(
            classified.cells[column],
            ClassifiedCell::External(cell_digest(&Value::Text("PRIVATE-CREDENTIAL-BYTES".into())))
        );
    }
}

#[test]
fn null_secret_remains_null_and_creates_no_private_dependency() {
    let classified = retained(classifier().classify("users", &row("users", &[])).unwrap());
    assert_eq!(
        classified.cells["password_hash"],
        ClassifiedCell::Scalar(SnapshotScalar::Null)
    );
    assert!(classified
        .private_dependencies
        .iter()
        .all(|dependency| dependency.column != "password_hash"));
}

#[test]
fn sealed_dynamic_setting_is_private_and_unknown_keys_fail_closed() {
    let input = row(
        "instance_config",
        &[
            ("config_key", Value::Text("draft_signing_key".into())),
            ("value", Value::Text("PRIVATE-SIGNING-SEED".into())),
        ],
    );
    let classified = retained(classifier().classify("instance_config", &input).unwrap());
    assert_eq!(
        classified.private_dependencies[0].reason,
        PrivateDependencyReason::Secret
    );
    assert!(!serde_json::to_string(&classified)
        .unwrap()
        .contains("PRIVATE-SIGNING-SEED"));

    let unknown = row(
        "instance_config",
        &[
            ("config_key", Value::Text("future_secret_key".into())),
            ("value", Value::Text("PRIVATE-UNKNOWN".into())),
        ],
    );
    let error = classifier()
        .classify("instance_config", &unknown)
        .unwrap_err()
        .to_string();
    assert!(!error.contains("PRIVATE-UNKNOWN"));
    assert!(!error.contains("future_secret_key"));
}

#[test]
fn all_current_dynamic_keys_have_explicit_classification() {
    let inputs = [
        ("site_title", "hub"),
        ("tagline", "hello"),
        ("announcement", "news"),
        ("tos_url", "https://test/tos"),
        ("privacy_url", "https://test/privacy"),
        ("support_url", "https://test/support"),
        ("signup_policy", "invite_only"),
        ("signup_domains", "test.example"),
        ("password_login", "on"),
        ("caches_public", "false"),
        ("session_lifetime_secs", "300"),
        ("default_crawl_policy", "allow_no_ai"),
        ("max_upload_bytes", "4194304"),
        ("root_crawl_policy", "deny_all"),
        ("root_robots_body", "User-agent: *"),
        ("root_llms_body", "Hub"),
        ("draft_signing_key", "sealed"),
    ];
    for (key, value) in inputs {
        let input = row(
            "instance_config",
            &[
                ("config_key", Value::Text(key.into())),
                ("value", Value::Text(value.into())),
            ],
        );
        assert!(
            classifier().classify("instance_config", &input).is_ok(),
            "{key}"
        );
    }
    for (key, value) in [
        ("signup_policy", "future"),
        ("default_crawl_policy", "future"),
        ("password_login", "maybe"),
        ("max_upload_bytes", "1.5"),
    ] {
        let input = row(
            "instance_config",
            &[
                ("config_key", Value::Text(key.into())),
                ("value", Value::Text(value.into())),
            ],
        );
        assert!(classifier().classify("instance_config", &input).is_err());
    }
}

#[test]
fn historical_idp_plan_externalizes_exact_cell_without_rewriting_hashes() {
    let json = serde_json::to_string_pretty(&idp()).unwrap();
    let classified = retained(
        classifier()
            .classify("topology_plans", &idp_plan(&json))
            .unwrap(),
    );
    let dependency = classified
        .private_dependencies
        .iter()
        .find(|dependency| dependency.column == "input_versions_json")
        .unwrap();
    assert_eq!(dependency.reason, PrivateDependencyReason::Secret);
    assert_eq!(
        dependency.cell_digest,
        cell_digest(&Value::Text(json.clone()))
    );
    assert_eq!(dependency.payload_bytes, json.len());
    assert_eq!(
        classified.cells["confirmation_hash"],
        ClassifiedCell::Scalar(SnapshotScalar::Text("original-confirmation-hash".into()))
    );
    assert!(!serde_json::to_string(&classified)
        .unwrap()
        .contains("PRIVATE-SEALED-IDP"));
    assert!(json::validate_private(
        "topology_plans",
        "input_versions_json",
        &json.replace("replace", "preserve"),
        Some("set_identity_provider")
    )
    .unwrap());
}

#[test]
fn secret_bearing_typed_json_rejects_unknown_fields_versions_and_nested_roles() {
    for field in ["schema_version", "unexpected_secret_field"] {
        let mut value = idp();
        value[field] = serde_json::json!("PRIVATE-FUTURE");
        let error = classifier()
            .classify("topology_plans", &idp_plan(&value.to_string()))
            .unwrap_err()
            .to_string();
        assert!(!error.contains("PRIVATE-FUTURE"));
    }
    let mut value = idp();
    value["role_map_json"] = serde_json::json!("{\"engineers\":\"future_superadmin\"}");
    assert!(classifier()
        .classify("topology_plans", &idp_plan(&value.to_string()))
        .is_err());
    let duplicate = serde_json::to_string(&idp())
        .unwrap()
        .replacen('{', "{\"org_id\":2,", 1);
    assert!(classifier()
        .classify("topology_plans", &idp_plan(&duplicate))
        .is_err());
}

#[test]
fn opaque_history_is_private_and_unknown_wire_versions_reject_recursively() {
    let history = row(
        "change_request_revisions",
        &[
            (
                "old_json",
                Value::Text("{\"client_secret_enc\":\"PRIVATE-HISTORY\"}".into()),
            ),
            (
                "new_json",
                Value::Text("{\"version\":\"ordinary-package-version\"}".into()),
            ),
        ],
    );
    let classified = retained(
        classifier()
            .classify("change_request_revisions", &history)
            .unwrap(),
    );
    assert!(!serde_json::to_string(&classified)
        .unwrap()
        .contains("PRIVATE-HISTORY"));
    for json in [
        "{\"schema_version\":99}",
        "{\"child\":{\"apiVersion\":\"future\"}}",
        "{\"x\":1,\"x\":2}",
        "{\"x\":1.5}",
    ] {
        let input = row(
            "change_request_revisions",
            &[("old_json", Value::Text(json.into()))],
        );
        assert!(classifier()
            .classify("change_request_revisions", &input)
            .is_err());
    }
}

#[test]
fn only_auth_ceremonies_are_transient_leases_sessions_and_fences_survive() {
    let contracts = contract().unwrap();
    for table in [
        "sessions",
        "oidc_flows",
        "magic_links",
        "webauthn_challenges",
        "device_codes",
        "refresh_tokens",
        "refresh_token_families",
        "rate_limits",
    ] {
        assert_eq!(
            classifier().classify(table, &row(table, &[])).unwrap(),
            SnapshotRowDisposition::AuthTransient
        );
    }
    for table in [
        "retention_leases",
        "cache_object_mutation_fences",
        "object_deletion_attempt_receipts",
        "oci_upload_sessions",
        "registry_publication_manifest_sessions",
        "worker_job_executions",
        "physical_storage_authorities",
        "storage_authority_admission_heads",
    ] {
        assert_eq!(contracts[table].disposition, "retain", "{table}");
    }
    assert!(matches!(
        classifier()
            .classify("retention_leases", &row("retention_leases", &[]))
            .unwrap(),
        SnapshotRowDisposition::Retained(_)
    ));
}

#[test]
fn integer_bytes_and_type_separated_digest_remain_lossless() {
    let classified = retained(
        classifier()
            .classify("users", &row("users", &[("id", Value::Int(i64::MAX))]))
            .unwrap(),
    );
    assert_eq!(
        classified.cells["id"],
        ClassifiedCell::Scalar(SnapshotScalar::Integer("9223372036854775807".into()))
    );
    assert_eq!(
        scalar(&Value::Bytes(vec![0, 128, 255])).unwrap(),
        SnapshotScalar::BytesHex("0080ff".into())
    );
    assert_ne!(
        cell_digest(&Value::Text("1".into())),
        cell_digest(&Value::Int(1))
    );
    assert_ne!(
        cell_digest(&Value::Text("".into())),
        cell_digest(&Value::Bytes(vec![]))
    );
    assert_ne!(
        cell_digest(&Value::Bytes(vec![])),
        cell_digest(&Value::Null)
    );
}

#[test]
fn exact_private_locator_distinguishes_rows_columns_and_original_json_whitespace() {
    let first = retained(
        classifier()
            .classify(
                "users",
                &row(
                    "users",
                    &[
                        ("id", Value::Int(1)),
                        ("password_hash", Value::Text("private".into())),
                    ],
                ),
            )
            .unwrap(),
    );
    let second = retained(
        classifier()
            .classify(
                "users",
                &row(
                    "users",
                    &[
                        ("id", Value::Int(2)),
                        ("password_hash", Value::Text("private".into())),
                    ],
                ),
            )
            .unwrap(),
    );
    assert_ne!(
        first.private_dependencies[0].primary_key_digest,
        second.private_dependencies[0].primary_key_digest
    );
    assert_eq!(
        first.private_dependencies[0].cell_digest,
        second.private_dependencies[0].cell_digest
    );
    let compact = serde_json::to_string(&idp()).unwrap();
    let pretty = serde_json::to_string_pretty(&idp()).unwrap();
    assert_ne!(
        cell_digest(&Value::Text(compact)),
        cell_digest(&Value::Text(pretty))
    );
}

#[test]
fn unknown_storage_classes_nulls_width_and_oversize_cells_reject() {
    let classifier = classifier();
    assert!(classifier.classify("future", &Row::new(vec![])).is_err());
    assert!(classifier.classify("users", &Row::new(vec![])).is_err());
    for value in [
        Value::Null,
        Value::Real(1.0),
        Value::Text("1".into()),
        Value::Bytes(vec![1]),
    ] {
        assert!(classifier
            .classify("users", &row("users", &[("id", value)]))
            .is_err());
    }
    assert!(classifier
        .classify(
            "users",
            &row(
                "users",
                &[("password_hash", Value::Text("p".repeat(MAX_CELL_BYTES + 1)))]
            )
        )
        .is_err());
    assert!(scalar(&Value::Real(f64::NAN)).is_err());
}

#[test]
fn metadata_is_explicitly_outside_rows_and_manifest_retains_exact_lineage() {
    let classifier = classifier();
    assert_eq!(
        classifier
            .classify("schema_version", &row("schema_version", &[]))
            .unwrap(),
        SnapshotRowDisposition::SourceMetadata
    );
    assert_eq!(classifier.manifest().identity, SCHEMA_IDENTITY);
    assert_eq!(classifier.manifest().migration_digests, digests());
    assert_eq!(
        classifier.manifest().classification_digest,
        hex::encode(Sha256::digest(CONTRACT))
    );
}

fn authority() -> serde_json::Value {
    serde_json::json!({
        "authority_id": "00000000-0000-4000-8000-000000000001",
        "guard_namespace_id": "guard-real-lifetime-identity",
        "physical_resource_evidence_digest": "1".repeat(64),
        "qualification_digest": "2".repeat(64),
        "qualified_managed_prefix": "managed/root"
    })
}

#[test]
fn authority_coordinates_and_original_json_survive_without_namespace_adoption() {
    let original = serde_json::to_string_pretty(&authority()).unwrap();
    let classified = retained(
        classifier()
            .classify(
                "physical_storage_authorities",
                &row(
                    "physical_storage_authorities",
                    &[
                        (
                            "authority_id",
                            Value::Text("00000000-0000-4000-8000-000000000001".into()),
                        ),
                        (
                            "guard_namespace_id",
                            Value::Text("guard-real-lifetime-identity".into()),
                        ),
                        ("specification_json", Value::Text(original.clone())),
                    ],
                ),
            )
            .unwrap(),
    );
    assert_eq!(
        classified.cells["specification_json"],
        ClassifiedCell::Scalar(SnapshotScalar::Text(original))
    );
    assert_eq!(
        classified.cells["guard_namespace_id"],
        ClassifiedCell::Scalar(SnapshotScalar::Text("guard-real-lifetime-identity".into()))
    );
    assert!(classified.private_dependencies.is_empty());
}

#[test]
fn authority_json_cannot_gain_unknown_keys_versions_or_missing_qualification_ceiling() {
    let mut variants = Vec::new();
    let mut unknown = authority();
    unknown["runtime_namespace_override"] = serde_json::json!("other");
    variants.push(unknown);
    let mut future = authority();
    future["schema_version"] = serde_json::json!(2);
    variants.push(future);
    let mut missing = authority();
    missing
        .as_object_mut()
        .unwrap()
        .remove("qualified_managed_prefix");
    variants.push(missing);
    let mut escape = authority();
    escape["qualified_managed_prefix"] = serde_json::json!("managed/../outside");
    variants.push(escape);
    for variant in variants {
        assert!(classifier()
            .classify(
                "physical_storage_authorities",
                &row(
                    "physical_storage_authorities",
                    &[("specification_json", Value::Text(variant.to_string())),]
                )
            )
            .is_err());
    }
    let wrong_plan = serde_json::json!({"kind":"create", "input":authority()});
    assert!(json::validate_private(
        "topology_plans",
        "input_versions_json",
        &wrong_plan.to_string(),
        Some("set_storage_authority_admission")
    )
    .is_err());
}

#[test]
fn recorded_executor_watermarks_and_secret_references_are_retained_as_evidence() {
    let classified = retained(
        classifier()
            .classify(
                "storage_authority_admission_heads",
                &row(
                    "storage_authority_admission_heads",
                    &[
                        ("desired_generation", Value::Int(i64::MAX)),
                        ("acknowledged_generation", Value::Int(i64::MAX)),
                        ("acknowledged_digest", Value::Text("3".repeat(64))),
                    ],
                ),
            )
            .unwrap(),
    );
    assert_eq!(
        classified.cells["acknowledged_generation"],
        ClassifiedCell::Scalar(SnapshotScalar::Integer(i64::MAX.to_string()))
    );
    assert!(classified.private_dependencies.is_empty());

    let reference = "native://example/provider-credential/v7";
    let binding = retained(
        classifier()
            .classify(
                "binding_credential_revisions",
                &row(
                    "binding_credential_revisions",
                    &[
                        ("secret_version_ref", Value::Text(reference.into())),
                        ("credential_fingerprint", Value::Text("4".repeat(64))),
                    ],
                ),
            )
            .unwrap(),
    );
    assert_eq!(
        binding.cells["secret_version_ref"],
        ClassifiedCell::Scalar(SnapshotScalar::Text(reference.into()))
    );
    // Keeping this immutable reference does not fetch the credential or turn
    // a recorded acknowledgement into a fresh authenticated remote watermark.
}

#[test]
fn typed_permissions_and_image_delivery_reject_unknown_contract_extensions() {
    let input = row(
        "tokens",
        &[("permissions", Value::Text("[\"future.permission\"]".into()))],
    );
    assert!(classifier().classify("tokens", &input).is_err());
    let input = row(
        "tokens",
        &[("permissions", Value::Text("{\"read\":true}".into()))],
    );
    assert!(classifier().classify("tokens", &input).is_err());

    let marker = aos_registry_surface::manifest::ImageDelivery::store_only();
    let value = serde_json::to_value(marker).unwrap();
    let current = serde_json::json!({"store_path":"/nix/store/example", "nar_hash":"sha256:example", "nar_size":1, "delivery":value});
    assert!(json::validate_private(
        "registry_system_images",
        "delivery",
        &current.to_string(),
        None
    )
    .is_ok());
    let mut future = current.clone();
    future["delivery"]["schema_version"] = serde_json::json!(99);
    assert!(json::validate_private(
        "registry_system_images",
        "delivery",
        &future.to_string(),
        None
    )
    .is_err());
    let mut extension = current;
    extension["delivery"]["secret_runtime_flags"] = serde_json::json!("private");
    assert!(json::validate_private(
        "registry_system_images",
        "delivery",
        &extension.to_string(),
        None
    )
    .is_err());
}

#[test]
fn classified_network_address_bytes_preserve_zero_and_non_utf8_values() {
    let input = row(
        "endpoints",
        &[("ipv4_bytes", Value::Bytes(vec![0, 128, 255, 1]))],
    );
    let classified = retained(classifier().classify("endpoints", &input).unwrap());
    assert_eq!(
        classified.cells["ipv4_bytes"],
        ClassifiedCell::Scalar(SnapshotScalar::BytesHex("0080ff01".into()))
    );
}

#[test]
fn oversized_total_row_rejects_before_structured_or_private_output() {
    let contracts = contract().unwrap();
    let values = contracts["topology_plans"]
        .columns
        .iter()
        .map(|column| match column.storage.as_str() {
            "integer" => Value::Int(1),
            _ => Value::Text("private".repeat(MAX_CELL_BYTES / 7)),
        })
        .collect();
    let error = classifier()
        .classify("topology_plans", &Row::new(values))
        .unwrap_err();
    assert_eq!(error.to_string(), "snapshot row payload exceeds limits");
}

#[tokio::test]
async fn bounded_reader_page_classifies_private_cells_without_source_mutation() {
    use crate::backend::sqlite_snapshot::{SqliteSnapshotLimits, SqliteSnapshotReader};
    use crate::backend::SqlxBackend;
    use crate::db::Database;

    let directory = tempfile::TempDir::new().unwrap();
    let path = directory.path().join("hub.db");
    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(&path)
        .create_if_missing(true);
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .unwrap();
    let database = Database::with_backend(Box::new(SqlxBackend::Sqlite(pool.clone())))
        .await
        .unwrap();
    sqlx::query("INSERT INTO users(id,email,password_hash,created_at) VALUES (1,'test@example.invalid','PRIVATE-SOURCE-PHC',1)")
        .execute(&pool).await.unwrap();
    drop(database);
    pool.close().await;
    let before = std::fs::read(&path).unwrap();

    let mut reader = SqliteSnapshotReader::open(&path).await.unwrap();
    let classifier = SnapshotClassifier::from_sqlite_schema(reader.schema()).unwrap();
    let mut table = reader.table("users").unwrap();
    let page = table
        .next_page(SqliteSnapshotLimits {
            max_rows: 1,
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(page.rows.len(), 1);
    let classified = classifier.classify("users", &page.rows[0]).unwrap();
    assert!(!serde_json::to_string(&classified)
        .unwrap()
        .contains("PRIVATE-SOURCE-PHC"));
    drop(table);
    reader.close().await.unwrap();

    assert_eq!(std::fs::read(&path).unwrap(), before);
}

mod authority_plan;

#[test]
fn original_session_owner_pin_remains_excluded_as_authentication_transient_state() {
    let classifier = SnapshotClassifier::for_supported_generation(4).unwrap();
    let input = row(
        "sessions",
        &[(
            "owner_incarnation",
            Value::Text("01234567-89ab-4def-8123-456789abcdef".into()),
        )],
    );
    assert!(matches!(
        classifier.classify("sessions", &input).unwrap(),
        SnapshotRowDisposition::AuthTransient
    ));
    assert_eq!(
        classifier.table_disposition("sessions").unwrap(),
        "auth_transient"
    );
    let historical = SnapshotClassifier::for_supported_generation(3).unwrap();
    assert!(!historical.tables["sessions"]
        .columns
        .iter()
        .any(|column| column.name == "owner_incarnation"));
}

#[test]
fn generation8_adds_channel_classification_without_changing_generation7() {
    let previous = SnapshotClassifier::for_supported_generation(7).unwrap();
    let current = SnapshotClassifier::for_supported_generation(8).unwrap();

    assert_eq!(previous.manifest.migration_digests, digests()[..7]);
    assert_eq!(
        previous.manifest.classification_digest,
        hex::encode(Sha256::digest(GENERATION7_CONTRACT))
    );
    assert!(!previous.tables.contains_key("release_channel_advances"));
    assert_eq!(current.tables.len(), previous.tables.len() + 1);
    assert_eq!(current.tables["release_channel_advances"].columns.len(), 11);
    assert_eq!(current.manifest.migration_digests, digests());
}
