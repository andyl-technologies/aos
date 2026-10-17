//! Regression coverage for source-admitted private values and reference checks.

use super::*;

#[test]
fn unrestricted_settings_mirror_auth_urls_and_body_error_cells_stay_private() {
    let inputs = [
        ("instance_config", "value", "PRIVATE-DOMAIN-CONTEXT"),
        (
            "mirror_sources",
            "auth_secret_ref",
            "PRIVATE-UNRESTRICTED-MIRROR-AUTH",
        ),
        (
            "mirror_sources",
            "upstream_url",
            "https://upstream.test/path?token=PRIVATE-URL-TOKEN",
        ),
        ("webhooks", "url", "https://hooks.test/PRIVATE-HOOK-TOKEN"),
        ("registries", "llms_txt_body", "PRIVATE-FREE-BODY"),
        (
            "mirror_sources",
            "last_sync_error",
            "PRIVATE-UPSTREAM-ERROR",
        ),
        ("registry_index", "error", "PRIVATE-PROVIDER-ERROR"),
        ("registry_index", "readme", "PRIVATE-ARTIFACT-MARKDOWN"),
    ];
    for (table, column, payload) in inputs {
        let mut overrides = vec![(column, Value::Text(payload.into()))];
        if table == "instance_config" {
            overrides.push(("config_key", Value::Text("signup_domains".into())));
        }
        let classified = retained(
            classifier()
                .classify(table, &row(table, &overrides))
                .unwrap(),
        );
        let dependency = classified
            .private_dependencies
            .iter()
            .find(|dependency| dependency.column == column)
            .unwrap();
        assert_eq!(dependency.reason, PrivateDependencyReason::PrivateContext);
        assert_eq!(
            dependency.cell_digest,
            cell_digest(&Value::Text(payload.into()))
        );
        assert!(
            !serde_json::to_string(&classified)
                .unwrap()
                .contains(payload),
            "{table}.{column}"
        );
        assert!(
            !format!("{classified:?}").contains(payload),
            "{table}.{column}"
        );
    }
}

#[test]
fn strict_reference_and_fingerprint_cells_reject_payloads_with_redacted_errors() {
    for (table, column) in [
        ("binding_credential_revisions", "secret_version_ref"),
        ("binding_write_revisions", "write_credential_version_ref"),
        ("webhooks", "secret_version_ref"),
        ("binding_credential_revisions", "credential_fingerprint"),
        ("webhooks", "credential_fingerprint"),
    ] {
        let error = classifier()
            .classify(
                table,
                &row(
                    table,
                    &[(column, Value::Text("PRIVATE-INLINE-CREDENTIAL".into()))],
                ),
            )
            .unwrap_err();
        assert!(!format!("{error:#}").contains("PRIVATE-INLINE-CREDENTIAL"));
        assert!(!format!("{error:?}").contains("PRIVATE-INLINE-CREDENTIAL"));
    }
    let valid = row(
        "binding_write_revisions",
        &[(
            "write_credential_version_ref",
            Value::Text("native://test/write/v7".into()),
        )],
    );
    assert!(classifier()
        .classify("binding_write_revisions", &valid)
        .is_ok());
}

#[test]
fn authority_nested_credentials_require_nonsecret_reference_shape_without_freshness_checks() {
    let input = serde_json::json!({
        "attestation_id":"attestation-1", "authority_id":"00000000-0000-4000-8000-000000000001",
        "managed_prefix":"managed/root", "qualification_digest":"1".repeat(64),
        "provider_policy_evidence_digest":"2".repeat(64), "executor_identity":"executor-lifetime-identity",
        "credentials":[{"association_id":"association-1", "purpose":"write", "generation":1,
            "secret_version_ref":"native://test/write/v7", "credential_fingerprint":"3".repeat(64)}],
        "valid_until":1
    });
    let classified = retained(
        classifier()
            .classify(
                "storage_authority_attestations",
                &row(
                    "storage_authority_attestations",
                    &[
                        ("specification_json", Value::Text(input.to_string())),
                        ("valid_until", Value::Int(1)),
                    ],
                ),
            )
            .unwrap(),
    );
    assert_eq!(
        classified.cells["valid_until"],
        ClassifiedCell::Scalar(SnapshotScalar::Integer("1".into()))
    );
    assert!(classified.private_dependencies.is_empty());

    for field in ["secret_version_ref", "credential_fingerprint"] {
        let mut invalid = input.clone();
        invalid["credentials"][0][field] = serde_json::json!("PRIVATE-NESTED-PAYLOAD");
        let error = classifier()
            .classify(
                "storage_authority_attestations",
                &row(
                    "storage_authority_attestations",
                    &[("specification_json", Value::Text(invalid.to_string()))],
                ),
            )
            .unwrap_err();
        assert!(!format!("{error:#}").contains("PRIVATE-NESTED-PAYLOAD"));
        let plan = serde_json::json!({"kind":"attest", "input":invalid});
        assert!(json::validate_private(
            "topology_plans",
            "input_versions_json",
            &plan.to_string(),
            Some("attest_storage_authority_exclusivity")
        )
        .is_err());
    }
}

#[test]
fn idp_locators_reject_credential_components_and_preserve_historical_debug_locators() {
    for field in [
        "issuer",
        "authorization_endpoint",
        "token_endpoint",
        "jwks_uri",
    ] {
        for raw in [
            "https://idp.test/?token=PRIVATE-CREDENTIAL",
            "https://user:PRIVATE-CREDENTIAL@idp.test/",
            "https://idp.test/#PRIVATE-CREDENTIAL",
        ] {
            let error = classifier()
                .classify(
                    "org_idp_configs",
                    &row("org_idp_configs", &[(field, Value::Text(raw.into()))]),
                )
                .unwrap_err();
            assert!(!format!("{error:#}").contains("PRIVATE-CREDENTIAL"));
        }
    }
    assert!(json::validate_idp_locator("http://127.0.0.1:8900/issuer").is_ok());
    assert!(json::validate_idp_locator("http://public.test/issuer").is_err());
}

fn upload_hash_row(state: &crate::db::OciSha256State) -> Row {
    let names = [
        "sha256_h0",
        "sha256_h1",
        "sha256_h2",
        "sha256_h3",
        "sha256_h4",
        "sha256_h5",
        "sha256_h6",
        "sha256_h7",
    ];
    let mut overrides: Vec<_> = names
        .into_iter()
        .zip(state.words)
        .map(|(name, word)| (name, Value::Int(i64::from(word))))
        .collect();
    overrides.extend([
        ("sha256_state_version", Value::Int(i64::from(state.version))),
        (
            "sha256_total_bytes",
            Value::Int(i64::try_from(state.total_bytes).unwrap()),
        ),
        ("sha256_tail_hex", Value::Text(state.tail_hex.clone())),
    ]);
    row("oci_upload_sessions", &overrides)
}

#[test]
fn real_oci_hash_tail_upload_bytes_are_private_and_unknown_continuation_versions_reject() {
    let mut state = crate::db::OciSha256State::initial();
    state.update(b"PRIVATE-RAW-UPLOAD-TAIL").unwrap();
    assert_eq!(
        hex::decode(&state.tail_hex).unwrap(),
        b"PRIVATE-RAW-UPLOAD-TAIL"
    );
    let classified = retained(
        classifier()
            .classify("oci_upload_sessions", &upload_hash_row(&state))
            .unwrap(),
    );
    let serialized = serde_json::to_string(&classified).unwrap();
    assert!(!serialized.contains("PRIVATE-RAW-UPLOAD-TAIL"));
    assert!(!serialized.contains(&state.tail_hex));
    assert!(!format!("{classified:?}").contains(&state.tail_hex));
    let dependency = classified
        .private_dependencies
        .iter()
        .find(|dependency| dependency.column == "sha256_tail_hex")
        .unwrap();
    assert_eq!(
        dependency.cell_digest,
        cell_digest(&Value::Text(state.tail_hex.clone()))
    );
    assert_eq!(dependency.reason, PrivateDependencyReason::PrivateContext);

    state.version += 1;
    assert!(classifier()
        .classify("oci_upload_sessions", &upload_hash_row(&state))
        .is_err());
}
