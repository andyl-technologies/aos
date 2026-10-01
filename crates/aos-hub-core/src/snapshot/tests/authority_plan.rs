//! Closed canonical review envelopes and unchanged historical private bytes.

use super::*;

#[test]
fn authority_review_envelope_preserves_exact_private_bytes_and_legacy_plan_shape() {
    let decision = serde_json::json!({"kind":"create", "input":authority()});
    let envelope = serde_json::json!({
        "schema_version":1, "expected_resource_version":"", "decision":decision
    });
    for input in [decision, envelope] {
        let original = serde_json::to_string_pretty(&input).unwrap();
        let classified = retained(
            classifier()
                .classify(
                    "topology_plans",
                    &row(
                        "topology_plans",
                        &[
                            ("plan_kind", Value::Text("create_storage_authority".into())),
                            ("input_versions_json", Value::Text(original.clone())),
                            ("confirmation_hash", Value::Text("7".repeat(64))),
                        ],
                    ),
                )
                .unwrap(),
        );
        let dependency = classified
            .private_dependencies
            .iter()
            .find(|dependency| dependency.column == "input_versions_json")
            .unwrap();
        assert_eq!(
            dependency.cell_digest,
            cell_digest(&Value::Text(original.clone()))
        );
        assert!(
            !serde_json::to_string(&classified)
                .unwrap()
                .contains(&original)
        );
        assert_eq!(
            classified.cells["confirmation_hash"],
            ClassifiedCell::Scalar(SnapshotScalar::Text("7".repeat(64)))
        );
    }
}

#[test]
fn authority_review_envelope_rejects_unknown_duplicate_and_disagreeing_versions() {
    let valid = serde_json::json!({
        "schema_version":1, "expected_resource_version":"",
        "decision":{"kind":"create", "input":authority()}
    });
    let mut unknown = valid.clone();
    unknown["schema_version"] = serde_json::json!(2);
    let mut extension = valid.clone();
    extension["PRIVATE-UNSUPPORTED-FIELD"] = serde_json::json!("PRIVATE-PAYLOAD");
    let mut mismatch = valid.clone();
    mismatch["expected_resource_version"] = serde_json::json!("not-empty");
    let duplicate = valid.to_string().replacen("{", "{\"schema_version\":1,", 1);
    for raw in [
        unknown.to_string(),
        extension.to_string(),
        mismatch.to_string(),
        duplicate,
    ] {
        let error = json::validate_private(
            "topology_plans",
            "input_versions_json",
            &raw,
            Some("create_storage_authority"),
        )
        .unwrap_err();
        assert!(!format!("{error:#}").contains("PRIVATE-PAYLOAD"));
        assert!(!format!("{error:?}").contains("PRIVATE-UNSUPPORTED-FIELD"));
    }
}
