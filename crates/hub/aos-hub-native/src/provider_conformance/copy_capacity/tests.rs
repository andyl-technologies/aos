//! Closed installed-ceiling declarations and fail-closed output regressions.

use super::*;

#[test]
fn declaration_rejects_unknown_fields_and_duplicate_domain_fields() {
    let mut declared = json!({
        "version": 1, "deployment_id": "deployment", "public_origin": "https://example.invalid/",
        "reviewer_key_id": "reviewer", "domains": [{
            "producer_profile_digest": "a".repeat(64), "admitted_provider_requests": 5,
        }],
    });
    assert!(serde_json::from_value::<Declaration>(declared.clone()).is_ok());
    declared["measured_peak"] = 5.into();
    assert!(serde_json::from_value::<Declaration>(declared).is_err());
    assert!(serde_json::from_str::<DomainCeiling>(
        r#"{"producer_profile_digest":"a","admitted_provider_requests":3,"admitted_provider_requests":5}"#,
    ).is_err());
}

#[test]
fn invalid_artifact_never_creates_a_capacity_projection() {
    let directory = tempfile::tempdir().unwrap();
    let artifact = directory.path().join("artifact.json");
    let key = directory.path().join("key");
    let declaration = directory.path().join("declaration.json");
    let output = directory.path().join("capacity.json");
    std::fs::write(&artifact, b"{}").unwrap();
    std::fs::write(&key, "a".repeat(64)).unwrap();
    std::fs::write(&declaration, b"{}").unwrap();

    assert!(project(&artifact, &key, &declaration, &output).is_err());
    assert!(!output.exists());
}
