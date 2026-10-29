//! Checks literal credential bytes, shared wire compatibility and private inputs.

use super::*;
use aos_hub_db::storage_authority::lease::control::verify_issuer_request;
use std::os::unix::fs::symlink;
use tempfile::TempDir;

// A hex-looking credential is still literal HMAC material, as in Native's loader.
const CREDENTIAL: &[u8] = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[test]
fn ingress_preserves_literal_key_and_distinct_signed_and_header_phases() {
    let root = TempDir::new().unwrap();
    write(root.path(), "key", CREDENTIAL).unwrap();
    write(root.path(), "body", b"controlled payload").unwrap();
    let output = root.path().join("prepared");

    execute(Selection::IngressPrepare {
        key_file: root.path().join("key"),
        deployment_id: "controlled-deployment".into(),
        authority: "controlled.test".into(),
        method: "PUT".into(),
        path_and_query: "/controlled".into(),
        body_file: root.path().join("body"),
        signed_phase: Some("preflight".into()),
        header_phase: Some("admit".into()),
        output_directory: output.clone(),
    })
    .unwrap();

    let headers = fs::read_to_string(output.join("headers.txt")).unwrap();
    let compact = headers
        .lines()
        .next()
        .unwrap()
        .strip_prefix("x-aos-hybrid-ingress: ")
        .unwrap();
    let assertion = HybridIngressKey::new(CREDENTIAL)
        .unwrap()
        .verify(
            compact,
            "controlled-deployment",
            "PUT",
            "/controlled",
            b"controlled payload",
            now().unwrap(),
        )
        .unwrap();
    assert_eq!(assertion.upload_phase.as_deref(), Some("preflight"));
    assert!(headers
        .lines()
        .any(|line| line == "x-aos-hybrid-upload-phase: admit"));
}

#[test]
fn issuer_request_round_trips_through_the_shared_literal_key_verifier() {
    let root = TempDir::new().unwrap();
    write(root.path(), "key", CREDENTIAL).unwrap();
    let installation: IssuerInstallation = serde_json::from_value(json!({
        "format_version": 1,
        "authority": {
            "authority_id": "00000000-0000-4000-8000-000000000001",
            "guard_namespace_id": "controlled-namespace",
            "physical_resource_evidence_digest": "a".repeat(64),
            "qualification_digest": "b".repeat(64),
            "qualified_managed_prefix": "controlled"
        },
        "issuer_resource_id": "controlled-resource",
        "runtime_identity": "controlled-runtime",
        "executor_identity": "controlled-executor"
    }))
    .unwrap();
    let output = root.path().join("prepared");

    execute(Selection::IssuerPrepare {
        key_file: root.path().join("key"),
        installation: installation.clone(),
        operation: IssuerOperation::Current,
        output_directory: output.clone(),
    })
    .unwrap();

    let bytes = fs::read(output.join("request.json")).unwrap();
    let request = IssuerRequest::decode(&bytes).unwrap();
    request.validate(&installation, now().unwrap()).unwrap();
    let headers = fs::read_to_string(output.join("headers.txt")).unwrap();
    let signature = headers
        .lines()
        .find_map(|line| line.strip_prefix("x-aos-storage-work-signature: "))
        .unwrap();
    verify_issuer_request(&StorageWorkKey::new(CREDENTIAL).unwrap(), signature, &bytes).unwrap();
}

#[test]
fn input_custody_refuses_links_and_group_readable_material() {
    let root = TempDir::new().unwrap();
    write(root.path(), "key", CREDENTIAL).unwrap();
    let key = root.path().join("key");
    let link = root.path().join("link");
    symlink(&key, &link).unwrap();

    assert!(read(&link, 256).is_err());
    fs::set_permissions(&key, fs::Permissions::from_mode(0o640)).unwrap();
    assert!(read(&key, 256).is_err());
}
