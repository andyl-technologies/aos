//! Tests for attestation metadata and content digests binding published artifacts.

#[test]
fn package_attestation_measurement_changes_when_manifest_digest_changes() {
    let root_hash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let first = crate::package_attestation::package_measurement_digest(
        "webapp",
        "1.0.0",
        root_hash,
        &crate::package_attestation::package_manifest_digest_bytes(br#"{\"network\":\"private\"}"#),
    );
    let second = crate::package_attestation::package_measurement_digest(
        "webapp",
        "1.0.0",
        root_hash,
        &crate::package_attestation::package_manifest_digest_bytes(br#"{\"network\":\"host\"}"#),
    );

    assert_ne!(first, second);
}
