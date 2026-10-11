//! Explicit opt-in loader rejects wrong Native incarnation and unknown reviewers.

use aos_hub_core::oci_sdk_emulation::oci_sdk_emulation_fixture;

use super::*;

#[test]
fn explicit_loader_matches_actual_process_audience_and_separate_reviewer() {
    let (artifact, reviewer) = oci_sdk_emulation_fixture();
    let bytes = serde_json::to_vec(&artifact).unwrap();
    let keys = serde_json::to_vec(&BTreeMap::from([(
        artifact.reviewer_key_id.clone(),
        reviewer.clone(),
    )]))
    .unwrap();
    let load = |keys: &[u8], process: &str, native_origin: &str, now| {
        NativeOciSdkEmulation::from_bytes(
            &bytes,
            keys,
            "test-deployment",
            "https://worker.oci.test",
            native_origin,
            process,
            now,
        )
    };
    let accepted = load(
        &keys,
        &artifact.evidence.installation.native_executable_sha256,
        "https://native.oci.test",
        110,
    )
    .unwrap();
    accepted
        .check("test-deployment", "https://worker.oci.test", 111)
        .unwrap();
    assert!(accepted
        .check("test-deployment", "https://worker.oci.test", 398)
        .is_err());
    assert!(accepted
        .check("other-deployment", "https://worker.oci.test", 111)
        .is_err());
    assert!(load(&keys, &"ff".repeat(32), "https://native.oci.test", 110).is_err());
    assert!(load(
        &keys,
        &artifact.evidence.installation.native_executable_sha256,
        "https://other.oci.test",
        110,
    )
    .is_err());
    let unknown = serde_json::to_vec(&BTreeMap::from([("another-reviewer", reviewer)])).unwrap();
    assert!(load(
        &unknown,
        &artifact.evidence.installation.native_executable_sha256,
        "https://native.oci.test",
        110,
    )
    .is_err());
    assert!(load(
        b"{}",
        &artifact.evidence.installation.native_executable_sha256,
        "https://native.oci.test",
        110,
    )
    .is_err());
}
