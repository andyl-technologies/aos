//! Explicitly synthetic test fixtures; these never qualify SDK or provider execution.

use ed25519_dalek::{Signer as _, SigningKey};

use crate::{
    direct_upload::{
        direct_private_stage_policy_commitment, direct_worker_emulated_script_id,
        DirectClockMeasurement, DirectClockPolicy, DirectClockPolicyMode,
        DirectPrivateStagePolicyRef, WireInteger,
    },
    storage_work::StorageObjectIdentity,
};

use super::*;

fn object(key: &str, hash: u8) -> OciSdkObjectObservation {
    OciSdkObjectObservation {
        object: StorageObjectIdentity {
            key: key.into(),
            size: 64,
            etag: format!("\"{:02x}\"", hash),
            provider_version: Some(format!("test-sdk-version-{hash}")),
        },
        sha256: format!("{hash:02x}").repeat(32),
    }
}

fn artifact() -> OciSdkEmulationArtifact {
    let source = "10".repeat(32);
    let script = direct_worker_emulated_script_id(&source).unwrap();
    let namespace = "oci-sdk-qualification-0123456789abcdef0123456789abcdef";
    let anchor = object(
        ".aos-oci-sdk-qualification/0123456789abcdef0123456789abcdef/anchor",
        21,
    );
    let profile = OciSdkEmulationProfile {
        deployment_id: "test-deployment".into(),
        public_origin: "https://worker.oci.test".into(),
        native_origin: "https://native.oci.test".into(),
        worker_source_digest: source.clone(),
        worker_script_version: script.clone(),
        worker_name: "test-oci-worker".into(),
        binding_name: crate::binding::DEPLOYMENT_R2_ATTACHMENT.into(),
        namespace_id: namespace.into(),
        namespace_object_id: "11".repeat(32),
        namespace_unique_key: "miniflare-R2BucketObject".into(),
        maximum_provider_requests: 8,
        clock_policy: DirectClockPolicy {
            version: 1,
            mode: DirectClockPolicyMode::BoundedUtc,
            uncertainty_seconds: WireInteger::new(2),
        },
        private_stage_policy: DirectPrivateStagePolicyRef {
            policy_id: "test-only-oci-private".into(),
            policy_digest: direct_private_stage_policy_commitment(
                "test-only-oci-private",
                namespace,
            )
            .unwrap(),
            namespace: namespace.into(),
        },
        anchor: anchor.clone(),
    };
    let installation = OciSdkInstallation {
        namespace_observation_sha256: "01".repeat(32),
        native_observation_sha256: "02".repeat(32),
        observed_at: 100,
        native_executable_sha256: "03".repeat(32),
        native_configuration_sha256: "04".repeat(32),
        source_nar_sha256: "05".repeat(32),
        distribution_nar_sha256: "06".repeat(32),
        wasm_sha256: "07".repeat(32),
        wasm_byte_size: 4096,
        shim_sha256: "08".repeat(32),
        runner_sha256: "09".repeat(32),
        configuration_sha256: "0a".repeat(32),
        miniflare_module_sha256: "0b".repeat(32),
        miniflare_entry_worker_sha256: "0c".repeat(32),
        miniflare_bucket_worker_sha256: "0d".repeat(32),
        workerd_executable_sha256: "0e".repeat(32),
        worker_source_digest: source,
        worker_script_version: script,
        worker_name: profile.worker_name.clone(),
        binding_name: profile.binding_name.clone(),
        namespace_id: namespace.into(),
        namespace_object_id: profile.namespace_object_id.clone(),
        namespace_unique_key: profile.namespace_unique_key.clone(),
    };
    let evidence = OciSdkEmulationEvidence {
        sdk_observation_scope: OciSdkObservationScope::AnchorCreateAndConditionalRead,
        installation,
        clock: DirectClockMeasurement {
            observation_sha256: "12".repeat(32),
            samples: WireInteger::new(2),
            maximum_observed_skew_millis: WireInteger::new(1),
            uncertainty_seconds: WireInteger::new(2),
            expired_mutation_dispatches: WireInteger::new(0),
        },
        sdk_observation_sha256: "13".repeat(32),
        anchor,
        expired_effects: 0,
    };
    let mut artifact = OciSdkEmulationArtifact {
        version: 1,
        purpose: OciSdkAcceptancePurpose::OciDocuments,
        execution_kind: OciSdkAcceptanceExecution::EmulatedManagedSdk,
        reviewer_key_id: "test-only-reviewer".into(),
        profile,
        evidence,
        evidence_sha256: String::new(),
        issued_at: 110,
        expires_at: 400,
        signature: String::new(),
    };
    artifact.evidence_sha256 = direct_qualification_digest(&artifact.evidence).unwrap();
    artifact.signature = hex::encode(
        reviewer()
            .sign(&artifact.signing_bytes().unwrap())
            .to_bytes(),
    );
    artifact
}

fn reviewer() -> SigningKey {
    SigningKey::from_bytes(&[0x31; 32])
}

/// Creates an explicitly synthetic OCI-only artifact and its test reviewer key.
///
/// No observation in this fixture is provider evidence. The function is
/// available only through the test-fixtures feature or internal tests.
#[must_use]
pub fn oci_sdk_emulation_fixture() -> (OciSdkEmulationArtifact, String) {
    (
        artifact(),
        hex::encode(reviewer().verifying_key().to_bytes()),
    )
}
