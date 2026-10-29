//! Functional-only signature, prerequisite, audience and scope regressions.

use ed25519_dalek::{Signer as _, SigningKey};

use super::*;

fn fixture() -> (ControlledExternalMirrorArtifact, MirrorOriginal) {
    let mut original = crate::mirror_work::external_test_original();
    let root = format!(".aos-mirror-qualification/{}/final", "ab".repeat(16));
    original.placement_prefix = format!("{root}/full");
    original.job_id = original.identity().unwrap();
    let hash = "41".repeat(32);
    let source = "42".repeat(32);
    let artifact = ControlledExternalMirrorArtifact {
        version: 1,
        purpose: ControlledExternalMirrorPurpose::FullAndPullThroughFunctionalProbeV1,
        execution: ControlledExternalMirrorExecution::EmulatedExternal,
        reviewer_key_id: "mirror-only-reviewer".into(),
        deployment_id: "deployment".into(),
        public_origin: "https://localhost:4673".into(),
        source_digest: source.clone(),
        script_version: direct_worker_emulated_script_id(&source).unwrap(),
        protected_profile: original
            .external_destination
            .as_ref()
            .unwrap()
            .protected_profile
            .clone(),
        direct_evidence_sha256: original
            .external_destination
            .as_ref()
            .unwrap()
            .acceptance_digest
            .clone(),
        external_domain_sha256: hash.clone(),
        upstream_base: original.upstream_base.clone(),
        placement_prefix: root,
        maximum_object_bytes: 8,
        installation: ControlledExternalMirrorInstallation {
            artifact_manifest_sha256: hash.clone(),
            wasm_sha256: hash.clone(),
            script_sha256: hash.clone(),
            native_executable_sha256: hash.clone(),
            configuration_sha256: hash.clone(),
            namespace_observation_sha256: hash.clone(),
            clock_observation_sha256: hash.clone(),
            provider_contract_observation_sha256: hash.clone(),
            prerequisite_artifact_sha256: hash,
        },
        issued_at: 100,
        valid_until: 200,
        signature: String::new(),
    };
    (artifact, original)
}

fn signed() -> (ControlledExternalMirrorArtifact, MirrorOriginal, String) {
    let (mut artifact, original) = fixture();
    let key = SigningKey::from_bytes(&[0xa2; 32]);
    artifact.signature = hex::encode(key.sign(&artifact.signing_bytes().unwrap()).to_bytes());
    (
        artifact,
        original,
        hex::encode(key.verifying_key().to_bytes()),
    )
}

fn verify(artifact: &ControlledExternalMirrorArtifact, public: &str) -> Result<()> {
    let protected = DirectProtectedProfile::External {
        profile: artifact.protected_profile.profile.clone(),
        runtime_qualification: artifact.protected_profile.runtime_qualification.clone(),
    };
    artifact.require_current(
        "deployment",
        "https://localhost:4673",
        &"42".repeat(32),
        &direct_worker_emulated_script_id(&"42".repeat(32))?,
        &protected,
        &"ff".repeat(32),
        public,
        150,
    )
}

#[test]
fn functional_signature_covers_scope_installation_and_does_not_decode_as_hosted() {
    let (artifact, original, public) = signed();
    verify(&artifact, &public).unwrap();
    require_distinct_external_mirror_reviewer(&public, &"77".repeat(32)).unwrap();
    assert!(
        require_distinct_external_mirror_reviewer(&public, &public.to_ascii_uppercase()).is_err()
    );
    artifact.require_original(&original, 150).unwrap();
    let bytes = serde_json::to_vec(&artifact).unwrap();
    assert!(serde_json::from_slice::<super::super::MirrorAcceptanceArtifact>(&bytes).is_err());

    for index in 0..5 {
        let mut changed = artifact.clone();
        match index {
            0 => changed.external_domain_sha256 = "77".repeat(32),
            1 => changed.installation.wasm_sha256 = "77".repeat(32),
            2 => changed.upstream_base = "https://different.example.org/git".into(),
            3 => {
                changed.placement_prefix =
                    format!(".aos-mirror-qualification/{}/final", "cd".repeat(16))
            }
            _ => changed.public_origin = "https://localhost:4674".into(),
        }
        assert!(verify(&changed, &public).is_err());
    }
}

#[test]
fn functional_original_refuses_other_mode_upstream_profile_and_cutoff() {
    let (artifact, original, _) = signed();
    let mut pull_through = original.clone();
    pull_through.placement_prefix = format!("{}/pull-through", artifact.placement_prefix);
    pull_through.job_id = pull_through.identity().unwrap();
    artifact.require_original(&pull_through, 150).unwrap();

    for index in 0..4 {
        let mut changed = original.clone();
        match index {
            0 => changed.placement_prefix = format!("{}/other", artifact.placement_prefix),
            1 => changed.upstream_base = "https://different.example.org/git".into(),
            2 => {
                changed
                    .external_destination
                    .as_mut()
                    .unwrap()
                    .acceptance_digest = "99".repeat(32)
            }
            _ => changed.external_destination = None,
        }
        changed.job_id = changed.identity().unwrap();
        assert!(artifact.require_original(&changed, 150).is_err());
    }
    assert!(artifact.require_original(&original, 200).is_err());
}
