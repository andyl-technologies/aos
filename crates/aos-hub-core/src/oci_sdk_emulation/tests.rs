//! Test-only independent review fixtures and closed-purpose refusal gates.

use ed25519_dalek::{Signer as _, SigningKey};

use crate::direct_upload::WireInteger;

use super::*;

fn fixture() -> OciSdkEmulationArtifact {
    fixtures::oci_sdk_emulation_fixture().0
}

fn reviewer() -> SigningKey {
    SigningKey::from_bytes(&[0x31; 32])
}

fn resign(artifact: &mut OciSdkEmulationArtifact) {
    artifact.evidence_sha256 = direct_qualification_digest(&artifact.evidence).unwrap();
    artifact.signature = hex::encode(
        reviewer()
            .sign(&artifact.signing_bytes().unwrap())
            .to_bytes(),
    );
}

fn verify(artifact: &OciSdkEmulationArtifact, now: u64) -> Result<()> {
    artifact.verify(
        "test-deployment",
        "https://worker.oci.test",
        &hex::encode(reviewer().verifying_key().to_bytes()),
        now,
    )
}

#[test]
fn independent_review_binds_all_facts_and_expires_without_other_purposes() {
    let artifact = fixture();
    verify(&artifact, 110).unwrap();
    assert!(verify(&artifact, 109).is_err());
    assert!(verify(&artifact, 400).is_err());
    assert!(artifact
        .verify(
            "another-deployment",
            "https://worker.oci.test",
            &hex::encode(reviewer().verifying_key().to_bytes()),
            110,
        )
        .is_err());
    assert!(artifact
        .verify(
            "test-deployment",
            "https://other.oci.test",
            &hex::encode(reviewer().verifying_key().to_bytes()),
            110,
        )
        .is_err());
    assert!(artifact
        .verify(
            "test-deployment",
            "https://worker.oci.test",
            &hex::encode(
                SigningKey::from_bytes(&[0x32; 32])
                    .verifying_key()
                    .to_bytes()
            ),
            110,
        )
        .is_err());

    let mut changed = artifact.clone();
    changed.evidence.installation.native_executable_sha256 = "ff".repeat(32);
    assert!(verify(&changed, 110).is_err());
    changed = artifact.clone();
    changed.signature.replace_range(..2, "00");
    assert!(verify(&changed, 110).is_err());

    // Closed enums cannot represent Hosted, Direct, presigning or mirror use.
    let mut json = serde_json::to_value(&artifact).unwrap();
    for purpose in ["direct_upload", "presign", "mirror", "hosted"] {
        json["purpose"] = purpose.into();
        assert!(OciSdkEmulationArtifact::decode(&serde_json::to_vec(&json).unwrap()).is_err());
    }
    json["purpose"] = "oci_documents".into();
    json["executionKind"] = "hosted".into();
    assert!(OciSdkEmulationArtifact::decode(&serde_json::to_vec(&json).unwrap()).is_err());
}

#[test]
fn configured_mapping_and_production_origins_cannot_replace_observations() {
    let artifact = fixture();
    for (field, value) in [
        ("namespaceObjectId", "ff".repeat(32)),
        ("namespaceId", "other-namespace".into()),
        ("bindingName", "OTHER_BUCKET".into()),
        ("workerSourceDigest", "ff".repeat(32)),
        ("publicOrigin", "https://worker.example.com".into()),
        ("nativeOrigin", "https://native.example.com".into()),
    ] {
        let mut json = serde_json::to_value(&artifact).unwrap();
        json["profile"][field] = value.into();
        let changed = OciSdkEmulationArtifact::decode(&serde_json::to_vec(&json).unwrap()).unwrap();
        assert!(changed
            .validate_unsigned("test-deployment", &changed.profile.public_origin, 110)
            .is_err());
    }
    let mut changed = artifact.clone();
    changed.profile.clock_policy.uncertainty_seconds = WireInteger::new(3);
    resign(&mut changed);
    assert!(verify(&changed, 110).is_err());

    let mut changed = artifact.clone();
    changed.evidence.anchor.object.provider_version = None;
    resign(&mut changed);
    assert!(verify(&changed, 110).is_err());
    let mut changed = artifact.clone();
    changed.evidence.expired_effects = 1;
    resign(&mut changed);
    assert!(verify(&changed, 110).is_err());
}

#[test]
fn closed_artifact_excludes_material_and_applies_encoded_bound_before_decode() {
    let artifact = fixture();
    let bytes = serde_json::to_vec(&artifact).unwrap();
    verify(&OciSdkEmulationArtifact::decode(&bytes).unwrap(), 110).unwrap();
    let mut json = serde_json::to_value(&artifact).unwrap();
    json["providerSecret"] = "unexpected-material".into();
    assert!(OciSdkEmulationArtifact::decode(&serde_json::to_vec(&json).unwrap()).is_err());
    assert!(
        OciSdkEmulationArtifact::decode(&vec![b' '; MAX_OCI_SDK_EMULATION_ARTIFACT_BYTES + 1])
            .is_err()
    );
}

#[test]
fn fresh_anchor_readback_is_guard_authenticated_and_cannot_renew_its_original() {
    use super::anchor::*;
    use crate::{mirror_guard::MirrorGuardIssuer, storage_work::StorageWorkKey};

    let artifact = fixture();
    let lookup = OciSdkAnchorLookup {
        version: 1,
        deployment_id: artifact.profile.deployment_id.clone(),
        profile_digest: artifact.profile.digest().unwrap(),
        issuer: MirrorGuardIssuer {
            source_digest: artifact.profile.worker_source_digest.clone(),
            script_version: artifact.profile.worker_script_version.clone(),
        },
        clock_uncertainty_seconds: 2,
        anchor: artifact.profile.anchor.clone(),
        nonce: "22".repeat(32),
        issued_at: 110,
        expires_at: 140,
    };
    let guard = StorageWorkKey::new([0x51; 32]).unwrap();
    let broker = StorageWorkKey::new([0x52; 32]).unwrap();
    let signed = sign_oci_sdk_anchor_lookup(&guard, &lookup).unwrap();
    assert_eq!(
        verify_oci_sdk_anchor_lookup(
            &guard,
            &signed.signature,
            &signed.body,
            "test-deployment",
            112
        )
        .unwrap(),
        lookup
    );
    assert!(verify_oci_sdk_anchor_lookup(
        &broker,
        &signed.signature,
        &signed.body,
        "test-deployment",
        112
    )
    .is_err());
    let reply = OciSdkAnchorReply {
        request: lookup.clone(),
        observed: lookup.anchor.clone(),
        observed_at: 112,
    };
    let signed = sign_oci_sdk_anchor_reply(&guard, &reply).unwrap();
    verify_oci_sdk_anchor_reply(&guard, &signed.signature, &signed.body, &lookup, 112).unwrap();
    assert!(
        verify_oci_sdk_anchor_reply(&guard, &signed.signature, &signed.body, &lookup, 140).is_err()
    );
    assert!(
        verify_oci_sdk_anchor_reply(&broker, &signed.signature, &signed.body, &lookup, 112)
            .is_err()
    );
    let mut changed = lookup.clone();
    changed.nonce = "23".repeat(32);
    assert!(
        verify_oci_sdk_anchor_reply(&guard, &signed.signature, &signed.body, &changed, 112)
            .is_err()
    );
    let mut wrong_version = reply;
    wrong_version.observed.object.provider_version = Some("another-actual-incarnation".into());
    assert!(sign_oci_sdk_anchor_reply(&guard, &wrong_version).is_err());
    assert!(oci_sdk_emulation_acceptance_key(
        "test-deployment",
        &lookup.issuer.source_digest,
        &lookup.issuer.script_version
    )
    .unwrap()
    .starts_with("oci-sdk-emulator-v1-"));
}

#[test]
fn anchor_scope_is_required_closed_and_bound_into_the_review_signature() {
    let artifact = fixture();
    verify(&artifact, 110).unwrap();
    let mut evidence = serde_json::to_value(&artifact.evidence).unwrap();
    evidence
        .as_object_mut()
        .unwrap()
        .remove("sdkObservationScope");
    let mut legacy = artifact.clone();
    legacy.evidence_sha256 = direct_qualification_digest(&evidence).unwrap();
    assert_ne!(
        legacy.signing_bytes().unwrap(),
        artifact.signing_bytes().unwrap()
    );
    let legacy_signature = reviewer().sign(&legacy.signing_bytes().unwrap());
    let mut changed = artifact.clone();
    changed.signature = hex::encode(legacy_signature.to_bytes());
    assert!(verify(&changed, 110).is_err());

    let mut value = serde_json::to_value(&artifact).unwrap();
    value["evidence"]
        .as_object_mut()
        .unwrap()
        .remove("sdkObservationScope");
    assert!(OciSdkEmulationArtifact::decode(&serde_json::to_vec(&value).unwrap()).is_err());
    value["evidence"]["sdkObservationScope"] = "business_expiry_refusal".into();
    assert!(OciSdkEmulationArtifact::decode(&serde_json::to_vec(&value).unwrap()).is_err());
}
