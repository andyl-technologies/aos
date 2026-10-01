//! Independent MAC, original, incarnation, fresh challenge and namespace tests.

use super::*;
use crate::{
    mirror_work::{MirrorVerification, MirrorVerifiedObject},
    storage_work::StorageObjectIdentity,
};

fn request() -> MirrorGuardLookup {
    let mut original = MirrorOriginal {
        version: 1,
        job_id: String::new(),
        copy_operation_id: Some("11".repeat(16)),
        registry_id: 1,
        registry_resource_version: 2,
        mirror_resource_version: 3,
        upstream_base: "https://mirror.example.org/".into(),
        path: "metadata.json".into(),
        placement_id: 4,
        placement_resource_version: 5,
        write_spec_version: 6,
        binding_id: 7,
        binding_resource_version: 8,
        placement_prefix: "managed".into(),
        protected_profile_digest: "22".repeat(32),
        verification: MirrorVerification::Sha256 {
            sha256: "33".repeat(32),
            size: 0,
        },
    };
    original.job_id = original.identity().unwrap();
    let object = StorageObjectIdentity {
        key: original.stage_key(),
        size: 0,
        etag: "\"stage-etag\"".into(),
        provider_version: Some("stage-incarnation".into()),
    };
    let verified = MirrorVerifiedObject {
        object: object.clone(),
        sha256: "33".repeat(32),
        nar_sha256: None,
        nar_size: None,
    };
    let mut final_object = verified.clone();
    final_object.object.key = crate::keymap::r2_key(&original.placement_prefix, &original.path);
    final_object.object.etag = "\"final-etag\"".into();
    final_object.object.provider_version = Some("final-incarnation".into());
    let expected = MirrorProgress {
        original_digest: digest(&original).unwrap(),
        stage_object: Some(object),
        verified: Some(verified),
        destination: Some(final_object),
        ..Default::default()
    };
    MirrorGuardLookup {
        version: 1,
        deployment_id: "fixture-deployment".into(),
        execution: MirrorGuardExecution::Hosted,
        issuer: MirrorGuardIssuer {
            source_digest: "44".repeat(32),
            script_version: "fixture-script".into(),
        },
        clock_uncertainty_seconds: 1,
        original,
        expected,
        request_nonce: "55".repeat(32),
        issued_at: 100,
        expires_at: 130,
    }
}

fn reply(request: &MirrorGuardLookup) -> MirrorGuardReply {
    MirrorGuardReply {
        version: 1,
        request_digest: digest(request).unwrap(),
        request_nonce: request.request_nonce.clone(),
        original_digest: digest(&request.original).unwrap(),
        issuer: request.issuer.clone(),
        progress: request.expected.clone(),
        observed_at: 105,
    }
}

#[test]
fn retained_observation_checks_do_not_grant_expired_live_proofs() {
    let request = request();
    let mut reply = reply(&request);
    let key = StorageWorkKey::new("independent-guard-role-secret-0001").unwrap();
    let signed = sign_mirror_guard_reply(&key, &reply, &request).unwrap();

    assert!(
        verify_mirror_guard_reply(&key, &signed.signature, &signed.body, &request, 200,).is_err()
    );
    assert!(validate_mirror_guard_reply_observation(&request, &reply).is_ok());

    reply.progress.destination.as_mut().unwrap().object.etag = "\"changed\"".into();
    assert!(validate_mirror_guard_reply_observation(&request, &reply).is_err());
    reply.progress = request.expected.clone();
    reply.observed_at = request.expires_at;
    assert!(validate_mirror_guard_reply_observation(&request, &reply).is_err());
}

#[test]
fn independent_mac_and_exact_fresh_body_binding() {
    let key = StorageWorkKey::new("independent-guard-role-secret-0001").unwrap();
    let producer = StorageWorkKey::new("producer-role-secret-00000000001").unwrap();
    let request = request();
    let control = sign_mirror_guard_lookup(&key, &request).unwrap();
    assert!(verify_mirror_guard_lookup(
        &producer,
        &control.signature,
        &control.body,
        "fixture-deployment",
        105
    )
    .is_err());
    let parsed = verify_mirror_guard_lookup(
        &key,
        &control.signature,
        &control.body,
        "fixture-deployment",
        105,
    )
    .unwrap();
    assert_eq!(parsed, request);
    let signed = sign_mirror_guard_reply(&key, &reply(&request), &request).unwrap();
    assert!(verify_mirror_guard_lookup(
        &key,
        &signed.signature,
        &signed.body,
        "fixture-deployment",
        105
    )
    .is_err());
    let proof =
        verify_mirror_guard_reply(&key, &signed.signature, &signed.body, &request, 106).unwrap();
    assert_eq!(proof.remaining_validity_seconds(106).unwrap(), 23);
    assert_eq!(proof.remaining_validity_seconds(128).unwrap(), 1);
    assert!(proof.remaining_validity_seconds(129).is_err());
    assert!(proof.remaining_validity_seconds(u64::MAX).is_err());
    proof
        .validate_for(&request.original, &request.expected, 128)
        .unwrap();
    assert!(proof
        .validate_for(&request.original, &request.expected, 129)
        .is_err());
    let mut next = request.clone();
    next.request_nonce = "66".repeat(32);
    assert!(verify_mirror_guard_reply(&key, &signed.signature, &signed.body, &next, 106).is_err());
    next = request.clone();
    next.expires_at = 129;
    assert!(verify_mirror_guard_reply(&key, &signed.signature, &signed.body, &next, 106).is_err());
    let mut bytes = control.body.clone();
    bytes.push(b' ');
    let signature = key.sign_body(&domain_body(REQUEST_DOMAIN, &bytes)).unwrap();
    assert!(
        verify_mirror_guard_lookup(&key, &signature, &bytes, "fixture-deployment", 105).is_err()
    );
}

#[test]
fn full_original_copy_operation_profile_and_final_incarnation_are_bound() {
    let key = StorageWorkKey::new("independent-guard-role-secret-0001").unwrap();
    let request = request();
    let signed = sign_mirror_guard_reply(&key, &reply(&request), &request).unwrap();
    let proof =
        verify_mirror_guard_reply(&key, &signed.signature, &signed.body, &request, 106).unwrap();
    for field in 0..4 {
        let mut original = request.original.clone();
        match field {
            0 => original.copy_operation_id = Some("77".repeat(16)),
            1 => original.protected_profile_digest = "77".repeat(32),
            2 => original.binding_resource_version += 1,
            _ => original.placement_prefix = "different".into(),
        }
        original.job_id = original.identity().unwrap();
        assert!(proof
            .validate_for(&original, &request.expected, 106)
            .is_err());
    }
    let mut changed = request.expected.clone();
    changed
        .destination
        .as_mut()
        .unwrap()
        .object
        .provider_version = Some("replacement".into());
    assert!(proof
        .validate_for(&request.original, &changed, 106)
        .is_err());
    let mut observed = reply(&request);
    observed.progress = changed;
    assert!(sign_mirror_guard_reply(&key, &observed, &request).is_err());
    observed = reply(&request);
    observed.issuer.source_digest = "88".repeat(32);
    assert!(sign_mirror_guard_reply(&key, &observed, &request).is_err());
    observed = reply(&request);
    observed.observed_at = 107;
    let future = sign_mirror_guard_reply(&key, &observed, &request).unwrap();
    assert!(
        verify_mirror_guard_reply(&key, &future.signature, &future.body, &request, 106).is_err()
    );
}

#[test]
fn execution_and_new_business_operation_cannot_be_reinterpreted() {
    let mut controlled = request();
    controlled.execution = MirrorGuardExecution::ControlledCandidate;
    controlled.issuer.script_version = format!("emulated-{}", controlled.issuer.source_digest);
    assert!(controlled.validate("fixture-deployment", 105).is_err());
    controlled.original.placement_prefix =
        format!(".aos-mirror-qualification/{}/final", "ab".repeat(16));
    controlled.original.job_id = controlled.original.identity().unwrap();
    controlled.expected.original_digest = digest(&controlled.original).unwrap();
    controlled.expected.stage_object.as_mut().unwrap().key = controlled.original.stage_key();
    controlled.expected.verified.as_mut().unwrap().object.key = controlled.original.stage_key();
    controlled.expected.destination.as_mut().unwrap().object.key = crate::keymap::r2_key(
        &controlled.original.placement_prefix,
        &controlled.original.path,
    );
    controlled.validate("fixture-deployment", 105).unwrap();
    controlled.execution = MirrorGuardExecution::Hosted;
    controlled.issuer.script_version = "fixture-script".into();
    assert!(controlled.validate("fixture-deployment", 105).is_err());
    let mut legacy = request();
    legacy.original.copy_operation_id = None;
    legacy.original.job_id = legacy.original.identity().unwrap();
    assert!(legacy.validate("fixture-deployment", 105).is_err());
    let mut stale = request();
    stale.expires_at = u64::MAX;
    assert!(stale.validate("fixture-deployment", 105).is_err());
}
