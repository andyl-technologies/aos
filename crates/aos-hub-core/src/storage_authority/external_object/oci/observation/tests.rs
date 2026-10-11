//! Historical correlation gates remain distinct from live authentication.

use super::*;
use crate::storage_authority::external_object::oci::{
    control::OciControl, reply::OciClosedObject, OciBytes, OciProviderIncarnation,
};
use crate::storage_authority::{canonical_digest, GuardIncarnation, StorageGuardStamp};
use crate::{db::OciSha256State, mirror_guard::MirrorGuardIssuer};

fn control() -> (ExternalOciRequest, ExternalOciReply) {
    let original = super::super::tests::original();
    let request = ExternalOciRequest::new(
        original.clone(),
        "e".repeat(64),
        original.actor.clone(),
        110,
        130,
        "f".repeat(64),
        OciControl::Stage,
    )
    .unwrap();
    let reply = ExternalOciReply {
        version: 1,
        request_digest: canonical_digest(&request).unwrap(),
        nonce: request.nonce.clone(),
        original_digest: original.fingerprint().unwrap(),
        retained_original: None,
        source_count: 0,
        next_part: 1,
        accepted_bytes: 0,
        upload_sha256: OciSha256State::initial(),
        pending_effect_digest: None,
        closed: None,
    };
    (request, reply)
}

fn source() -> (OciSourceLookup, OciSourceReply) {
    let original = super::super::tests::original();
    let bytes = OciBytes {
        sha256: aos_oci_types::Sha256Digest::digest(b"x").encoded(),
        size: 1,
    };
    let request = OciSourceLookup {
        version: 1,
        deployment_id: original.deployment_id.clone(),
        issuer: MirrorGuardIssuer {
            source_digest: "a".repeat(64),
            script_version: "observed-parser".into(),
        },
        clock_uncertainty_seconds: 2,
        writer: original.writer.clone(),
        binding_spec_revision: original.binding_spec_revision.clone(),
        profile_digest: original.profile_digest.clone(),
        scope: original.scope.clone(),
        expected: bytes.clone(),
        range: None,
        upload_id: Some(original.upload.upload_id.clone()),
        nonce: "f".repeat(64),
        issued_at: 110,
        expires_at: 130,
    };
    let closed = OciClosedObject {
        bytes,
        etag: "\"exact-etag\"".into(),
        incarnation: OciProviderIncarnation::Versioned {
            provider_version: "retained-provider-version".into(),
            guard_stamp: StorageGuardStamp {
                physical_authority_id: original.scope.physical_authority_id.clone(),
                incarnation: GuardIncarnation::parse("1").unwrap(),
            },
        },
        receipt_digest: "e".repeat(64),
    };
    let reply = OciSourceReply {
        request_digest: canonical_digest(&request).unwrap(),
        nonce: request.nonce.clone(),
        original,
        closed,
        observed_at: 120,
    };
    (request, reply)
}

fn cleanup() -> (OciCleanupRequest, OciCleanupReply) {
    use super::super::cleanup::OciCleanupOriginal;
    let (source, positive) = source();
    let original = OciCleanupOriginal {
        upload_id: "a".repeat(32),
        upload_resource_version: 3,
        registry_id: 1,
        repository_id: 2,
        writer_id: "actual-writer-slot".into(),
        token_id: "actual-upload-owner".into(),
        terminal_state: "cancelled".into(),
        finished_at: 140,
        ordinal: 0,
        offset: 0,
        bytes: source.expected.clone(),
        staging_key: format!("oci/uploads/{}/chunks/0-{}", "a".repeat(32), "d".repeat(32)),
        placement_id: 3,
        placement_resource_version: 4,
        placement_prefix: "registry".into(),
        binding_id: 6,
        binding_resource_version: 7,
        binding_write_revision: 8,
        binding_spec_revision: "b".repeat(64),
        delete_generation: 1,
        delete_capability_fingerprint: "c".repeat(64),
        delete_capability_resource_version: 1,
    };
    let request = OciCleanupRequest {
        deployment_id: source.deployment_id,
        original,
        scope: source.scope,
        issuer: source.issuer,
        clock_uncertainty_seconds: 2,
        nonce: "f".repeat(64),
        issued_at: 150,
        expires_at: 170,
    };
    let reply = OciCleanupReply {
        request_digest: canonical_digest(&request).unwrap(),
        original_digest: request.original.fingerprint().unwrap(),
        nonce: request.nonce.clone(),
        closed: positive.closed,
        delete_receipt_digest: "d".repeat(64),
    };
    (request, reply)
}

#[test]
fn retained_control_decodes_after_live_expiry_without_renewing_permission() {
    let (request, reply) = control();
    assert!(request
        .validate(&request.original.deployment_id, 130)
        .is_err());
    let decoded = decode_external_oci_control_observation(
        &serde_json::to_vec(&request).unwrap(),
        &serde_json::to_vec(&reply).unwrap(),
        &request.original.deployment_id,
    )
    .unwrap();
    assert_eq!(decoded, (request, reply));
}

#[test]
fn control_substitution_impossible_window_and_noncanonical_bytes_refuse() {
    let (request, reply) = control();
    let body = serde_json::to_vec(&request).unwrap();
    let mut wrong = reply.clone();
    wrong.nonce = "0".repeat(64);
    assert!(decode_external_oci_control_observation(
        &body,
        &serde_json::to_vec(&wrong).unwrap(),
        &request.original.deployment_id
    )
    .is_err());
    let mut wrong = request.clone();
    wrong.expires_at = wrong.issued_at;
    assert!(wrong
        .validate_observation_shape(&wrong.original.deployment_id)
        .is_err());
    let mut noncanonical = body.clone();
    noncanonical.push(b' ');
    assert!(decode_external_oci_control_observation(
        &noncanonical,
        &serde_json::to_vec(&reply).unwrap(),
        &request.original.deployment_id
    )
    .is_err());
    assert!(decode_external_oci_control_observation(
        &vec![b' '; MAX_EXTERNAL_OCI_CONTROL_BYTES + 1],
        &serde_json::to_vec(&reply).unwrap(),
        &request.original.deployment_id
    )
    .is_err());
}

#[test]
fn retained_source_decodes_exact_coordinates_after_expiry() {
    let (request, reply) = source();
    assert!(reply.validate_for(&request, 130).is_err());
    let decoded = decode_external_oci_source_observation(
        &serde_json::to_vec(&request).unwrap(),
        &serde_json::to_vec(&reply).unwrap(),
        &request.deployment_id,
    )
    .unwrap();
    assert_eq!(decoded, (request, reply));
}

#[test]
fn source_observation_time_and_original_substitution_refuse() {
    let (request, reply) = source();
    for time in [109, 130, 131] {
        let mut wrong = reply.clone();
        wrong.observed_at = time;
        assert!(wrong.validate_observation_for(&request).is_err());
    }
    let mut wrong = reply;
    wrong.original.writer.binding_stable_id = "another-lifetime".into();
    assert!(wrong.validate_observation_for(&request).is_err());
}

#[test]
fn retained_cleanup_keeps_exact_positive_version_and_original() {
    let (request, reply) = cleanup();
    assert!(request.validate(&request.deployment_id, 170).is_err());
    let decoded = decode_external_oci_cleanup_observation(
        &serde_json::to_vec(&request).unwrap(),
        &serde_json::to_vec(&reply).unwrap(),
        &request.deployment_id,
    )
    .unwrap();
    assert_eq!(decoded, (request, reply));
}

#[test]
fn cleanup_without_provider_version_or_with_substituted_original_refuses() {
    let (request, reply) = cleanup();
    let mut wrong = reply.clone();
    wrong.nonce = "0".repeat(64);
    assert!(wrong.validate_for(&request).is_err());
    let mut wrong = reply;
    let OciProviderIncarnation::Versioned { guard_stamp, .. } = wrong.closed.incarnation else {
        panic!()
    };
    wrong.closed.incarnation = OciProviderIncarnation::Guarded { guard_stamp };
    assert!(wrong.validate_for(&request).is_err());
}
