//! Original byte identity, shared parser bounds and closed projection checks.

use super::*;
use aos_oci_types::Annotations;

fn descriptor(bytes: &[u8], media_type: MediaType) -> Descriptor {
    Descriptor {
        media_type,
        digest: Sha256Digest::digest(bytes),
        size: bytes.len() as u64,
        urls: Vec::new(),
        annotations: Annotations::new(),
        data: None,
        artifact_type: None,
        platform: None,
    }
}

#[test]
fn noncanonical_original_identity_is_independent_from_projection() {
    let bytes = b"{ \"schemaVersion\" : 2, \"manifests\" : [ ] }\n";
    let original = descriptor(bytes, MediaType::OciImageIndex);
    let projection = OciDocumentProjection::from_stored_bytes(&original, bytes).unwrap();
    let OciDocumentProjection::Index(index) = &projection else {
        panic!("wrong projection");
    };
    let canonical = aos_oci_types::to_canonical_json(index).unwrap();
    assert_ne!(Sha256Digest::digest(&canonical), original.digest);
    assert_eq!(original.size, bytes.len() as u64);

    assert!(OciDocumentProjection::from_stored_bytes(&original, &canonical).is_err());
    assert!(projection.validate(MediaType::OciImageManifest).is_err());
}

#[test]
fn legal_four_mib_input_and_canonical_projection_keep_shared_limits() {
    let mut bytes = b"{\"schemaVersion\":2,\"manifests\":[]}".to_vec();
    bytes.resize(aos_oci_types::limits::MAX_JSON_BYTES, b' ');
    let original = descriptor(&bytes, MediaType::OciImageIndex);
    let projection = OciDocumentProjection::from_stored_bytes(&original, &bytes).unwrap();
    assert!(serde_json::to_vec(&projection).unwrap().len() < MAX_OCI_PROJECTION_BYTES);

    bytes.push(b' ');
    let oversized = descriptor(&bytes, MediaType::OciImageIndex);
    assert!(OciDocumentProjection::from_stored_bytes(&oversized, &bytes).is_err());
}

#[test]
fn image_config_is_parsed_with_exact_digest_and_shared_validation() {
    let bytes = b"{\"architecture\":\"amd64\",\"os\":\"linux\",\"rootfs\":{\"type\":\"layers\",\"diff_ids\":[]}}";
    let original = descriptor(bytes, MediaType::OciImageConfig);
    let projection = OciDocumentProjection::from_stored_bytes(&original, bytes).unwrap();
    assert!(matches!(projection, OciDocumentProjection::Config(_)));
    let mut changed = original.clone();
    changed.digest = Sha256Digest::digest(b"different");
    assert!(OciDocumentProjection::from_stored_bytes(&changed, bytes).is_err());
}

#[test]
fn independent_readback_authenticates_a_near_four_mib_projection() {
    use crate::mirror_guard::MirrorGuardIssuer;
    use crate::oci_projection::guard::*;
    use crate::storage_work::{StorageObjectIdentity, StorageWorkKey};

    let bytes = format!("{{\"architecture\":\"amd64\",\"os\":\"linux\",\"author\":\"{}\",\"rootfs\":{{\"type\":\"layers\",\"diff_ids\":[]}}}}", "a".repeat(aos_oci_types::limits::MAX_JSON_BYTES - 1024));
    let descriptor = descriptor(bytes.as_bytes(), MediaType::OciImageConfig);
    let projection =
        OciDocumentProjection::from_stored_bytes(&descriptor, bytes.as_bytes()).unwrap();
    let request = OciProjectionLookup {
        version: 1,
        protected_profile_digest: "c".repeat(64),
        deployment_id: "deployment".into(),
        issuer: MirrorGuardIssuer {
            source_digest: "a".repeat(64),
            script_version: "actual-script".into(),
        },
        clock_uncertainty_seconds: 2,
        key: "registry/oci/blobs/config".into(),
        descriptor,
        admission: None,
        nonce: "b".repeat(64),
        issued_at: 100,
        expires_at: 130,
    };
    let guard = StorageWorkKey::new([1; 32]).unwrap();
    let producer = StorageWorkKey::new([2; 32]).unwrap();
    let lookup = sign_oci_projection_lookup(&guard, &request).unwrap();
    verify_oci_projection_lookup(&guard, &lookup.signature, &lookup.body, "deployment", 102)
        .unwrap();
    assert!(verify_oci_projection_lookup(
        &producer,
        &lookup.signature,
        &lookup.body,
        "deployment",
        102
    )
    .is_err());

    let reply = OciProjectionReply {
        request: request.clone(),
        object: StorageObjectIdentity {
            key: request.key.clone(),
            size: bytes.len() as u64,
            etag: "\"actual-etag\"".into(),
            provider_version: Some("actual-version".into()),
        },
        projection,
        observed_at: 103,
    };
    let signed = sign_oci_projection_reply(&guard, &reply).unwrap();
    assert!(signed.body.len() > crate::storage_work::MAX_PLAN_BYTES);
    assert!(signed.body.len() < MAX_OCI_PROJECTION_BYTES);
    verify_oci_projection_reply(&guard, &signed.signature, &signed.body, &request, 104).unwrap();
    assert!(
        verify_oci_projection_reply(&producer, &signed.signature, &signed.body, &request, 104)
            .is_err()
    );
    assert!(
        verify_oci_projection_reply(&guard, &lookup.signature, &signed.body, &request, 104)
            .is_err()
    );
    assert!(
        verify_oci_projection_reply(&guard, &signed.signature, &signed.body, &request, 130)
            .is_err()
    );
    let mut changed = request.clone();
    changed.nonce = "c".repeat(64);
    assert!(
        verify_oci_projection_reply(&guard, &signed.signature, &signed.body, &changed, 104)
            .is_err()
    );

    let mut tampered = signed.body;
    let position = tampered.iter().position(|byte| *byte == b'a').unwrap();
    tampered[position] = b'z';
    assert!(
        verify_oci_projection_reply(&guard, &signed.signature, &tampered, &request, 104).is_err()
    );
}

#[test]
fn historical_oci_observation_keeps_exact_original_incarnation_and_parser_binding() {
    use crate::mirror_guard::MirrorGuardIssuer;
    use crate::oci_projection::guard::*;
    use crate::storage_work::StorageObjectIdentity;

    let raw = br#"{ "schemaVersion" : 2, "manifests" : [] }"#;
    let descriptor = descriptor(raw, MediaType::OciImageIndex);
    let request = OciProjectionLookup {
        version: 1,
        deployment_id: "deployment".into(),
        protected_profile_digest: "c".repeat(64),
        issuer: MirrorGuardIssuer {
            source_digest: "a".repeat(64),
            script_version: "script".into(),
        },
        clock_uncertainty_seconds: 2,
        key: "registry/oci/blobs/index".into(),
        descriptor,
        admission: None,
        nonce: "b".repeat(64),
        issued_at: 100,
        expires_at: 130,
    };
    let reply = OciProjectionReply {
        request: request.clone(),
        object: StorageObjectIdentity {
            key: request.key.clone(),
            size: raw.len() as u64,
            etag: "\"exact-tag\"".into(),
            provider_version: Some("exact-version".into()),
        },
        projection: OciDocumentProjection::from_stored_bytes(&request.descriptor, raw).unwrap(),
        observed_at: 101,
    };
    let request_bytes = serde_json::to_vec(&request).unwrap();
    let reply_bytes = serde_json::to_vec(&reply).unwrap();

    let observed =
        decode_oci_projection_observation(&request_bytes, &reply_bytes, "deployment").unwrap();
    assert_eq!(observed.0, request);
    assert!(observed.0.validate("deployment", 131).is_err());
    let mut changed = reply.clone();
    changed.object.provider_version = Some(String::new());
    assert!(decode_oci_projection_observation(
        &request_bytes,
        &serde_json::to_vec(&changed).unwrap(),
        "deployment"
    )
    .is_err());
    changed = reply.clone();
    changed.request.nonce = "d".repeat(64);
    assert!(decode_oci_projection_observation(
        &request_bytes,
        &serde_json::to_vec(&changed).unwrap(),
        "deployment"
    )
    .is_err());
    changed = reply;
    changed.observed_at = 130;
    assert!(decode_oci_projection_observation(
        &request_bytes,
        &serde_json::to_vec(&changed).unwrap(),
        "deployment"
    )
    .is_err());
    assert!(decode_oci_projection_observation(
        &request_bytes,
        &reply_bytes[..reply_bytes.len() - 1],
        "deployment"
    )
    .is_err());
}

#[test]
fn historical_oci_observation_retains_managed_effect_scope_without_renewal() {
    use crate::hybrid_ingress::{HybridOciManifestAdmission, OciDocumentEffect};
    use crate::mirror_guard::MirrorGuardIssuer;
    use crate::oci_projection::guard::*;
    use crate::storage_work::StorageObjectIdentity;

    let raw = br#"{ "schemaVersion" : 2, "manifests" : [] }"#;
    let descriptor = descriptor(raw, MediaType::OciImageIndex);
    let admission = HybridOciManifestAdmission {
        managed_effect: Some(OciDocumentEffect {
            protected_profile_digest: "c".repeat(64),
            acceptance_digest: "d".repeat(64),
            issued_at: 100,
            expires_at: 130,
            clock_uncertainty_seconds: 2,
        }),
        original_digest: "e".repeat(64),
        upload_id: "f".repeat(32),
        placement_prefix: "registry".into(),
        staging_object_key: "oci/uploads/original/chunks/0".into(),
        byte_size: descriptor.size,
        sha256: descriptor.digest.encoded().into(),
    };
    let request = OciProjectionLookup {
        version: 1,
        deployment_id: "deployment".into(),
        protected_profile_digest: "c".repeat(64),
        issuer: MirrorGuardIssuer {
            source_digest: "a".repeat(64),
            script_version: "script".into(),
        },
        clock_uncertainty_seconds: 2,
        key: crate::keymap::r2_key(&admission.placement_prefix, &admission.staging_object_key),
        descriptor,
        admission: Some(admission),
        nonce: "b".repeat(64),
        issued_at: 100,
        expires_at: 130,
    };
    let reply = OciProjectionReply {
        request: request.clone(),
        object: StorageObjectIdentity {
            key: request.key.clone(),
            size: raw.len() as u64,
            etag: "\"exact-tag\"".into(),
            provider_version: Some("exact-version".into()),
        },
        projection: OciDocumentProjection::from_stored_bytes(&request.descriptor, raw).unwrap(),
        observed_at: 101,
    };
    let request_bytes = serde_json::to_vec(&request).unwrap();
    let reply_bytes = serde_json::to_vec(&reply).unwrap();

    let observed =
        decode_oci_projection_observation(&request_bytes, &reply_bytes, "deployment").unwrap();
    assert_eq!(observed.0.admission, request.admission);
    let effect = observed
        .0
        .admission
        .as_ref()
        .unwrap()
        .managed_effect
        .as_ref()
        .unwrap();
    assert!(effect.check(131).is_err());
    assert!(observed.0.validate("deployment", 131).is_err());

    for substitution in ["acceptance", "profile", "expiry", "omitted"] {
        let mut changed = reply.clone();
        let admission = changed.request.admission.as_mut().unwrap();
        if substitution == "omitted" {
            admission.managed_effect = None;
        } else {
            let effect = admission.managed_effect.as_mut().unwrap();
            match substitution {
                "acceptance" => effect.acceptance_digest = "a".repeat(64),
                "profile" => effect.protected_profile_digest = "b".repeat(64),
                "expiry" => effect.expires_at = 140,
                _ => unreachable!(),
            }
        }
        assert!(
            decode_oci_projection_observation(
                &request_bytes,
                &serde_json::to_vec(&changed).unwrap(),
                "deployment",
            )
            .is_err(),
            "{substitution}"
        );
    }
}
