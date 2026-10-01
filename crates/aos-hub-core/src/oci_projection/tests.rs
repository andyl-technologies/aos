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
