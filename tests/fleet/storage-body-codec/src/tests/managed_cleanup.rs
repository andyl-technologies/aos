//! The cleanup body partition is distinct from real transport authentication.

use aos_hub_core::{
    mirror_guard::MirrorGuardIssuer,
    oci_cleanup::{
        ManagedOciCleanupOriginal, ManagedOciCleanupReply, ManagedOciCleanupRequest,
        MANAGED_OCI_CLEANUP_PATH,
    },
    storage_work::StorageObjectIdentity,
};

use super::*;

fn cleanup() -> (ManagedOciCleanupRequest, ManagedOciCleanupReply) {
    let upload = "a".repeat(32);
    let request = ManagedOciCleanupRequest {
        deployment_id: "fixture".into(),
        original: ManagedOciCleanupOriginal {
            upload_id: upload.clone(),
            upload_resource_version: 2,
            terminal_state: "failed".into(),
            finished_at: 99,
            registry_id: 1,
            repository_id: 2,
            writer_id: "fixture-writer".into(),
            token_id: "fixture-owner".into(),
            ordinal: 0,
            offset: 0,
            path: format!("oci/uploads/{upload}/chunks/0-retained"),
            sha256: "b".repeat(64),
            size: 17,
            placement_id: 3,
            placement_resource_version: 4,
            placement_prefix: "qualification/cleanup".into(),
            binding_id: 5,
            binding_resource_version: 6,
            binding_write_revision: 7,
            delete_capability_fingerprint: "fixture-delete-capability".into(),
            delete_capability_resource_version: 8,
        },
        protected_profile_digest: "c".repeat(64),
        issuer: MirrorGuardIssuer {
            source_digest: "b".repeat(64),
            script_version: "fixture-source".into(),
        },
        clock_uncertainty_seconds: 2,
        nonce: "e".repeat(64),
        issued_at: 100,
        expires_at: 130,
    };
    let reply = ManagedOciCleanupReply {
        request_digest: files::digest(&serde_json::to_vec(&request).unwrap()),
        original_digest: request.original.fingerprint().unwrap(),
        nonce: request.nonce.clone(),
        object: StorageObjectIdentity {
            key: request.original.key(),
            size: request.original.size,
            etag: "\"retained-etag\"".into(),
            provider_version: Some("opaque-r2-version".into()),
        },
        receipt_digest: "f".repeat(64),
    };
    (request, reply)
}

fn manifest(
    fixture: &Fixture,
    request: &ManagedOciCleanupRequest,
    reply: &ManagedOciCleanupReply,
) -> Manifest {
    let mut manifest = fixture.manifest(b"", b"", false);
    let case = &mut manifest.cases[0];
    case.method = "POST".into();
    case.path_and_query = MANAGED_OCI_CLEANUP_PATH.into();
    case.phase = None;
    case.status = 200;
    case.response_content_type = Some("application/json".into());
    case.original_ingress = None;
    case.received_ingress = None;
    let request = serde_json::to_vec(request).unwrap();
    case.original_request = fixture.body("cleanup-original", &request);
    case.received_request = fixture.body("cleanup-received", &request);
    case.received_reply = fixture.body("cleanup-reply", &serde_json::to_vec(reply).unwrap());
    manifest
}

#[test]
fn managed_cleanup_metadata_is_decoded_without_raw_payload_or_permission() {
    let fixture = Fixture::new();
    let (request, reply) = cleanup();
    let rows = inspect(manifest(&fixture, &request, &reply)).unwrap();

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].operation, "managed_oci_cleanup");
    assert_eq!(rows[0].class, "managed_oci_terminal_cleanup_metadata");
    assert_eq!(
        rows[0].request_sha256,
        files::digest(&serde_json::to_vec(&request).unwrap())
    );
    assert_eq!(
        rows[0].reply_sha256,
        files::digest(&serde_json::to_vec(&reply).unwrap())
    );
    assert_eq!(rows[0].payload.request_raw_object_bytes, "0");
    assert_eq!(rows[0].payload.reply_raw_object_bytes, "0");
    assert!(request.validate("fixture", 130).is_err());
}

#[test]
fn managed_cleanup_missing_partial_substituted_source_or_phase_refuses() {
    let fixture = Fixture::new();
    for defect in [
        "source",
        "original",
        "absent",
        "truncated",
        "phase",
        "status",
        "query",
        "encoding",
    ] {
        let (mut request, mut reply) = cleanup();
        if defect == "source" {
            request.issuer.source_digest = "d".repeat(64);
            reply.request_digest = files::digest(&serde_json::to_vec(&request).unwrap());
        }
        let mut selected = manifest(&fixture, &request, &reply);
        let case = &mut selected.cases[0];
        match defect {
            "source" => {}
            "original" => case.original_request = fixture.body("different-original", b"{}"),
            "absent" => case.received_reply = fixture.body("absent-reply", b""),
            "truncated" => {
                let mut body = serde_json::to_vec(&reply).unwrap();
                body.pop();
                case.received_reply = fixture.body("partial-reply", &body);
            }
            "phase" => case.phase = Some("complete".into()),
            "status" => case.status = 502,
            "query" => case.path_and_query.push_str("?unknown=true"),
            "encoding" => case.response_content_encoding = Some("gzip".into()),
            _ => unreachable!(),
        }
        assert!(inspect(selected).is_err(), "{defect}");
    }
}
