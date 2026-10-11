//! Controlled exact body and ingress substitution tests without authentication.

use std::{
    fs,
    os::unix::fs::PermissionsExt as _,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use aos_hub_core::hybrid_ingress::{body_sha256, HybridIngressAssertion, HybridIngressKey};

use super::*;

mod ingress;
mod managed_cleanup;

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn upload_control(
        &self,
        method: &str,
        query: &str,
        phase: Option<&str>,
        reply: &[u8],
        status: u16,
    ) -> Manifest {
        let mut manifest = self.manifest(b"", reply, false);
        let case = &mut manifest.cases[0];
        case.method = method.into();
        case.path_and_query = format!("/v2/aos/blobs/uploads/{}{}", "a".repeat(32), query);
        case.phase = phase.map(str::to_owned);
        case.status = status;
        let assertion = HybridIngressAssertion {
            version: 1,
            deployment_id: "fixture".into(),
            issued_at: 100,
            expires_at: 130,
            request_id: "fixture-original".into(),
            scheme: "https".into(),
            authority: "storage.test".into(),
            method: case.method.clone(),
            path_and_query: case.path_and_query.clone(),
            body_sha256: body_sha256(b""),
            upload_phase: case.phase.clone(),
            client_ip: "127.0.0.1".into(),
        };
        let compact = HybridIngressKey::new([1; 32])
            .unwrap()
            .sign(&assertion)
            .unwrap();
        case.original_ingress = Some(self.body("upload-original-ingress", compact.as_bytes()));
        case.received_ingress = Some(self.body("upload-received-ingress", compact.as_bytes()));
        manifest
    }

    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "aos-body-codec-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        Self(directory)
    }

    fn body(&self, name: &str, bytes: &[u8]) -> BodyFile {
        let path = self.0.join(name);
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        BodyFile {
            file: path.to_str().unwrap().into(),
            sha256: files::digest(bytes),
            byte_size: bytes.len().to_string(),
        }
    }

    fn manifest(&self, request: &[u8], reply: &[u8], raw: bool) -> Manifest {
        let path = if raw {
            format!("/v2/aos/blobs/sha256:{}", files::digest(reply))
        } else {
            format!(
                "/v2/aos/manifests/fixture?aos_hybrid_manifest_upload={}",
                "a".repeat(32)
            )
        };
        let assertion = HybridIngressAssertion {
            version: 1,
            deployment_id: "fixture".into(),
            issued_at: 100,
            expires_at: 130,
            request_id: "fixture-original".into(),
            scheme: "https".into(),
            authority: "storage.test".into(),
            method: if raw { "GET" } else { "PUT" }.into(),
            path_and_query: path.clone(),
            body_sha256: body_sha256(request),
            upload_phase: if raw { None } else { Some("complete".into()) },
            client_ip: "127.0.0.1".into(),
        };
        let compact = HybridIngressKey::new([1; 32])
            .unwrap()
            .sign(&assertion)
            .unwrap();
        let case = Case {
            request_id: "capture".into(),
            method: assertion.method,
            path_and_query: path,
            phase: assertion.upload_phase,
            status: if raw { 200 } else { 201 },
            response_content_type: Some("application/octet-stream".into()),
            response_content_encoding: None,
            original_request: self.body("original", request),
            received_request: self.body("request", request),
            received_reply: self.body("reply", reply),
            original_ingress: Some(self.body("original-ingress", compact.as_bytes())),
            received_ingress: Some(self.body("received-ingress", compact.as_bytes())),
        };
        Manifest {
            version: 1,
            source_digest: "b".repeat(64),
            deployment_id: "fixture".into(),
            cases: vec![case],
        }
    }
}

#[test]
fn final_authorization_uses_exact_ingress_query_and_closed_routing_hint() {
    let fixture = Fixture::new();
    let query = format!("?digest=sha256%3A{}", "d".repeat(64));
    let reply = br#"{"external":true,"completion_only":false}"#;
    let manifest = fixture.upload_control("PATCH", &query, Some("authorize-final"), reply, 200);
    let rows = inspect(manifest).unwrap();
    assert_eq!(rows[0].operation, "oci_upload_final_authorize");
    assert_eq!(rows[0].payload.request_raw_object_bytes, "0");
    for defect in ["phase", "query", "raw", "unknown"] {
        let mut manifest =
            fixture.upload_control("PATCH", &query, Some("authorize-final"), reply, 200);
        let case = &mut manifest.cases[0];
        match defect {
            "phase" => case.phase = Some("complete".into()),
            "query" => case.path_and_query.push_str("&digest=bad"),
            "raw" => {
                case.original_request = fixture.body("raw-original", b"raw blob");
                case.received_request = fixture.body("raw-received", b"raw blob");
            }
            "unknown" => {
                case.received_reply =
                    fixture.body("unknown-reply", br#"{"external":true,"permission":true}"#)
            }
            _ => unreachable!(),
        }
        assert!(inspect(manifest).is_err(), "{defect}");
    }
}

#[test]
fn exact_empty_upload_status_cancel_and_final_are_metadata_observations() {
    let fixture = Fixture::new();
    for method in ["GET", "HEAD", "DELETE"] {
        let rows = inspect(fixture.upload_control(method, "", None, b"", 204)).unwrap();
        assert_eq!(rows[0].class, "oci_distribution_control_metadata");
    }
    let query = format!("?digest=sha256%3A{}", "d".repeat(64));
    let rows = inspect(fixture.upload_control("PUT", &query, None, b"", 201)).unwrap();
    assert_eq!(rows[0].operation, "oci_upload_finalize");
    assert!(inspect(fixture.upload_control("PUT", &query, None, b"unexpected", 201)).is_err());
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn fixed_completion_metadata_and_original_blob_bytes_remain_distinct() {
    let fixture = Fixture::new();
    let rows = inspect(fixture.manifest(b"{}", b"", false)).unwrap();
    assert_eq!(rows[0].operation, "oci_manifest_complete");
    assert_eq!(rows[0].payload.reply_raw_object_bytes, "0");
    let rows = inspect(fixture.manifest(b"", b"actual controlled blob", true)).unwrap();
    assert_eq!(rows[0].class, "oci_distribution_blob_body");
    assert_eq!(rows[0].payload.reply_raw_object_bytes, "22");
}

#[test]
fn a_complete_phase_cannot_hide_an_original_document_as_metadata() {
    let fixture = Fixture::new();
    let manifest = fixture.manifest(br#"{"schemaVersion":2,"manifests":[]}"#, b"", false);
    assert!(inspect(manifest).is_err());
}

#[test]
fn missing_substituted_or_encoded_ingress_and_body_remain_refusal() {
    let fixture = Fixture::new();
    for defect in [
        "original", "compact", "missing", "encoding", "phase", "status", "unknown",
    ] {
        let mut manifest = fixture.manifest(b"{}", b"", false);
        let case = &mut manifest.cases[0];
        match defect {
            "original" => case.original_request = fixture.body("different-original", b"{} "),
            "compact" => {
                case.received_ingress = Some(fixture.body("different-compact", b"malformed"))
            }
            "missing" => case.original_ingress = None,
            "encoding" => case.response_content_encoding = Some("gzip".into()),
            "phase" => case.phase = Some("preflight".into()),
            "status" => case.status = 200,
            "unknown" => case.path_and_query = "/unsupported".into(),
            _ => unreachable!(),
        }
        assert!(inspect(manifest).is_err(), "{defect}");
    }
}

#[test]
fn changed_or_nonprivate_body_files_and_raw_blob_mismatch_refuse() {
    let fixture = Fixture::new();
    let mut manifest = fixture.manifest(b"", b"actual controlled blob", true);
    manifest.cases[0].received_reply.sha256 = "c".repeat(64);
    assert!(inspect(manifest).is_err());
    let manifest = fixture.manifest(b"{}", b"", false);
    fs::set_permissions(
        &manifest.cases[0].original_request.file,
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(inspect(manifest).is_err());
}

#[test]
fn stored_projection_uses_shared_original_incarnation_and_source_correlation() {
    use aos_hub_core::{
        mirror_guard::MirrorGuardIssuer,
        oci_projection::{guard::*, OciDocumentProjection},
        storage_work::StorageObjectIdentity,
    };
    use aos_oci_types::{Annotations, Descriptor, MediaType, Sha256Digest};

    let fixture = Fixture::new();
    let raw = br#"{ "schemaVersion" : 2, "manifests" : [] }"#;
    let descriptor = Descriptor {
        media_type: MediaType::OciImageIndex,
        digest: Sha256Digest::digest(raw),
        size: raw.len() as u64,
        urls: Vec::new(),
        annotations: Annotations::new(),
        data: None,
        artifact_type: None,
        platform: None,
    };
    let lookup = OciProjectionLookup {
        version: 1,
        deployment_id: "fixture".into(),
        protected_profile_digest: "c".repeat(64),
        source: aos_hub_core::oci_projection::OciProjectionSource::Managed,
        issuer: MirrorGuardIssuer {
            source_digest: "b".repeat(64),
            script_version: "fixture-script".into(),
        },
        clock_uncertainty_seconds: 2,
        key: "registry/oci/index".into(),
        descriptor,
        admission: None,
        nonce: "a".repeat(64),
        issued_at: 100,
        expires_at: 130,
    };
    let reply = OciProjectionReply {
        request: lookup.clone(),
        object: StorageObjectIdentity {
            key: lookup.key.clone(),
            size: raw.len() as u64,
            etag: "\"fixture\"".into(),
            provider_version: Some("fixture-version".into()),
        },
        projection: OciDocumentProjection::from_stored_bytes(&lookup.descriptor, raw).unwrap(),
        observed_at: 101,
    };
    let request = serde_json::to_vec(&lookup).unwrap();
    let reply_bytes = serde_json::to_vec(&reply).unwrap();
    let mut manifest = fixture.manifest(b"{}", b"", false);
    let case = &mut manifest.cases[0];
    case.path_and_query = OCI_PROJECTION_PATH.into();
    case.method = "POST".into();
    case.phase = None;
    case.status = 200;
    case.response_content_type = Some("application/json".into());
    case.original_ingress = None;
    case.received_ingress = None;
    case.original_request = fixture.body("original", &request);
    case.received_request = fixture.body("request", &request);
    case.received_reply = fixture.body("reply", &reply_bytes);

    let rows = inspect(manifest).unwrap();
    assert_eq!(rows[0].class, "oci_stored_document_projection");
    assert_eq!(rows[0].payload.reply_raw_object_bytes, "0");
    assert_eq!(
        rows[0].payload.semantic_oci_projection_bytes,
        serde_json::to_vec(&reply.projection)
            .unwrap()
            .len()
            .to_string()
    );

    // A semantically valid descriptor can contain a whole inline object body.
    // Such content must not silently become a zero-bulk metadata observation.
    let mut embedded = reply;
    let OciDocumentProjection::Index(index) = &mut embedded.projection else {
        panic!("wrong fixture projection");
    };
    index.manifests.push(Descriptor {
        media_type: MediaType::OciImageManifest,
        digest: Sha256Digest::digest(b"inline-body"),
        size: 11,
        urls: Vec::new(),
        annotations: Annotations::new(),
        data: Some("aW5saW5lLWJvZHk=".into()),
        artifact_type: None,
        platform: None,
    });
    let embedded_raw = serde_json::to_vec(index).unwrap();
    embedded.request.descriptor.digest = Sha256Digest::digest(&embedded_raw);
    embedded.request.descriptor.size = embedded_raw.len() as u64;
    embedded.object.size = embedded_raw.len() as u64;
    OciDocumentProjection::from_stored_bytes(&embedded.request.descriptor, &embedded_raw).unwrap();

    let mut manifest = fixture.manifest(b"{}", b"", false);
    let case = &mut manifest.cases[0];
    case.path_and_query = OCI_PROJECTION_PATH.into();
    case.method = "POST".into();
    case.phase = None;
    case.status = 200;
    case.response_content_type = Some("application/json".into());
    case.original_ingress = None;
    case.received_ingress = None;
    let embedded_request = serde_json::to_vec(&embedded.request).unwrap();
    case.original_request = fixture.body("original", &embedded_request);
    case.received_request = fixture.body("request", &embedded_request);
    case.received_reply = fixture.body("reply", &serde_json::to_vec(&embedded).unwrap());
    assert!(inspect(manifest).is_err());
}
