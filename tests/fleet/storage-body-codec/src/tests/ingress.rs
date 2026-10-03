//! Shared typed read bodies, exact original correlation and real refused controls.

use super::*;

fn ingress_case(
    fixture: &Fixture,
    path: &str,
    method: &str,
    phase: Option<&str>,
    request: &[u8],
    reply: &[u8],
    status: u16,
) -> Manifest {
    let mut manifest = fixture.manifest(request, reply, true);
    let case = &mut manifest.cases[0];
    case.path_and_query = path.into();
    case.method = method.into();
    case.phase = phase.map(str::to_owned);
    case.status = status;
    case.response_content_type = Some("application/json".into());
    let original = HybridIngressAssertion {
        version: 1,
        deployment_id: "fixture".into(),
        issued_at: 100,
        expires_at: 130,
        request_id: "actual-controlled-original".into(),
        scheme: "https".into(),
        authority: "storage.test".into(),
        method: method.into(),
        path_and_query: path.into(),
        body_sha256: body_sha256(request),
        upload_phase: phase.map(str::to_owned),
        client_ip: "127.0.0.1".into(),
    };
    let compact = HybridIngressKey::new([1; 32])
        .unwrap()
        .sign(&original)
        .unwrap();
    case.original_ingress = Some(fixture.body("read-original-ingress", compact.as_bytes()));
    case.received_ingress = Some(fixture.body("read-received-ingress", compact.as_bytes()));
    manifest
}

#[test]
fn empty_machine_read_does_not_admit_a_nonempty_object_or_swapped_method() {
    let fixture = Fixture::new();
    let path = "/managed/containers/objects/aa/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let rows = inspect(ingress_case(&fixture, path, "GET", None, b"", b"", 200)).unwrap();
    assert_eq!(rows[0].class, "ingress_empty_read_authorization");
    assert_eq!(rows[0].payload.reply_raw_object_bytes, "0");
    assert!(inspect(ingress_case(
        &fixture,
        path,
        "GET",
        None,
        b"",
        b"raw object",
        200
    ))
    .is_err());
    let mut original = ingress_case(&fixture, path, "GET", None, b"", b"", 200);
    original.cases[0].method = "HEAD".into();
    assert!(inspect(original).is_err());
}

#[test]
fn head_object_authorization_requires_the_exact_empty_read_exchange() {
    let fixture = Fixture::new();
    let paths = [
        format!("/v2/aos/blobs/sha256:{}", "d".repeat(64)),
        "/v2/aos/manifests/tag".into(),
    ];

    for path in paths {
        let rows = inspect(ingress_case(&fixture, &path, "HEAD", None, b"", b"", 200)).unwrap();
        assert_eq!(rows[0].class, "ingress_empty_read_authorization");
        assert_eq!(rows[0].payload.request_raw_object_bytes, "0");
        assert_eq!(rows[0].payload.reply_raw_object_bytes, "0");

        for (phase, request, reply, status) in [
            (Some("preflight"), b"".as_slice(), b"".as_slice(), 200),
            (None, b"unexpected".as_slice(), b"".as_slice(), 200),
            (None, b"".as_slice(), b"unexpected".as_slice(), 200),
            (None, b"".as_slice(), b"".as_slice(), 201),
            (None, b"".as_slice(), b"".as_slice(), 204),
        ] {
            assert!(inspect(ingress_case(
                &fixture, &path, "HEAD", phase, request, reply, status,
            ))
            .is_err());
        }
        assert!(inspect(ingress_case(
            &fixture,
            &format!("{path}?unexpected=1"),
            "HEAD",
            None,
            b"",
            b"",
            200,
        ))
        .is_err());

        let mut original = ingress_case(&fixture, &path, "HEAD", None, b"", b"", 200);
        let other_fixture = Fixture::new();
        let mut other = ingress_case(
            &other_fixture,
            "/v2/aos/manifests/other",
            "HEAD",
            None,
            b"",
            b"",
            200,
        );
        original.cases[0].received_ingress = other.cases.remove(0).received_ingress;
        assert!(inspect(original).is_err());
    }
}

#[test]
fn head_upload_status_keeps_the_shared_control_constraints() {
    let fixture = Fixture::new();
    let rows = inspect(fixture.upload_control("HEAD", "", None, b"", 204)).unwrap();
    assert_eq!(rows[0].operation, "oci_upload_status");

    for (query, phase, reply, status) in [
        ("", None, b"".as_slice(), 200),
        ("", Some("preflight"), b"".as_slice(), 204),
        ("?unexpected=1", None, b"".as_slice(), 204),
        ("", None, b"unexpected".as_slice(), 204),
    ] {
        assert!(inspect(fixture.upload_control("HEAD", query, phase, reply, status)).is_err());
    }
}

#[test]
fn semantic_browse_counts_actual_selected_json_and_rejects_unknown_content() {
    let fixture = Fixture::new();
    let body = br#"[{"name":"package","description":"summary"}]"#;
    let rows = inspect(ingress_case(
        &fixture,
        "/managed/containers/-/api/packages",
        "GET",
        None,
        b"",
        body,
        200,
    ))
    .unwrap();
    assert_eq!(rows[0].payload.selected_data_bytes, body.len().to_string());
    assert_eq!(rows[0].payload.reply_raw_object_bytes, "0");
    let unknown = br#"[{"name":"package","contentBase64":"Ynl0ZXM="}]"#;
    assert!(inspect(ingress_case(
        &fixture,
        "/managed/containers/-/api/packages",
        "GET",
        None,
        b"",
        unknown,
        200
    ))
    .is_err());
}

#[test]
fn canonical_document_is_counted_as_document_bytes_and_bound_to_its_digest() {
    use aos_doc_model::{
        DocumentationIdentity, DocumentedPackage, PackageDocumentation, DOCUMENT_SCHEMA,
    };

    let fixture = Fixture::new();
    let mut document = PackageDocumentation {
        schema: DOCUMENT_SCHEMA.into(),
        package: DocumentedPackage {
            name: "package".into(),
            version: "1".into(),
            platform: "x86_64-linux".into(),
            summary: "summary".into(),
            homepage: None,
            license: "MIT".into(),
        },
        identity: DocumentationIdentity {
            semantic_schema_sha256: format!("sha256:{}", "0".repeat(64)),
            runtime_nar_hash: format!("sha256:{}", "1".repeat(64)),
            config_module_nar_hash: None,
            system_module_nar_hash: None,
            expose_artifact_nar_hash: None,
            source_nar_hash: format!("sha256:{}", "2".repeat(64)),
        },
        sections: vec![],
        options: vec![],
        runtime: Default::default(),
    };
    document.identity.semantic_schema_sha256 = document.computed_semantic_schema_sha256().unwrap();
    let body = document.canonical_json().unwrap();
    let path = format!(
        "/managed/containers/-/api/v1/documentation/{}",
        document.document_sha256().unwrap()
    );
    let rows = inspect(ingress_case(&fixture, &path, "GET", None, b"", &body, 200)).unwrap();
    assert_eq!(rows[0].class, "ingress_canonical_document_body");
    assert_eq!(
        rows[0].payload.reply_raw_object_bytes,
        body.len().to_string()
    );
    let other = format!(
        "/managed/containers/-/api/v1/documentation/sha256:{}",
        "f".repeat(64)
    );
    assert!(inspect(ingress_case(&fixture, &other, "GET", None, b"", &body, 200)).is_err());
}

#[test]
fn refused_completion_needs_its_fixed_body_and_bounded_closed_error() {
    let fixture = Fixture::new();
    let path = format!(
        "/v2/aos/manifests/tag?aos_hybrid_manifest_upload={}",
        "c".repeat(32)
    );
    let reply = br#"{"errors":[{"code":"DENIED","message":"denied"}]}"#;
    let rows = inspect(ingress_case(
        &fixture,
        &path,
        "PUT",
        Some("complete"),
        b"{}",
        reply,
        403,
    ))
    .unwrap();
    assert_eq!(rows[0].class, "ingress_refused_metadata");
    assert!(inspect(ingress_case(
        &fixture,
        &path,
        "PUT",
        Some("complete"),
        b"raw document",
        reply,
        403
    ))
    .is_err());
    let substitution = br#"{"errors":[{"code":"DENIED","message":"denied","blob":"raw"}]}"#;
    assert!(inspect(ingress_case(
        &fixture,
        &path,
        "PUT",
        Some("complete"),
        b"{}",
        substitution,
        403
    ))
    .is_err());
}

#[test]
fn legacy_capability_observation_preserves_shared_bundle_and_operation_checks() {
    use aos_hub_core::storage_work::{
        StorageCapabilities, MAX_RESULT_BYTES, MAX_VERIFY_SOURCE_BYTES,
        STORAGE_CAPABILITIES_CHALLENGE, STORAGE_CAPABILITIES_PATH,
    };

    let fixture = Fixture::new();
    let capabilities = StorageCapabilities {
        version: 1,
        deployment_id: "fixture".into(),
        binding_kind: "deployment_r2".into(),
        console_asset_version: Some(aos_hub_core::web::assets::asset_version().into()),
        r2_gc_incarnation_v1: true,
        operations: [
            "head",
            "list_page",
            "inspect_sha256",
            "inspect_git_object",
            "inspect_git_objects",
            "filter_git_tree_entries_v1",
            "inspect_metadata",
            "inspect_metadata_objects",
            "inspect_documentation",
            "inspect_documentation_content",
            "inspect_oci_range",
            "hash_oci_range",
            "copy_object",
            "compose_oci_blob",
            "stage_oci_manifest",
            "delete_oci_staging",
            "delete_if_matches",
            "put_metadata",
            "put_probe",
            "delete_probe",
            "create_multipart",
            "complete_multipart",
            "abort_multipart",
            "credential_probe",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        max_result_bytes: MAX_RESULT_BYTES,
        max_verify_source_bytes: MAX_VERIFY_SOURCE_BYTES,
    };
    let build = |reply: &[u8]| {
        let mut manifest = fixture.manifest(STORAGE_CAPABILITIES_CHALLENGE, reply, false);
        let case = &mut manifest.cases[0];
        case.path_and_query = STORAGE_CAPABILITIES_PATH.into();
        case.method = "POST".into();
        case.phase = None;
        case.status = 200;
        case.response_content_type = Some("application/json".into());
        case.original_ingress = None;
        case.received_ingress = None;
        manifest
    };
    let rows = inspect(build(&serde_json::to_vec(&capabilities).unwrap())).unwrap();
    assert_eq!(rows[0].class, "storage_control_metadata");

    let mut substituted = capabilities.clone();
    substituted.console_asset_version = Some("foreign-bundle".into());
    assert!(inspect(build(&serde_json::to_vec(&substituted).unwrap())).is_err());
    substituted = capabilities;
    substituted.operations.retain(|kind| kind != "head");
    assert!(inspect(build(&serde_json::to_vec(&substituted).unwrap())).is_err());
}

#[test]
fn capability_refusal_counts_exact_source_owned_control_text_without_acceptance() {
    use aos_hub_core::storage_work::{STORAGE_CAPABILITIES_CHALLENGE, STORAGE_CAPABILITIES_PATH};

    let fixture = Fixture::new();
    let build = |reply: &[u8]| {
        let mut manifest = fixture.manifest(STORAGE_CAPABILITIES_CHALLENGE, reply, false);
        let case = &mut manifest.cases[0];
        case.path_and_query = STORAGE_CAPABILITIES_PATH.into();
        case.method = "POST".into();
        case.phase = None;
        case.status = 401;
        case.response_content_type = Some("text/plain; charset=utf-8".into());
        case.original_ingress = None;
        case.received_ingress = None;
        manifest
    };
    assert_eq!(
        inspect(build(b"storage capability challenge is invalid")).unwrap()[0].operation,
        "storage_control_refused"
    );
    assert!(inspect(build(b"raw object")).is_err());
}
