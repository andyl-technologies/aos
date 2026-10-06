//! Real production codec positives and refusal boundaries for the observer.

use super::*;
use aos_hub_core::{direct_upload::*, storage_work::*};
use std::{fs, os::unix::fs::PermissionsExt as _};

fn reference(raw: &[u8], label: &str) -> BodyFile {
    let root = std::env::temp_dir().join(format!(
        "native-body-observer-{}-{label}",
        std::process::id()
    ));
    fs::create_dir_all(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let path = root.join("body");
    fs::write(&path, raw).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    BodyFile {
        file: path.to_string_lossy().into(),
        sha256: files::digest(raw),
        byte_size: raw.len().to_string(),
    }
}

fn capture(path: &str, request: &[u8], response: &[u8], label: &str) -> Capture {
    Capture {
        request_id: label.into(),
        procedure: path.into(),
        method: "POST".into(),
        phase: None,
        status: 200,
        response_content_type: Some("application/json".into()),
        response_content_encoding: None,
        bodies: Bodies {
            request: reference(request, &format!("{label}-request")),
            response: reference(response, &format!("{label}-response")),
        },
        control_selection: None,
        storage_work_selection: None,
        empty_response_observation: None,
    }
}

fn selection(captures: Vec<Capture>) -> Selection {
    Selection {
        version: 1,
        codec_revision: env!("NATIVE_CODEC_REVISION").into(),
        source_digest: env!("NATIVE_WORKER_SOURCE_DIGEST").into(),
        issuer_verifier: None,
        captures,
    }
}

#[test]
fn canonical_public_manifest_is_correlated_and_unknown_bytes_refuse() {
    use aos_proto_types::*;
    let original = BeginRegistryPublicationManifestRequest {
        registry: "registry".into(),
        generation: "generation".into(),
        manifest_digest: "a".repeat(64),
        object_count: 12538,
        ..Default::default()
    };
    let reply = RegistryPublicationManifestSession {
        publication_id: "original-publication".into(),
        lease_token: "original-lease".into(),
        manifest_digest: original.manifest_digest.clone(),
        object_count: original.object_count,
        ..Default::default()
    };
    let request = serde_json::to_vec(&original).unwrap();
    let response = serde_json::to_vec(&reply).unwrap();
    let path = "/aos.hub.v1.PublishService/BeginRegistryPublicationManifest";
    let selected = capture(path, &request, &response, "manifest");
    let (rows, count) = inspect(selection(vec![selected])).unwrap();
    assert_eq!(count, request.len() + response.len());
    assert_eq!(rows[0].class, "public_protojson_control_metadata");

    let mut changed = reply;
    changed.manifest_digest = "b".repeat(64);
    assert!(public_rpc::classify(
        &capture(path, &request, &response, "manifest-context"),
        &request,
        &serde_json::to_vec(&changed).unwrap()
    )
    .is_err());
    let mut unknown = serde_json::to_value(&original).unwrap();
    unknown["unclassifiedBytes"] = serde_json::json!("payload");
    assert!(
        public_rpc::exact::<BeginRegistryPublicationManifestRequest>(
            &serde_json::to_vec(&unknown).unwrap()
        )
        .is_err()
    );
    assert!(
        public_rpc::exact::<BeginRegistryPublicationManifestRequest>(
            &[request.as_slice(), b" "].concat()
        )
        .is_err()
    );
    let mut append = AppendRegistryPublicationManifestRequest {
        publication_id: "original-publication".into(),
        lease_token: "original-lease".into(),
        objects: vec![RegistryPublicationObjectInput {
            path: "HEAD".into(),
            sha256: "d".repeat(64),
            byte_size: 64,
            kind: "mutable_pointer".into(),
            media_type: "text/plain".into(),
        }],
        ..Default::default()
    };
    append.chunk_digest = manifest_digest::digest(&append.objects).unwrap();
    let reply = RegistryPublicationManifestSession {
        publication_id: append.publication_id.clone(),
        lease_token: append.lease_token.clone(),
        next_chunk_index: 1,
        ..Default::default()
    };
    let response = serde_json::to_vec(&reply).unwrap();
    let request = serde_json::to_vec(&append).unwrap();
    let selected = capture(
        "/aos.hub.v1.PublishService/AppendRegistryPublicationManifest",
        &request,
        &response,
        "append",
    );
    public_rpc::classify(&selected, &request, &response).unwrap();
    append.chunk_digest = "e".repeat(64);
    assert!(
        public_rpc::classify(&selected, &serde_json::to_vec(&append).unwrap(), &response).is_err()
    );
    append.objects[0].path = "../unclassified".into();
    append.chunk_digest = manifest_digest::digest(&append.objects).unwrap();
    assert!(
        public_rpc::classify(&selected, &serde_json::to_vec(&append).unwrap(), &response).is_err()
    );
}

#[test]
fn direct_batch_uses_actual_closed_codecs_and_exact_original_operation() {
    let original = DirectBatch {
        operation_id: "a".repeat(64),
        items: vec![DirectStatusQuery {
            session: DirectSessionRef {
                session_id: "original-session".into(),
                logical_fingerprint: "b".repeat(64),
            },
            after: None,
            maximum_parts: 32,
        }],
    };
    let reply = DirectUploadResponse {
        operation_id: original.operation_id.clone(),
        sessions: Vec::new(),
        grants: Vec::new(),
        errors: vec![DirectItemError {
            item_id: "original-session".into(),
            code: DirectItemErrorCode::Unavailable,
        }],
    };
    let request = encode_direct_control(&original).unwrap();
    let response = encode_direct_control(&reply).unwrap();
    let selected = capture(
        "/aos.hub.v1.DirectUploadService/StatusBatch",
        &request,
        &response,
        "direct",
    );
    public_rpc::classify(&selected, &request, &response).unwrap();
    let mut changed = reply;
    changed.operation_id = "c".repeat(64);
    assert!(public_rpc::classify(
        &selected,
        &request,
        &encode_direct_control(&changed).unwrap()
    )
    .is_err());
    assert!(public_rpc::classify(
        &capture("/unsupported", &request, &response, "foreign"),
        &request,
        &response
    )
    .is_err());
}

#[test]
fn logical_envelope_preserves_context_phase_and_closed_projection() {
    let original = DirectLogicalRequestEnvelope {
        context: DirectRequestContext {
            deployment_id: "deployment".into(),
            executor_public_origin: "https://executor.example.test".into(),
            public_authority: "hub.example.test".into(),
            foreground: DirectForegroundBudget {
                invocation_id: "a".repeat(64),
                issued_at: WireInteger::new(100),
                expires_at: WireInteger::new(130),
            },
            request_nonce: "b".repeat(64),
            request_body_sha256: "c".repeat(64),
            public_method: "POST".into(),
            public_path: "/aos.hub.v1.DirectUploadService/BeginBatch".into(),
            issued_at: WireInteger::new(100),
            expires_at: WireInteger::new(130),
        },
        request: DirectUploadLogicalRequest::Admission {
            intents: vec![DirectUploadIntent {
                version: 1,
                client_operation_id: "d".repeat(64),
                target: DirectUploadTarget::CacheObject {
                    cache_id: "cache".into(),
                    path: "object".into(),
                },
                expected_sha256: "e".repeat(64),
                byte_size: WireInteger::new(1),
                part_size: WireInteger::new(8 * 1024 * 1024),
                dependency_phase: DirectDependencyPhase::Content,
                transfer_mode: DirectTransferMode::DirectRequired,
            }],
        },
    };
    let reply = DirectLogicalReplyEnvelope {
        context: original.context.clone(),
        reply: DirectUploadLogicalReply {
            admissions: Vec::new(),
            sessions: Vec::new(),
            session_summaries: Vec::new(),
            authorizations: Vec::new(),
            baseline_permissions: Vec::new(),
            errors: vec![DirectItemError {
                item_id: "d".repeat(64),
                code: DirectItemErrorCode::Unavailable,
            }],
        },
    };
    let request = encode_direct_control(&original).unwrap();
    let response = encode_direct_control(&reply).unwrap();
    let mut selected = capture(
        &original.context.public_path,
        &request,
        &response,
        "logical",
    );
    selected.phase = Some("admission".into());
    assert_eq!(
        logical::classify(&selected, &request, &response).unwrap(),
        original.context.request_body_sha256
    );
    let mut changed = reply;
    changed.context.request_nonce = "f".repeat(64);
    assert!(logical::classify(
        &selected,
        &request,
        &encode_direct_control(&changed).unwrap()
    )
    .is_err());
    selected.phase = Some("commit".into());
    assert!(logical::classify(&selected, &request, &response).is_err());
}

#[test]
fn exact_shell_matches_current_assets_and_rejects_escape_or_trailing_substitution() {
    let mut shell = browser::TEMPLATE.to_owned();
    for (name, value) in [
        ("title", "AOS Hub"),
        ("csrf", "a-test-csrf"),
        ("brand", ""),
        ("tagline", ""),
        ("announcement", ""),
        ("tos_url", ""),
        ("privacy_url", ""),
        ("support_url", ""),
        ("app_version", env!("NATIVE_APP_VERSION")),
        ("container_gc_enabled", "false"),
        ("asset_version", aos_hub_core::web::assets::asset_version()),
        ("css", &aos_hub_core::web::assets::console_css_name()),
        (
            "bootstrap",
            &aos_hub_core::web::assets::console_bootstrap_name(),
        ),
    ] {
        shell = shell.replace(&format!("{{{name}}}"), value);
    }
    let mut selected = capture("/-/instance", b"", shell.as_bytes(), "browser");
    selected.method = "GET".into();
    selected.response_content_type = Some("text/html; charset=utf-8".into());
    browser::classify(&selected, b"", shell.as_bytes()).unwrap();
    assert!(browser::classify(&selected, b"", format!("{shell}payload").as_bytes()).is_err());
    assert!(browser::classify(
        &selected,
        b"",
        shell
            .replace("<title>AOS Hub</title>", "<title>&#65;OS Hub</title>")
            .as_bytes()
    )
    .is_err());
    assert!(browser::classify(&selected, b"payload", shell.as_bytes()).is_err());
}

#[test]
fn ordinary_storage_uses_real_result_validator_and_original_fences() {
    let plan = StorageWorkPlan {
        version: 1,
        plan_id: "a".repeat(32),
        deployment_id: "fixture".into(),
        issued_at: 100,
        expires_at: 130,
        placement_id: 4,
        placement_resource_version: 2,
        binding_id: 3,
        binding_resource_version: 1,
        binding_kind: "deployment_r2".into(),
        binding_snapshot_revision: None,
        credential_references: Vec::new(),
        placement_prefix: "registry/".into(),
        operation: StorageWorkOperation::Head {
            path: "HEAD".into(),
        },
    };
    let result = StorageWorkResult {
        plan_id: plan.plan_id.clone(),
        placement_id: 4,
        placement_resource_version: 2,
        binding_id: 3,
        binding_resource_version: 1,
        source_bytes: 0,
        versioned_sources: Vec::new(),
        outcome: StorageWorkOutcome::NotFound,
    };
    let request = serde_json::to_vec(&plan).unwrap();
    let response = serde_json::to_vec(&result).unwrap();
    let mut selected = capture(STORAGE_WORK_PATH, &request, &response, "storage");
    selected.storage_work_selection = Some(StorageSelection {
        source_digest: env!("NATIVE_WORKER_SOURCE_DIGEST").into(),
        completion_observed_at_unix_millis: "100000".into(),
        original_plan: reference(&request, "storage-original"),
    });
    let (rows, bytes) = inspect(selection(vec![selected])).unwrap();
    assert_eq!(bytes, request.len() + response.len());
    assert_eq!(
        rows[0].storage_work.as_ref().unwrap()["executorSourceBytes"],
        "0"
    );
    let mut changed = result;
    changed.placement_resource_version += 1;
    assert!(crate::storage_work::decode_transport(
        &request,
        &serde_json::to_vec(&changed).unwrap(),
        "fixture",
        200
    )
    .is_err());
}

#[test]
fn selected_source_file_custody_and_member_limits_remain_fail_closed() {
    let raw = b"{}";
    let selected = capture("/aos.hub.v1.IdentityService/WhoAmI", raw, raw, "bounds");
    let path = selected.bodies.request.file.clone();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(inspect(selection(vec![selected])).is_err());
    let mut reference = reference(raw, "bounds-size");
    reference.byte_size = (8 * 1024 * 1024 + 1).to_string();
    assert!(files::read(&reference, &mut 0).is_err());
    let mut selected = selection(Vec::new());
    selected.source_digest = "f".repeat(64);
    assert!(inspect(selected).is_err());
}
