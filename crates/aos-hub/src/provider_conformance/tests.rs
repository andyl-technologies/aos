//! Real TLS dispatch, multipart state, checksum failures and restart fences.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use axum::{
    body::{Body, Bytes},
    extract::{Request, State},
    response::Response,
    routing::any,
    Router,
};
use base64::Engine as _;
use md5::{Digest as _, Md5};

use super::{
    journal::digest,
    model::{Phase, Report},
    provider_conformance_status, run_provider_conformance,
};

#[derive(Default)]
struct Upload {
    key: String,
    parts: BTreeMap<u32, Vec<u8>>,
}

#[derive(Clone)]
struct Object {
    bytes: Vec<u8>,
    etag: String,
    version: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    None,
    LostComplete,
    CopyError,
    ChangedSource,
    EchoCredential,
}

struct Provider {
    uploads: BTreeMap<String, Upload>,
    objects: BTreeMap<String, Object>,
    requests: usize,
    completed: usize,
    copies: usize,
    bad_checksums: usize,
    late_parts: usize,
    fault: Fault,
}

impl Provider {
    fn new(fault: Fault) -> Self {
        Self {
            uploads: BTreeMap::new(),
            objects: BTreeMap::new(),
            requests: 0,
            completed: 0,
            copies: 0,
            bad_checksums: 0,
            late_parts: 0,
            fault,
        }
    }
}

fn response(status: u16, bytes: impl Into<Body>) -> Response {
    Response::builder()
        .status(status)
        .header("x-amz-request-id", "fixture-request")
        .body(bytes.into())
        .unwrap()
}

fn error(status: u16, code: &str) -> Response {
    response(status, format!("<Error><Code>{code}</Code></Error>"))
}

fn etag(bytes: &[u8]) -> String {
    format!("\"{}\"", hex::encode(Md5::digest(bytes)))
}

async fn execute(State(state): State<Arc<Mutex<Provider>>>, request: Request) -> Response {
    let (request, body) = request.into_parts();
    let body = axum::body::to_bytes(body, 8 * 1024 * 1024).await.unwrap();
    let mut provider = state.lock().unwrap();
    provider.requests += 1;
    let query: BTreeMap<_, _> =
        url::form_urlencoded::parse(request.uri.query().unwrap_or("").as_bytes())
            .into_owned()
            .collect();
    let key = request
        .uri
        .path()
        .strip_prefix("/probe-bucket/")
        .unwrap()
        .to_owned();
    if !query.contains_key("X-Amz-Signature") {
        return error(403, "AccessDenied");
    }
    assert!(query["X-Amz-Credential"].starts_with("fixture-access/"));
    assert!(query["X-Amz-Signature"].len() == 64);
    if request.method == "POST" && query.contains_key("uploads") {
        let upload_id = format!("upload-{}", provider.requests);
        provider.uploads.insert(
            upload_id.clone(),
            Upload {
                key: key.clone(),
                parts: BTreeMap::new(),
            },
        );
        return response(200, format!("<InitiateMultipartUploadResult><Bucket>probe-bucket</Bucket><Key>{key}</Key><UploadId>{upload_id}</UploadId></InitiateMultipartUploadResult>"));
    }
    if let Some(upload_id) = query.get("uploadId") {
        if !provider.uploads.contains_key(upload_id) {
            provider.late_parts += 1;
            return error(404, "NoSuchUpload");
        }
        assert_eq!(provider.uploads[upload_id].key, key);
        if request.method == "DELETE" {
            provider.uploads.remove(upload_id);
            return response(204, Body::empty());
        }
        if request.method == "PUT" {
            let part: u32 = query["partNumber"].parse().unwrap();
            if let Some(source) = request.headers.get("x-amz-copy-source") {
                assert!(query["X-Amz-SignedHeaders"].contains("x-amz-copy-source-range"));
                provider.copies += 1;
                if provider.fault == Fault::CopyError {
                    return error(200, "InternalError");
                }
                let source_key = source
                    .to_str()
                    .unwrap()
                    .strip_prefix("/probe-bucket/")
                    .unwrap();
                let range = request.headers["x-amz-copy-source-range"]
                    .to_str()
                    .unwrap()
                    .strip_prefix("bytes=")
                    .unwrap();
                let (first, last) = range.split_once('-').unwrap();
                let first: usize = first.parse().unwrap();
                let last: usize = last.parse().unwrap();
                let bytes = provider.objects[source_key].bytes[first..=last].to_vec();
                let tag = etag(&bytes);
                provider
                    .uploads
                    .get_mut(upload_id)
                    .unwrap()
                    .parts
                    .insert(part, bytes);
                return response(
                    200,
                    format!("<CopyPartResult><ETag>{tag}</ETag></CopyPartResult>"),
                );
            }
            assert!(query["X-Amz-SignedHeaders"].contains("content-md5"));
            assert!(query["X-Amz-SignedHeaders"].contains("content-length"));
            let expected = base64::engine::general_purpose::STANDARD.encode(Md5::digest(&body));
            if request.headers["content-md5"].to_str().unwrap() != expected {
                provider.bad_checksums += 1;
                return error(400, "BadDigest");
            }
            let tag = etag(&body);
            provider
                .uploads
                .get_mut(upload_id)
                .unwrap()
                .parts
                .insert(part, body.to_vec());
            return Response::builder()
                .status(200)
                .header("etag", tag)
                .header("x-amz-request-id", "fixture-part")
                .body(Body::empty())
                .unwrap();
        }
        if request.method == "POST" {
            let upload = provider.uploads.remove(upload_id).unwrap();
            let manifest = std::str::from_utf8(&body).unwrap();
            for (part, bytes) in &upload.parts {
                assert!(manifest.contains(&format!("<PartNumber>{part}</PartNumber>")));
                assert!(manifest.contains(&etag(bytes)));
            }
            assert_eq!(manifest.matches("<Part>").count(), upload.parts.len());
            let bytes: Vec<u8> = upload.parts.into_values().flatten().collect();
            let tag = if provider.fault == Fault::EchoCredential {
                "\"fixture-secret\"".into()
            } else {
                etag(&bytes)
            };
            provider.completed += 1;
            let version = format!("version-{}", provider.completed);
            provider.objects.insert(
                key.clone(),
                Object {
                    bytes,
                    etag: tag.clone(),
                    version,
                },
            );
            if provider.fault == Fault::LostComplete && provider.completed == 1 {
                return response(
                    200,
                    Body::from_stream(futures_util::stream::once(async {
                        Err::<Bytes, _>(std::io::Error::new(
                            std::io::ErrorKind::ConnectionReset,
                            "fixture lost reply",
                        ))
                    })),
                );
            }
            if provider.fault == Fault::ChangedSource && key.ends_with("provider-copy") {
                provider
                    .objects
                    .iter_mut()
                    .find(|(key, _)| key.ends_with("/source"))
                    .unwrap()
                    .1
                    .bytes[0] ^= 1;
            }
            return response(200, format!("<CompleteMultipartUploadResult><Bucket>probe-bucket</Bucket><Key>{key}</Key><ETag>{tag}</ETag></CompleteMultipartUploadResult>"));
        }
    }
    let object = provider.objects.get(&key).unwrap();
    if request.method == "HEAD" {
        return Response::builder()
            .status(200)
            .header("etag", &object.etag)
            .header("x-amz-version-id", &object.version)
            .header("content-length", object.bytes.len())
            .body(Body::empty())
            .unwrap();
    }
    assert_eq!(request.method, "GET");
    assert_eq!(request.headers["if-match"].to_str().unwrap(), object.etag);
    let mut builder = Response::builder()
        .header("etag", &object.etag)
        .header("x-amz-version-id", &object.version);
    if let Some(range) = request.headers.get("range") {
        let (first, last) = range
            .to_str()
            .unwrap()
            .strip_prefix("bytes=")
            .unwrap()
            .split_once('-')
            .unwrap();
        let first: usize = first.parse().unwrap();
        let last: usize = last.parse().unwrap();
        builder = builder.status(206).header(
            "content-range",
            format!("bytes {first}-{last}/{}", object.bytes.len()),
        );
        builder
            .body(Body::from(object.bytes[first..=last].to_vec()))
            .unwrap()
    } else {
        builder
            .status(200)
            .body(Body::from(object.bytes.clone()))
            .unwrap()
    }
}

fn write(path: &std::path::Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap();
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

struct Fixture {
    directory: tempfile::TempDir,
    state: Arc<Mutex<Provider>>,
    task: tokio::task::JoinHandle<()>,
}

impl Fixture {
    async fn new(fault: Fault) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let state = Arc::new(Mutex::new(Provider::new(fault)));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let fixtures =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
        let tls = crate::native_tls::NativeTlsListener::new(
            listener,
            &fixtures.join("hub-hybrid-fleet-server.crt"),
            &fixtures.join("hub-hybrid-fleet-server.key"),
            "localhost".into(),
        )
        .unwrap();
        let app = Router::new()
            .fallback(any(execute))
            .with_state(state.clone())
            .layer(axum::extract::DefaultBodyLimit::max(8 * 1024 * 1024));
        let task = tokio::spawn(async move {
            axum::serve(tls, app).await.unwrap();
        });
        write(&directory.path().join("credentials.json"), br#"{"access_key":"fixture-access","secret_key":"fixture-secret","region":"fixture-region"}"#);
        let policy = aos_hub_core::direct_upload::DirectPrivateStagePolicyRef {
            policy_id: "independently-reviewed-fixture".into(),
            namespace: "fixture-guard-domain".into(),
            policy_digest: aos_hub_core::direct_upload::direct_private_stage_policy_commitment(
                "independently-reviewed-fixture",
                "fixture-guard-domain",
            )
            .unwrap(),
        };
        write(
            &directory.path().join("policy.json"),
            &serde_json::to_vec(&policy).unwrap(),
        );
        let reviewed = br#"{"independent_policy_review_fixture":1}"#;
        write(&directory.path().join("review.json"), reviewed);
        let config = serde_json::json!({
            "version":1, "endpoint":format!("https://localhost:{port}"), "bucket":"probe-bucket",
            "staging_prefix":"reviewed/.aos-direct-upload", "credential_file":"credentials.json",
            "private_policy_file":"policy.json", "policy_review_file":"review.json",
            "policy_review_sha256":digest(reviewed), "tls_ca_file":fixtures.join("hub-hybrid-fleet-ca.crt")
        });
        write(
            &directory.path().join("config.json"),
            &serde_json::to_vec(&config).unwrap(),
        );
        Self {
            directory,
            state,
            task,
        }
    }

    async fn run(&self) -> anyhow::Result<String> {
        run_provider_conformance(
            &self.directory.path().join("config.json"),
            &self.directory.path().join("journal"),
            &self.directory.path().join("report.json"),
        )
        .await
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test]
async fn actual_tls_pipeline_retains_closed_observations_without_authorizing_a_profile() {
    let fixture = Fixture::new(Fault::None).await;
    let commitment = fixture.run().await.unwrap();
    let bytes = std::fs::read(fixture.directory.path().join("report.json")).unwrap();
    assert_eq!(commitment, digest(&bytes));
    let report: Report = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(report.original.source_kind, "operator_core_s3surface_http");
    assert_eq!(report.source.sha256, report.original.expected_sha256);
    assert_eq!(report.streamed_copy.sha256, report.source.sha256);
    assert_eq!(report.provider_copy.sha256, report.source.sha256);
    assert_eq!(report.source.size, 5 * 1024 * 1024 + 32 * 1024);
    assert_eq!(report.cleanup_state, "retained_known_objects");
    for phase in [
        Phase::RejectBadChecksum,
        Phase::LatePartAfterComplete,
        Phase::LatePartAfterAbort,
        Phase::AnonymousRead,
        Phase::SourceRangeRead,
        Phase::ProviderCopyPart,
        Phase::SourceFinalRead,
    ] {
        assert!(report
            .observations
            .iter()
            .any(|observation| observation.phase == phase));
    }
    let json = std::str::from_utf8(&bytes).unwrap();
    for forbidden in [
        "fixture-access",
        "fixture-secret",
        "X-Amz-Signature",
        "provider_contract",
        "private_completed_stage",
    ] {
        assert!(!json.contains(forbidden));
    }
    let state = fixture.state.lock().unwrap();
    assert_eq!(state.completed, 3);
    assert_eq!(state.copies, 2);
    assert_eq!(state.bad_checksums, 1);
    assert_eq!(state.late_parts, 2);
    assert!(state.uploads.is_empty());
    assert_eq!(state.objects.len(), 3);
    assert_eq!(state.requests, report.observations.len());
    drop(state);
    let status = provider_conformance_status(&fixture.directory.path().join("journal")).unwrap();
    assert!(!status.contains("fixture-secret"));
    let status: serde_json::Value = serde_json::from_str(&status).unwrap();
    assert_eq!(status["unknown_operation_ids"].as_array().unwrap().len(), 0);
    let journal = fixture.directory.path().join("journal");
    let first: serde_json::Value =
        serde_json::from_slice(&std::fs::read(journal.join("002.intent.json")).unwrap()).unwrap();
    let late: serde_json::Value =
        serde_json::from_slice(&std::fs::read(journal.join("005.intent.json")).unwrap()).unwrap();
    assert_eq!(first["authorization_sha256"], late["authorization_sha256"]);
    eprintln!(
        "operator TLS provider conformance requests={} result_bytes={}",
        report.observations.len(),
        bytes.len()
    );
}

#[tokio::test]
async fn lost_complete_reply_retains_original_forever_and_status_never_replays() {
    let fixture = Fixture::new(Fault::LostComplete).await;
    assert!(fixture.run().await.is_err());
    let before = fixture.state.lock().unwrap().requests;
    assert_eq!(fixture.state.lock().unwrap().completed, 1);
    assert!(!fixture.directory.path().join("report.json").exists());
    for _ in 0..2 {
        let status =
            provider_conformance_status(&fixture.directory.path().join("journal")).unwrap();
        let status: serde_json::Value = serde_json::from_str(&status).unwrap();
        assert_eq!(status["unknown_operation_ids"].as_array().unwrap().len(), 1);
        assert_eq!(status["provider_requests_dispatched"], 0);
    }
    assert!(fixture.run().await.is_err());
    assert_eq!(fixture.state.lock().unwrap().requests, before);
    let original = std::fs::read(fixture.directory.path().join("journal/004.intent.json")).unwrap();
    assert!(std::str::from_utf8(&original)
        .unwrap()
        .contains("complete_source"));
    assert!(!std::str::from_utf8(&original).unwrap().contains("X-Amz-"));
}

#[tokio::test]
async fn body_level_copy_failure_and_changed_source_cannot_produce_a_contract_report() {
    for fault in [Fault::CopyError, Fault::ChangedSource] {
        let fixture = Fixture::new(fault).await;
        assert!(fixture.run().await.is_err());
        assert!(!fixture.directory.path().join("report.json").exists());
        let status =
            provider_conformance_status(&fixture.directory.path().join("journal")).unwrap();
        let value: serde_json::Value = serde_json::from_str(&status).unwrap();
        assert_eq!(value["unknown_operation_ids"].as_array().unwrap().len(), 1);
        let index = value["observations"].as_array().unwrap().len();
        let intent: serde_json::Value = serde_json::from_slice(
            &std::fs::read(
                fixture
                    .directory
                    .path()
                    .join(format!("journal/{index:03}.intent.json")),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            intent["phase"],
            if fault == Fault::CopyError {
                "provider_copy_part"
            } else {
                "source_final_read"
            }
        );
    }
}

#[tokio::test]
async fn provider_echoed_secrets_are_never_retained_as_receipts_or_printed_by_status() {
    let fixture = Fixture::new(Fault::EchoCredential).await;
    let failure = fixture.run().await.unwrap_err();
    assert!(!failure.to_string().contains("fixture-secret"));
    assert!(!fixture.directory.path().join("report.json").exists());
    let status = provider_conformance_status(&fixture.directory.path().join("journal")).unwrap();
    assert!(!status.contains("fixture-secret"));
    assert!(!status.contains("X-Amz-Signature"));
}

#[tokio::test]
async fn actual_tls_and_connection_failures_have_safe_labels_and_retain_unknown_intents() {
    for failure_class in ["tls_untrusted_certificate", "connection_refused"] {
        let fixture = Fixture::new(Fault::None).await;
        let config_path = fixture.directory.path().join("config.json");
        let mut config: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&config_path).unwrap()).unwrap();
        let unavailable = tokio::net::TcpSocket::new_v4().unwrap();
        unavailable.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        if failure_class == "tls_untrusted_certificate" {
            config["tls_ca_file"] = serde_json::Value::Null;
        } else {
            config["endpoint"] = format!(
                "https://localhost:{}",
                unavailable.local_addr().unwrap().port()
            )
            .into();
        }
        write(&config_path, &serde_json::to_vec(&config).unwrap());

        let error = fixture.run().await.unwrap_err();
        let rendered = format!("{error:#}");
        assert!(rendered.contains(&format!("transport_class={failure_class}")));
        assert!(rendered.contains("retained operation remains unknown"));
        for forbidden in ["https://", "X-Amz-", "fixture-access", "fixture-secret"] {
            assert!(!rendered.contains(forbidden));
        }

        let journal = fixture.directory.path().join("journal");
        let original = std::fs::read(journal.join("original.json")).unwrap();
        let intent = std::fs::read(journal.join("000.intent.json")).unwrap();
        assert!(!journal.join("000.response.json").exists());
        assert!(!journal.join("000.observation.json").exists());
        assert!(!fixture.directory.path().join("report.json").exists());
        assert_eq!(fixture.state.lock().unwrap().requests, 0);
        for _ in 0..2 {
            let status: serde_json::Value =
                serde_json::from_str(&provider_conformance_status(&journal).unwrap()).unwrap();
            assert_eq!(status["unknown_operation_ids"].as_array().unwrap().len(), 1);
        }
        assert_eq!(
            std::fs::read(journal.join("original.json")).unwrap(),
            original
        );
        assert_eq!(
            std::fs::read(journal.join("000.intent.json")).unwrap(),
            intent
        );
        assert_eq!(fixture.state.lock().unwrap().requests, 0);
    }
}

#[tokio::test]
async fn private_credential_and_policy_custody_fail_before_provider_dispatch() {
    use std::os::unix::fs::PermissionsExt as _;
    let fixture = Fixture::new(Fault::None).await;
    std::fs::set_permissions(
        fixture.directory.path().join("credentials.json"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(fixture.run().await.is_err());
    assert_eq!(fixture.state.lock().unwrap().requests, 0);
    std::fs::set_permissions(
        fixture.directory.path().join("credentials.json"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    write(
        &fixture.directory.path().join("review.json"),
        b"changed review",
    );
    assert!(fixture.run().await.is_err());
    assert_eq!(fixture.state.lock().unwrap().requests, 0);
}
