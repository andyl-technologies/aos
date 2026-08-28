//! Process-level pull/push coverage for daemon-free OCI transfers.

#![allow(clippy::expect_used)]

#[path = "../../aos-oci/tests/support/mod.rs"]
mod oci_support;

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use aos_oci::{PlatformSelector, verify_layout, write_oci_archive};
use aos_oci_types::{MediaType, Sha256Digest, to_canonical_json};
use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::header::{
    AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, LOCATION, RANGE, WWW_AUTHENTICATE,
};
use axum::http::{HeaderMap, Method, Request, Response, StatusCode, Uri};
use axum::routing::any;
use serde_json::Value;
use tokio::net::TcpListener;

const SEED_CREDENTIAL: &str = "process-transfer-seed-credential";
const EXCHANGED_CREDENTIAL: &str = "process-transfer-registry-credential";
const SEED_AUTHORIZATION: &str = "Bearer process-transfer-seed-credential";
const EXCHANGED_AUTHORIZATION: &str = "Bearer process-transfer-registry-credential";

struct RegistryState {
    origin: String,
    repository: String,
    blobs: Mutex<BTreeMap<String, Vec<u8>>>,
    manifests: Mutex<BTreeMap<String, (String, Vec<u8>)>>,
    uploads: Mutex<BTreeMap<String, Vec<u8>>>,
    events: Mutex<Vec<String>>,
    control_calls: Mutex<Vec<String>>,
    publication_root: Mutex<Option<String>>,
    next_upload: AtomicU64,
    token_requests: AtomicU64,
}

struct TestRegistry {
    state: Arc<RegistryState>,
    authority: String,
    origin: String,
    repository: String,
    task: tokio::task::JoinHandle<()>,
}

impl TestRegistry {
    fn reference(&self, tag: &str) -> String {
        format!("{}/{}:{tag}", self.authority, self.repository)
    }
}

impl Drop for TestRegistry {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn process_pull_then_push_is_checkout_and_nix_independent() {
    let fixture = oci_support::fixture();
    let source = spawn_registry("source", Some(&fixture)).await;
    let destination = spawn_registry("destination", None).await;
    let workspace = tempfile::tempdir().expect("process workspace");
    let home = workspace.path().join("home");
    fs::create_dir(&home).expect("process home");
    assert!(!workspace.path().join("default.nix").exists());

    let source_reference = source.reference("latest");
    let pull = run_aos(
        workspace.path(),
        &home,
        &[
            "--json",
            "--progress",
            "off",
            "--color",
            "never",
            "container",
            "pull",
            &source_reference,
            "--hub",
            &source.origin,
            "--token",
            SEED_CREDENTIAL,
            "--platform",
            "linux/amd64",
            "--output",
            "pulled.oci",
        ],
    );
    let pull_json = successful_json("pull", &pull);
    assert_eq!(pull_json["operation"], "pull");
    assert_output_is_redacted(&pull);

    let pulled = workspace.path().join("pulled.oci");
    assert_eq!(
        fs::read(pulled.join("oci-layout")).expect("pulled layout marker"),
        br#"{"imageLayoutVersion":"1.0.0"}"#
    );
    let verified = verify_layout(
        &pulled,
        Some(&PlatformSelector::parse("linux/amd64").expect("fixture platform")),
    )
    .expect("verify pulled layout");
    assert_eq!(verified.manifest.digest, fixture.manifest_descriptor.digest);
    assert_eq!(verified.layers, vec![fixture.layer_descriptor.clone()]);
    for (digest, expected) in &fixture.blobs {
        let actual = fs::read(pulled.join("blobs/sha256").join(digest.encoded()))
            .expect("pulled fixture blob");
        assert_eq!(&actual, expected, "pulled blob differs for {digest}");
    }
    write_oci_archive(&pulled, &workspace.path().join("pulled.oci.tar"))
        .expect("archive pulled layout for daemon-free push");

    let destination_reference = destination.reference("stable");
    let push = run_aos(
        workspace.path(),
        &home,
        &[
            "--json",
            "--progress",
            "off",
            "--color",
            "never",
            "container",
            "push",
            "pulled.oci.tar",
            &destination_reference,
            "--hub",
            &destination.origin,
            "--token",
            SEED_CREDENTIAL,
            "--platform",
            "linux/amd64",
        ],
    );
    let push_json = successful_json("push", &push);
    assert_eq!(push_json["operation"], "push");
    assert_output_is_redacted(&push);

    assert_eq!(source.state.token_requests.load(Ordering::SeqCst), 1);
    assert_eq!(destination.state.token_requests.load(Ordering::SeqCst), 1);
    let manifests = destination
        .state
        .manifests
        .lock()
        .expect("destination manifests");
    let tagged_index = &manifests.get("stable").expect("stable tag upload").1;
    let published_index_digest = Sha256Digest::digest(tagged_index);
    assert_eq!(
        push_json["index_digest"],
        Value::String(published_index_digest.to_string())
    );
    drop(manifests);

    let events = destination.state.events.lock().expect("destination events");
    let immutable_index = format!("manifest:{published_index_digest}");
    let immutable_position = events
        .iter()
        .position(|event| event == &immutable_index)
        .expect("immutable index upload");
    let tag_position = events
        .iter()
        .position(|event| event == "manifest:stable")
        .expect("mutable tag upload");
    assert!(immutable_position < tag_position, "events: {events:?}");
    assert_eq!(events.last().map(String::as_str), Some("manifest:stable"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn process_publish_finalizes_complete_signed_graph_without_a_data_plane_tag_write() {
    let fixture = oci_support::fixture();
    let release = oci_support::add_signed_release_graph(&fixture);
    let registry = spawn_registry("aos", None).await;
    *registry
        .state
        .publication_root
        .lock()
        .expect("publication root") = Some(release.oci.index.digest.to_string());
    let workspace = tempfile::tempdir().expect("process workspace");
    let home = workspace.path().join("home");
    fs::create_dir(&home).expect("process home");
    let sidecar = workspace.path().join("containers-v1-index.json");
    fs::write(
        &sidecar,
        to_canonical_json(&release).expect("canonical release sidecar"),
    )
    .expect("release sidecar");
    let release_value = serde_json::to_value(&release).expect("release JSON");
    let signature_input = serde_json::json!({
        "schema": "aos.container.signature-input/v1",
        "identity": release_value["identity"].clone(),
        "oci": release_value["oci"].clone(),
        "nix": release_value["nix"].clone(),
        "evidence": {
            "sbom": release_value["evidence"]["sbom"].clone(),
            "source": release_value["evidence"]["source"].clone(),
            "license": release_value["evidence"]["license"].clone(),
            "provenance": release_value["evidence"]["provenance"].clone(),
        },
        "qualification": release_value["qualification"].clone(),
    });
    let signature_input_path = workspace.path().join("signature-input.json");
    fs::write(
        &signature_input_path,
        to_canonical_json(&signature_input).expect("canonical signature input JSON"),
    )
    .expect("signature input");
    let reference = registry.reference("stable");

    let staged = run_aos(
        workspace.path(),
        &home,
        &[
            "--json",
            "--progress",
            "off",
            "--color",
            "never",
            "container",
            "publish",
            "aos",
            &reference,
            "--release",
            sidecar.to_str().expect("sidecar path"),
            "--release-layout",
            fixture.root().to_str().expect("layout path"),
            "--signature-input",
            signature_input_path.to_str().expect("signature input path"),
            "--registry",
            "core",
            "--idempotency-key",
            "process-release-1",
            "--registry-origin",
            &registry.origin,
            "--registry-token",
            SEED_CREDENTIAL,
            "--stage-only",
        ],
    );
    let staged_output = successful_json("publish --stage-only", &staged);
    assert_eq!(staged_output["state"], "staged");
    assert_eq!(
        staged_output["verification"],
        "pending-control-plane-commit"
    );
    assert_eq!(staged_output["tag_updated"], false);
    assert_eq!(staged_output["object_count"], 18);
    assert_output_is_redacted(&staged);
    assert!(
        registry
            .state
            .control_calls
            .lock()
            .expect("stage control calls")
            .is_empty()
    );
    {
        let manifests = registry.state.manifests.lock().expect("staged manifests");
        assert!(manifests.contains_key(&release.oci.index.digest.to_string()));
        assert!(!manifests.contains_key("stable"));
    }

    let publish = run_aos(
        workspace.path(),
        &home,
        &[
            "--json",
            "--progress",
            "off",
            "--color",
            "never",
            "container",
            "publish",
            "aos",
            &reference,
            "--release",
            sidecar.to_str().expect("sidecar path"),
            "--release-layout",
            fixture.root().to_str().expect("layout path"),
            "--signature-input",
            signature_input_path.to_str().expect("signature input path"),
            "--registry",
            "core",
            "--idempotency-key",
            "process-release-1",
            "--registry-origin",
            &registry.origin,
            "--hub",
            &registry.origin,
            "--token",
            SEED_CREDENTIAL,
        ],
    );
    let output = successful_json("publish", &publish);
    assert_eq!(output["operation"], "publish");
    assert_eq!(output["verification"], "verified");
    assert_eq!(output["object_count"], 18);
    assert_eq!(
        output["verified_release_root"],
        release.oci.index.digest.to_string()
    );
    assert_output_is_redacted(&publish);

    assert_eq!(
        *registry.state.control_calls.lock().expect("control calls"),
        [
            "/aos.hub.v1.ContainerService/BeginContainerPublication",
            "/aos.hub.v1.ContainerService/GetContainerPublication",
            "/aos.hub.v1.ContainerService/CommitContainerPublication",
        ]
    );
    let manifests = registry.state.manifests.lock().expect("registry manifests");
    assert!(manifests.contains_key(&release.oci.index.digest.to_string()));
    assert!(!manifests.contains_key("stable"));
}

fn run_aos(directory: &Path, home: &Path, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_aos"))
        .args(arguments)
        .current_dir(directory)
        .env_clear()
        .env("HOME", home)
        .env("PATH", "")
        .output()
        .expect("run process-level aos command")
}

fn successful_json(operation: &str, output: &Output) -> Value {
    if !output.status.success() {
        let stdout = redact(&String::from_utf8_lossy(&output.stdout));
        let stderr = redact(&String::from_utf8_lossy(&output.stderr));
        panic!("container {operation} failed\nstdout: {stdout}\nstderr: {stderr}");
    }
    serde_json::from_slice(&output.stdout).expect("CLI JSON output")
}

fn assert_output_is_redacted(output: &Output) {
    for stream in [&output.stdout, &output.stderr] {
        assert!(
            !stream
                .windows(SEED_CREDENTIAL.len())
                .any(|window| window == SEED_CREDENTIAL.as_bytes()),
            "seed credential appeared in CLI output"
        );
        assert!(
            !stream
                .windows(EXCHANGED_CREDENTIAL.len())
                .any(|window| window == EXCHANGED_CREDENTIAL.as_bytes()),
            "exchanged credential appeared in CLI output"
        );
    }
}

fn redact(value: &str) -> String {
    value
        .replace(SEED_CREDENTIAL, "<redacted>")
        .replace(EXCHANGED_CREDENTIAL, "<redacted>")
}

async fn spawn_registry(repository: &str, fixture: Option<&oci_support::Fixture>) -> TestRegistry {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("registry listener");
    let address = listener.local_addr().expect("registry address");
    let origin = format!("http://{address}/");

    let mut blobs = BTreeMap::new();
    let mut manifests = BTreeMap::new();
    if let Some(fixture) = fixture {
        for (digest, bytes) in &fixture.blobs {
            blobs.insert(digest.to_string(), bytes.clone());
        }
        let index_digest = Sha256Digest::digest(&fixture.index);
        manifests.insert(
            "latest".to_string(),
            (
                MediaType::OciImageIndex.as_str().to_string(),
                fixture.index.clone(),
            ),
        );
        manifests.insert(
            index_digest.to_string(),
            (
                MediaType::OciImageIndex.as_str().to_string(),
                fixture.index.clone(),
            ),
        );
        manifests.insert(
            fixture.manifest_descriptor.digest.to_string(),
            (
                MediaType::OciImageManifest.as_str().to_string(),
                fixture.manifest.clone(),
            ),
        );
    }

    let state = Arc::new(RegistryState {
        origin: origin.clone(),
        repository: repository.to_string(),
        blobs: Mutex::new(blobs),
        manifests: Mutex::new(manifests),
        uploads: Mutex::new(BTreeMap::new()),
        events: Mutex::new(Vec::new()),
        control_calls: Mutex::new(Vec::new()),
        publication_root: Mutex::new(None),
        next_upload: AtomicU64::new(1),
        token_requests: AtomicU64::new(0),
    });
    let router = Router::new()
        .fallback(any(handle_registry_request))
        .with_state(state.clone());
    let task = tokio::spawn(async move {
        axum::serve(listener, router)
            .await
            .expect("registry server");
    });
    TestRegistry {
        state,
        authority: address.to_string(),
        origin,
        repository: repository.to_string(),
        task,
    }
}

async fn handle_registry_request(
    State(state): State<Arc<RegistryState>>,
    request: Request<Body>,
) -> Response<Body> {
    let (parts, body) = request.into_parts();
    let body = axum::body::to_bytes(body, 16 * 1024 * 1024)
        .await
        .expect("registry request body");
    let path = parts.uri.path();
    if path.starts_with("/aos.hub.v1.ContainerService/") {
        return container_control_response(&state, path, &parts.headers, body);
    }
    if path == "/token" {
        return token_response(&state, &parts.headers);
    }
    if !authorized(&parts.headers) {
        return challenge(&state);
    }
    state
        .events
        .lock()
        .expect("registry events")
        .push(format!("{}:{path}", parts.method));

    let manifests = format!("/v2/{}/manifests/", state.repository);
    if let Some(reference) = path.strip_prefix(&manifests) {
        return manifest_response(&state, &parts.method, reference, &parts.headers, body);
    }
    let blobs = format!("/v2/{}/blobs/", state.repository);
    if let Some(digest) = path.strip_prefix(&blobs)
        && !digest.starts_with("uploads/")
    {
        return blob_response(&state, &parts.method, digest);
    }
    let uploads = format!("/v2/{}/blobs/uploads/", state.repository);
    if path == uploads && parts.method == Method::POST {
        return start_upload(&state);
    }
    if let Some(identifier) = path.strip_prefix(&uploads) {
        return upload_response(&state, &parts.method, identifier, &parts.uri, body);
    }
    response(StatusCode::NOT_FOUND, Body::empty())
}

fn container_control_response(
    state: &RegistryState,
    path: &str,
    headers: &HeaderMap,
    body: Bytes,
) -> Response<Body> {
    assert_eq!(
        headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok()),
        Some(SEED_AUTHORIZATION)
    );
    assert_eq!(
        headers
            .get("connect-protocol-version")
            .and_then(|value| value.to_str().ok()),
        Some("1")
    );
    let request: Value = serde_json::from_slice(&body).expect("container control request");
    if path.ends_with("/BeginContainerPublication") {
        assert_eq!(request["registry"], "core");
        assert_eq!(request["repository"], "aos");
        assert_eq!(request["targetTag"], "stable");
        assert_eq!(request["idempotencyKey"], "process-release-1");
        assert!(request["containerReleaseJson"].is_string());
    } else if path.ends_with("/CommitContainerPublication") {
        assert_eq!(request["expectedResourceVersion"], "2");
        assert_eq!(request["idempotencyKey"], "process-release-1:commit");
    }
    state
        .control_calls
        .lock()
        .expect("control calls")
        .push(path.to_string());

    let ready = path.ends_with("/CommitContainerPublication");
    let root = state
        .publication_root
        .lock()
        .expect("publication root")
        .clone()
        .expect("configured publication root");
    let value = serde_json::json!({
        "publicationId": "publication-1",
        "registry": "core",
        "repository": "aos",
        "rootDigest": root,
        "catalogDigest": Sha256Digest::digest(b"catalog").to_string(),
        "topologyDigest": Sha256Digest::digest(b"topology").to_string(),
        "requiredPlacementCount": "1",
        "sourceKind": "channel",
        "state": if ready { "ready" } else { "preparing" },
        "targetTag": "stable",
        "resourceVersion": if ready { "3" } else { "2" },
        "expiresAt": "1800000000",
        "createdAt": "1700000000",
        "committedAt": if ready { "1700000001" } else { "0" },
        "confirmationHash": Sha256Digest::digest(b"confirmation").to_string(),
        "verifiedReleaseRoot": if ready { root } else { String::new() },
    });
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&value).expect("container control response"),
        ))
        .expect("container control response")
}

fn authorized(headers: &HeaderMap) -> bool {
    headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        == Some(EXCHANGED_AUTHORIZATION)
}

fn challenge(state: &RegistryState) -> Response<Body> {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(
            WWW_AUTHENTICATE,
            format!(
                "Bearer realm=\"{}token\",service=\"aos-test\"",
                state.origin
            ),
        )
        .body(Body::empty())
        .expect("registry challenge")
}

fn token_response(state: &RegistryState, headers: &HeaderMap) -> Response<Body> {
    state.token_requests.fetch_add(1, Ordering::SeqCst);
    let authorization = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    assert!(authorization.is_none() || authorization == Some(SEED_AUTHORIZATION));
    response(
        StatusCode::OK,
        Body::from(format!(r#"{{"token":"{EXCHANGED_CREDENTIAL}"}}"#)),
    )
}

fn manifest_response(
    state: &RegistryState,
    method: &Method,
    reference: &str,
    headers: &HeaderMap,
    body: Bytes,
) -> Response<Body> {
    if method == Method::GET || method == Method::HEAD {
        let manifests = state.manifests.lock().expect("registry manifests");
        let Some((media_type, bytes)) = manifests.get(reference) else {
            return response(StatusCode::NOT_FOUND, Body::empty());
        };
        return Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, media_type)
            .header(
                "docker-content-digest",
                Sha256Digest::digest(bytes).to_string(),
            )
            .body(if method == Method::HEAD {
                Body::empty()
            } else {
                Body::from(bytes.clone())
            })
            .expect("manifest response");
    }
    if method == Method::PUT {
        let media_type = headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .expect("manifest content type")
            .to_string();
        state
            .manifests
            .lock()
            .expect("registry manifests")
            .insert(reference.to_string(), (media_type, body.to_vec()));
        state
            .events
            .lock()
            .expect("registry events")
            .push(format!("manifest:{reference}"));
        return response(StatusCode::CREATED, Body::empty());
    }
    response(StatusCode::METHOD_NOT_ALLOWED, Body::empty())
}

fn blob_response(state: &RegistryState, method: &Method, digest: &str) -> Response<Body> {
    let blobs = state.blobs.lock().expect("registry blobs");
    let Some(bytes) = blobs.get(digest) else {
        return response(StatusCode::NOT_FOUND, Body::empty());
    };
    if method == Method::HEAD {
        return Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_LENGTH, bytes.len())
            .header("docker-content-digest", digest)
            .body(Body::empty())
            .expect("blob HEAD response");
    }
    if method == Method::GET {
        return response(StatusCode::OK, Body::from(bytes.clone()));
    }
    response(StatusCode::METHOD_NOT_ALLOWED, Body::empty())
}

fn start_upload(state: &RegistryState) -> Response<Body> {
    let identifier = state.next_upload.fetch_add(1, Ordering::SeqCst).to_string();
    state
        .uploads
        .lock()
        .expect("registry uploads")
        .insert(identifier.clone(), Vec::new());
    Response::builder()
        .status(StatusCode::ACCEPTED)
        .header(
            LOCATION,
            format!("/v2/{}/blobs/uploads/{identifier}", state.repository),
        )
        .body(Body::empty())
        .expect("start upload response")
}

fn upload_response(
    state: &RegistryState,
    method: &Method,
    identifier: &str,
    uri: &Uri,
    body: Bytes,
) -> Response<Body> {
    let location = format!("/v2/{}/blobs/uploads/{identifier}", state.repository);
    if method == Method::GET {
        let uploads = state.uploads.lock().expect("registry uploads");
        let Some(bytes) = uploads.get(identifier) else {
            return response(StatusCode::NOT_FOUND, Body::empty());
        };
        let mut builder = Response::builder()
            .status(StatusCode::NO_CONTENT)
            .header(LOCATION, &location);
        if !bytes.is_empty() {
            builder = builder.header(RANGE, format!("0-{}", bytes.len() - 1));
        }
        return builder.body(Body::empty()).expect("upload query response");
    }
    if method == Method::PATCH {
        let mut uploads = state.uploads.lock().expect("registry uploads");
        let bytes = uploads.get_mut(identifier).expect("upload session");
        bytes.extend_from_slice(&body);
        return Response::builder()
            .status(StatusCode::ACCEPTED)
            .header(LOCATION, &location)
            .header(RANGE, format!("0-{}", bytes.len() - 1))
            .body(Body::empty())
            .expect("upload patch response");
    }
    if method == Method::PUT {
        let digest = uri
            .query()
            .into_iter()
            .flat_map(|query| url::form_urlencoded::parse(query.as_bytes()))
            .find_map(|(key, value)| (key == "digest").then(|| value.into_owned()))
            .expect("final upload digest");
        let mut bytes = state
            .uploads
            .lock()
            .expect("registry uploads")
            .remove(identifier)
            .expect("upload session");
        bytes.extend_from_slice(&body);
        assert_eq!(Sha256Digest::digest(&bytes).to_string(), digest);
        state
            .blobs
            .lock()
            .expect("registry blobs")
            .insert(digest.clone(), bytes);
        return Response::builder()
            .status(StatusCode::CREATED)
            .header("docker-content-digest", digest)
            .body(Body::empty())
            .expect("finish upload response");
    }
    response(StatusCode::METHOD_NOT_ALLOWED, Body::empty())
}

fn response(status: StatusCode, body: Body) -> Response<Body> {
    Response::builder()
        .status(status)
        .body(body)
        .expect("test registry response")
}
