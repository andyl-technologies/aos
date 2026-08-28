//! Loopback OCI Distribution fixtures for resumability and ordering.

#![allow(clippy::expect_used)]

mod support;

use std::collections::BTreeMap;
use std::fs;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use aos_oci::{PlatformSelector, PullOptions, PushOptions, RegistryClient, RegistryReference};
use aos_oci_types::{
    Annotations, Descriptor, ImageIndex, MediaType, Platform, Sha256Digest, to_canonical_json,
};
use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::header::{
    AUTHORIZATION, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, LOCATION, RANGE, WWW_AUTHENTICATE,
};
use axum::http::{HeaderMap, Method, Request, Response, StatusCode, Uri};
use axum::routing::any;
use tokio::net::TcpListener;
use tokio::sync::{Notify, mpsc};
use tokio_util::sync::CancellationToken;

struct RegistryState {
    base: String,
    blobs: Mutex<BTreeMap<String, Vec<u8>>>,
    manifests: Mutex<BTreeMap<String, (String, Vec<u8>)>>,
    mount_sources: Mutex<BTreeMap<(String, String), Vec<u8>>>,
    uploads: Mutex<BTreeMap<String, Vec<u8>>>,
    events: Mutex<Vec<String>>,
    next_upload: AtomicU64,
    interrupt_blob_once: AtomicBool,
    stall_blob_once: AtomicBool,
    fail_patch_once: AtomicBool,
    fail_cancel_once: AtomicBool,
    stall_patch_once: AtomicBool,
    invalid_ack_once: AtomicBool,
    delay_tag_once: AtomicBool,
    tag_started: Notify,
    fail_token: AtomicBool,
    reject_registry_token_once: AtomicBool,
    token_requests: AtomicU64,
    token_scopes: Mutex<Vec<Vec<String>>>,
    challenge_scope: Mutex<Option<String>>,
}

struct TestRegistry {
    state: Arc<RegistryState>,
    reference: RegistryReference,
    origin: String,
    task: tokio::task::JoinHandle<()>,
}

#[tokio::test]
async fn signed_release_push_uploads_every_evidence_object_by_digest_only() {
    let fixture = support::fixture();
    let release = support::add_signed_release_graph(&fixture);
    let registry = spawn_registry(None, false, false, false).await;
    let reference = RegistryReference::parse(&format!(
        "{}/aos@{}",
        registry.reference.authority(),
        release.oci.index.digest
    ))
    .expect("immutable release reference");
    let client =
        RegistryClient::new(&reference, Some(&registry.origin), None).expect("registry client");
    let options = PushOptions {
        source: fixture.root().to_path_buf(),
        platform: PlatformSelector::native(),
        state_directory: tempfile::tempdir()
            .expect("state parent")
            .path()
            .join("state"),
        chunk_bytes: 17,
        cancellation: CancellationToken::new(),
        events: None,
    };

    let pushed = client
        .push_release_graph(&reference, &options, &release, &[])
        .await
        .expect("complete signed graph push");
    assert_eq!(pushed.root_index_digest, release.oci.index.digest);
    assert_eq!(pushed.object_count, 18);

    let manifests = registry.state.manifests.lock().expect("manifest lock");
    for descriptor in [
        &release.oci.index,
        &release.oci.platform_manifests[0],
        &release.nix.closure,
        &release.evidence.sbom,
        &release.evidence.source,
        &release.evidence.license,
        &release.evidence.provenance,
        &release.evidence.signature,
    ] {
        assert!(
            manifests.contains_key(&descriptor.digest.to_string()),
            "missing document {}",
            descriptor.digest
        );
    }
    assert!(!manifests.contains_key("latest"));
    assert!(!manifests.contains_key("stable"));
}

impl Drop for TestRegistry {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test]
async fn interrupted_pull_resumes_by_range_and_verifies_the_layout() {
    let fixture = support::fixture();
    let registry = spawn_registry(Some(&fixture), true, false, false).await;
    let client = RegistryClient::new(
        &registry.reference,
        Some(&registry.origin),
        Some("hub-seed-secret".to_string()),
    )
    .expect("registry client");
    let destination = tempfile::tempdir()
        .expect("pull parent")
        .path()
        .join("layout");
    let (event_sender, mut event_receiver) = mpsc::unbounded_channel();
    let options = PullOptions {
        destination: destination.clone(),
        platform: PlatformSelector::parse("linux/amd64").expect("platform"),
        cancellation: CancellationToken::new(),
        events: Some(event_sender),
    };

    let error = client
        .pull(&registry.reference, &options)
        .await
        .expect_err("first response is deliberately truncated");
    assert!(error.to_string().contains("ended before descriptor size"));
    assert!(
        fs::read_dir(destination.join("blobs/sha256"))
            .expect("partial directory")
            .any(|entry| entry
                .expect("partial entry")
                .path()
                .extension()
                .is_some_and(|ext| ext == "partial"))
    );

    let verified = client
        .pull(&registry.reference, &options)
        .await
        .expect("resumed pull");
    assert_eq!(verified.layers.len(), 1);
    let registry_events = registry.state.events.lock().expect("event lock");
    assert!(
        registry_events
            .iter()
            .any(|event| event.starts_with("range:"))
    );
    assert_eq!(registry.state.token_requests.load(Ordering::SeqCst), 1);
    drop(registry_events);
    drop(options);
    assert!(
        std::iter::from_fn(|| event_receiver.try_recv().ok())
            .any(|event| { matches!(event, aos_oci::TransferEvent::Downloading { .. }) })
    );
}

#[tokio::test]
async fn pull_state_refuses_unowned_directories() {
    let fixture = support::fixture();
    let registry = spawn_registry(Some(&fixture), false, false, false).await;
    let client = RegistryClient::new(&registry.reference, Some(&registry.origin), None)
        .expect("registry client");
    let destination = tempfile::tempdir().expect("unowned destination");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(destination.path(), fs::Permissions::from_mode(0o755))
            .expect("unowned mode fixture");
    }
    fs::write(destination.path().join("sentinel"), b"keep").expect("sentinel");
    let options = PullOptions::native(destination.path().to_path_buf());
    client
        .pull(&registry.reference, &options)
        .await
        .expect_err("unowned directory must be refused");
    assert_eq!(
        fs::read(destination.path().join("sentinel")).expect("preserved sentinel"),
        b"keep"
    );
    assert!(!destination.path().join("blobs").exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            fs::metadata(destination.path())
                .expect("unowned metadata")
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
    }
    assert!(registry.state.events.lock().expect("event lock").is_empty());
}

#[cfg(unix)]
#[tokio::test]
async fn pull_state_refuses_directory_symlinks_and_partial_hardlinks() {
    let fixture = support::fixture();
    let registry = spawn_registry(Some(&fixture), true, false, false).await;
    let client = RegistryClient::new(&registry.reference, Some(&registry.origin), None)
        .expect("registry client");

    let symlink_parent = tempfile::tempdir().expect("symlink parent");
    let target = symlink_parent.path().join("target");
    fs::create_dir(&target).expect("symlink target");
    let destination = symlink_parent.path().join("state");
    std::os::unix::fs::symlink(&target, &destination).expect("state symlink");
    client
        .pull(
            &registry.reference,
            &PullOptions::native(destination.clone()),
        )
        .await
        .expect_err("state symlink must be refused");

    fs::remove_file(&destination).expect("remove state symlink");
    let options = PullOptions::native(destination.clone());
    client
        .pull(&registry.reference, &options)
        .await
        .expect_err("truncated first pull");
    let partial = fs::read_dir(destination.join("blobs/sha256"))
        .expect("partial directory")
        .map(|entry| entry.expect("partial entry").path())
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "partial")
        })
        .expect("partial blob");
    fs::hard_link(&partial, symlink_parent.path().join("external-partial"))
        .expect("hardlink partial");
    let error = client
        .pull(&registry.reference, &options)
        .await
        .expect_err("hardlinked partial must be refused");
    assert!(format!("{error:#}").contains("hard-linked"));
}

#[tokio::test]
async fn cancellation_is_observed_before_network_or_pointer_effects() {
    let fixture = support::fixture();
    let registry = spawn_registry(Some(&fixture), false, false, false).await;
    let client = RegistryClient::new(&registry.reference, Some(&registry.origin), None)
        .expect("registry client");
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let options = PullOptions {
        destination: tempfile::tempdir()
            .expect("pull root")
            .path()
            .join("layout"),
        platform: PlatformSelector::parse("linux/amd64").expect("platform"),
        cancellation,
        events: None,
    };
    let error = client
        .pull(&registry.reference, &options)
        .await
        .expect_err("cancelled pull");
    assert!(error.to_string().contains("cancelled"));
    assert!(registry.state.events.lock().expect("event lock").is_empty());
}

#[tokio::test]
async fn manifest_redirect_does_not_forward_credentials_or_follow_the_body() {
    let sink_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("redirect sink listener");
    let sink_address = sink_listener.local_addr().expect("redirect sink address");
    let sink_requests = Arc::new(AtomicU64::new(0));
    let sink_router = Router::new()
        .fallback(any(record_redirect_sink))
        .with_state(sink_requests.clone());
    let sink_task = tokio::spawn(async move {
        axum::serve(sink_listener, sink_router)
            .await
            .expect("redirect sink");
    });

    let registry_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("redirect registry listener");
    let registry_address = registry_listener
        .local_addr()
        .expect("redirect registry address");
    let redirect = format!("http://{sink_address}/credential-sink");
    let registry_router = Router::new()
        .fallback(any(redirect_every_request))
        .with_state(redirect);
    let registry_task = tokio::spawn(async move {
        axum::serve(registry_listener, registry_router)
            .await
            .expect("redirect registry");
    });

    let reference = RegistryReference::parse(&format!("{registry_address}/aos:latest"))
        .expect("redirect reference");
    let client = RegistryClient::new(
        &reference,
        Some(&format!("http://{registry_address}/")),
        Some("credential-that-must-not-be-forwarded".to_string()),
    )
    .expect("redirect client");
    let options = PullOptions::native(
        tempfile::tempdir()
            .expect("redirect output")
            .path()
            .join("layout"),
    );
    client
        .pull(&reference, &options)
        .await
        .expect_err("manifest redirect must be refused");
    assert_eq!(sink_requests.load(Ordering::SeqCst), 0);
    registry_task.abort();
    sink_task.abort();
}

#[tokio::test]
async fn upload_redirect_does_not_forward_credentials_or_chunk_bodies() {
    let fixture = support::fixture();
    let sink_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upload redirect sink listener");
    let sink_address = sink_listener.local_addr().expect("upload sink address");
    let sink_requests = Arc::new(AtomicU64::new(0));
    let sink_router = Router::new()
        .fallback(any(record_redirect_sink))
        .with_state(sink_requests.clone());
    let sink_task = tokio::spawn(async move {
        axum::serve(sink_listener, sink_router)
            .await
            .expect("upload redirect sink");
    });

    let registry_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upload redirect registry listener");
    let registry_address = registry_listener
        .local_addr()
        .expect("upload redirect registry address");
    let redirect = format!("http://{sink_address}/credential-and-body-sink");
    let registry_router = Router::new()
        .fallback(any(redirect_upload_chunk))
        .with_state(redirect);
    let registry_task = tokio::spawn(async move {
        axum::serve(registry_listener, registry_router)
            .await
            .expect("upload redirect registry");
    });

    let reference = RegistryReference::parse(&format!("{registry_address}/aos:latest"))
        .expect("upload redirect reference");
    let client = RegistryClient::new(
        &reference,
        Some(&format!("http://{registry_address}/")),
        Some("credential-that-must-not-be-forwarded".to_string()),
    )
    .expect("upload redirect client");
    let state_parent = tempfile::tempdir().expect("upload redirect state");
    let options = PushOptions {
        source: fixture.root().to_path_buf(),
        platform: PlatformSelector::parse("linux/amd64").expect("platform"),
        state_directory: state_parent.path().join("uploads"),
        chunk_bytes: 11,
        cancellation: CancellationToken::new(),
        events: None,
    };
    let error = client
        .push(&reference, &options)
        .await
        .expect_err("cross-origin upload redirect must be refused");
    assert!(format!("{error:#}").contains("HTTP 307"));
    assert_eq!(sink_requests.load(Ordering::SeqCst), 0);
    registry_task.abort();
    sink_task.abort();
}

#[tokio::test]
async fn in_flight_manifest_wait_is_cancellable_and_clients_are_authority_bound() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("stall listener");
    let address = listener.local_addr().expect("stall address");
    let router = Router::new().fallback(any(stall_forever));
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.expect("stall server");
    });
    let reference =
        RegistryReference::parse(&format!("{address}/aos:latest")).expect("stall reference");
    let client = RegistryClient::new(
        &reference,
        Some(&format!("http://{address}/")),
        Some("token".to_string()),
    )
    .expect("stall client");
    let cancellation = CancellationToken::new();
    let cancel = cancellation.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        cancel.cancel();
    });
    let options = PullOptions {
        destination: tempfile::tempdir()
            .expect("stall output")
            .path()
            .join("layout"),
        platform: PlatformSelector::parse("linux/amd64").expect("platform"),
        cancellation,
        events: None,
    };
    let error = client
        .pull(&reference, &options)
        .await
        .expect_err("stalled manifest cancellation");
    assert!(format!("{error:#}").contains("cancelled"));

    let other = RegistryReference::parse("127.0.0.1:9/aos:latest").expect("other authority");
    let error = client
        .pull(&other, &PullOptions::native(options.destination.clone()))
        .await
        .expect_err("authority mismatch");
    assert!(format!("{error:#}").contains("different reference authority"));
    task.abort();
}

#[tokio::test]
async fn in_flight_blob_and_upload_waits_are_cancellable() {
    let fixture = support::fixture();
    let pull_registry = spawn_registry(Some(&fixture), false, false, false).await;
    pull_registry
        .state
        .stall_blob_once
        .store(true, Ordering::SeqCst);
    let pull_client =
        RegistryClient::new(&pull_registry.reference, Some(&pull_registry.origin), None)
            .expect("pull client");
    let pull_cancellation = CancellationToken::new();
    let cancel = pull_cancellation.clone();
    let pull_state = pull_registry.state.clone();
    tokio::spawn(async move {
        loop {
            if pull_state
                .events
                .lock()
                .expect("pull events")
                .iter()
                .any(|event| event.starts_with("GET:/v2/aos/blobs/"))
            {
                cancel.cancel();
                break;
            }
            tokio::task::yield_now().await;
        }
    });
    let pull_options = PullOptions {
        destination: tempfile::tempdir()
            .expect("pull parent")
            .path()
            .join("layout"),
        platform: PlatformSelector::parse("linux/amd64").expect("platform"),
        cancellation: pull_cancellation,
        events: None,
    };
    let error = pull_client
        .pull(&pull_registry.reference, &pull_options)
        .await
        .expect_err("stalled blob cancellation");
    assert!(format!("{error:#}").contains("cancelled"));

    let push_registry = spawn_registry(None, false, false, false).await;
    push_registry
        .state
        .stall_patch_once
        .store(true, Ordering::SeqCst);
    let push_client =
        RegistryClient::new(&push_registry.reference, Some(&push_registry.origin), None)
            .expect("push client");
    let push_cancellation = CancellationToken::new();
    let cancel = push_cancellation.clone();
    let push_state = push_registry.state.clone();
    tokio::spawn(async move {
        loop {
            if push_state
                .events
                .lock()
                .expect("push events")
                .iter()
                .any(|event| event.starts_with("PATCH:/v2/aos/blobs/uploads/"))
            {
                cancel.cancel();
                break;
            }
            tokio::task::yield_now().await;
        }
    });
    let state_parent = tempfile::tempdir().expect("upload state parent");
    let push_options = PushOptions {
        source: fixture.root().to_path_buf(),
        platform: PlatformSelector::parse("linux/amd64").expect("platform"),
        state_directory: state_parent.path().join("uploads"),
        chunk_bytes: 11,
        cancellation: push_cancellation,
        events: None,
    };
    let error = push_client
        .push(&push_registry.reference, &push_options)
        .await
        .expect_err("stalled upload cancellation");
    assert!(format!("{error:#}").contains("cancelled"));

    let resumed = PushOptions {
        source: push_options.source.clone(),
        platform: push_options.platform.clone(),
        state_directory: push_options.state_directory.clone(),
        chunk_bytes: push_options.chunk_bytes,
        cancellation: CancellationToken::new(),
        events: None,
    };
    push_client
        .push(&push_registry.reference, &resumed)
        .await
        .expect("resume zero-byte live upload");
    assert!(
        push_registry
            .state
            .events
            .lock()
            .expect("push events")
            .iter()
            .any(|event| event == "upload-query:0")
    );
}

#[tokio::test]
async fn oversized_manifest_bodies_are_rejected_before_buffering() {
    let fixture = support::fixture();
    let registry = spawn_registry(Some(&fixture), false, false, false).await;
    registry
        .state
        .manifests
        .lock()
        .expect("manifest lock")
        .insert(
            "latest".to_string(),
            (
                MediaType::OciImageIndex.as_str().to_string(),
                vec![b' '; aos_oci_types::limits::MAX_JSON_BYTES + 1],
            ),
        );
    let client = RegistryClient::new(&registry.reference, Some(&registry.origin), None)
        .expect("registry client");
    let options = PullOptions::native(
        tempfile::tempdir()
            .expect("pull parent")
            .path()
            .join("layout"),
    );
    let error = client
        .pull(&registry.reference, &options)
        .await
        .expect_err("oversized manifest");
    assert!(format!("{error:#}").contains("oversized"));
}

#[tokio::test]
async fn interrupted_push_resumes_and_updates_the_tag_last() {
    let fixture = support::fixture();
    let registry = spawn_registry(None, false, true, false).await;
    let client = RegistryClient::new(
        &registry.reference,
        Some(&registry.origin),
        Some("hub-seed-secret".to_string()),
    )
    .expect("registry client");
    let state_directory = tempfile::tempdir().expect("upload state");
    let upload_state = state_directory.path().join("uploads");
    let options = PushOptions {
        source: fixture.root().to_path_buf(),
        platform: PlatformSelector::parse("linux/amd64").expect("platform"),
        state_directory: upload_state,
        chunk_bytes: 11,
        cancellation: CancellationToken::new(),
        events: None,
    };

    client
        .push(&registry.reference, &options)
        .await
        .expect_err("first PATCH fails after retaining bytes");
    assert!(
        !registry
            .state
            .events
            .lock()
            .expect("event lock")
            .iter()
            .any(|event| event == "manifest:latest")
    );

    let published = client
        .push(&registry.reference, &options)
        .await
        .expect("resumed push");
    let events = registry.state.events.lock().expect("event lock");
    assert!(
        events
            .iter()
            .any(|event| event.starts_with("upload-query:"))
    );
    assert!(
        events
            .iter()
            .any(|event| event.starts_with("upload-hint:sha256:") && event.contains(":size="))
    );
    assert_eq!(events.last().map(String::as_str), Some("manifest:latest"));
    let digest_event = format!("manifest:{}", published.published_index_digest);
    let digest_position = events
        .iter()
        .position(|event| event == &digest_event)
        .expect("immutable index PUT");
    let tag_position = events
        .iter()
        .position(|event| event == "manifest:latest")
        .expect("tag PUT");
    assert!(digest_position < tag_position);
    let tagged = registry
        .state
        .manifests
        .lock()
        .expect("manifest lock")
        .get("latest")
        .expect("tagged index")
        .1
        .clone();
    assert_eq!(
        Sha256Digest::digest(&tagged),
        published.published_index_digest
    );
}

#[tokio::test]
async fn duplicate_blobs_are_reused_and_cross_repository_mounts_use_both_grants() {
    let fixture = support::fixture();
    let registry = spawn_registry(None, false, false, false).await;
    {
        let mut sources = registry
            .state
            .mount_sources
            .lock()
            .expect("mount source lock");
        for (digest, bytes) in &fixture.blobs {
            if digest != &fixture.manifest_descriptor.digest {
                sources.insert(("base".to_string(), digest.to_string()), bytes.clone());
            }
        }
    }
    let client = RegistryClient::new(
        &registry.reference,
        Some(&registry.origin),
        Some("hub-seed-secret".to_string()),
    )
    .expect("registry client");
    let state_directory = tempfile::tempdir().expect("upload state");
    let options = PushOptions {
        source: fixture.root().to_path_buf(),
        platform: PlatformSelector::parse("linux/amd64").expect("platform"),
        state_directory: state_directory.path().join("uploads"),
        chunk_bytes: 11,
        cancellation: CancellationToken::new(),
        events: None,
    };
    let source = aos_oci_types::RepositoryName::parse("base").expect("source repository");

    client
        .push_with_mounts(&registry.reference, &options, &[source])
        .await
        .expect("mounted push");
    let source = aos_oci_types::RepositoryName::parse("base").expect("source repository");
    client
        .push_with_mounts(&registry.reference, &options, &[source])
        .await
        .expect("duplicate-reuse push");

    let events = registry.state.events.lock().expect("events");
    assert_eq!(
        events
            .iter()
            .filter(|event| event.starts_with("mount:base:"))
            .count(),
        2,
        "events: {events:?}"
    );
    assert!(
        events
            .iter()
            .filter(|event| event.starts_with("mount:base:"))
            .all(|event| !event.ends_with("size=missing")),
        "events: {events:?}"
    );
    assert!(
        !events
            .iter()
            .any(|event| event.starts_with("PATCH:/v2/aos/blobs/uploads/")),
        "events: {events:?}"
    );
    drop(events);

    let scopes = registry.state.token_scopes.lock().expect("token scopes");
    assert!(scopes.iter().any(|scopes| {
        scopes
            == &[
                "repository:aos:pull,push".to_string(),
                "repository:base:pull".to_string(),
            ]
    }));
}

#[tokio::test]
async fn exact_noncanonical_manifest_and_index_bytes_are_preserved() {
    let fixture = support::fixture();
    let source_index = serde_json::to_vec_pretty(
        &serde_json::from_slice::<serde_json::Value>(&fixture.index).expect("fixture index JSON"),
    )
    .expect("pretty index");
    fs::write(fixture.root().join("index.json"), &source_index).expect("replace exact index");

    let registry = spawn_registry(None, false, false, false).await;
    let client = RegistryClient::new(&registry.reference, Some(&registry.origin), None)
        .expect("registry client");
    let state_directory = tempfile::tempdir().expect("upload state");
    let options = PushOptions {
        source: fixture.root().to_path_buf(),
        platform: PlatformSelector::parse("linux/amd64").expect("platform"),
        state_directory: state_directory.path().join("uploads"),
        chunk_bytes: 1024,
        cancellation: CancellationToken::new(),
        events: None,
    };
    client
        .push(&registry.reference, &options)
        .await
        .expect("exact push");

    let manifests = registry.state.manifests.lock().expect("manifests");
    assert_eq!(
        &manifests.get("latest").expect("tagged exact index").1,
        &source_index
    );
    assert_eq!(
        &manifests
            .get(&fixture.manifest_descriptor.digest.to_string())
            .expect("exact child manifest")
            .1,
        &fixture.manifest
    );
}

#[tokio::test]
async fn multi_platform_push_publishes_only_the_selected_closed_graph() {
    let fixture = support::fixture();
    let mut index = ImageIndex::from_json(&fixture.index).expect("fixture index");
    let unselected_digest = Sha256Digest::digest(b"unselected-arm64-manifest");
    index.manifests.push(Descriptor {
        media_type: MediaType::OciImageManifest,
        digest: unselected_digest,
        size: 4096,
        urls: Vec::new(),
        annotations: Annotations::new(),
        data: None,
        artifact_type: None,
        platform: Some(Platform {
            architecture: "arm64".to_string(),
            os: "linux".to_string(),
            os_version: None,
            os_features: Vec::new(),
            variant: None,
            features: Vec::new(),
        }),
    });
    index.validate().expect("multi-platform fixture index");
    fs::write(
        fixture.root().join("index.json"),
        to_canonical_json(&index).expect("multi-platform fixture JSON"),
    )
    .expect("multi-platform index");

    let registry = spawn_registry(None, false, false, false).await;
    let client = RegistryClient::new(&registry.reference, Some(&registry.origin), None)
        .expect("registry client");
    let state_directory = tempfile::tempdir().expect("upload state");
    let options = PushOptions {
        source: fixture.root().to_path_buf(),
        platform: PlatformSelector::parse("linux/amd64").expect("platform"),
        state_directory: state_directory.path().join("uploads"),
        chunk_bytes: 1024,
        cancellation: CancellationToken::new(),
        events: None,
    };
    client
        .push(&registry.reference, &options)
        .await
        .expect("selected-platform push");

    let manifests = registry.state.manifests.lock().expect("manifests");
    let selected = ImageIndex::from_json(&manifests.get("latest").expect("tagged index").1)
        .expect("selected index");
    assert_eq!(selected.manifests.len(), 1);
    assert_eq!(
        selected.manifests[0].platform.as_ref(),
        Some(&Platform::linux_amd64())
    );
    assert!(
        !registry
            .state
            .events
            .lock()
            .expect("events")
            .iter()
            .any(|event| event.contains(&unselected_digest.to_string()))
    );
}

#[tokio::test]
async fn digest_delete_and_upload_cancellation_retries_transient_unavailability() {
    let fixture = support::fixture();
    let registry = spawn_registry(None, false, true, false).await;
    let client = RegistryClient::new(&registry.reference, Some(&registry.origin), None)
        .expect("registry client");
    let state_directory = tempfile::tempdir().expect("upload state");
    let upload_state = state_directory.path().join("uploads");
    let options = PushOptions {
        source: fixture.root().to_path_buf(),
        platform: PlatformSelector::parse("linux/amd64").expect("platform"),
        state_directory: upload_state.clone(),
        chunk_bytes: 11,
        cancellation: CancellationToken::new(),
        events: None,
    };
    client
        .push(&registry.reference, &options)
        .await
        .expect_err("interrupted upload fixture");
    registry
        .state
        .fail_cancel_once
        .store(true, Ordering::SeqCst);
    assert_eq!(
        client
            .cancel_uploads(
                &registry.reference,
                &upload_state,
                &CancellationToken::new()
            )
            .await
            .expect("cancel upload"),
        1
    );
    assert_eq!(
        client
            .cancel_uploads(
                &registry.reference,
                &upload_state,
                &CancellationToken::new()
            )
            .await
            .expect("idempotent cancellation"),
        0
    );
    assert_eq!(
        registry
            .state
            .events
            .lock()
            .expect("events")
            .iter()
            .filter(|event| event.starts_with("DELETE:/v2/aos/blobs/uploads/"))
            .count(),
        2
    );

    client
        .delete_manifest(&registry.reference, &CancellationToken::new())
        .await
        .expect_err("tag deletion is forbidden");
    let digest = Sha256Digest::digest(b"delete-me");
    registry.state.manifests.lock().expect("manifests").insert(
        digest.to_string(),
        (
            MediaType::OciImageIndex.as_str().to_string(),
            b"delete-me".to_vec(),
        ),
    );
    let digest_reference =
        RegistryReference::parse(&format!("{}/aos@{digest}", registry.reference.authority()))
            .expect("digest reference");
    client
        .delete_manifest(&digest_reference, &CancellationToken::new())
        .await
        .expect("delete digest");
    assert!(
        !registry
            .state
            .manifests
            .lock()
            .expect("manifests")
            .contains_key(&digest.to_string())
    );
}

#[tokio::test]
async fn tag_commit_reports_a_definitive_result_after_cancellation() {
    let fixture = support::fixture();
    let registry = spawn_registry(None, false, false, false).await;
    registry.state.delay_tag_once.store(true, Ordering::SeqCst);
    let client = RegistryClient::new(&registry.reference, Some(&registry.origin), None)
        .expect("registry client");
    let state_parent = tempfile::tempdir().expect("upload state parent");
    let options = PushOptions {
        source: fixture.root().to_path_buf(),
        platform: PlatformSelector::parse("linux/amd64").expect("platform"),
        state_directory: state_parent.path().join("uploads"),
        chunk_bytes: 1024,
        cancellation: CancellationToken::new(),
        events: None,
    };
    let cancellation = options.cancellation.clone();
    let pushed_client = client.clone();
    let pushed_reference = registry.reference.clone();
    let task = tokio::spawn(async move { pushed_client.push(&pushed_reference, &options).await });

    registry.state.tag_started.notified().await;
    cancellation.cancel();
    let published = task.await.expect("push task").expect("tag commit outcome");
    let tagged = registry
        .state
        .manifests
        .lock()
        .expect("manifest lock")
        .get("latest")
        .expect("tagged index")
        .1
        .clone();
    assert_eq!(
        Sha256Digest::digest(&tagged),
        published.published_index_digest
    );
}

#[tokio::test]
async fn nested_multi_platform_index_selects_the_matching_branch() {
    let fixture = support::fixture();
    let registry = spawn_registry(Some(&fixture), false, false, false).await;

    let nested_amd64 = ImageIndex {
        schema_version: 2,
        media_type: Some(MediaType::OciImageIndex),
        artifact_type: None,
        manifests: vec![fixture.manifest_descriptor.clone()],
        subject: None,
        annotations: Annotations::new(),
    };
    let nested_amd64 = to_canonical_json(&nested_amd64).expect("amd64 nested index");
    let mut arm_annotations = Annotations::new();
    arm_annotations
        .insert("fixture.branch".to_string(), "arm64".to_string())
        .expect("arm annotation");
    let nested_arm64 = ImageIndex {
        schema_version: 2,
        media_type: Some(MediaType::OciImageIndex),
        artifact_type: None,
        manifests: vec![fixture.manifest_descriptor.clone()],
        subject: None,
        annotations: arm_annotations,
    };
    let nested_arm64 = to_canonical_json(&nested_arm64).expect("arm64 nested index");
    let nested_descriptor = |bytes: &[u8], platform: Platform| Descriptor {
        media_type: MediaType::OciImageIndex,
        digest: Sha256Digest::digest(bytes),
        size: bytes.len() as u64,
        urls: Vec::new(),
        annotations: Annotations::new(),
        data: None,
        artifact_type: None,
        platform: Some(platform),
    };
    let root = ImageIndex {
        schema_version: 2,
        media_type: Some(MediaType::OciImageIndex),
        artifact_type: None,
        manifests: vec![
            nested_descriptor(&nested_amd64, Platform::linux_amd64()),
            nested_descriptor(
                &nested_arm64,
                Platform {
                    architecture: "arm64".to_string(),
                    os: "linux".to_string(),
                    os_version: None,
                    os_features: Vec::new(),
                    variant: None,
                    features: Vec::new(),
                },
            ),
        ],
        subject: None,
        annotations: Annotations::new(),
    };
    let root = to_canonical_json(&root).expect("root nested index");
    {
        let mut manifests = registry.state.manifests.lock().expect("manifest lock");
        manifests.insert(
            "latest".to_string(),
            (MediaType::OciImageIndex.as_str().to_string(), root),
        );
        manifests.insert(
            Sha256Digest::digest(&nested_amd64).to_string(),
            (MediaType::OciImageIndex.as_str().to_string(), nested_amd64),
        );
        manifests.insert(
            Sha256Digest::digest(&nested_arm64).to_string(),
            (MediaType::OciImageIndex.as_str().to_string(), nested_arm64),
        );
    }
    let client = RegistryClient::new(&registry.reference, Some(&registry.origin), None)
        .expect("registry client");
    let options = PullOptions::native(
        tempfile::tempdir()
            .expect("nested pull")
            .path()
            .join("layout"),
    );
    let verified = client
        .pull(&registry.reference, &options)
        .await
        .expect("nested amd64 pull");
    assert_eq!(verified.platform.architecture, "amd64");
}

#[tokio::test]
async fn child_manifest_media_type_must_match_its_descriptor() {
    let fixture = support::fixture();
    let registry = spawn_registry(Some(&fixture), false, false, false).await;
    registry
        .state
        .manifests
        .lock()
        .expect("manifest lock")
        .get_mut(&fixture.manifest_descriptor.digest.to_string())
        .expect("child manifest")
        .0 = MediaType::DockerImageManifest.as_str().to_string();
    let client = RegistryClient::new(&registry.reference, Some(&registry.origin), None)
        .expect("registry client");
    let options = PullOptions::native(
        tempfile::tempdir()
            .expect("media mismatch pull")
            .path()
            .join("layout"),
    );
    let error = client
        .pull(&registry.reference, &options)
        .await
        .expect_err("child media mismatch");
    assert!(format!("{error:#}").contains("Content-Type differs"));
}

#[tokio::test]
async fn upload_rejects_forward_acknowledgements_and_hardlinked_checkpoints() {
    let fixture = support::fixture();
    let registry = spawn_registry(None, false, false, false).await;
    registry
        .state
        .invalid_ack_once
        .store(true, Ordering::SeqCst);
    let client = RegistryClient::new(&registry.reference, Some(&registry.origin), None)
        .expect("registry client");
    let state_directory = tempfile::tempdir().expect("upload state");
    let upload_state = state_directory.path().join("uploads");
    let options = PushOptions {
        source: fixture.root().to_path_buf(),
        platform: PlatformSelector::parse("linux/amd64").expect("platform"),
        state_directory: upload_state.clone(),
        chunk_bytes: 11,
        cancellation: CancellationToken::new(),
        events: None,
    };
    let error = client
        .push(&registry.reference, &options)
        .await
        .expect_err("forward acknowledgement");
    assert!(format!("{error:#}").contains("submitted upload range"));
    assert!(
        !registry
            .state
            .events
            .lock()
            .expect("event lock")
            .iter()
            .any(|event| event == "manifest:latest")
    );

    let checkpoint = fs::read_dir(&upload_state)
        .expect("checkpoint directory")
        .map(|entry| entry.expect("checkpoint entry").path())
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .expect("checkpoint");
    fs::hard_link(&checkpoint, upload_state.join("checkpoint-hardlink"))
        .expect("checkpoint hardlink");
    let error = client
        .push(&registry.reference, &options)
        .await
        .expect_err("hardlinked checkpoint");
    assert!(format!("{error:#}").contains("hard-linked"));
}

#[tokio::test]
async fn upload_state_refuses_unowned_directories_without_mutation() {
    let fixture = support::fixture();
    let registry = spawn_registry(None, false, false, false).await;
    let client = RegistryClient::new(&registry.reference, Some(&registry.origin), None)
        .expect("registry client");
    let state = tempfile::tempdir().expect("unowned upload state");
    fs::write(state.path().join("sentinel"), b"keep").expect("sentinel");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(state.path(), fs::Permissions::from_mode(0o755))
            .expect("unowned mode fixture");
    }
    let options = PushOptions {
        source: fixture.root().to_path_buf(),
        platform: PlatformSelector::parse("linux/amd64").expect("platform"),
        state_directory: state.path().to_path_buf(),
        chunk_bytes: 11,
        cancellation: CancellationToken::new(),
        events: None,
    };
    client
        .push(&registry.reference, &options)
        .await
        .expect_err("unowned upload state must be refused");
    assert_eq!(
        fs::read(state.path().join("sentinel")).expect("preserved sentinel"),
        b"keep"
    );
    assert!(registry.state.events.lock().expect("events").is_empty());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            fs::metadata(state.path())
                .expect("unowned metadata")
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
    }
}

#[tokio::test]
async fn local_corruption_prevents_every_registry_mutation() {
    let fixture = support::fixture();
    let layer = fixture
        .root()
        .join("blobs/sha256")
        .join(fixture.layer_descriptor.digest.encoded());
    let mut bytes = fs::read(&layer).expect("fixture layer");
    bytes[0] ^= 0xff;
    fs::write(&layer, bytes).expect("corrupt fixture layer");

    let registry = spawn_registry(None, false, false, false).await;
    let client = RegistryClient::new(&registry.reference, Some(&registry.origin), None)
        .expect("registry client");
    let state_directory = tempfile::tempdir().expect("upload state");
    let options = PushOptions {
        source: fixture.root().to_path_buf(),
        platform: PlatformSelector::parse("linux/amd64").expect("platform"),
        state_directory: state_directory.path().join("uploads"),
        chunk_bytes: 16,
        cancellation: CancellationToken::new(),
        events: None,
    };
    client
        .push(&registry.reference, &options)
        .await
        .expect_err("corrupt source");
    assert!(registry.state.events.lock().expect("event lock").is_empty());
}

#[tokio::test]
async fn bearer_failures_never_render_seed_credentials() {
    let fixture = support::fixture();
    let registry = spawn_registry(Some(&fixture), false, false, true).await;
    let secret = "credential-that-must-not-appear";
    let client = RegistryClient::new(
        &registry.reference,
        Some(&registry.origin),
        Some(secret.to_string()),
    )
    .expect("registry client");
    let destination = tempfile::tempdir()
        .expect("pull parent")
        .path()
        .join("layout");
    let options = PullOptions::native(destination);
    let error = client
        .pull(&registry.reference, &options)
        .await
        .expect_err("token service failure");
    assert!(!format!("{error:#}").contains(secret));
}

#[tokio::test]
async fn bearer_challenge_accepts_only_same_repository_action_subsets() {
    let fixture = support::fixture();
    let registry = spawn_registry(None, false, false, false).await;
    *registry
        .state
        .challenge_scope
        .lock()
        .expect("challenge scope lock") = Some("repository:aos:pull".to_string());
    let client = RegistryClient::new(
        &registry.reference,
        Some(&registry.origin),
        Some("hub-seed-secret".to_string()),
    )
    .expect("registry client");
    let state_parent = tempfile::tempdir().expect("upload state parent");
    let options = PushOptions::native(
        fixture.root().to_path_buf(),
        state_parent.path().join("uploads"),
    );

    client
        .push(&registry.reference, &options)
        .await
        .expect("same-repository pull challenge must narrow pull,push");
    assert_eq!(
        *registry.state.token_scopes.lock().expect("token scopes"),
        vec![vec!["repository:aos:pull,push".to_string()]]
    );

    assert_push_challenge_rejected(&fixture, "repository:other:pull").await;
    assert_push_challenge_rejected(&fixture, "repository:aos:pull,delete").await;
}

async fn assert_push_challenge_rejected(fixture: &support::Fixture, challenge_scope: &str) {
    let registry = spawn_registry(None, false, false, false).await;
    *registry
        .state
        .challenge_scope
        .lock()
        .expect("challenge scope lock") = Some(challenge_scope.to_string());
    let client = RegistryClient::new(
        &registry.reference,
        Some(&registry.origin),
        Some("hub-seed-secret".to_string()),
    )
    .expect("registry client");
    let state_parent = tempfile::tempdir().expect("upload state parent");
    let options = PushOptions::native(
        fixture.root().to_path_buf(),
        state_parent.path().join("uploads"),
    );

    let error = client
        .push(&registry.reference, &options)
        .await
        .expect_err("challenge must not expand the requested repository grant");
    assert!(
        error
            .to_string()
            .contains("different repository or additional action scope")
    );
    assert_eq!(registry.state.token_requests.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn an_expired_cached_registry_token_is_refreshed_once() {
    let fixture = support::fixture();
    let registry = spawn_registry(Some(&fixture), false, false, false).await;
    let client = RegistryClient::new(
        &registry.reference,
        Some(&registry.origin),
        Some("hub-seed-secret".to_string()),
    )
    .expect("registry client");
    let first_parent = tempfile::tempdir().expect("first pull parent");
    let first = PullOptions::native(first_parent.path().join("layout"));
    client
        .pull(&registry.reference, &first)
        .await
        .expect("initial authenticated pull");
    registry
        .state
        .reject_registry_token_once
        .store(true, Ordering::SeqCst);
    let second_parent = tempfile::tempdir().expect("second pull parent");
    let second = PullOptions::native(second_parent.path().join("layout"));
    client
        .pull(&registry.reference, &second)
        .await
        .expect("pull after token refresh");
    assert_eq!(registry.state.token_requests.load(Ordering::SeqCst), 2);
}

async fn spawn_registry(
    fixture: Option<&support::Fixture>,
    interrupt_blob_once: bool,
    fail_patch_once: bool,
    fail_token: bool,
) -> TestRegistry {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("registry listener");
    let address = listener.local_addr().expect("registry address");
    let origin = format!("http://{address}/");
    let reference =
        RegistryReference::parse(&format!("{address}/aos:latest")).expect("registry reference");

    let mut blobs = BTreeMap::new();
    let mut manifests = BTreeMap::new();
    if let Some(fixture) = fixture {
        for (digest, bytes) in &fixture.blobs {
            blobs.insert(digest.to_string(), bytes.clone());
        }
        let index_digest = aos_oci_types::Sha256Digest::digest(&fixture.index);
        manifests.insert(
            "latest".to_string(),
            (
                "application/vnd.oci.image.index.v1+json".to_string(),
                fixture.index.clone(),
            ),
        );
        manifests.insert(
            index_digest.to_string(),
            (
                "application/vnd.oci.image.index.v1+json".to_string(),
                fixture.index.clone(),
            ),
        );
        manifests.insert(
            fixture.manifest_descriptor.digest.to_string(),
            (
                "application/vnd.oci.image.manifest.v1+json".to_string(),
                fixture.manifest.clone(),
            ),
        );
    }
    let state = Arc::new(RegistryState {
        base: origin.clone(),
        blobs: Mutex::new(blobs),
        manifests: Mutex::new(manifests),
        mount_sources: Mutex::new(BTreeMap::new()),
        uploads: Mutex::new(BTreeMap::new()),
        events: Mutex::new(Vec::new()),
        next_upload: AtomicU64::new(1),
        interrupt_blob_once: AtomicBool::new(interrupt_blob_once),
        stall_blob_once: AtomicBool::new(false),
        fail_patch_once: AtomicBool::new(fail_patch_once),
        fail_cancel_once: AtomicBool::new(false),
        stall_patch_once: AtomicBool::new(false),
        invalid_ack_once: AtomicBool::new(false),
        delay_tag_once: AtomicBool::new(false),
        tag_started: Notify::new(),
        fail_token: AtomicBool::new(fail_token),
        reject_registry_token_once: AtomicBool::new(false),
        token_requests: AtomicU64::new(0),
        token_scopes: Mutex::new(Vec::new()),
        challenge_scope: Mutex::new(None),
    });
    let router = Router::new()
        .fallback(any(handle))
        .with_state(state.clone());
    let task = tokio::spawn(async move {
        axum::serve(listener, router)
            .await
            .expect("registry server");
    });
    TestRegistry {
        state,
        reference,
        origin,
        task,
    }
}

async fn record_redirect_sink(
    State(requests): State<Arc<AtomicU64>>,
    _request: Request<Body>,
) -> Response<Body> {
    requests.fetch_add(1, Ordering::SeqCst);
    response(StatusCode::OK, Body::empty())
}

async fn redirect_every_request(
    State(location): State<String>,
    _request: Request<Body>,
) -> Response<Body> {
    Response::builder()
        .status(StatusCode::TEMPORARY_REDIRECT)
        .header(LOCATION, location)
        .body(Body::empty())
        .expect("redirect response")
}

async fn redirect_upload_chunk(
    State(location): State<String>,
    request: Request<Body>,
) -> Response<Body> {
    let path = request.uri().path();
    match (request.method(), path) {
        (&Method::HEAD, path) if path.starts_with("/v2/aos/blobs/") => {
            response(StatusCode::NOT_FOUND, Body::empty())
        }
        (&Method::POST, "/v2/aos/blobs/uploads/") => Response::builder()
            .status(StatusCode::ACCEPTED)
            .header(LOCATION, "/upload/1")
            .body(Body::empty())
            .expect("upload start response"),
        (&Method::PATCH, "/upload/1") => Response::builder()
            .status(StatusCode::TEMPORARY_REDIRECT)
            .header(LOCATION, location)
            .body(Body::empty())
            .expect("upload body redirect"),
        _ => response(StatusCode::NOT_FOUND, Body::empty()),
    }
}

async fn stall_forever(_request: Request<Body>) -> Response<Body> {
    std::future::pending::<Response<Body>>().await
}

async fn handle(State(state): State<Arc<RegistryState>>, request: Request<Body>) -> Response<Body> {
    let (parts, body) = request.into_parts();
    let body = axum::body::to_bytes(body, 16 * 1024 * 1024)
        .await
        .expect("request body");
    let path = parts.uri.path();
    if path == "/token" {
        return token_response(&state, &parts.headers, &parts.uri);
    }
    if state
        .reject_registry_token_once
        .swap(false, Ordering::SeqCst)
    {
        return challenge(&state);
    }
    if !authorized(&parts.headers) {
        return challenge(&state);
    }
    state
        .events
        .lock()
        .expect("event lock")
        .push(format!("{}:{path}", parts.method));

    if let Some(reference) = path.strip_prefix("/v2/aos/manifests/") {
        if parts.method == Method::PUT
            && reference == "latest"
            && state.delay_tag_once.swap(false, Ordering::SeqCst)
        {
            state.tag_started.notify_one();
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        return manifest_response(&state, &parts.method, reference, &parts.headers, body);
    }
    if let Some(digest) = path.strip_prefix("/v2/aos/blobs/")
        && !digest.starts_with("uploads/")
    {
        return blob_response(&state, &parts.method, digest, &parts.headers);
    }
    if let Some(remainder) = path.strip_prefix("/v2/")
        && let Some((repository, digest)) = remainder.split_once("/blobs/")
        && repository != "aos"
        && parts.method == Method::HEAD
    {
        let sources = state.mount_sources.lock().expect("mount source lock");
        let Some(bytes) = sources.get(&(repository.to_string(), digest.to_string())) else {
            return response(StatusCode::NOT_FOUND, Body::empty());
        };
        return Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_LENGTH, bytes.len())
            .header("docker-content-digest", digest)
            .body(Body::empty())
            .expect("mount source HEAD response");
    }
    if path == "/v2/aos/blobs/uploads/" && parts.method == Method::POST {
        if let Some(mounted) = mount_response(&state, &parts.uri) {
            return mounted;
        }
        return start_upload(&state, &parts.uri);
    }
    if let Some(identifier) = path.strip_prefix("/v2/aos/blobs/uploads/") {
        return upload_response(&state, &parts.method, identifier, &parts.uri, body).await;
    }
    response(StatusCode::NOT_FOUND, Body::empty())
}

fn authorized(headers: &HeaderMap) -> bool {
    headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        == Some("Bearer registry-token")
}

fn challenge(state: &RegistryState) -> Response<Body> {
    let scope = state
        .challenge_scope
        .lock()
        .expect("challenge scope lock")
        .as_ref()
        .map(|scope| format!(",scope=\"{scope}\""))
        .unwrap_or_default();
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(
            WWW_AUTHENTICATE,
            format!(
                "Bearer realm=\"{}token\",service=\"aos-test\"{scope}",
                state.base
            ),
        )
        .body(Body::empty())
        .expect("challenge response")
}

fn token_response(state: &RegistryState, headers: &HeaderMap, uri: &Uri) -> Response<Body> {
    state.token_requests.fetch_add(1, Ordering::SeqCst);
    let authorization = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    assert!(
        authorization.is_none()
            || matches!(
                authorization,
                Some("Bearer hub-seed-secret" | "Bearer credential-that-must-not-appear")
            )
    );
    if state.fail_token.load(Ordering::SeqCst) {
        return response(StatusCode::INTERNAL_SERVER_ERROR, Body::empty());
    }
    let mut scopes = uri
        .query()
        .into_iter()
        .flat_map(|query| url::form_urlencoded::parse(query.as_bytes()))
        .filter_map(|(key, value)| (key == "scope").then(|| value.into_owned()))
        .collect::<Vec<_>>();
    scopes.sort();
    state
        .token_scopes
        .lock()
        .expect("token scopes")
        .push(scopes);
    response(StatusCode::OK, Body::from(r#"{"token":"registry-token"}"#))
}

fn mount_response(state: &RegistryState, uri: &Uri) -> Option<Response<Body>> {
    let query = url::form_urlencoded::parse(uri.query()?.as_bytes())
        .into_owned()
        .collect::<BTreeMap<_, _>>();
    let source = query.get("from")?;
    let digest = query.get("mount")?;
    let bytes = state
        .mount_sources
        .lock()
        .expect("mount source lock")
        .get(&(source.clone(), digest.clone()))
        .cloned()?;
    state
        .blobs
        .lock()
        .expect("blob lock")
        .insert(digest.clone(), bytes);
    state.events.lock().expect("event lock").push(format!(
        "mount:{source}:{digest}:size={}",
        query.get("size").map(String::as_str).unwrap_or("missing")
    ));
    Some(
        Response::builder()
            .status(StatusCode::CREATED)
            .header("docker-content-digest", digest)
            .body(Body::empty())
            .expect("mount response"),
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
        let manifests = state.manifests.lock().expect("manifest lock");
        let Some((media_type, bytes)) = manifests.get(reference) else {
            return response(StatusCode::NOT_FOUND, Body::empty());
        };
        let digest = aos_oci_types::Sha256Digest::digest(bytes);
        return Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, media_type)
            .header("docker-content-digest", digest.to_string())
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
            .expect("manifest lock")
            .insert(reference.to_string(), (media_type, body.to_vec()));
        state
            .events
            .lock()
            .expect("event lock")
            .push(format!("manifest:{reference}"));
        return response(StatusCode::CREATED, Body::empty());
    }
    if method == Method::DELETE {
        state
            .manifests
            .lock()
            .expect("manifest lock")
            .remove(reference);
        return response(StatusCode::ACCEPTED, Body::empty());
    }
    response(StatusCode::METHOD_NOT_ALLOWED, Body::empty())
}

fn blob_response(
    state: &RegistryState,
    method: &Method,
    digest: &str,
    headers: &HeaderMap,
) -> Response<Body> {
    let blobs = state.blobs.lock().expect("blob lock");
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
    if method != Method::GET {
        return response(StatusCode::METHOD_NOT_ALLOWED, Body::empty());
    }
    if let Some(range) = headers.get(RANGE).and_then(|value| value.to_str().ok()) {
        let offset = range
            .strip_prefix("bytes=")
            .and_then(|value| value.strip_suffix('-'))
            .and_then(|value| value.parse::<usize>().ok())
            .expect("range offset");
        state
            .events
            .lock()
            .expect("event lock")
            .push(format!("range:{offset}"));
        return Response::builder()
            .status(StatusCode::PARTIAL_CONTENT)
            .header(
                CONTENT_RANGE,
                format!("bytes {offset}-{}/{}", bytes.len() - 1, bytes.len()),
            )
            .body(Body::from(bytes[offset..].to_vec()))
            .expect("range response");
    }
    if state.interrupt_blob_once.swap(false, Ordering::SeqCst) {
        return response(
            StatusCode::OK,
            Body::from(bytes[..bytes.len() / 2].to_vec()),
        );
    }
    if state.stall_blob_once.swap(false, Ordering::SeqCst) {
        let stream = futures_util::stream::pending::<Result<Bytes, std::io::Error>>();
        return response(StatusCode::OK, Body::from_stream(stream));
    }
    response(StatusCode::OK, Body::from(bytes.clone()))
}

fn start_upload(state: &RegistryState, uri: &Uri) -> Response<Body> {
    let hints = uri
        .query()
        .into_iter()
        .flat_map(|query| url::form_urlencoded::parse(query.as_bytes()))
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<BTreeMap<_, _>>();
    state.events.lock().expect("event lock").push(format!(
        "upload-hint:{}:size={}",
        hints.get("digest").map(String::as_str).unwrap_or("missing"),
        hints.get("size").map(String::as_str).unwrap_or("missing")
    ));
    let identifier = state.next_upload.fetch_add(1, Ordering::SeqCst).to_string();
    state
        .uploads
        .lock()
        .expect("upload lock")
        .insert(identifier.clone(), Vec::new());
    Response::builder()
        .status(StatusCode::ACCEPTED)
        .header(LOCATION, format!("/v2/aos/blobs/uploads/{identifier}"))
        .body(Body::empty())
        .expect("start upload response")
}

async fn upload_response(
    state: &RegistryState,
    method: &Method,
    identifier: &str,
    uri: &Uri,
    body: Bytes,
) -> Response<Body> {
    if method == Method::GET {
        let uploads = state.uploads.lock().expect("upload lock");
        let Some(bytes) = uploads.get(identifier) else {
            return response(StatusCode::NOT_FOUND, Body::empty());
        };
        state
            .events
            .lock()
            .expect("event lock")
            .push(format!("upload-query:{}", bytes.len()));
        let mut builder = Response::builder()
            .status(StatusCode::NO_CONTENT)
            .header(LOCATION, format!("/v2/aos/blobs/uploads/{identifier}"));
        if !bytes.is_empty() {
            builder = builder.header(RANGE, format!("0-{}", bytes.len() - 1));
        }
        return builder.body(Body::empty()).expect("query upload response");
    }
    if method == Method::PATCH {
        if state.stall_patch_once.swap(false, Ordering::SeqCst) {
            return std::future::pending::<Response<Body>>().await;
        }
        let mut uploads = state.uploads.lock().expect("upload lock");
        let bytes = uploads.get_mut(identifier).expect("upload session");
        bytes.extend_from_slice(&body);
        if state.fail_patch_once.swap(false, Ordering::SeqCst) {
            return response(StatusCode::INTERNAL_SERVER_ERROR, Body::empty());
        }
        if state.invalid_ack_once.swap(false, Ordering::SeqCst) {
            return Response::builder()
                .status(StatusCode::ACCEPTED)
                .header(LOCATION, format!("/v2/aos/blobs/uploads/{identifier}"))
                .header(RANGE, format!("0-{}", bytes.len() + 100))
                .body(Body::empty())
                .expect("invalid acknowledgement response");
        }
        return Response::builder()
            .status(StatusCode::ACCEPTED)
            .header(LOCATION, format!("/v2/aos/blobs/uploads/{identifier}"))
            .header(RANGE, format!("0-{}", bytes.len() - 1))
            .body(Body::empty())
            .expect("patch upload response");
    }
    if method == Method::PUT {
        let digest = uri
            .query()
            .into_iter()
            .flat_map(|query| url::form_urlencoded::parse(query.as_bytes()))
            .find_map(|(key, value)| (key == "digest").then(|| value.into_owned()))
            .expect("final upload digest");
        let bytes = state
            .uploads
            .lock()
            .expect("upload lock")
            .remove(identifier)
            .expect("upload session");
        assert_eq!(
            aos_oci_types::Sha256Digest::digest(&bytes).to_string(),
            digest
        );
        state
            .blobs
            .lock()
            .expect("blob lock")
            .insert(digest.clone(), bytes);
        return Response::builder()
            .status(StatusCode::CREATED)
            .header("docker-content-digest", digest)
            .body(Body::empty())
            .expect("final upload response");
    }
    if method == Method::DELETE {
        if state.fail_cancel_once.swap(false, Ordering::SeqCst) {
            return response(StatusCode::SERVICE_UNAVAILABLE, Body::empty());
        }
        state
            .uploads
            .lock()
            .expect("upload lock")
            .remove(identifier);
        return response(StatusCode::NO_CONTENT, Body::empty());
    }
    response(StatusCode::METHOD_NOT_ALLOWED, Body::empty())
}

fn response(status: StatusCode, body: Body) -> Response<Body> {
    Response::builder()
        .status(status)
        .body(body)
        .expect("test response")
}
