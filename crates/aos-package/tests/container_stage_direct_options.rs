//! Exercises staged Direct discovery with the caller's provider and retry options.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aos_net::direct_upload::{DirectClientError, DirectControlKind, DirectTransferMetrics};
use aos_oci::{PushOptions, RegistryClient, RegistryReference};
use aos_package::registry::container_stage::{
    capture_layout_objects, graph_objects, prepare_container_stage,
    upload_container_stage_with_client,
};
use aos_proto_types::direct_upload::*;
use aos_registry_surface::staging::{STAGE_SCHEMA, StageRevision, inventory_digest};
use aos_remote::DirectUploadOptions;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

// Reuse the actual closed signed OCI graph fixture instead of a reduced graph
// that bypasses the staging helper's inventory and source checks.
#[path = "../../aos-oci/tests/support/mod.rs"]
mod support;

struct Server {
    origin: String,
    requests: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Server {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}/", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let observed = Arc::clone(&requests);
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                let request = loop {
                    let mut buffer = [0; 4096];
                    let count = stream.read(&mut buffer).await.unwrap();
                    assert!(count > 0);
                    bytes.extend_from_slice(&buffer[..count]);
                    assert!(bytes.len() <= MAX_DIRECT_CONTROL_BYTES + 8192);
                    let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") else {
                        continue;
                    };
                    let headers = std::str::from_utf8(&bytes[..end]).unwrap();
                    let length = headers
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length: ")
                                .map(|value| value.parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    if bytes.len() >= end + 4 + length {
                        break headers.lines().next().unwrap().to_string();
                    }
                };
                observed.lock().unwrap().push(request.clone());

                let (status, headers, body) = if request.starts_with("HEAD ") {
                    (
                        404,
                        "Aos-Direct-Upload: 1\r\nAos-Registry-Id: registry\r\n",
                        Vec::new(),
                    )
                } else if request
                    .starts_with("POST /aos.hub.v1.DirectUploadService/GetCapabilities ")
                {
                    (200, "", serde_json::to_vec(&capabilities()).unwrap())
                } else {
                    assert!(request.starts_with("POST /v2/aos/blobs/uploads/?"));
                    // Stop after journal admission; this fixture never grants a
                    // provider transfer or reports a completed publication.
                    (409, "", Vec::new())
                };
                let response = format!(
                    "HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n",
                    body.len(),
                );
                stream.write_all(response.as_bytes()).await.unwrap();
                stream.write_all(&body).await.unwrap();
            }
        });
        Self {
            origin,
            requests,
            task,
        }
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn capabilities() -> DirectUploadCapabilities {
    DirectUploadCapabilities {
        target: DirectCapabilitiesTarget::OciRepository {
            registry: "registry".into(),
            repository: "aos".into(),
        },
        requested_delivery_url: None,
        deployment_id: "deployment".into(),
        principal_id: "de".repeat(32),
        version: 1,
        capability: DIRECT_UPLOAD_CAPABILITY.into(),
        transfer_mode: DirectAdvertisedTransferMode::DirectRequired,
        config_generation: WireInteger::new(1),
        valid_until: WireInteger::new(now() + 600),
        maximum_control_bytes: MAX_DIRECT_CONTROL_BYTES as u32,
        maximum_batch_items: 64,
        maximum_batch_parts: 64,
        maximum_object_bytes: WireInteger::new(MAX_DIRECT_OBJECT_BYTES),
        minimum_object_bytes: WireInteger::new(0),
        minimum_part_bytes: WireInteger::new(MIN_DIRECT_PART_BYTES),
        maximum_part_bytes: WireInteger::new(MAX_DIRECT_PART_BYTES),
        profiles: vec![DirectProviderProfile {
            placement_id: WireInteger::new(1),
            placement_resource_version: WireInteger::new(1),
            write_spec_version: WireInteger::new(1),
            binding_id: WireInteger::new(1),
            binding_resource_version: WireInteger::new(1),
            binding_write_revision: WireInteger::new(1),
            checksum_algorithm: DirectChecksumAlgorithm::Md5,
            provider_origin: "https://provider.invalid".into(),
            profile_fingerprint: "af".repeat(32),
            private_policy_digest: "fe".repeat(32),
        }],
    }
}

fn candidate(objects: &Path) -> StageRevision {
    let source = support::fixture();
    let release = support::add_signed_release_graph(&source);
    let graph = prepare_container_stage(source.root(), "aos", &release).unwrap();
    capture_layout_objects(source.root(), &graph, objects).unwrap();
    let mut inventory = graph_objects(&graph);
    inventory.sort_by(|left, right| left.path.cmp(&right.path));
    let candidate = StageRevision {
        schema: STAGE_SCHEMA.into(),
        id: "candidate".into(),
        registry: "example/main".into(),
        revision: 1,
        release_id: release.identity.release.clone(),
        source_branch: "dplecki/candidate".into(),
        commit: "a".repeat(64),
        inventory_digest: inventory_digest(&inventory).unwrap(),
        inventory,
        container: Some(graph),
        publication: Vec::new(),
        store_roots: Vec::new(),
    };
    candidate.validate().unwrap();
    candidate
}

async fn upload(
    root: &Path,
    server: &Server,
    direct: DirectUploadOptions,
) -> anyhow::Result<aos_oci::ReleaseGraphPushResult> {
    let objects = root.join("objects");
    let candidate = candidate(&objects);
    let reference = RegistryReference::parse(&format!(
        "{}/aos@{}",
        server
            .origin
            .trim_start_matches("http://")
            .trim_end_matches('/'),
        candidate
            .container
            .as_ref()
            .unwrap()
            .release
            .oci
            .index
            .digest,
    ))
    .unwrap();
    let client = RegistryClient::new(
        &reference,
        Some(&server.origin),
        Some("fixture-token".into()),
    )
    .unwrap()
    .with_direct_upload_options(direct);
    let options = PushOptions::native(objects.clone(), root.join("uploads"));

    tokio::time::timeout(
        Duration::from_secs(5),
        upload_container_stage_with_client(
            &candidate,
            &objects,
            &server.origin,
            None,
            &client,
            &options,
            &[],
        ),
    )
    .await
    .unwrap()
}

fn foreign_absolute_root_owner() -> bool {
    let root_owner = fs::metadata("/").unwrap().uid();
    ![0, rustix::process::geteuid().as_raw()].contains(&root_owner)
}

#[tokio::test]
async fn staged_client_preserves_selected_provider_policy_before_blob_allocation() {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let policy = root.path().join("provider-policy.json");
    fs::write(
        &policy,
        br#"{"version":2,"privateEndpoints":[],"rootCertificateFiles":[]}"#,
    )
    .unwrap();
    let metrics = Arc::new(DirectTransferMetrics::default());
    let server = Server::start().await;
    let direct = DirectUploadOptions {
        provider_policy: Some(policy),
        journal: Some(root.path().join("selected.sqlite")),
        metrics: Arc::clone(&metrics),
        ..Default::default()
    };

    let result = upload(root.path(), &server, direct).await;

    let failure = result.unwrap_err();
    let expected = if foreign_absolute_root_owner() {
        // A foreign absolute ancestor is refused before reading the policy.
        DirectClientError::Checkpoint
    } else {
        DirectClientError::Invalid
    };
    assert_eq!(failure.downcast_ref::<DirectClientError>(), Some(&expected));
    assert_eq!(
        metrics
            .snapshot()
            .control_attempts(DirectControlKind::Capabilities),
        1
    );
    assert_eq!(metrics.snapshot().provider_attempts, 0);
    let requests = server.requests();
    assert_eq!(requests.len(), 3);
    assert!(requests[0].starts_with("HEAD /v2/aos/blobs/"));
    assert!(requests[1].starts_with("HEAD /v2/aos/blobs/"));
    assert!(requests[2].starts_with("POST /aos.hub.v1.DirectUploadService/GetCapabilities "));
    assert!(!root.path().join("selected.sqlite").exists());
}

#[tokio::test]
async fn staged_client_preserves_selected_journal_and_new_run_without_replacing_old_bytes() {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let old_journal = root.path().join("selected.sqlite");
    let unresolved = b"retained older run must never be opened or replaced";
    fs::write(&old_journal, unresolved).unwrap();
    let metrics = Arc::new(DirectTransferMetrics::default());
    let server = Server::start().await;
    let direct = DirectUploadOptions {
        journal: Some(old_journal.clone()),
        new_run: true,
        metrics: Arc::clone(&metrics),
        ..Default::default()
    };

    let result = upload(root.path(), &server, direct).await;

    assert!(result.is_err());
    assert_eq!(fs::read(&old_journal).unwrap(), unresolved);
    let new_journals = fs::read_dir(root.path())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("selected.sqlite.")
        })
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension.len() == 32)
        })
        .collect::<Vec<_>>();
    if foreign_absolute_root_owner() {
        // This is the production ancestry refusal, not a skipped admission.
        let failure = result.unwrap_err();
        assert_eq!(
            failure.downcast_ref::<DirectClientError>(),
            Some(&DirectClientError::Checkpoint),
        );
        assert!(new_journals.is_empty());
        assert_eq!(
            metrics
                .snapshot()
                .control_attempts(DirectControlKind::Capabilities),
            1,
        );
        assert_eq!(metrics.snapshot().provider_attempts, 0);
        let requests = server.requests();
        assert_eq!(requests.len(), 3);
        assert!(requests[0].starts_with("HEAD /v2/aos/blobs/"));
        assert!(requests[1].starts_with("HEAD /v2/aos/blobs/"));
        assert!(requests[2].starts_with("POST /aos.hub.v1.DirectUploadService/GetCapabilities "));
        return;
    }

    assert_eq!(new_journals.len(), 1);
    let journal = rusqlite::Connection::open(&new_journals[0]).unwrap();
    let integrity: String = journal
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .unwrap();
    assert_eq!(integrity, "ok");
    assert_eq!(
        metrics
            .snapshot()
            .control_attempts(DirectControlKind::Capabilities),
        1
    );
    assert_eq!(metrics.snapshot().provider_attempts, 0);
    let requests = server.requests();
    assert_eq!(requests.len(), 4);
    assert!(requests[3].starts_with("POST /v2/aos/blobs/uploads/?"));
}
