//! Actual HTTP allocation replay, credential custody and readiness refusal.

use std::sync::Mutex;

use aos_net::direct_upload::ProviderOptions;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

use super::*;

const SCOPE: &str = "repository:aos:pull,push";

#[tokio::test]
async fn unsupported_platform_policy_probes_metadata_and_never_admits_direct_marker() {
    for marker in [None, Some("0"), Some("1"), Some("unknown")] {
        let server = Server::start(|_| {
            let reply = Reply::status(404);
            vec![match marker {
                Some(marker) => reply.header(&format!(
                    "Aos-Direct-Upload: {marker}\r\nAos-Registry-Id: registry\r\n"
                )),
                None => reply,
            }]
        })
        .await;
        let (client, _) = server.client();

        let result = super::super::push::ensure_legacy_policy_on_unsupported_platform(
            &client,
            client.url("v2/aos/blobs/sha256:0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
            SCOPE,
            &tokio_util::sync::CancellationToken::new(),
        ).await;

        assert_eq!(result.is_ok(), marker.is_none());
        let requests = server.requests();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].starts_with("HEAD /v2/aos/blobs/"));
        assert!(requests[0].ends_with("\r\n\r\n"));
        assert!(!requests.iter().any(|request| request.starts_with("POST ")));
    }
}

struct Reply {
    status: u16,
    headers: String,
    body: Vec<u8>,
    reset: bool,
    before: Option<Box<dyn FnOnce() + Send>>,
}

impl Reply {
    fn status(status: u16) -> Self {
        Self {
            status,
            headers: String::new(),
            body: Vec::new(),
            reset: false,
            before: None,
        }
    }

    fn capabilities(caps: &DirectUploadCapabilities) -> Self {
        Self {
            body: serde_json::to_vec(caps).unwrap(),
            ..Self::status(200)
        }
    }

    fn header(mut self, value: &str) -> Self {
        self.headers.push_str(value);
        self
    }
}

struct Server {
    origin: String,
    requests: Arc<Mutex<Vec<Vec<u8>>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Server {
    async fn start(replies: impl FnOnce(&str) -> Vec<Reply>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}/", listener.local_addr().unwrap());
        let replies = replies(&origin);
        let requests = Arc::new(Mutex::new(Vec::new()));
        let observed = requests.clone();
        let task = tokio::spawn(async move {
            for mut reply in replies {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                loop {
                    let mut buffer = [0; 4096];
                    let size = stream.read(&mut buffer).await.unwrap();
                    assert!(size > 0);
                    request.extend_from_slice(&buffer[..size]);
                    assert!(request.len() <= 4 * 1024 * 1024 + 8192);
                    if let Some(end) = request.windows(4).position(|v| v == b"\r\n\r\n") {
                        let headers = std::str::from_utf8(&request[..end])
                            .unwrap()
                            .to_ascii_lowercase();
                        let length: usize = headers
                            .lines()
                            .find_map(|line| line.strip_prefix("content-length: "))
                            .unwrap_or("0")
                            .parse()
                            .unwrap();
                        if request.len() >= end + 4 + length {
                            break;
                        }
                    }
                }
                observed.lock().unwrap().push(request);
                if let Some(before) = reply.before.take() {
                    before();
                }
                if reply.reset {
                    #[allow(deprecated)]
                    stream.set_linger(Some(Duration::ZERO)).unwrap();
                    continue;
                }
                let header = format!(
                    "HTTP/1.1 {} Fixture\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n{}\r\n",
                    reply.status,
                    reply.body.len(),
                    reply.headers
                );
                stream.write_all(header.as_bytes()).await.unwrap();
                stream.write_all(&reply.body).await.unwrap();
            }
        });
        Self {
            origin,
            requests,
            task,
        }
    }

    fn client(&self) -> (RegistryClient, RegistryReference) {
        let authority = self
            .origin
            .trim_start_matches("http://")
            .trim_end_matches('/');
        let reference = RegistryReference::parse(&format!("{authority}/aos:latest")).unwrap();
        let client = RegistryClient::new(&reference, Some(&self.origin), None).unwrap();
        client
            .store_scoped_token(SCOPE, zeroize::Zeroizing::new("original-oci-token".into()))
            .unwrap();
        (client, reference)
    }

    fn requests(&self) -> Vec<String> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .map(|v| String::from_utf8(v.clone()).unwrap())
            .collect()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
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

fn authority(client: &RegistryClient, caps: DirectUploadCapabilities) -> DirectOciAuthority {
    DirectOciAuthority {
        authentication: Arc::new(OciAuthentication {
            client: client.clone(),
            scope: SCOPE.into(),
            probe: client.url("v2/aos/blobs/sha256:fixture").unwrap(),
            cancellation: CancellationToken::new(),
        }),
        proved: tokio::sync::Mutex::new(ProvedAllocationToken {
            token: zeroize::Zeroizing::new("original-oci-token".into()),
            valid_until: caps.valid_until.get(),
            checked: tokio::time::Instant::now(),
        }),
        capabilities: caps,
    }
}

fn descriptor() -> Descriptor {
    serde_json::from_value(serde_json::json!({
        "mediaType":"application/octet-stream", "digest":aos_oci_types::Sha256Digest::digest(b"private-object").to_string(), "size":14,
    })).unwrap()
}

#[tokio::test]
async fn coordinator_checks_object_bounds_before_oci_allocation_or_empty_begin() {
    use std::os::unix::fs::PermissionsExt as _;

    for minimum in [0, 1] {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let empty_source = directory.path().join("empty-object");
        std::fs::write(&empty_source, []).unwrap();
        let server = Server::start(|_| vec![]).await;
        let hub = HubClient::connect_with_token(&server.origin, "original-oci-token").unwrap();
        let mut capabilities = capabilities();
        capabilities.minimum_object_bytes = WireInteger::new(minimum);
        capabilities.maximum_object_bytes = WireInteger::new(1);
        let coordinator = DirectUploadCoordinator::open(
            &hub,
            capabilities,
            &directory.path().join("direct.sqlite"),
            ProviderOptions::default(),
        )
        .await
        .unwrap();
        let empty_sha = aos_oci_types::Sha256Digest::digest(b"").encoded();

        let allocation = coordinator.prepare_oci_allocation(&empty_sha, 0).await;

        if minimum == 0 {
            assert!(allocation.unwrap().upload_id.is_none());
        } else {
            assert_eq!(allocation.unwrap_err(), DirectClientError::Invalid);
            let result = coordinator
                .stage_paths(vec![aos_remote::DirectStagePath {
                    source: empty_source,
                    expected_sha256: Some(empty_sha.clone()),
                    target: DirectUploadTarget::OciBlob {
                        upload_id: "retained-upload".into(),
                    },
                    phase: DirectDependencyPhase::Content,
                }])
                .await;
            assert_eq!(result, Err(DirectClientError::Invalid));
        }
        assert_eq!(
            coordinator
                .prepare_oci_allocation(&empty_sha, 2)
                .await
                .unwrap_err(),
            DirectClientError::Invalid
        );
        assert!(server.requests().is_empty());
    }
}

#[tokio::test]
async fn lost_allocation_reply_restart_replays_original_bodyless_uri_and_owner() {
    use std::os::unix::fs::PermissionsExt as _;

    let server = Server::start(|_| {
        vec![
            Reply {
                reset: true,
                ..Reply::status(202)
            },
            Reply::status(202).header("Docker-Upload-UUID: retained-upload\r\n"),
        ]
    })
    .await;
    let (client, reference) = server.client();
    let caps = capabilities();
    let authority = authority(&client, caps.clone());
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = directory.path().join("direct.sqlite");
    let hub = HubClient::connect_with_token(&server.origin, "original-oci-token").unwrap();
    let coordinator =
        DirectUploadCoordinator::open(&hub, caps.clone(), &path, ProviderOptions::default())
            .await
            .unwrap();
    let descriptor = descriptor();

    assert!(
        allocate(
            &client,
            &reference,
            &descriptor,
            SCOPE,
            &coordinator,
            &authority,
            &CancellationToken::new()
        )
        .await
        .is_err()
    );
    let before = coordinator
        .prepare_oci_allocation(&descriptor.digest.encoded(), descriptor.size)
        .await
        .unwrap();
    assert!(before.upload_id.is_none());
    drop(coordinator);
    let coordinator = DirectUploadCoordinator::open(&hub, caps, &path, ProviderOptions::default())
        .await
        .unwrap();
    let result = allocate(
        &client,
        &reference,
        &descriptor,
        SCOPE,
        &coordinator,
        &authority,
        &CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(result.as_deref(), Some("retained-upload"));
    assert_eq!(
        allocate(
            &client,
            &reference,
            &descriptor,
            SCOPE,
            &coordinator,
            &authority,
            &CancellationToken::new()
        )
        .await
        .unwrap(),
        result
    );
    let after = coordinator
        .prepare_oci_allocation(&descriptor.digest.encoded(), descriptor.size)
        .await
        .unwrap();
    assert_eq!(before.operation_id, after.operation_id);
    assert_eq!(before.byte_size, after.byte_size);

    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0], requests[1]);
    let uri = requests[0].lines().next().unwrap();
    assert!(uri.starts_with("POST /v2/aos/blobs/uploads/?digest=sha256%3A"));
    assert!(uri.contains(&format!(
        "&size=14&aos_operation_id={}",
        before.operation_id
    )));
    assert!(requests[0].contains("content-length: 0\r\n"));
    assert!(
        requests
            .iter()
            .all(|r| r.ends_with("\r\n\r\n") && !r.contains("private-object"))
    );
}

#[tokio::test]
async fn concurrent_shared_token_drift_never_replaces_proved_allocator_bearer() {
    let caps = capabilities();
    let mut changed = caps.clone();
    changed.principal_id = "aa".repeat(32);
    let installed = Arc::new(Mutex::new(None::<RegistryClient>));
    let replacement = installed.clone();
    let server = Server::start(|_| {
        let mut proved = Reply::capabilities(&caps);
        proved.before = Some(Box::new(move || {
            replacement
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .store_scoped_token(
                    SCOPE,
                    zeroize::Zeroizing::new("different-actor-token".into()),
                )
                .unwrap();
        }));
        vec![
            Reply::status(404),
            proved,
            Reply::status(202),
            Reply::status(404),
            Reply::capabilities(&changed),
        ]
    })
    .await;
    let (client, _) = server.client();
    *installed.lock().unwrap() = Some(client.clone());
    let authority = authority(&client, caps);
    client
        .store_scoped_token(
            SCOPE,
            zeroize::Zeroizing::new("renewed-same-actor-token".into()),
        )
        .unwrap();
    let url = client
        .url(&format!(
            "v2/aos/blobs/uploads/?digest=sha256:fixture&size=14&aos_operation_id={}",
            "ab".repeat(32)
        ))
        .unwrap();

    assert_eq!(
        authority
            .post(&client, url.clone(), &CancellationToken::new())
            .await
            .unwrap()
            .0
            .status(),
        StatusCode::ACCEPTED
    );
    assert!(
        authority
            .post(&client, url, &CancellationToken::new())
            .await
            .is_err()
    );
    let requests = server.requests();
    assert_eq!(requests.len(), 5);
    assert!(requests[2].starts_with("POST /v2/aos/blobs/uploads/"));
    assert!(requests[2].contains("authorization: Bearer renewed-same-actor-token\r\n"));
    assert!(!requests[2].contains("different-actor-token"));
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.starts_with("POST /v2/"))
            .count(),
        1
    );
}

#[tokio::test]
async fn denied_allocator_reproves_original_actor_then_replays_identical_uri() {
    let caps = capabilities();
    let server = Server::start(|origin| {
        let challenge = format!("WWW-Authenticate: Bearer realm=\"{origin}token\",service=\"registry\",scope=\"{SCOPE}\"\r\n");
        vec![
            Reply::status(401), Reply::status(401).header(&challenge),
            Reply { body: br#"{"token":"renewed-oci-token"}"#.to_vec(), ..Reply::status(200) },
            Reply::status(404), Reply::capabilities(&caps), Reply::status(202),
        ]
    }).await;
    let (client, _) = server.client();
    let authority = authority(&client, caps);
    let url = client
        .url(&format!(
            "v2/aos/blobs/uploads/?digest=sha256:fixture&size=14&aos_operation_id={}",
            "ab".repeat(32)
        ))
        .unwrap();

    assert_eq!(
        authority
            .post(&client, url, &CancellationToken::new())
            .await
            .unwrap()
            .0
            .status(),
        StatusCode::ACCEPTED
    );
    let requests = server.requests();
    assert_eq!(requests.len(), 6);
    assert_eq!(requests[0].lines().next(), requests[5].lines().next());
    assert!(requests[0].contains("authorization: Bearer original-oci-token\r\n"));
    assert!(requests[4].contains("authorization: Bearer renewed-oci-token\r\n"));
    assert!(requests[5].contains("authorization: Bearer renewed-oci-token\r\n"));
    assert!(requests[0].ends_with("\r\n\r\n") && requests[5].ends_with("\r\n\r\n"));
}

#[tokio::test]
async fn positive_readiness_unavailable_capabilities_never_sends_legacy_bytes() {
    let server = Server::start(|_| {
        vec![
            Reply::status(404).header("Aos-Direct-Upload: 1\r\nAos-Registry-Id: registry\r\n"),
            Reply::status(404),
            Reply::status(503),
        ]
    })
    .await;
    let (client, reference) = server.client();
    let directory = tempfile::tempdir().unwrap();
    let options = PushOptions::native(directory.path().to_owned(), directory.path().join("state"));

    assert!(
        upload_blobs_if_required(&client, &reference, &[descriptor()], SCOPE, &options)
            .await
            .is_err()
    );
    let requests = server.requests();
    assert_eq!(requests.len(), 3);
    assert!(requests[..2].iter().all(|r| r.starts_with("HEAD /v2/")));
    assert!(requests[2].starts_with("POST /aos.hub.v1.DirectUploadService/GetCapabilities "));
    assert!(requests.iter().all(|r| !r.starts_with("PATCH ")
        && !r.starts_with("PUT ")
        && !r.contains("private-object")));
}

#[tokio::test]
async fn readiness_is_positive_closed_and_registry_stable() {
    let server = Server::start(|_| {
        vec![
            Reply::status(404),
            Reply::status(404).header("Aos-Direct-Upload: 1\r\nAos-Registry-Id: registry\r\n"),
            Reply::status(404).header("Aos-Direct-Upload: 1\r\nAos-Registry-Id: changed\r\n"),
            Reply::status(404).header(
                "Aos-Direct-Upload: 1\r\nAos-Direct-Upload: 1\r\nAos-Registry-Id: registry\r\n",
            ),
        ]
    })
    .await;
    let (client, _) = server.client();
    let url = client.url("v2/aos/blobs/sha256:fixture").unwrap();
    let token = CancellationToken::new();

    client
        .send(
            Method::HEAD,
            url.clone(),
            SCOPE,
            &HeaderMap::new(),
            None,
            &token,
        )
        .await
        .unwrap();
    assert!(client.inner.direct_registry.lock().unwrap().is_none());
    client
        .send(
            Method::HEAD,
            url.clone(),
            SCOPE,
            &HeaderMap::new(),
            None,
            &token,
        )
        .await
        .unwrap();
    assert_eq!(
        client.inner.direct_registry.lock().unwrap().as_deref(),
        Some("registry")
    );
    assert!(
        client
            .send(
                Method::HEAD,
                url.clone(),
                SCOPE,
                &HeaderMap::new(),
                None,
                &token
            )
            .await
            .is_err()
    );
    assert!(
        client
            .send(Method::HEAD, url, SCOPE, &HeaderMap::new(), None, &token)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn manifest_shared_token_drift_preserves_proved_actor_and_refuses_changed_actor() {
    let caps = capabilities();
    let mut changed = caps.clone();
    changed.principal_id = "aa".repeat(32);
    let installed = Arc::new(Mutex::new(None::<RegistryClient>));
    let replacement = installed.clone();
    let server = Server::start(|_| {
        let mut proved = Reply::capabilities(&caps);
        proved.before = Some(Box::new(move || {
            replacement
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .store_scoped_token(
                    SCOPE,
                    zeroize::Zeroizing::new("different-actor-token".into()),
                )
                .unwrap();
        }));
        vec![
            Reply::status(404),
            proved,
            Reply::status(201),
            Reply::status(404),
            Reply::capabilities(&changed),
        ]
    })
    .await;
    let (client, _) = server.client();
    *installed.lock().unwrap() = Some(client.clone());
    let authority = authority(&client, caps);
    client
        .store_scoped_token(
            SCOPE,
            zeroize::Zeroizing::new("renewed-same-actor-token".into()),
        )
        .unwrap();
    let url = client.url("v2/aos/manifests/latest").unwrap();
    let body = Bytes::from_static(b"exact-original-manifest");

    assert_eq!(
        authority
            .put_manifest(
                &client,
                url.clone(),
                &HeaderMap::new(),
                body.clone(),
                &CancellationToken::new()
            )
            .await
            .unwrap()
            .status(),
        StatusCode::CREATED
    );
    assert!(
        authority
            .put_manifest(
                &client,
                url,
                &HeaderMap::new(),
                body,
                &CancellationToken::new()
            )
            .await
            .is_err()
    );

    let requests = server.requests();
    assert_eq!(requests.len(), 5);
    assert!(requests[2].starts_with("PUT /v2/aos/manifests/latest "));
    assert!(requests[2].contains("authorization: Bearer renewed-same-actor-token\r\n"));
    assert!(requests[2].ends_with("exact-original-manifest"));
    assert!(!requests[2].contains("different-actor-token"));
    assert_eq!(requests.iter().filter(|r| r.starts_with("PUT ")).count(), 1);
}

#[tokio::test]
async fn denied_manifest_renews_genuine_realm_and_preserves_exact_document_reference() {
    let caps = capabilities();
    let server = Server::start(|origin| {
        let challenge = format!("WWW-Authenticate: Bearer realm=\"{origin}token\",service=\"registry\",scope=\"{SCOPE}\"\r\n");
        vec![Reply::status(401), Reply::status(401).header(&challenge), Reply { body: br#"{"token":"renewed-oci-token"}"#.to_vec(), ..Reply::status(200) }, Reply::status(404), Reply::capabilities(&caps), Reply::status(201)]
    }).await;
    let (client, _) = server.client();
    let authority = authority(&client, caps);
    let url = client.url("v2/aos/manifests/latest").unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        "content-type",
        "application/vnd.oci.image.index.v1+json".parse().unwrap(),
    );

    assert_eq!(
        authority
            .put_manifest(
                &client,
                url,
                &headers,
                Bytes::from_static(b"exact-original-manifest"),
                &CancellationToken::new()
            )
            .await
            .unwrap()
            .status(),
        StatusCode::CREATED
    );

    let requests = server.requests();
    assert_eq!(requests.len(), 6);
    assert_eq!(requests[0].lines().next(), requests[5].lines().next());
    assert!(requests[0].contains("authorization: Bearer original-oci-token\r\n"));
    assert!(requests[5].contains("authorization: Bearer renewed-oci-token\r\n"));
    for request in [&requests[0], &requests[5]] {
        assert!(request.ends_with("exact-original-manifest"));
        assert!(request.contains("content-type: application/vnd.oci.image.index.v1+json\r\n"));
    }
}

#[tokio::test]
async fn manifest_document_bound_is_enforced_before_network_and_accepts_exact_limit() {
    let server = Server::start(|_| vec![Reply::status(201)]).await;
    let (client, _) = server.client();
    let authority = authority(&client, capabilities());
    let url = client.url("v2/aos/manifests/latest").unwrap();
    for path in [
        "v2/other/manifests/latest",
        "v2/aos/manifests/latest?unexpected=1",
    ] {
        assert!(
            authority
                .put_manifest(
                    &client,
                    client.url(path).unwrap(),
                    &HeaderMap::new(),
                    Bytes::from_static(b"document"),
                    &CancellationToken::new()
                )
                .await
                .is_err()
        );
    }

    assert!(
        authority
            .put_manifest(
                &client,
                url.clone(),
                &HeaderMap::new(),
                Bytes::from(vec![b'x'; 4 * 1024 * 1024 + 1]),
                &CancellationToken::new()
            )
            .await
            .is_err()
    );
    assert!(server.requests.lock().unwrap().is_empty());
    assert_eq!(
        authority
            .put_manifest(
                &client,
                url,
                &HeaderMap::new(),
                Bytes::from(vec![b'x'; 4 * 1024 * 1024]),
                &CancellationToken::new()
            )
            .await
            .unwrap()
            .status(),
        StatusCode::CREATED
    );

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].split_once("\r\n\r\n").unwrap().1.len(),
        4 * 1024 * 1024
    );
}

#[tokio::test]
async fn local_stage_paths_refuses_fifo_before_any_control_or_provider_effect() {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};

    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let fifo = directory.path().join("source.fifo");
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .unwrap();
    let server = Server::start(|_| vec![]).await;
    let hub = HubClient::connect_with_token(&server.origin, "original-oci-token").unwrap();
    let metrics = Arc::new(aos_net::direct_upload::DirectTransferMetrics::default());
    let options = aos_remote::DirectUploadOptions {
        journal: Some(directory.path().join("direct.sqlite")),
        metrics: metrics.clone(),
        ..Default::default()
    };
    let opened = options.open(&hub, capabilities()).await;
    let root_owner = std::fs::metadata("/").unwrap().uid();
    if ![0, rustix::process::geteuid().as_raw()].contains(&root_owner) {
        // Custody must refuse a foreign sandbox root before opening any source.
        assert_eq!(opened.unwrap_err(), DirectClientError::Checkpoint);
        assert!(!directory.path().join("direct.sqlite").exists());
        assert!(server.requests().is_empty());
        assert_eq!(metrics.snapshot().provider_attempts, 0);
        return;
    }
    let coordinator = opened.unwrap();

    let result = tokio::time::timeout(
        Duration::from_secs(1),
        coordinator.stage_paths(vec![aos_remote::DirectStagePath {
            source: fifo.clone(),
            expected_sha256: None,
            target: DirectUploadTarget::OciBlob {
                upload_id: "retained-upload".into(),
            },
            phase: DirectDependencyPhase::Content,
        }]),
    )
    .await;
    if result.is_err() {
        // Permit a defective blocking opener to finish after the timeout.
        let _ = std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32)
            .open(&fifo);
    }

    assert_eq!(result.unwrap().unwrap_err(), DirectClientError::Invalid);
    assert!(server.requests().is_empty());
    let observed = metrics.snapshot();
    use aos_net::direct_upload::DirectControlKind::*;
    for kind in [
        Capabilities,
        Begin,
        Status,
        Grant,
        Report,
        Complete,
        Abort,
        Identity,
        ManifestBegin,
        ManifestAppend,
        ManifestSeal,
        PublicationCommit,
        MetadataRead,
    ] {
        assert_eq!(observed.control_attempts(kind), 0);
    }
    assert_eq!(observed.provider_attempts, 0);
    assert_eq!(observed.acknowledged_payload_bytes, 0);
}
