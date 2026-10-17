//! Actual old-server discovery and legacy-body credential confinement.

use super::*;
use crate::backend::{AuthOptions, CacheBackend};
use aos_net::{Credential, TransferEngine, TransferEngineConfig, TransferRequest};
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

fn server(
    replies: Vec<(u16, Vec<u8>)>,
) -> (String, mpsc::Receiver<String>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    server_on(listener, origin, replies)
}

fn server_on(
    listener: TcpListener,
    origin: String,
    replies: Vec<(u16, Vec<u8>)>,
) -> (String, mpsc::Receiver<String>, thread::JoinHandle<()>) {
    let (send, receive) = mpsc::channel();
    let worker = thread::spawn(move || {
        for (status, body) in replies {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            loop {
                let mut bytes = [0_u8; 4096];
                let count = stream.read(&mut bytes).unwrap();
                assert_ne!(count, 0);
                request.extend_from_slice(&bytes[..count]);
                assert!(request.len() < 256 * 1024 + 8192);
                if let Some(end) = request.windows(4).position(|value| value == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&request[..end]).to_lowercase();
                    let size = headers
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length: "))
                        .unwrap_or("0")
                        .parse::<usize>()
                        .unwrap();
                    if request.len() >= end + 4 + size {
                        break;
                    }
                }
            }
            send.send(String::from_utf8(request).unwrap()).unwrap();
            write!(stream, "HTTP/1.1 {status} Reply\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n", body.len()).unwrap();
            stream.write_all(&body).unwrap();
        }
    });
    (origin, receive, worker)
}

async fn backend(origin: &str) -> (HttpBackend, Arc<TransferEngine>) {
    let engine = Arc::new(TransferEngine::new(TransferEngineConfig::default()));
    let auth = AuthOptions {
        headers: vec!["Authorization: Bearer private-actor-a".into()],
        ..Default::default()
    };
    let backend = HttpBackend::new(&format!("{origin}/default"), &auth, engine.clone())
        .await
        .unwrap();
    backend.is_hub.store(true, Ordering::Relaxed);
    (backend, engine)
}

fn legacy_proof(mode: &str, reference: &str, modern: bool) -> Vec<u8> {
    serde_json::to_vec(&aos_proto_types::WhoAmIResponse {
        principal_kind: "user".into(),
        principal_ref: reference.into(),
        deployment_id: if modern {
            "deployment".into()
        } else {
            String::new()
        },
        principal_id: if modern {
            "ab".repeat(32)
        } else {
            String::new()
        },
        transfer_mode: mode.into(),
        ..Default::default()
    })
    .unwrap()
}

#[tokio::test]
async fn unsupported_direct_policy_preserves_reads_but_refuses_upload_dispatch() {
    let (origin, receive, worker) = server(vec![
        (200, b"downloaded-object".to_vec()),
        (200, vec![]),
        (200, legacy_proof("direct_required", "a@example.test", true)),
    ]);
    let (backend, engine) = backend(&origin).await;

    for request in [
        TransferRequest::get(&format!("{origin}/default/nar/object")),
        TransferRequest::head(&format!("{origin}/default/nar/object")),
    ] {
        let request = backend.add_headers(request).await.unwrap();
        let admitted = backend.guard_unsupported_hub_upload(request).await.unwrap();
        let response = engine.execute(admitted).await.unwrap();
        assert_eq!(response.status, 200);
    }
    let request = backend
        .add_headers(TransferRequest::put(
            &format!("{origin}/default/nar/object"),
            b"never-dispatched-upload-canary".to_vec(),
        ))
        .await
        .unwrap();
    assert!(backend.guard_unsupported_hub_upload(request).await.is_err());

    worker.join().unwrap();
    let requests = receive.into_iter().collect::<Vec<_>>();
    assert_eq!(requests.len(), 3);
    assert!(requests[0].starts_with("GET /default/nar/object "));
    assert!(requests[1].starts_with("HEAD /default/nar/object "));
    assert!(requests[2].starts_with("POST /aos.hub.v1.IdentityService/WhoAmI "));
    assert!(requests.iter().all(|request| !request.starts_with("PUT ")
        && !request.contains("never-dispatched-upload-canary")));
}

#[derive(Debug)]
struct ExpiringAuthentication {
    started: std::time::Instant,
}

#[async_trait::async_trait]
impl aos_remote::DirectHubAuthentication for ExpiringAuthentication {
    async fn authenticate(
        &self,
        base: &str,
    ) -> Result<HubClient, aos_net::direct_upload::DirectClientError> {
        let token = if self.started.elapsed() >= Duration::from_secs(1) {
            "renewed-private-actor-a"
        } else {
            "private-actor-a"
        };
        HubClient::connect_with_token(base, token)
            .map_err(|_| aos_net::direct_upload::DirectClientError::Invalid)
    }
}

#[tokio::test]
async fn real_elapsed_original_provider_renewal_reproves_legacy_tuple_before_body() {
    let (origin, receive, worker) = server(vec![
        (200, legacy_proof("", "a@example.test", false)),
        (200, legacy_proof("", "a@example.test", false)),
        (200, vec![]),
    ]);
    let (mut backend, engine) = backend(&origin).await;
    backend.direct_options.authentication = Some(Arc::new(ExpiringAuthentication {
        started: std::time::Instant::now(),
    }));
    assert!(backend.discover_direct(32, 0).await.unwrap().is_none());
    tokio::time::sleep(Duration::from_millis(1100)).await;
    // An unrelated shared-cache actor must not override the original provider.
    engine.auth().set(
        "127.0.0.1",
        Credential::Bearer {
            token: "private-actor-b".into(),
            refresh: None,
        },
    );
    backend.put_cache_info("private-cache-body").await.unwrap();
    worker.join().unwrap();
    let requests = receive.into_iter().collect::<Vec<_>>();
    assert_eq!(requests.len(), 3);
    assert!(requests[0].contains("authorization: Bearer private-actor-a"));
    assert!(
        requests[1].contains("/WhoAmI ")
            && requests[1].contains("authorization: Bearer renewed-private-actor-a")
    );
    assert!(requests[2].starts_with("PUT /default/nix-cache-info "));
    assert!(requests[2].contains("authorization: Bearer renewed-private-actor-a"));
    assert!(
        requests
            .iter()
            .all(|r| !r.contains("private-actor-b") && !r.contains("GetCapabilities"))
    );
}

#[tokio::test]
async fn changed_legacy_tuple_modern_pin_or_direct_policy_refuses_new_bearer_before_body() {
    for (modern, response) in [
        (false, legacy_proof("legacy", "b@example.test", false)),
        (true, legacy_proof("legacy", "a@example.test", false)),
        (
            false,
            legacy_proof("direct_required", "a@example.test", true),
        ),
    ] {
        let (origin, receive, worker) = server(vec![
            (200, legacy_proof("legacy", "a@example.test", modern)),
            (200, response),
        ]);
        let engine = Arc::new(TransferEngine::new(TransferEngineConfig::default()));
        engine.auth().set(
            "127.0.0.1",
            Credential::Bearer {
                token: "private-actor-a".into(),
                refresh: None,
            },
        );
        let backend = HttpBackend::new(
            &format!("{origin}/default"),
            &AuthOptions::default(),
            engine.clone(),
        )
        .await
        .unwrap();
        backend.is_hub.store(true, Ordering::Relaxed);
        engine.auth().set(
            "127.0.0.1",
            Credential::Bearer {
                token: "private-actor-a".into(),
                refresh: None,
            },
        );
        assert!(backend.discover_direct(32, 0).await.unwrap().is_none());
        engine.auth().set(
            "127.0.0.1",
            Credential::Bearer {
                token: "private-actor-b".into(),
                refresh: None,
            },
        );
        assert!(backend.put_cache_info("private-cache-body").await.is_err());
        worker.join().unwrap();
        let requests = receive.into_iter().collect::<Vec<_>>();
        assert_eq!(requests.len(), 2);
        assert!(requests.iter().all(|r| r.contains("/WhoAmI ")
            && !r.contains("private-cache-body")
            && !r.starts_with("PUT ")));
    }
}

#[tokio::test]
async fn old_server_without_getcaps_preserves_legacy_and_sends_only_the_proved_bearer() {
    let (origin, receive, worker) = server(vec![
        (200, legacy_proof("legacy", "a@example.test", false)),
        (200, vec![]),
        (200, b"narinfo".to_vec()),
        (200, vec![]),
    ]);
    let (backend, engine) = backend(&origin).await;
    engine.auth().set(
        "127.0.0.1",
        Credential::Bearer {
            token: "private-actor-b".into(),
            refresh: None,
        },
    );
    assert!(
        matches!(engine.auth().get(&origin), Some(Credential::Bearer { token, .. }) if token == "private-actor-b")
    );
    assert!(backend.discover_direct(32, 0).await.unwrap().is_none());
    engine.auth().set(
        "127.0.0.1",
        Credential::Bearer {
            token: "private-actor-b".into(),
            refresh: None,
        },
    );
    backend.put_cache_info("private-cache-body").await.unwrap();
    assert_eq!(backend.get_narinfo("store-hash").await.unwrap(), "narinfo");
    assert!(backend.has_narinfo("store-hash").await.unwrap());
    worker.join().unwrap();
    let requests = receive.into_iter().collect::<Vec<_>>();
    assert_eq!(requests.len(), 4);
    assert!(requests[0].starts_with("POST /aos.hub.v1.IdentityService/WhoAmI "));
    assert!(requests[1].starts_with("PUT /default/nix-cache-info "));
    for request in &requests {
        let lower = request.to_lowercase();
        assert_eq!(lower.matches("authorization:").count(), 1);
        assert!(lower.contains("authorization: bearer private-actor-a"));
        assert!(!lower.contains("private-actor-b"));
        assert!(!request.contains("GetCapabilities"));
    }
}

#[tokio::test]
async fn direct_required_unready_target_sends_zero_legacy_file_bodies() {
    let proof = serde_json::to_vec(&aos_proto_types::WhoAmIResponse {
        deployment_id: "deployment".into(),
        principal_id: "ab".repeat(32),
        transfer_mode: "direct_required".into(),
        ..Default::default()
    })
    .unwrap();
    let (origin, receive, worker) = server(vec![
        (200, proof),
        (503, b"private-provider-error".to_vec()),
    ]);
    let (backend, _) = backend(&origin).await;
    assert!(backend.put_cache_info("private-cache-body").await.is_err());
    worker.join().unwrap();
    let requests = receive.into_iter().collect::<Vec<_>>();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].contains("/WhoAmI "));
    assert!(requests[1].contains("/GetCapabilities "));
    assert!(
        requests
            .iter()
            .all(|request| !request.contains("private-cache-body") && !request.starts_with("PUT "))
    );
    assert!(backend.legacy_direct_bearer.get().is_none());
}

#[tokio::test]
async fn changed_actor_target_reply_never_adopts_legacy_or_sends_cache_bytes() {
    let proof = serde_json::to_vec(&aos_proto_types::WhoAmIResponse {
        deployment_id: "deployment".into(),
        principal_id: "ab".repeat(32),
        transfer_mode: "direct_required".into(),
        ..Default::default()
    })
    .unwrap();
    let (origin, receive, worker) = {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let caps = DirectUploadCapabilities {
            target: DirectCapabilitiesTarget::Cache {
                cache_id: "cache".into(),
            },
            requested_delivery_url: Some(format!("{origin}/default")),
            deployment_id: "deployment".into(),
            principal_id: "cd".repeat(32),
            version: 1,
            capability: DIRECT_UPLOAD_CAPABILITY.into(),
            transfer_mode: DirectAdvertisedTransferMode::DirectRequired,
            config_generation: WireInteger::new(1),
            valid_until: WireInteger::new(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    + 600,
            ),
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
        };
        server_on(
            listener,
            origin,
            vec![(200, proof), (200, encode_direct_control(&caps).unwrap())],
        )
    };
    let (backend, _) = backend(&origin).await;
    assert!(backend.put_cache_info("private-cache-body").await.is_err());
    worker.join().unwrap();
    let requests = receive.into_iter().collect::<Vec<_>>();
    assert_eq!(requests.len(), 2);
    assert!(
        requests
            .iter()
            .all(|request| !request.contains("private-cache-body") && !request.starts_with("PUT "))
    );
    assert!(backend.legacy_direct_bearer.get().is_none());
}

#[tokio::test]
async fn generic_bearer_store_preserves_transport_without_hub_discovery() {
    let (origin, receive, worker) = server(vec![(200, vec![])]);
    let engine = Arc::new(TransferEngine::new(TransferEngineConfig::default()));
    let auth = AuthOptions {
        headers: vec!["Authorization: Bearer generic-private-token".into()],
        ..Default::default()
    };
    let backend = HttpBackend::new(&format!("{origin}/default"), &auth, engine)
        .await
        .unwrap();

    backend.put_cache_info("generic-cache-body").await.unwrap();

    worker.join().unwrap();
    let requests = receive.into_iter().collect::<Vec<_>>();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].starts_with("PUT /default/nix-cache-info "));
    assert!(requests[0].contains("authorization: Bearer generic-private-token"));
    assert!(requests[0].contains("generic-cache-body"));
    assert!(!requests[0].contains("WhoAmI") && !requests[0].contains("GetCapabilities"));
}
