//! Real elapsed-expiry renewal, exact request replay and changed-authority refusal.

use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
    mpsc,
};
use std::thread;

use super::*;

#[derive(Debug)]
struct Authentication(AtomicUsize);

#[async_trait]
impl DirectHubAuthentication for Authentication {
    async fn authenticate(&self, base: &str) -> Result<HubClient, DirectClientError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        HubClient::connect_with_token(base, "renewed-private-jwt")
            .map_err(|_| DirectClientError::Invalid)
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn capabilities(expiry: u64) -> DirectUploadCapabilities {
    DirectUploadCapabilities {
        target: DirectCapabilitiesTarget::Publication {
            publication_id: "publication".into(),
        },
        requested_delivery_url: None,
        deployment_id: "deployment".into(),
        principal_id: "de".repeat(32),
        version: 1,
        capability: DIRECT_UPLOAD_CAPABILITY.into(),
        transfer_mode: DirectAdvertisedTransferMode::DirectRequired,
        config_generation: WireInteger::new(1),
        valid_until: WireInteger::new(expiry),
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

fn server(
    replies: Vec<(u16, Vec<u8>)>,
) -> (String, mpsc::Receiver<Vec<u8>>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let (tx, rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        for (status, reply) in replies {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            loop {
                let mut bytes = [0_u8; 4096];
                let count = stream.read(&mut bytes).unwrap();
                assert!(count > 0);
                request.extend_from_slice(&bytes[..count]);
                assert!(request.len() <= MAX_DIRECT_CONTROL_BYTES + 8192);
                if let Some(end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                    let header = String::from_utf8_lossy(&request[..end]).to_ascii_lowercase();
                    let length = header
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length: "))
                        .unwrap()
                        .parse::<usize>()
                        .unwrap();
                    if request.len() >= end + 4 + length {
                        break;
                    }
                }
            }
            tx.send(request).unwrap();
            write!(stream, "HTTP/1.1 {status} Reply\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", reply.len()).unwrap();
            stream.write_all(&reply).unwrap();
        }
    });
    (origin, rx, worker)
}

#[tokio::test]
async fn elapsed_real_expiry_renews_same_actor_and_profile_from_original_authentication() {
    let original = capabilities(now() + 1);
    let renewed = capabilities(now() + 600);
    let (origin, requests, worker) = server(vec![(200, encode_direct_control(&renewed).unwrap())]);
    let hub = HubClient::connect_with_token(&origin, "expired-private-jwt").unwrap();
    let provider = Arc::new(Authentication(AtomicUsize::new(0)));
    let control = RefreshingControl::new(
        &hub,
        original.clone(),
        Some(provider.clone()),
        Arc::default(),
    )
    .unwrap();

    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(original.valid_until.get() <= now());
    let snapshot = control.snapshot().await.unwrap();

    assert_eq!(snapshot, renewed);
    assert_eq!(provider.0.load(Ordering::SeqCst), 1);
    let request =
        String::from_utf8(requests.recv_timeout(Duration::from_secs(5)).unwrap()).unwrap();
    assert!(request.starts_with("POST /aos.hub.v1.DirectUploadService/GetCapabilities"));
    assert!(
        request
            .to_ascii_lowercase()
            .contains("authorization: bearer renewed-private-jwt")
    );
    worker.join().unwrap();
}

#[tokio::test]
async fn renewed_actor_or_provider_profile_cannot_be_adopted_even_after_expiry() {
    for changed in [0, 1, 2, 3] {
        let original = capabilities(now());
        let mut renewed = capabilities(now() + 600);
        match changed {
            0 => renewed.principal_id = "11".repeat(32),
            1 => renewed.profiles[0].profile_fingerprint = "12".repeat(32),
            2 => renewed.maximum_batch_parts = 32,
            _ => renewed.minimum_object_bytes = WireInteger::new(1),
        }
        let (origin, requests, worker) =
            server(vec![(200, encode_direct_control(&renewed).unwrap())]);
        let hub = HubClient::connect_with_token(&origin, "expired-private-jwt").unwrap();
        let control = RefreshingControl::new(
            &hub,
            original,
            Some(Arc::new(Authentication(AtomicUsize::new(0)))),
            Arc::default(),
        )
        .unwrap();

        assert_eq!(
            control.snapshot().await.unwrap_err(),
            DirectClientError::Invalid
        );

        requests.recv_timeout(Duration::from_secs(5)).unwrap();
        worker.join().unwrap();
    }
}

#[tokio::test]
async fn actual_unauthorized_control_rotates_only_auth_and_replays_original_bytes() {
    let caps = capabilities(now() + 600);
    let request = DirectUploadRequest::StatusBatch(DirectBatch {
        operation_id: "ba".repeat(32),
        items: vec![DirectStatusQuery {
            session: DirectSessionRef {
                session_id: "session".into(),
                logical_fingerprint: "bf".repeat(32),
            },
            after: None,
            maximum_parts: 1,
        }],
    });
    let response = DirectUploadResponse {
        operation_id: "ba".repeat(32),
        sessions: vec![],
        grants: vec![],
        errors: vec![],
    };
    let (origin, requests, worker) = server(vec![
        (401, vec![]),
        (200, encode_direct_control(&caps).unwrap()),
        (200, encode_direct_control(&response).unwrap()),
    ]);
    let hub = HubClient::connect_with_token(&origin, "expired-private-jwt").unwrap();
    let provider = Arc::new(Authentication(AtomicUsize::new(0)));
    let control =
        RefreshingControl::new(&hub, caps, Some(provider.clone()), Arc::default()).unwrap();

    assert_eq!(control.execute(&request).await.unwrap(), response);

    let captured: Vec<_> = (0..3)
        .map(|_| requests.recv_timeout(Duration::from_secs(5)).unwrap())
        .collect();
    let first = String::from_utf8(captured[0].clone()).unwrap();
    let last = String::from_utf8(captured[2].clone()).unwrap();
    assert_eq!(
        first.split_once("\r\n\r\n").unwrap().1,
        last.split_once("\r\n\r\n").unwrap().1
    );
    assert!(
        first
            .to_ascii_lowercase()
            .contains("authorization: bearer expired-private-jwt")
    );
    assert!(
        last.to_ascii_lowercase()
            .contains("authorization: bearer renewed-private-jwt")
    );
    assert_eq!(provider.0.load(Ordering::SeqCst), 1);
    worker.join().unwrap();
}

#[tokio::test]
async fn changed_minimum_refuses_original_empty_begin_replay_after_authentication_renewal() {
    let original = capabilities(now() + 600);
    let mut renewed = original.clone();
    renewed.minimum_object_bytes = WireInteger::new(1);
    let intent = DirectUploadIntent {
        version: 1,
        client_operation_id: "aa".repeat(32),
        target: DirectUploadTarget::PublicationObject {
            publication_id: "publication".into(),
            surface_object_id: WireInteger::new(1),
            path: "empty-object".into(),
        },
        expected_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
        byte_size: WireInteger::new(0),
        part_size: WireInteger::new(8 * 1024 * 1024),
        dependency_phase: DirectDependencyPhase::Content,
        transfer_mode: DirectTransferMode::DirectRequired,
    };
    let request = DirectUploadRequest::BeginBatch(DirectBeginBatch {
        operation_id: "bb".repeat(32),
        items: vec![intent.clone()],
    });
    let (origin, requests, worker) = server(vec![
        (401, vec![]),
        (200, encode_direct_control(&renewed).unwrap()),
    ]);
    let hub = HubClient::connect_with_token(&origin, "original-private-jwt").unwrap();
    let control = RefreshingControl::new(
        &hub,
        original,
        Some(Arc::new(Authentication(AtomicUsize::new(0)))),
        Arc::default(),
    )
    .unwrap();

    assert_eq!(
        control.execute(&request).await,
        Err(DirectClientError::Invalid)
    );

    let first = requests.recv_timeout(Duration::from_secs(5)).unwrap();
    let end = first
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .unwrap();
    let original_begin: DirectBeginBatch = decode_direct_control(&first[end + 4..]).unwrap();
    assert_eq!(original_begin.items, vec![intent]);
    let renewal = requests.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(
        String::from_utf8(renewal)
            .unwrap()
            .starts_with("POST /aos.hub.v1.DirectUploadService/GetCapabilities")
    );
    worker.join().unwrap();
    assert!(requests.try_recv().is_err());
}
