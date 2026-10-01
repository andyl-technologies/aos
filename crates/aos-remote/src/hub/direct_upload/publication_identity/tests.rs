//! Actual HTTP identity proof, token snapshot and pre-mutation refusal.

use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
    mpsc,
};
use std::thread;

use super::*;
use aos_proto_types::*;

struct Authentication(AtomicUsize);
impl std::fmt::Debug for Authentication {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Authentication([private])")
    }
}
#[async_trait::async_trait]
impl super::super::DirectHubAuthentication for Authentication {
    async fn authenticate(&self, base: &str) -> Result<HubClient, DirectClientError> {
        let token = if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
            "private-jwt-a"
        } else {
            "private-jwt-b"
        };
        HubClient::connect_with_token(base, token).map_err(|_| DirectClientError::Invalid)
    }
}

fn proof(mode: &str, principal: &str) -> Vec<u8> {
    serde_json::to_vec(&WhoAmIResponse {
        deployment_id: "deployment".into(),
        principal_id: principal.into(),
        transfer_mode: mode.into(),
        ..Default::default()
    })
    .unwrap()
}

fn server(
    replies: Vec<(u16, Vec<u8>)>,
) -> (String, mpsc::Receiver<Vec<u8>>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let (sender, receiver) = mpsc::channel();
    let worker = thread::spawn(move || {
        for (status, body) in replies {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            loop {
                let mut buffer = [0_u8; 4096];
                let count = stream.read(&mut buffer).unwrap();
                assert_ne!(count, 0);
                request.extend_from_slice(&buffer[..count]);
                assert!(request.len() <= 256 * 1024 + 8192);
                if let Some(end) = request.windows(4).position(|value| value == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&request[..end]).to_lowercase();
                    let length = headers
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
            let _ = sender.send(request);
            write!(stream, "HTTP/1.1 {status} Reply\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
            stream.write_all(&body).unwrap();
        }
    });
    (origin, receiver, worker)
}

#[tokio::test]
async fn changed_actor_after_discovery_refuses_before_any_registry_read_or_manifest_mutation() {
    let a = "aa".repeat(32);
    let b = "bb".repeat(32);
    let (origin, requests, worker) = server(vec![
        (200, proof("direct_required", &a)),
        (200, proof("direct_required", &b)),
    ]);
    let hub = HubClient::connect_with_token(&origin, "seed-jwt").unwrap();
    let options = DirectUploadOptions {
        authentication: Some(Arc::new(Authentication(AtomicUsize::new(0)))),
        ..Default::default()
    };
    let discovery = discover_publication_transport(&hub, &options)
        .await
        .unwrap();
    let request = BeginRegistryPublicationRequest {
        registry: "registry".into(),
        generation: "cc".repeat(32),
        refs_digest: "dd".repeat(32),
        default_commit: "ee".repeat(32),
        parent_publication_id: String::new(),
        objects: vec![RegistryPublicationObjectInput {
            path: "HEAD".into(),
            sha256: "ff".repeat(32),
            byte_size: 1,
            kind: "mutable_pointer".into(),
            media_type: "text/plain".into(),
        }],
    };
    assert_eq!(
        super::super::prepare_direct_publication(&hub, &request, &options, &discovery)
            .await
            .unwrap_err(),
        DirectClientError::Invalid
    );
    worker.join().unwrap();
    let requests = requests.into_iter().collect::<Vec<_>>();
    assert_eq!(requests.len(), 2);
    assert!(requests.iter().all(|request| {
        String::from_utf8_lossy(request).starts_with("POST /aos.hub.v1.IdentityService/WhoAmI ")
    }));
}

#[tokio::test]
async fn renewal_proves_and_sends_same_owned_bearer_without_shared_token_reread() {
    let a = "aa".repeat(32);
    let (origin, requests, worker) = server(vec![
        (200, proof("direct_required", &a)),
        (200, proof("direct_required", &a)),
        (
            200,
            serde_json::to_vec(&RegistryPublicationManifestSession::default()).unwrap(),
        ),
    ]);
    let hub = HubClient::connect_with_token(&origin, "seed-jwt").unwrap();
    let options = DirectUploadOptions {
        authentication: Some(Arc::new(Authentication(AtomicUsize::new(0)))),
        ..Default::default()
    };
    let control = PublicationControl::new(&hub, &options).await.unwrap();
    let _: RegistryPublicationManifestSession = control
        .call(
            HubTopologyMethod::BeginRegistryPublicationManifest,
            &BeginRegistryPublicationManifestRequest::default(),
            256 * 1024,
        )
        .await
        .unwrap();
    worker.join().unwrap();
    let requests = requests
        .into_iter()
        .map(|bytes| String::from_utf8(bytes).unwrap().to_lowercase())
        .collect::<Vec<_>>();
    assert_eq!(requests.len(), 3);
    assert!(requests[0].contains("authorization: bearer private-jwt-a"));
    assert!(requests[1].contains("authorization: bearer private-jwt-b"));
    assert!(requests[2].contains("authorization: bearer private-jwt-b"));
    assert!(
        requests[2]
            .starts_with("post /aos.hub.v1.publishservice/beginregistrypublicationmanifest ")
    );
    assert!(!format!("{:?}", options).contains("private-jwt"));
}

#[tokio::test]
async fn transport_discovery_preserves_successful_legacy_but_never_errors_unknown_or_missing_direct_identity()
 {
    for (mode, principal, accepted) in [
        ("", "", true),
        ("legacy", "", true),
        ("direct_required", "", false),
        ("not-a-protocol", "", false),
    ] {
        let (origin, _, worker) = server(vec![(200, proof(mode, principal))]);
        let hub = HubClient::connect_with_token(&origin, "seed-jwt").unwrap();
        let result = discover_publication_transport(&hub, &DirectUploadOptions::default()).await;
        assert_eq!(result.is_ok(), accepted);
        if let Ok(discovery) = result {
            assert_eq!(
                discovery.transfer_mode(),
                DirectAdvertisedTransferMode::Legacy
            );
        }
        worker.join().unwrap();
    }
    let (origin, _, worker) = server(vec![(503, b"private-error-canary".to_vec())]);
    let hub = HubClient::connect_with_token(&origin, "seed-jwt").unwrap();
    let error = discover_publication_transport(&hub, &DirectUploadOptions::default())
        .await
        .unwrap_err();
    assert_eq!(error, DirectClientError::ControlUnavailable);
    assert!(!format!("{error:?} {error}").contains("private-error-canary"));
    worker.join().unwrap();
}
