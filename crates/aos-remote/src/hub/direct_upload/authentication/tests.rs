//! Actual OAuth returned-lifetime reuse and consuming-protocol actor proof.

use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::*;
use crate::{DirectUploadOptions, discover_publication_transport};

struct Reply {
    status: u16,
    body: Vec<u8>,
    headers: &'static str,
    delay: Duration,
}

fn grant(token: &str, seconds: i64) -> Reply {
    Reply {
        status: 200,
        body: serde_json::to_vec(&serde_json::json!({
            "access_token": token, "token_type": "Bearer", "expires_in": seconds,
        }))
        .unwrap(),
        headers: "",
        delay: Duration::ZERO,
    }
}

fn identity(reference: &str) -> Reply {
    Reply {
        status: 200,
        body: serde_json::to_vec(&aos_proto_types::WhoAmIResponse {
            principal_kind: "user".into(),
            principal_ref: reference.into(),
            deployment_id: "deployment".into(),
            principal_id: "ab".repeat(32),
            transfer_mode: "legacy".into(),
            ..Default::default()
        })
        .unwrap(),
        headers: "",
        delay: Duration::ZERO,
    }
}

struct Server {
    origin: String,
    requests: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Server {
    async fn new(replies: Vec<Reply>) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = requests.clone();
        let task = tokio::spawn(async move {
            for reply in replies {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                loop {
                    let mut buffer = [0; 4096];
                    let read = stream.read(&mut buffer).await.unwrap();
                    assert!(read > 0);
                    request.extend_from_slice(&buffer[..read]);
                    assert!(request.len() < 64 * 1024 + 8192);
                    if let Some(end) = request.windows(4).position(|v| v == b"\r\n\r\n") {
                        let headers = std::str::from_utf8(&request[..end]).unwrap().to_lowercase();
                        let length = headers
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length: "))
                            .unwrap_or("0")
                            .parse::<usize>()
                            .unwrap();
                        if request.len() >= end + 4 + length {
                            break;
                        }
                    }
                }
                captured
                    .lock()
                    .unwrap()
                    .push(String::from_utf8(request).unwrap());
                tokio::time::sleep(reply.delay).await;
                let head = format!(
                    "HTTP/1.1 {} Reply\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n{}\r\n",
                    reply.status,
                    reply.body.len(),
                    reply.headers
                );
                stream.write_all(head.as_bytes()).await.unwrap();
                let _ = stream.write_all(&reply.body).await;
            }
        });
        Self {
            origin,
            requests,
            task,
        }
    }

    async fn finish(self) -> Vec<String> {
        self.task.await.unwrap();
        self.requests.lock().unwrap().clone()
    }
}

#[tokio::test]
async fn genuine_returned_ttl_reuses_owned_grant_then_reproves_renewed_legacy_actor() {
    for reference in ["actor-a@example.test", "actor-b@example.test"] {
        let server = Server::new(vec![
            grant("owned-token-a", 1),
            identity("actor-a@example.test"),
            grant("owned-renewed-token", 600),
            identity(reference),
        ])
        .await;
        let provider = Arc::new(
            DirectProvisioningAuthentication::new(
                &server.origin,
                "private-provisioning-canary".into(),
            )
            .unwrap(),
        );
        let options = DirectUploadOptions {
            authentication: Some(provider.clone()),
            ..Default::default()
        };
        let shared =
            HubClient::connect_with_token(&server.origin, "unrelated-shared-token").unwrap();
        let proof = discover_publication_transport(&shared, &options)
            .await
            .unwrap();
        let mut bearer = proof.legacy_bearer().unwrap();

        for _ in 0..8 {
            bearer.refresh(&shared, &options).await.unwrap();
        }
        assert_eq!(server.requests.lock().unwrap().len(), 2);
        tokio::time::sleep(Duration::from_millis(1050)).await;
        let renewed = bearer.refresh(&shared, &options).await;

        assert_eq!(renewed.is_ok(), reference == "actor-a@example.test");
        let requests = server.finish().await;
        assert_eq!(requests.len(), 4);
        assert_eq!(
            requests
                .iter()
                .filter(|r| r.starts_with("POST /oauth2/token "))
                .count(),
            2
        );
        assert!(requests[0].contains("authorization: Bearer private-provisioning-canary"));
        assert!(
            requests[0].contains(
                "grant_type=urn%3Aaos%3Aparams%3Aoauth%3Agrant-type%3Aprovisioning-token"
            )
        );
        assert!(requests[3].contains("authorization: Bearer owned-renewed-token"));
        assert!(
            requests
                .iter()
                .all(|r| !r.contains("unrelated-shared-token"))
        );
        assert!(!format!("{provider:?}").contains("private-provisioning-canary"));
    }
}

#[tokio::test]
async fn response_latency_consumes_returned_ttl_and_invalid_grants_are_never_cached() {
    for first in [
        grant("invalid-token", 0),
        grant("invalid-token", -1),
        Reply {
            delay: Duration::from_millis(1000),
            ..grant("too-late-token", 1)
        },
        Reply {
            body: vec![b'x'; MAX_GRANT_BYTES + 1],
            ..grant("too-large-token", 600)
        },
    ] {
        let server = Server::new(vec![first, grant("valid-owned-token", 600)]).await;
        let provider = DirectProvisioningAuthentication::new(
            &server.origin,
            "private-provisioning-canary".into(),
        )
        .unwrap();

        let error = provider.authenticate(&server.origin).await.err().unwrap();
        assert!(!format!("{error:?} {error}").contains("token"));
        let valid = provider.authenticate(&server.origin).await.unwrap();
        assert_eq!(valid.token.as_deref(), Some("valid-owned-token"));

        assert_eq!(server.finish().await.len(), 2);
    }
}

#[tokio::test]
async fn different_origin_and_redirect_never_exchange_elsewhere_or_extend_authority() {
    let server = Server::new(vec![Reply {
        status: 302,
        body: b"private-provider-error-canary".to_vec(),
        headers: "Location: http://127.0.0.1:9/foreign\r\n",
        delay: Duration::ZERO,
    }])
    .await;
    let provider =
        DirectProvisioningAuthentication::new(&server.origin, "private-provisioning-canary".into())
            .unwrap();

    assert_eq!(
        provider
            .authenticate("http://127.0.0.1:9")
            .await
            .err()
            .unwrap(),
        DirectClientError::Invalid
    );
    assert!(server.requests.lock().unwrap().is_empty());
    let error = provider.authenticate(&server.origin).await.err().unwrap();

    assert_eq!(error, DirectClientError::Denied);
    assert!(!format!("{error:?} {error} {provider:?}").contains("canary"));
    assert_eq!(server.finish().await.len(), 1);
}
