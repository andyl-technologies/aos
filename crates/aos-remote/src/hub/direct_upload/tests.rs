//! Real local Hub HTTP request confinement, bounded replies and privacy.

use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;

use super::*;

#[tokio::test]
async fn unsupported_platform_policy_requires_positive_legacy_reply_before_body() {
    for (status, mode, accepted) in [
        ("200 OK", "", true),
        ("200 OK", "legacy", true),
        ("200 OK", "direct_required", false),
        ("200 OK", "future_mode", false),
        ("401 Unauthorized", "legacy", false),
    ] {
        let body = serde_json::to_vec(&aos_proto_types::WhoAmIResponse {
            transfer_mode: mode.into(),
            ..Default::default()
        })
        .unwrap();
        let (origin, captured, handle) = server(status, "Content-Type: application/json\r\n", body);
        let hub = HubClient::connect_with_token(&origin, "owned-policy-bearer").unwrap();

        let result = DirectHubControl::new(&hub)
            .unwrap()
            .require_legacy_transport()
            .await;

        assert_eq!(result.is_ok(), accepted);
        let request =
            String::from_utf8(captured.recv_timeout(Duration::from_secs(5)).unwrap()).unwrap();
        assert!(request.starts_with("POST /aos.hub.v1.IdentityService/WhoAmI "));
        assert!(
            request
                .to_ascii_lowercase()
                .contains("authorization: bearer owned-policy-bearer")
        );
        assert!(request.ends_with("{}"));
        handle.join().unwrap();
    }
}

fn server(
    status: &str,
    headers: &str,
    body: Vec<u8>,
) -> (String, mpsc::Receiver<Vec<u8>>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n",
        body.len()
    );
    let (sender, receiver) = mpsc::channel();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut request = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            let read = stream.read(&mut buffer).unwrap();
            assert!(read > 0);
            request.extend_from_slice(&buffer[..read]);
            assert!(request.len() <= MAX_DIRECT_CONTROL_BYTES + 8192);
            if let Some(offset) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                let header = String::from_utf8_lossy(&request[..offset]).to_ascii_lowercase();
                let length = header
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length: "))
                    .unwrap()
                    .parse::<usize>()
                    .unwrap();
                if request.len() >= offset + 4 + length {
                    break;
                }
            }
        }
        sender.send(request).unwrap();
        stream.write_all(response.as_bytes()).unwrap();
        // Oversized replies may be refused before the payload is consumed.
        let _ = stream.write_all(&body);
    });
    (origin, receiver, handle)
}

fn status_request() -> DirectUploadRequest {
    DirectUploadRequest::StatusBatch(DirectBatch {
        operation_id: "1a".repeat(32),
        items: vec![DirectStatusQuery {
            session: DirectSessionRef {
                session_id: "session".into(),
                logical_fingerprint: "1b".repeat(32),
            },
            after: None,
            maximum_parts: 1,
        }],
    })
}

#[tokio::test]
async fn actual_hub_request_is_bounded_typed_control_and_keeps_auth_on_hub() {
    let body = format!(
        "{{\"operationId\":\"{}\",\"sessions\":[],\"grants\":[],\"errors\":[]}}",
        "1a".repeat(32)
    )
    .into_bytes();
    let (origin, captured, handle) = server("200 OK", "Content-Type: application/json\r\n", body);
    let hub = HubClient::connect_with_token(&origin, "hub-credential-canary").unwrap();
    let control = DirectHubControl::new(&hub).unwrap();

    let response = control.execute(&status_request()).await.unwrap();

    assert_eq!(response.operation_id, "1a".repeat(32));
    let request =
        String::from_utf8(captured.recv_timeout(Duration::from_secs(5)).unwrap()).unwrap();
    assert!(request.starts_with("POST /aos.hub.v1.DirectUploadService/StatusBatch HTTP/1.1"));
    let (headers, body) = request.split_once("\r\n\r\n").unwrap();
    let headers = headers.to_ascii_lowercase();
    assert!(headers.contains("authorization: bearer hub-credential-canary"));
    assert!(headers.contains("connect-protocol-version: 1"));
    let body: DirectBatch<DirectStatusQuery> = decode_direct_control(body.as_bytes()).unwrap();
    assert_eq!(body.items.len(), 1);
    assert!(!format!("{control:?}").contains("hub-credential-canary"));
    handle.join().unwrap();
}

#[tokio::test]
async fn raw_failure_envelope_and_redirect_are_never_logged_or_used_as_fallback() {
    for (status, headers) in [
        ("503 Unavailable", ""),
        (
            "302 Found",
            "Location: https://provider.invalid/private?X-Amz-Signature=credential-canary\r\n",
        ),
    ] {
        let (origin, captured, handle) = server(
            status,
            headers,
            b"provider-error credential-canary".to_vec(),
        );
        let hub = HubClient::connect_with_token(&origin, "hub-credential-canary").unwrap();
        let error = DirectHubControl::new(&hub)
            .unwrap()
            .execute(&status_request())
            .await
            .unwrap_err();

        assert_eq!(
            error,
            if status.starts_with("503") {
                DirectClientError::ControlUnavailable
            } else {
                DirectClientError::Invalid
            }
        );
        assert!(!format!("{error:?} {error}").contains("credential-canary"));
        assert!(std::error::Error::source(&error).is_none());
        captured.recv_timeout(Duration::from_secs(5)).unwrap();
        handle.join().unwrap();
    }
}

#[tokio::test]
async fn oversized_unknown_duplicate_and_mismatched_success_responses_are_refused() {
    let operation = "1a".repeat(32);
    for body in [
        vec![b' '; MAX_DIRECT_CONTROL_BYTES + 1],
        format!("{{\"operationId\":\"{operation}\",\"unexpected\":\"credential-canary\"}}")
            .into_bytes(),
        format!("{{\"operationId\":\"{operation}\",\"operationId\":\"{operation}\"}}").into_bytes(),
        format!("{{\"operationId\":\"{}\"}}", "2a".repeat(32)).into_bytes(),
    ] {
        let (origin, captured, handle) =
            server("200 OK", "Content-Type: application/json\r\n", body);
        let hub = HubClient::connect_with_token(&origin, "hub-credential-canary").unwrap();
        let error = DirectHubControl::new(&hub)
            .unwrap()
            .execute(&status_request())
            .await
            .unwrap_err();

        assert_eq!(error, DirectClientError::Invalid);
        assert!(!format!("{error:?} {error}").contains("credential-canary"));
        captured.recv_timeout(Duration::from_secs(5)).unwrap();
        handle.join().unwrap();
    }
}

#[tokio::test]
async fn failed_discovery_never_selects_legacy_body_upload() {
    let (origin, captured, handle) = server(
        "404 Not Found",
        "",
        b"old-server credential-canary".to_vec(),
    );
    let hub = HubClient::connect_with_token(&origin, "hub-credential-canary").unwrap();
    let target = DirectCapabilitiesTarget::Cache {
        cache_id: "cache".into(),
    };

    let error = DirectHubControl::new(&hub)
        .unwrap()
        .capabilities(&target)
        .await
        .unwrap_err();

    assert_eq!(error, DirectClientError::Invalid);
    assert!(!format!("{error:?} {error}").contains("credential-canary"));
    let request =
        String::from_utf8(captured.recv_timeout(Duration::from_secs(5)).unwrap()).unwrap();
    assert!(request.starts_with("POST /aos.hub.v1.DirectUploadService/GetCapabilities"));
    handle.join().unwrap();
}

#[tokio::test]
async fn repeated_committed_session_cannot_cover_two_original_requests() {
    let session = DirectSessionStatus {
        session: DirectSessionRef {
            session_id: "session-1".into(),
            logical_fingerprint: "1b".repeat(32),
        },
        resource_version: WireInteger::new(1),
        intent: DirectUploadIntent {
            version: 1,
            client_operation_id: "1c".repeat(32),
            target: DirectUploadTarget::CacheObject {
                cache_id: "cache-1".into(),
                path: "nar/source.nar".into(),
            },
            expected_sha256: "1d".repeat(32),
            byte_size: WireInteger::new(3),
            part_size: WireInteger::new(8 * 1024 * 1024),
            dependency_phase: DirectDependencyPhase::Content,
            transfer_mode: DirectTransferMode::DirectRequired,
        },
        placements: vec![DirectPlacementRef {
            placement_id: WireInteger::new(1),
            placement_fingerprint: "ab".repeat(32),
            placement_resource_version: WireInteger::new(1),
            write_spec_version: WireInteger::new(1),
            binding_id: WireInteger::new(1),
            binding_resource_version: WireInteger::new(1),
            binding_write_revision: WireInteger::new(1),
            profile_fingerprint: "cd".repeat(32),
            private_policy_digest: "ef".repeat(32),
            checksum_algorithm: DirectChecksumAlgorithm::Sha256,
        }],
        state: DirectSessionState::Committed,
        parts: vec![],
        next_cursor: None,
        outstanding_grants: false,
    };
    session.validate().unwrap();
    let operation_id = "1a".repeat(32);
    let body = encode_direct_control(&DirectUploadResponse {
        operation_id: operation_id.clone(),
        sessions: vec![session.clone(), session.clone()],
        grants: vec![],
        errors: vec![],
    })
    .unwrap();
    let (origin, captured, handle) = server("200 OK", "Content-Type: application/json\r\n", body);
    let hub = HubClient::connect_with_token(&origin, "hub-credential-canary").unwrap();
    let request = DirectUploadRequest::StatusBatch(DirectBatch {
        operation_id,
        items: vec!["session-1", "session-2"]
            .into_iter()
            .map(|session_id| DirectStatusQuery {
                session: DirectSessionRef {
                    session_id: session_id.into(),
                    logical_fingerprint: "1b".repeat(32),
                },
                after: None,
                maximum_parts: 1,
            })
            .collect(),
    });

    let error = DirectHubControl::new(&hub)
        .unwrap()
        .execute(&request)
        .await
        .unwrap_err();

    assert_eq!(error, DirectClientError::Invalid);
    captured.recv_timeout(Duration::from_secs(5)).unwrap();
    handle.join().unwrap();
}
