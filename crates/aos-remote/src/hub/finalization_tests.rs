//! Actual HTTP coverage of exact, bounded staged-release finalization retries.

use std::sync::{Arc, Mutex};

use aos_proto_types::{FinalizeStagedReleaseRequest, StagedRelease};
use serde_json::json;
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

use super::{HubClient, hub_rpc};

type CapturedRequests = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

async fn peer(
    replies: Vec<(u16, serde_json::Value)>,
) -> (HubClient, CapturedRequests, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let captured = Arc::new(Mutex::new(Vec::new()));
    let requests = Arc::clone(&captured);
    let task = tokio::spawn(async move {
        for (status, body) in replies {
            let (socket, _) = listener.accept().await.unwrap();
            let mut input = tokio::io::BufReader::new(socket);
            let mut first = String::new();
            input.read_line(&mut first).await.unwrap();
            let mut length = None;
            loop {
                let mut line = String::new();
                assert!(input.read_line(&mut line).await.unwrap() > 0);
                if line == "\r\n" {
                    break;
                }
                if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = Some(value.trim().parse::<usize>().unwrap());
                }
            }
            let length = length.unwrap();
            assert!(length < 4096);
            let mut bytes = vec![0; length];
            input.read_exact(&mut bytes).await.unwrap();
            requests.lock().unwrap().push((first, bytes));

            let body = serde_json::to_vec(&body).unwrap();
            let header = format!(
                "HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            input.get_mut().write_all(header.as_bytes()).await.unwrap();
            input.get_mut().write_all(&body).await.unwrap();
        }
    });
    (
        HubClient::connect_anonymous(&origin).unwrap(),
        captured,
        task,
    )
}

fn request() -> FinalizeStagedReleaseRequest {
    FinalizeStagedReleaseRequest {
        registry: "fixture/registry".into(),
        stage_id: "fixture-stage".into(),
        expected_revision: 7,
        release_id: "1.0.0".into(),
    }
}

#[tokio::test]
async fn temporary_finalization_refusal_retries_identical_request_bytes() {
    let (client, captured, task) = peer(vec![
        (
            503,
            json!({"code": "unavailable", "message": "temporarily unavailable"}),
        ),
        (200, serde_json::to_value(StagedRelease::default()).unwrap()),
    ])
    .await;

    let result = client
        .call_topology(hub_rpc::FinalizeStagedRelease, &request())
        .await;
    task.abort();
    assert!(result.is_ok());
    let requests = captured.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0], requests[1]);
    assert_eq!(requests[0].1, serde_json::to_vec(&request()).unwrap());
}

#[tokio::test]
async fn finalization_conflict_is_not_retried() {
    let (client, captured, task) = peer(vec![
        (
            400,
            json!({"code": "failed_precondition", "message": "stage changed"}),
        ),
        (200, serde_json::to_value(StagedRelease::default()).unwrap()),
    ])
    .await;

    let result = client
        .call_topology(hub_rpc::FinalizeStagedRelease, &request())
        .await;
    task.abort();

    assert!(result.is_err());
    assert_eq!(captured.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn temporary_finalization_refusals_are_bounded_to_three_attempts() {
    let refusal = json!({"code": "unavailable", "message": "temporarily unavailable"});
    let (client, captured, task) = peer(vec![(503, refusal); 4]).await;

    let result = client
        .call_topology(hub_rpc::FinalizeStagedRelease, &request())
        .await;
    task.abort();

    assert!(result.is_err());
    assert_eq!(captured.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn ordinary_stage_reads_do_not_retry_service_refusals() {
    let refusal = json!({"code": "unavailable", "message": "temporarily unavailable"});
    let (client, captured, task) = peer(vec![(503, refusal); 2]).await;
    let request = aos_proto_types::GetStagedReleaseRequest {
        registry: "fixture/registry".into(),
        stage_id: "fixture-stage".into(),
    };

    let result = client
        .call_topology(hub_rpc::GetStagedRelease, &request)
        .await;
    task.abort();

    assert!(result.is_err());
    assert_eq!(captured.lock().unwrap().len(), 1);
}
