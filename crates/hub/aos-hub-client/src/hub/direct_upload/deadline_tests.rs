//! Real HTTP deadlines for metadata controls and storage-bearing completion.

use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use super::{
    COMPLETE_TIMEOUT, CONTROL_TIMEOUT, DirectClientError, DirectHubControl, Duration, HubClient,
};

struct HeldControl {
    result: JoinHandle<Result<Vec<u8>, DirectClientError>>,
    received: oneshot::Receiver<()>,
    release: oneshot::Sender<()>,
    server: JoinHandle<()>,
}

async fn held_control(method: &'static str) -> HeldControl {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hub = HubClient::connect_anonymous(&format!("http://{}", listener.local_addr().unwrap()))
        .unwrap();
    let control = DirectHubControl::new(&hub).unwrap();
    let (received_tx, received) = oneshot::channel();
    let (release, release_rx) = oneshot::channel();

    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut input = tokio::io::BufReader::new(socket);
        let mut first = String::new();
        input.read_line(&mut first).await.unwrap();
        assert_eq!(
            first,
            format!("POST /aos.hub.v1.DirectUploadService/{method} HTTP/1.1\r\n")
        );

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
        let mut body = vec![0; length];
        input.read_exact(&mut body).await.unwrap();
        received_tx.send(()).unwrap();
        release_rx.await.unwrap();

        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}";
        // The metadata-control case deliberately closes before this response.
        let _ = input.get_mut().write_all(response).await;
    });

    let result = tokio::spawn(async move {
        control
            .post_bytes(
                &format!("aos.hub.v1.DirectUploadService/{method}"),
                &serde_json::json!({"operationId": "fixture", "items": []}),
                4096,
            )
            .await
    });
    HeldControl {
        result,
        received,
        release,
        server,
    }
}

#[tokio::test]
async fn completion_response_can_outlive_the_metadata_control_deadline() {
    let held = held_control("CompleteBatch").await;
    held.received.await.unwrap();

    tokio::time::pause();
    tokio::time::advance(CONTROL_TIMEOUT + Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    assert!(
        !held.result.is_finished(),
        "completion must retain its caller while destination copies finish"
    );
    tokio::time::resume();

    held.release.send(()).unwrap();
    assert_eq!(held.result.await.unwrap().unwrap(), b"{}");
    held.server.await.unwrap();
}

#[tokio::test]
async fn metadata_controls_keep_the_original_deadline() {
    let held = held_control("StatusBatch").await;
    held.received.await.unwrap();

    tokio::time::pause();
    tokio::time::advance(CONTROL_TIMEOUT + Duration::from_secs(1)).await;
    let result = tokio::time::timeout(Duration::from_secs(1), held.result)
        .await
        .expect("metadata controls must release their caller at the original deadline")
        .unwrap();
    assert_eq!(result, Err(DirectClientError::ControlUnavailable));
    tokio::time::resume();

    held.release.send(()).unwrap();
    held.server.await.unwrap();
}

#[tokio::test]
async fn stalled_completion_still_has_a_bounded_deadline() {
    let held = held_control("CompleteBatch").await;
    held.received.await.unwrap();

    tokio::time::pause();
    tokio::time::advance(COMPLETE_TIMEOUT + Duration::from_secs(1)).await;
    let result = tokio::time::timeout(Duration::from_secs(1), held.result)
        .await
        .expect("completion must release its caller if storage never replies")
        .unwrap();
    assert_eq!(result, Err(DirectClientError::ControlUnavailable));
    tokio::time::resume();

    held.release.send(()).unwrap();
    held.server.await.unwrap();
}
