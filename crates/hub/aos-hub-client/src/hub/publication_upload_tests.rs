//! Real HTTP coverage of stalled publication uploads and exact-byte replay.

use std::fs::File;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

use super::{HubClient, PUBLICATION_UPLOAD_TIMEOUT_SECS};

async fn read_upload(socket: TcpStream) -> (TcpStream, String, Vec<u8>) {
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
    (input.into_inner(), first, bytes)
}

#[tokio::test]
async fn stalled_object_response_times_out_and_allows_exact_replay() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let upload_url = format!("{origin}/aos.hub.v1.PublishService/UploadObject/publication/object");
    let client = HubClient::connect_anonymous(&origin).unwrap();
    let source = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");
    let expected_bytes = std::fs::read(source).unwrap();
    let (received_tx, received_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();

    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let (socket, first, bytes) = read_upload(socket).await;
        received_tx.send((first.clone(), bytes.clone())).unwrap();
        // Keep the connection open after consuming the entire body, modelling
        // a lost response rather than a failed connection or interrupted read.
        release_rx.await.unwrap();
        drop(socket);

        let (socket, _) = listener.accept().await.unwrap();
        let (mut socket, retried_first, retried_bytes) = read_upload(socket).await;
        assert_eq!(retried_first, first);
        assert_eq!(retried_bytes, bytes);
        socket
            .write_all(b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
    });

    let first_client = client.clone();
    let first_url = upload_url.clone();
    let upload = tokio::spawn(async move {
        first_client
            .upload_publication_object(&first_url, File::open(source).unwrap(), "fixture")
            .await
    });
    let (first, bytes) = received_rx.await.unwrap();
    assert_eq!(
        first,
        "PUT /aos.hub.v1.PublishService/UploadObject/publication/object HTTP/1.1\r\n"
    );
    assert_eq!(bytes, expected_bytes);

    // Advance only after actual socket I/O completes; auto-advancing time
    // during connection establishment can race the transport's connect timer.
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(PUBLICATION_UPLOAD_TIMEOUT_SECS + 1)).await;
    let error = tokio::time::timeout(Duration::from_secs(1), upload)
        .await
        .expect("the bounded upload must release its caller")
        .unwrap()
        .unwrap_err();
    assert!(error.chain().any(|cause| {
        cause
            .downcast_ref::<reqwest::Error>()
            .is_some_and(reqwest::Error::is_timeout)
    }));
    tokio::time::resume();

    release_tx.send(()).unwrap();
    client
        .upload_publication_object(&upload_url, File::open(source).unwrap(), "fixture")
        .await
        .unwrap();
    server.await.unwrap();
}
