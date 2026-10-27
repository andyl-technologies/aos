//! Verifies finite body accounting and incremental native HTTP over real sockets.

#![cfg(feature = "tokio")]
#![allow(clippy::unwrap_used, reason = "Fixture failures intentionally panic.")]

use std::{
    collections::VecDeque,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use terrane_sdk::store::{
    TokioHttpClient,
    http_stream::{
        HttpBodyStream, HttpStreamError, HttpStreamLimits, LimitedHttpBody, OwnedHttpBody,
        StreamingHttpClient, StreamingHttpRequest,
    },
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot},
};

struct Chunks(VecDeque<Result<Vec<u8>, HttpStreamError>>);

#[async_trait::async_trait]
impl HttpBodyStream for Chunks {
    async fn next(&mut self) -> Result<Option<Vec<u8>>, HttpStreamError> {
        self.0.pop_front().transpose()
    }
}

fn chunks(parts: &[&[u8]]) -> OwnedHttpBody {
    Box::new(Chunks(parts.iter().map(|part| Ok(part.to_vec())).collect()))
}

fn limits(chunk: usize, total: u64) -> HttpStreamLimits {
    HttpStreamLimits::new(chunk, total).unwrap()
}

#[tokio::test]
async fn body_limits_require_real_eof_and_latch_failures() {
    assert!(HttpStreamLimits::new(0, 1).is_err());
    assert!(HttpStreamLimits::new(1, 0).is_err());
    assert!(HttpStreamLimits::new(2, 1).is_err());

    let mut exact = LimitedHttpBody::new(chunks(&[b"abc", b"de"]), limits(3, 5));
    assert_eq!(exact.next().await.unwrap(), Some(b"abc".to_vec()));
    assert_eq!(exact.next().await.unwrap(), Some(b"de".to_vec()));
    assert_eq!(exact.next().await.unwrap(), None);
    assert_eq!(exact.next().await.unwrap(), None);

    let mut total = LimitedHttpBody::new(chunks(&[b"abc", b"def"]), limits(3, 5));
    assert!(total.next().await.unwrap().is_some());
    assert!(matches!(
        total.next().await,
        Err(HttpStreamError::Limit {
            maximum: 5,
            observed: 6
        })
    ));
    assert!(matches!(
        total.next().await,
        Err(HttpStreamError::Terminated)
    ));

    let mut chunk = LimitedHttpBody::new(chunks(&[b"abcd"]), limits(3, 5));
    assert!(matches!(
        chunk.next().await,
        Err(HttpStreamError::Limit {
            maximum: 3,
            observed: 4
        })
    ));

    let mut empty = LimitedHttpBody::new(chunks(&[b""]), limits(3, 5));
    assert!(matches!(
        empty.next().await,
        Err(HttpStreamError::EmptyChunk)
    ));
    assert!(matches!(
        empty.next().await,
        Err(HttpStreamError::Terminated)
    ));

    let mut failed = LimitedHttpBody::new(
        Box::new(Chunks(VecDeque::from([Err(
            HttpStreamError::InvalidLimits,
        )]))),
        limits(3, 5),
    );
    assert!(matches!(
        failed.next().await,
        Err(HttpStreamError::InvalidLimits)
    ));
    assert!(matches!(
        failed.next().await,
        Err(HttpStreamError::Terminated)
    ));
}

struct DropBody(Arc<AtomicBool>);

impl Drop for DropBody {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[async_trait::async_trait]
impl HttpBodyStream for DropBody {
    async fn next(&mut self) -> Result<Option<Vec<u8>>, HttpStreamError> {
        std::future::pending().await
    }
}

#[test]
fn abandoned_body_releases_its_owned_source() {
    let dropped = Arc::new(AtomicBool::new(false));
    let body = LimitedHttpBody::new(Box::new(DropBody(dropped.clone())), limits(3, 5));
    drop(body);
    assert!(dropped.load(Ordering::SeqCst));
}

fn client() -> TokioHttpClient {
    TokioHttpClient::new(
        reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .unwrap(),
    )
}

fn request(address: std::net::SocketAddr, body: OwnedHttpBody) -> StreamingHttpRequest {
    StreamingHttpRequest {
        method: "POST".into(),
        url: format!("http://{address}/stream"),
        headers: Vec::new(),
        body,
    }
}

async fn read_headers(reader: &mut BufReader<TcpStream>) -> Vec<String> {
    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        assert_ne!(reader.read_line(&mut line).await.unwrap(), 0);
        if line == "\r\n" {
            return headers;
        }
        headers.push(line);
    }
}

#[tokio::test]
async fn response_delivers_headers_and_first_bytes_before_the_rest_exists() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (release, waiting) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(socket);
        read_headers(&mut reader).await;
        reader.get_mut().write_all(b"HTTP/1.1 206 Partial Content\r\nTransfer-Encoding: chunked\r\nX-Proof: first\r\nX-Proof: second\r\n\r\n3\r\nabc\r\n").await.unwrap();
        waiting.await.unwrap();
        reader
            .get_mut()
            .write_all(b"3\r\ndef\r\n0\r\n\r\n")
            .await
            .unwrap();
    });

    let mut response = client()
        .send_stream(request(address, chunks(&[])), limits(3, 6), limits(2, 6))
        .await
        .unwrap();
    assert_eq!(response.status, 206);
    let values: Vec<_> = response
        .headers
        .iter()
        .filter(|(name, _)| name == "x-proof")
        .map(|(_, value)| value.as_slice())
        .collect();
    assert_eq!(values, [b"first".as_slice(), b"second".as_slice()]);

    let mut received = Vec::new();
    while received.len() < 3 {
        let part = response.body.next().await.unwrap().unwrap();
        assert!(part.len() <= 2);
        received.extend(part);
    }
    assert_eq!(received, b"abc");
    release.send(()).unwrap();
    while let Some(part) = response.body.next().await.unwrap() {
        assert!(part.len() <= 2);
        received.extend(part);
    }
    assert_eq!(received, b"abcdef");
    server.await.unwrap();
}

struct ChannelBody(mpsc::Receiver<Vec<u8>>);

#[async_trait::async_trait]
impl HttpBodyStream for ChannelBody {
    async fn next(&mut self) -> Result<Option<Vec<u8>>, HttpStreamError> {
        Ok(self.0.recv().await)
    }
}

async fn read_chunk(reader: &mut BufReader<TcpStream>) -> Vec<u8> {
    let mut size = String::new();
    reader.read_line(&mut size).await.unwrap();
    let length = usize::from_str_radix(size.trim(), 16).unwrap();
    let mut body = vec![0; length];
    reader.read_exact(&mut body).await.unwrap();
    let mut ending = [0; 2];
    reader.read_exact(&mut ending).await.unwrap();
    assert_eq!(ending, *b"\r\n");
    body
}

#[tokio::test]
async fn upload_reaches_socket_before_producer_finishes() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (observed, observation) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(socket);
        let headers = read_headers(&mut reader).await;
        assert!(
            headers
                .iter()
                .any(|line| line.eq_ignore_ascii_case("transfer-encoding: chunked\r\n"))
        );
        assert_eq!(read_chunk(&mut reader).await, b"abc");
        observed.send(()).unwrap();
        assert_eq!(read_chunk(&mut reader).await, b"def");
        assert!(read_chunk(&mut reader).await.is_empty());
        reader
            .get_mut()
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .await
            .unwrap();
    });
    let (producer, receiver) = mpsc::channel(1);
    producer.send(b"abc".to_vec()).await.unwrap();
    let exchange = tokio::spawn(async move {
        client()
            .send_stream(
                request(address, Box::new(ChannelBody(receiver))),
                limits(3, 6),
                limits(2, 2),
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(3), observation)
        .await
        .unwrap()
        .unwrap();
    producer.send(b"def".to_vec()).await.unwrap();
    drop(producer);
    let mut response = exchange.await.unwrap().unwrap();
    assert_eq!(response.body.next().await.unwrap(), Some(b"ok".to_vec()));
    assert_eq!(response.body.next().await.unwrap(), None);
    server.await.unwrap();
}

async fn fixed_response(
    bytes: &'static [u8],
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(socket);
        read_headers(&mut reader).await;
        reader.get_mut().write_all(bytes).await.unwrap();
    });
    (address, server)
}

#[tokio::test]
async fn declared_response_over_limit_is_refused_before_body_delivery() {
    let (address, server) =
        fixed_response(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nabcdef").await;
    let result = client()
        .send_stream(request(address, chunks(&[])), limits(1, 1), limits(3, 5))
        .await;
    assert!(matches!(
        result,
        Err(HttpStreamError::Limit {
            maximum: 5,
            observed: 6
        })
    ));
    server.await.unwrap();
}

#[tokio::test]
async fn undeclared_response_over_limit_cannot_turn_into_eof() {
    let (address, server) = fixed_response(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n6\r\nabcdef\r\n0\r\n\r\n",
    )
    .await;
    let mut response = client()
        .send_stream(request(address, chunks(&[])), limits(1, 1), limits(3, 5))
        .await
        .unwrap();
    loop {
        match response.body.next().await {
            Ok(Some(_)) => continue,
            Err(HttpStreamError::Limit {
                maximum: 5,
                observed: 6,
            }) => break,
            other => panic!("expected actual body limit refusal, got {other:?}"),
        }
    }
    assert!(matches!(
        response.body.next().await,
        Err(HttpStreamError::Terminated)
    ));
    server.await.unwrap();
}

#[tokio::test]
async fn truncated_response_is_a_transport_failure_without_successful_eof() {
    let (address, server) =
        fixed_response(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nabc").await;
    let mut response = client()
        .send_stream(request(address, chunks(&[])), limits(1, 1), limits(3, 6))
        .await
        .unwrap();
    loop {
        match response.body.next().await {
            Ok(Some(_)) => continue,
            Err(HttpStreamError::Transport(_)) => break,
            other => panic!("expected truncation failure, got {other:?}"),
        }
    }
    assert!(matches!(
        response.body.next().await,
        Err(HttpStreamError::Terminated)
    ));
    server.await.unwrap();
}

#[tokio::test]
async fn refused_upload_preserves_source_error_and_never_sends_offending_bytes() {
    use std::error::Error;

    for source_error in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut received = Vec::new();
            // A failed upload closes the actual transport without completing
            // its chunked body. No application acknowledgement is sent.
            socket.read_to_end(&mut received).await.unwrap();
            assert!(!received.windows(9).any(|window| window == b"forbidden"));
            received
        });
        let (producer, receiver) = mpsc::channel(1);
        let source: OwnedHttpBody = if source_error {
            Box::new(Chunks(VecDeque::from([Err(HttpStreamError::EmptyChunk)])))
        } else {
            producer.send(b"forbidden".to_vec()).await.unwrap();
            Box::new(ChannelBody(receiver))
        };
        drop(producer);

        let error = match client()
            .send_stream(request(address, source), limits(3, 6), limits(2, 2))
            .await
        {
            Ok(_) => panic!("a refused upload cannot produce a successful exchange"),
            Err(error) => error,
        };
        let mut cause: &(dyn Error + 'static) = &error;
        let mut found = false;
        loop {
            if let Some(original) = cause.downcast_ref::<HttpStreamError>() {
                found |= if source_error {
                    matches!(original, HttpStreamError::EmptyChunk)
                } else {
                    matches!(
                        original,
                        HttpStreamError::Limit {
                            maximum: 3,
                            observed: 9
                        }
                    )
                };
            }
            match cause.source() {
                Some(source) => cause = source,
                None => break,
            }
        }
        assert!(
            found,
            "the actual producer refusal must survive the HTTP error chain: {error:?}"
        );
        tokio::time::timeout(Duration::from_secs(3), server)
            .await
            .unwrap()
            .unwrap();
    }
}
