//! Supplies byte-framing peers for actual generated-client HTTP socket tests.
//!
//! Peers establish no repository authentication, authorization or custody.

use connectrpc::client::{ClientConfig, HttpClient};
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use terrane_sdk::wire::services::ContentServiceClient;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

pub(super) type TestError = Box<dyn std::error::Error + Send + Sync>;
pub(super) type TestResult = Result<(), TestError>;

pub(super) fn client(
    address: std::net::SocketAddr,
) -> Result<ContentServiceClient<HttpClient>, TestError> {
    Ok(ContentServiceClient::new(
        HttpClient::plaintext(),
        ClientConfig::new(format!("http://{address}").parse()?),
    ))
}

pub(super) fn envelope(flag: u8, bytes: &[u8]) -> Result<Vec<u8>, TestError> {
    let mut frame = vec![flag];
    frame.extend_from_slice(&u32::try_from(bytes.len())?.to_be_bytes());
    frame.extend_from_slice(bytes);
    Ok(frame)
}

pub(super) struct Peer {
    pub(super) address: std::net::SocketAddr,
    pub(super) sent: tokio::sync::oneshot::Receiver<()>,
    pub(super) disconnected: Arc<AtomicBool>,
    worker: tokio::task::JoinHandle<io::Result<()>>,
}

impl Peer {
    pub(super) async fn start(
        body: Vec<u8>,
        promised: usize,
        stall: bool,
    ) -> Result<Self, TestError> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let (sent, signal) = tokio::sync::oneshot::channel();
        let disconnected = Arc::new(AtomicBool::new(false));
        let observation = Arc::clone(&disconnected);
        let worker = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await?;
            drain_request(&mut socket).await?;
            socket.write_all(format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/connect+proto\r\nContent-Length: {promised}\r\nConnection: close\r\n\r\n"
            ).as_bytes()).await?;
            socket.write_all(&body).await?;
            let _ = sent.send(());
            if stall {
                let mut byte = [0; 1];
                match socket.read(&mut byte).await {
                    Ok(0) => {
                        observation.store(true, Ordering::SeqCst);
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
                        ) =>
                    {
                        observation.store(true, Ordering::SeqCst);
                    }
                    Ok(_) => return Err(io::Error::other("unexpected second request")),
                    Err(error) => return Err(error),
                }
            }
            Ok(())
        });
        Ok(Self {
            address,
            sent: signal,
            disconnected,
            worker,
        })
    }

    pub(super) async fn complete(body: Vec<u8>) -> Result<Self, TestError> {
        let promised = body.len();
        Self::start(body, promised, false).await
    }

    pub(super) async fn stop(self) -> TestResult {
        tokio::time::timeout(Duration::from_secs(3), self.worker).await???;
        Ok(())
    }
}

// The generated client sends this small fixture request with Content-Length.
// Drain it before closing to avoid a reset caused by unread request bytes.
async fn drain_request(socket: &mut TcpStream) -> io::Result<()> {
    let mut bytes = Vec::new();
    let mut buffer = [0; 1024];
    let (header_end, length) = loop {
        let read = socket.read(&mut buffer).await?;
        if read == 0 || bytes.len() + read > 8192 {
            return Err(io::Error::other("missing or oversized fixture request"));
        }
        bytes.extend_from_slice(&buffer[..read]);
        if let Some(position) = bytes.windows(4).position(|value| value == b"\r\n\r\n") {
            let headers = std::str::from_utf8(&bytes[..position]).map_err(io::Error::other)?;
            let length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>())
                })
                .ok_or_else(|| io::Error::other("fixture request needs Content-Length"))?
                .map_err(io::Error::other)?;
            break (position + 4, length);
        }
    };
    if length > 8192 - header_end {
        return Err(io::Error::other("oversized fixture request body"));
    }
    while bytes.len() < header_end + length {
        let read = socket.read(&mut buffer).await?;
        if read == 0 {
            return Err(io::Error::other("truncated fixture request body"));
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
    Ok(())
}
