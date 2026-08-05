//! Loopback HTTP fixture shared by L3 memo-tier tests.

use std::collections::HashMap;
use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use anyhow::Result;

/// A minimal single-request-per-connection HTTP record server.
///
/// Every `PUT /v1/...` stores its body under the complete request path, and a
/// matching `GET` returns those bytes. Other requests return 404. When a forced
/// status is set (see [`MemoTestServer::force_status`]) every request is
/// answered with that status and an empty body instead, so tests can drive the
/// client's server-error and rejection paths.
pub(crate) struct MemoTestServer {
    addr: SocketAddr,
    records: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    forced_status: Arc<AtomicU16>,
    hang: Arc<AtomicBool>,
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl MemoTestServer {
    /// Binds a loopback listener and starts its serving thread.
    ///
    /// # Errors
    ///
    /// Returns an error if the loopback listener cannot bind or report its
    /// local address.
    pub(crate) fn spawn() -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let records: Arc<Mutex<HashMap<String, Vec<u8>>>> = Arc::new(Mutex::new(HashMap::new()));
        let forced_status = Arc::new(AtomicU16::new(0));
        let hang = Arc::new(AtomicBool::new(false));
        let shutdown = Arc::new(AtomicBool::new(false));
        let thread_records = Arc::clone(&records);
        let thread_forced = Arc::clone(&forced_status);
        let thread_hang = Arc::clone(&hang);
        let thread_shutdown = Arc::clone(&shutdown);
        let handle = std::thread::spawn(move || {
            for stream in listener.incoming() {
                if thread_shutdown.load(Ordering::Relaxed) {
                    break;
                }
                let Ok(stream) = stream else { continue };
                let _ = serve_one(stream, &thread_records, &thread_forced, &thread_hang);
            }
        });
        Ok(Self {
            addr,
            records,
            forced_status,
            hang,
            shutdown,
            handle: Some(handle),
        })
    }

    /// Makes the server hold each connection open without replying, so a client
    /// with a short `timeout_ms` hits a request timeout. Used to drive the
    /// transport-timeout backoff path.
    pub(crate) fn set_hang(&self, on: bool) {
        self.hang.store(on, Ordering::Relaxed);
    }

    /// Forces every subsequent response to `status` with an empty body.
    ///
    /// A `status` of `0` restores normal record-serving behavior. Used to drive
    /// the client's non-success-status path (for example a `500`).
    pub(crate) fn force_status(&self, status: u16) {
        self.forced_status.store(status, Ordering::Relaxed);
    }

    /// Returns the endpoint base URL.
    pub(crate) fn endpoint(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Returns the total number of stored request paths.
    pub(crate) fn record_count(&self) -> usize {
        self.records.lock().map_or(0, |records| records.len())
    }

    /// Returns the number of stored request paths under `prefix`.
    pub(crate) fn record_count_with_prefix(&self, prefix: &str) -> usize {
        self.records.lock().map_or(0, |records| {
            records
                .keys()
                .filter(|path| path.starts_with(prefix))
                .count()
        })
    }

    /// Applies `mutate` to the stored path-to-record map.
    pub(crate) fn mutate_records(&self, mutate: impl FnOnce(&mut HashMap<String, Vec<u8>>)) {
        if let Ok(mut records) = self.records.lock() {
            mutate(&mut records);
        }
    }
}

impl Drop for MemoTestServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        // Nudge the accept loop awake so the thread observes the flag.
        let _ = TcpStream::connect(self.addr);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn serve_one(
    mut stream: TcpStream,
    records: &Arc<Mutex<HashMap<String, Vec<u8>>>>,
    forced_status: &Arc<AtomicU16>,
    hang: &Arc<AtomicBool>,
) -> std::io::Result<()> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Ok(());
        }
        buffer.extend_from_slice(&chunk[..read]);
    };
    let head = String::from_utf8_lossy(&buffer[..header_end]).into_owned();
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or_default().to_string();
    let content_length = lines
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .next()
        .unwrap_or(0);
    let mut body = buffer[header_end..].to_vec();
    while body.len() < content_length {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
    }

    if hang.load(Ordering::Relaxed) {
        // Hold the connection open without replying so a short-timeout client
        // hits a request timeout; then drop it.
        std::thread::sleep(Duration::from_millis(600));
        return Ok(());
    }

    let forced = forced_status.load(Ordering::Relaxed);
    if forced != 0 {
        stream.write_all(&http_response(forced, "Forced", b""))?;
        return stream.flush();
    }

    let response = match method.as_str() {
        "GET" => match records.lock().ok().and_then(|map| map.get(&path).cloned()) {
            Some(bytes) => http_response(200, "OK", &bytes),
            None => http_response(404, "Not Found", b""),
        },
        "PUT" if path.starts_with("/v1/") => {
            if let Ok(mut map) = records.lock() {
                map.insert(path, body);
            }
            http_response(201, "Created", b"")
        }
        _ => http_response(404, "Not Found", b""),
    };
    stream.write_all(&response)?;
    stream.flush()
}

fn http_response(status: u16, reason: &str, body: &[u8]) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}
