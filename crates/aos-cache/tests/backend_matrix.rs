use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use aos_cache::backend::{IMMUTABLE_CACHE_CONTROL, MUTABLE_CACHE_CONTROL};
use aos_cache::{AuthOptions, from_url};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

const STORE_HASH: &str = "abc123abc123abc123abc123abc123ab";
const MISSING_HASH: &str = "def456def456def456def456def456de";
const NAR_FILE: &str = "abc123abc123abc123abc123abc123ab-sha256-feedface.nar.zst";
const NAR_BYTES: &[u8] = b"static nar bytes";
const CACHE_INFO: &str = "StoreDir: /nix/store\nWantMassQuery: 1\nPriority: 37\n";

fn narinfo_text() -> String {
    format!(
        "\
StorePath: /nix/store/{STORE_HASH}-demo
URL: nar/{NAR_FILE}
Compression: zstd
FileHash: sha256:feedface
FileSize: {}
NarHash: sha256:cafebabe
NarSize: 123
References:
",
        NAR_BYTES.len(),
    )
}

async fn backend_write_read_round_trip(url: &str) -> anyhow::Result<()> {
    let auth = AuthOptions::default();
    let backend = from_url(url, &auth).await?;
    let narinfo = narinfo_text();

    backend.ensure_cache_info("/nix/store").await?;
    backend.put_cache_info(CACHE_INFO).await?;
    backend.put_narinfo(STORE_HASH, &narinfo).await?;
    backend.put_nar(NAR_FILE, NAR_BYTES).await?;

    assert!(backend.exists(&format!("{STORE_HASH}.narinfo")).await?);
    assert!(backend.exists(&format!("nar/{NAR_FILE}")).await?);
    assert!(!backend.exists(&format!("{MISSING_HASH}.narinfo")).await?);
    assert!(backend.has_narinfo(STORE_HASH).await?);
    assert!(!backend.has_narinfo(MISSING_HASH).await?);
    assert_eq!(
        backend.query_missing(&[STORE_HASH, MISSING_HASH]).await?,
        vec![MISSING_HASH.to_string()],
    );
    assert_eq!(backend.get_narinfo(STORE_HASH).await?, narinfo);
    assert_eq!(
        backend.get_nar(&format!("nar/{NAR_FILE}")).await?,
        NAR_BYTES
    );

    Ok(())
}

#[tokio::test]
async fn file_backend_writes_standard_static_cache_layout() -> anyhow::Result<()> {
    let cache_dir = tempfile::tempdir()?;
    let url = format!("file://{}", cache_dir.path().display());

    backend_write_read_round_trip(&url).await?;

    let cache_info = tokio::fs::read_to_string(cache_dir.path().join("nix-cache-info")).await?;
    assert_eq!(cache_info, CACHE_INFO,);
    assert_eq!(
        tokio::fs::read_to_string(cache_dir.path().join(format!("{STORE_HASH}.narinfo"))).await?,
        narinfo_text(),
    );
    assert_eq!(
        tokio::fs::read(cache_dir.path().join("nar").join(NAR_FILE)).await?,
        NAR_BYTES,
    );

    Ok(())
}

#[tokio::test]
async fn static_http_backend_reads_standard_cache_layout() -> anyhow::Result<()> {
    let narinfo = narinfo_text();
    let mut files = BTreeMap::new();
    files.insert(
        "/cache/nix-cache-info".to_string(),
        b"StoreDir: /nix/store\nWantMassQuery: 1\nPriority: 40\n".to_vec(),
    );
    files.insert(
        format!("/cache/{STORE_HASH}.narinfo"),
        narinfo.clone().into_bytes(),
    );
    files.insert(format!("/cache/nar/{NAR_FILE}"), NAR_BYTES.to_vec());

    let Some((base_url, server)) = spawn_static_http_cache(files).await? else {
        eprintln!("localhost bind denied; skipping static HTTP backend matrix test");
        return Ok(());
    };
    let auth = AuthOptions::default();
    let backend = from_url(&base_url, &auth).await?;

    assert!(backend.has_narinfo(STORE_HASH).await?);
    assert!(backend.exists(&format!("{STORE_HASH}.narinfo")).await?);
    assert!(backend.exists(&format!("nar/{NAR_FILE}")).await?);
    assert!(!backend.has_narinfo(MISSING_HASH).await?);
    assert!(!backend.exists(&format!("{MISSING_HASH}.narinfo")).await?);
    assert_eq!(
        backend.query_missing(&[STORE_HASH, MISSING_HASH]).await?,
        vec![MISSING_HASH.to_string()],
    );
    assert_eq!(backend.get_narinfo(STORE_HASH).await?, narinfo);
    assert_eq!(
        backend.get_nar(&format!("nar/{NAR_FILE}")).await?,
        NAR_BYTES
    );

    server.abort();
    Ok(())
}

#[tokio::test]
#[ignore = "requires AOS_CACHE_TEST_S3_URL and working S3-compatible credentials"]
async fn s3_backend_round_trips_against_env_url() -> anyhow::Result<()> {
    let Ok(url) = std::env::var("AOS_CACHE_TEST_S3_URL") else {
        eprintln!("AOS_CACHE_TEST_S3_URL not set; skipping ignored S3 backend matrix test");
        return Ok(());
    };
    backend_write_read_round_trip(&url).await
}

#[tokio::test]
#[ignore = "requires AOS_CACHE_TEST_SFTP_URL and working SFTP credentials"]
async fn sftp_backend_round_trips_against_env_url() -> anyhow::Result<()> {
    let Ok(url) = std::env::var("AOS_CACHE_TEST_SFTP_URL") else {
        eprintln!("AOS_CACHE_TEST_SFTP_URL not set; skipping ignored SFTP backend matrix test");
        return Ok(());
    };
    backend_write_read_round_trip(&url).await
}

async fn spawn_static_http_cache(
    files: BTreeMap<String, Vec<u8>>,
) -> anyhow::Result<Option<(String, JoinHandle<()>)>> {
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    let addr = listener.local_addr()?;
    let files = Arc::new(files);
    let server = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let files = Arc::clone(&files);
            tokio::spawn(async move {
                let _ = serve_static_response(stream, files).await;
            });
        }
    });

    Ok(Some((format!("http://{addr}/cache"), server)))
}

async fn serve_static_response(
    mut stream: TcpStream,
    files: Arc<BTreeMap<String, Vec<u8>>>,
) -> anyhow::Result<()> {
    let mut buf = [0_u8; 4096];
    let mut request = Vec::new();
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        request.extend_from_slice(&buf[..n]);
        if request.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    let request = String::from_utf8_lossy(&request);
    let mut parts = request
        .lines()
        .next()
        .unwrap_or_default()
        .split_whitespace();
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or_default();
    let body = files.get(path);

    match (method, body) {
        ("GET", Some(body)) => {
            write_response(&mut stream, "200 OK", body, true).await?;
        }
        ("HEAD", Some(body)) => {
            write_response(&mut stream, "200 OK", body, false).await?;
        }
        ("GET" | "HEAD", None) => {
            write_response(&mut stream, "404 Not Found", b"", method == "GET").await?;
        }
        _ => {
            write_response(&mut stream, "405 Method Not Allowed", b"", true).await?;
        }
    }

    Ok(())
}

async fn write_response(
    stream: &mut TcpStream,
    status: &str,
    body: &[u8],
    include_body: bool,
) -> anyhow::Result<()> {
    let headers = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len(),
    );
    stream.write_all(headers.as_bytes()).await?;
    if include_body {
        stream.write_all(body).await?;
    }
    Ok(())
}

/// The method, path, and caching headers of one captured request.
struct CapturedRequest {
    method: String,
    path: String,
    cache_control: Option<String>,
    content_type: Option<String>,
}

type Captured = Arc<Mutex<Vec<CapturedRequest>>>;

/// Asserts that the HTTP backend tags its cache-object uploads with the
/// caching policy the registry's CDN origin depends on: revalidatable for the
/// in-place-rewritten narinfo and `nix-cache-info`, immutable for the
/// content-addressed NAR.
#[tokio::test]
async fn http_backend_tags_uploads_with_cache_control() -> anyhow::Result<()> {
    let Some((base_url, server, captured)) = spawn_capture_server().await? else {
        eprintln!("localhost bind denied; skipping cache-control header matrix test");
        return Ok(());
    };

    // A token-less HTTP backend is a generic cache (not an AOS server), so the
    // narinfo/NAR/cache-info PUTs hit the wire instead of being synthesised.
    let auth = AuthOptions::default();
    let backend = from_url(&base_url, &auth).await?;

    backend.put_cache_info(CACHE_INFO).await?;
    backend.put_narinfo(STORE_HASH, &narinfo_text()).await?;
    backend.put_nar(NAR_FILE, NAR_BYTES).await?;

    server.abort();

    let rows = captured.lock().unwrap();
    let find = |suffix: &str| {
        rows.iter()
            .find(|r| r.method == "PUT" && r.path.ends_with(suffix))
            .unwrap_or_else(|| {
                panic!(
                    "no PUT captured ending in {suffix}; saw {:?}",
                    rows.iter()
                        .map(|r| (r.method.as_str(), r.path.as_str()))
                        .collect::<Vec<_>>()
                )
            })
    };

    let cache_info = find("/nix-cache-info");
    assert_eq!(
        cache_info.cache_control.as_deref(),
        Some(MUTABLE_CACHE_CONTROL)
    );
    assert_eq!(cache_info.content_type.as_deref(), Some("text/plain"));

    let narinfo = find(&format!("/{STORE_HASH}.narinfo"));
    assert_eq!(
        narinfo.cache_control.as_deref(),
        Some(MUTABLE_CACHE_CONTROL)
    );
    assert_eq!(narinfo.content_type.as_deref(), Some("text/x-nix-narinfo"));

    let nar = find(&format!("/nar/{NAR_FILE}"));
    assert_eq!(nar.cache_control.as_deref(), Some(IMMUTABLE_CACHE_CONTROL));
    assert_eq!(nar.content_type.as_deref(), Some("application/x-nix-nar"));

    Ok(())
}

/// Spawns an HTTP server that records the method, path, and caching headers of
/// every request (draining any body) and always replies `200`. Returns `None`
/// when binding localhost is denied (sandbox), so callers can skip.
async fn spawn_capture_server() -> anyhow::Result<Option<(String, JoinHandle<()>, Captured)>> {
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    let addr = listener.local_addr()?;
    let captured: Captured = Arc::new(Mutex::new(Vec::new()));
    let captured_for_server = Arc::clone(&captured);
    let server = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let captured = Arc::clone(&captured_for_server);
            tokio::spawn(async move {
                let _ = capture_request(stream, captured).await;
            });
        }
    });

    Ok(Some((format!("http://{addr}/cache"), server, captured)))
}

async fn capture_request(mut stream: TcpStream, captured: Captured) -> anyhow::Result<()> {
    let mut buf = [0_u8; 4096];
    let mut raw = Vec::new();
    let header_end = loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        raw.extend_from_slice(&buf[..n]);
        if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
    };

    let header_text = String::from_utf8_lossy(&raw[..header_end]).into_owned();
    let mut request_line = header_text
        .lines()
        .next()
        .unwrap_or_default()
        .split_whitespace();
    let method = request_line.next().unwrap_or_default().to_string();
    let path = request_line.next().unwrap_or_default().to_string();

    let header_value = |name: &str| -> Option<String> {
        header_text.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.trim()
                .eq_ignore_ascii_case(name)
                .then(|| value.trim().to_string())
        })
    };

    // Drain the request body so the client sees a clean, complete response.
    let content_length: usize = header_value("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut body_read = raw.len() - header_end;
    while body_read < content_length {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        body_read += n;
    }

    captured.lock().unwrap().push(CapturedRequest {
        method,
        path,
        cache_control: header_value("cache-control"),
        content_type: header_value("content-type"),
    });

    stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .await?;
    Ok(())
}
