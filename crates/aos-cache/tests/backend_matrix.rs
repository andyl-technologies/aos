use std::collections::BTreeMap;
use std::sync::Arc;

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
