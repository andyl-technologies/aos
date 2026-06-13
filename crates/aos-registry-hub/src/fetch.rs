//! Transport abstraction for reading a registry surface.
//!
//! The surface reader and indexer are transport-agnostic: they ask a
//! [`SurfaceFetch`] for relative paths (`HEAD`, `info/refs`,
//! `objects/ab/cd…`, `channels/stable/00`, …) and get bytes or a definite
//! "not present". Two transports cover the deployment matrix:
//!
//! - [`LocalFsFetch`] for `file://` storage bindings — the local-first
//!   mode, where the registry surface is a directory on disk.
//! - [`HttpFetch`] for registration-only registries indexed through their
//!   public CDN URL, exactly as an `apm` client would fetch them.
//!
//! Transport-level failures (network errors, non-404 HTTP statuses, local
//! IO errors other than absence) are wrapped in [`FetchError`] so callers
//! can classify them with [`is_fetch_error`] — e.g. the indexer marks a
//! registry *stale* (surface unreachable) rather than *failed* (surface
//! invalid) when the underlying error is a fetch error.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Result};
use async_trait::async_trait;

/// Maximum response body size accepted from a surface fetch (64 MiB).
///
/// Applies to HTTP responses: a `Content-Length` past the cap is rejected
/// before the body is read, and chunked/streamed bodies are accumulated
/// with the same cap (and additionally bounded by the client's 30-second
/// total-request timeout).
pub const MAX_FETCH_BYTES: u64 = 64 * 1024 * 1024;

/// Maximum NAR body size accepted by deep-validation and repair reads
/// (2 GiB).
///
/// NAR payloads are content-addressed store archives and can legitimately be
/// far larger than a surface pointer file, so the cap on a NAR read is
/// deliberately generous — large packages are not rejected — while still
/// bounding the read so a hostile or buggy upstream cannot stream an
/// unbounded body into memory. The 30-second client timeout bounds duration
/// independently.
pub const MAX_NAR_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Read a response body into memory, rejecting anything past `cap` bytes.
///
/// Rejects up front when the server declares a `Content-Length` over `cap`,
/// then accumulates the (possibly chunked) body with the same cap so a
/// response that omits or lies about its length is bounded too. Use this for
/// every hub-originated full-body read so no upstream can OOM the process.
///
/// # Errors
///
/// Returns a [`FetchError`] when the declared length exceeds `cap`, the
/// accumulated body exceeds `cap`, or a chunk read fails.
pub async fn read_body_capped(
    mut response: reqwest::Response,
    cap: u64,
    what: &str,
) -> Result<Vec<u8>> {
    if let Some(declared) = response.content_length() {
        if declared > cap {
            return Err(fetch_err(format!(
                "{what}: response is {declared} bytes (cap {cap})"
            )));
        }
    }
    let mut body: Vec<u8> = Vec::new();
    loop {
        let chunk = response
            .chunk()
            .await
            .map_err(|err| fetch_err(format!("reading {what}: {err}")))?;
        let Some(chunk) = chunk else { break };
        if body.len() as u64 + chunk.len() as u64 > cap {
            return Err(fetch_err(format!(
                "{what}: response exceeds the {cap}-byte cap"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Read a response body as UTF-8 text, rejecting anything past `cap` bytes.
///
/// A thin wrapper over [`read_body_capped`] that decodes the bounded body
/// lossily, for text surfaces (narinfo, `info/refs`) where a small cap is
/// appropriate.
///
/// # Errors
///
/// Returns a [`FetchError`] when the body exceeds `cap` (see
/// [`read_body_capped`]).
pub async fn read_text_capped(response: reqwest::Response, cap: u64, what: &str) -> Result<String> {
    let bytes = read_body_capped(response, cap, what).await?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Marker error for transport-level surface fetch failures.
///
/// All transport failures — reqwest errors, non-404 HTTP statuses, local
/// IO errors other than `NotFound`, symlink escapes — are wrapped in this
/// type (with the detail preserved in the message) so callers can
/// classify them through `anyhow` context chains via [`is_fetch_error`].
#[derive(Debug, thiserror::Error)]
#[error("surface fetch failed: {0}")]
pub struct FetchError(pub String);

/// Whether any error in `err`'s chain is a transport-level [`FetchError`].
///
/// Walks the full `anyhow` context chain, so classification survives any
/// number of `.context(…)` layers added by callers.
pub fn is_fetch_error(err: &anyhow::Error) -> bool {
    err.chain()
        .any(|cause| cause.downcast_ref::<FetchError>().is_some())
}

/// Wrap a message as a transport-level fetch failure.
fn fetch_err(message: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(FetchError(message.into()))
}

/// Build the hardened HTTP client used for all hub-originated requests.
///
/// 30-second total-request timeout, 10-second connect timeout. Shared by
/// [`HttpFetch`] and the cache validators so every outbound request is
/// bounded.
pub fn hardened_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .build()
        // Building only fails when the TLS backend cannot initialize, in
        // which case `Client::new()` would panic identically; fall back
        // to the default client rather than aborting.
        .unwrap_or_else(|_| reqwest::Client::new())
}

/// Read access to a registry surface by relative path.
#[async_trait]
pub trait SurfaceFetch: Send + Sync {
    /// Fetch one surface path.
    ///
    /// Returns `Ok(None)` when the path definitively does not exist
    /// (missing file, HTTP 404) — a meaningful state for channel partition
    /// probing — and an error for transport failures.
    ///
    /// # Errors
    ///
    /// Returns an error for IO or transport failures other than absence;
    /// transport-level failures carry a [`FetchError`] in their chain.
    async fn fetch(&self, path: &str) -> Result<Option<Vec<u8>>>;

    /// A human-readable description of the source (for health/audit text).
    fn describe(&self) -> String;
}

/// Filesystem-backed surface access for `file://` bindings.
pub struct LocalFsFetch {
    root: PathBuf,
}

impl LocalFsFetch {
    /// Create a fetcher rooted at a surface directory.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The surface root directory.
    pub fn root(&self) -> &std::path::Path {
        &self.root
    }
}

#[async_trait]
impl SurfaceFetch for LocalFsFetch {
    async fn fetch(&self, path: &str) -> Result<Option<Vec<u8>>> {
        let full = safe_join(&self.root, path)?;
        // Containment: resolve symlinks and require the real file to live
        // under the real root, so a hostile surface cannot link out of it.
        let root = tokio::fs::canonicalize(&self.root).await.map_err(|err| {
            fetch_err(format!(
                "canonicalizing surface root {}: {err}",
                self.root.display()
            ))
        })?;
        let canonical = match tokio::fs::canonicalize(&full).await {
            Ok(canonical) => canonical,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => {
                return Err(fetch_err(format!("resolving {}: {err}", full.display())));
            }
        };
        if !canonical.starts_with(&root) {
            return Err(fetch_err(format!(
                "surface path '{path}' escapes the surface root via symlink"
            )));
        }
        match tokio::fs::read(&canonical).await {
            Ok(bytes) => Ok(Some(bytes)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(fetch_err(format!("reading {}: {err}", canonical.display()))),
        }
    }

    fn describe(&self) -> String {
        format!("file://{}", self.root.display())
    }
}

/// HTTP(S)-backed surface access for registration-only registries.
pub struct HttpFetch {
    base: String,
    client: reqwest::Client,
}

impl HttpFetch {
    /// Create a fetcher for a registry base URL.
    pub fn new(base: impl Into<String>) -> Self {
        Self {
            base: base.into().trim_end_matches('/').to_string(),
            client: hardened_client(),
        }
    }
}

#[async_trait]
impl SurfaceFetch for HttpFetch {
    async fn fetch(&self, path: &str) -> Result<Option<Vec<u8>>> {
        let url = format!("{}/{path}", self.base);
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|err| fetch_err(format!("fetching {url}: {err}")))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !response.status().is_success() {
            return Err(fetch_err(format!(
                "fetching {url}: HTTP {}",
                response.status()
            )));
        }
        // Reject oversized bodies up front when the server declares a length,
        // then stream with the same cap so chunked responses (no
        // Content-Length) are bounded too.
        let body = read_body_capped(response, MAX_FETCH_BYTES, &format!("fetching {url}")).await?;
        Ok(Some(body))
    }

    fn describe(&self) -> String {
        self.base.clone()
    }
}

/// Construct a fetcher from a registry source URL.
///
/// `file://` and bare absolute paths map to [`LocalFsFetch`]; `http://`
/// and `https://` map to [`HttpFetch`].
///
/// # Errors
///
/// Returns an error for unsupported URL schemes.
pub fn fetch_for_url(source_url: &str) -> Result<Box<dyn SurfaceFetch>> {
    if let Some(path) = source_url.strip_prefix("file://") {
        return Ok(Box::new(LocalFsFetch::new(path)));
    }
    if source_url.starts_with('/') {
        return Ok(Box::new(LocalFsFetch::new(source_url)));
    }
    if source_url.starts_with("http://") || source_url.starts_with("https://") {
        return Ok(Box::new(HttpFetch::new(source_url)));
    }
    bail!(
        "unsupported registry source URL '{source_url}' (expected file://, /path, or http(s)://)"
    );
}

/// Reject a network-origin URL that is local, internal, or non-HTTP — an SSRF
/// guard for operator-configured mirror upstreams and frontend domains.
///
/// A mirror upstream or frontend the hub will *fetch over the network* must be
/// an `http(s)://` URL whose host does not resolve to an address the hub could
/// otherwise be tricked into reaching internally. This rejects:
///
/// - non-`http(s)` schemes (`file://`, bare paths) — a network origin must not
///   read the local filesystem or a metadata endpoint by path,
/// - hosts that resolve to **loopback** (`127.0.0.0/8`, `::1`),
///   **link-local** (`169.254.0.0/16` — the cloud metadata range — and
///   `fe80::/10`), **RFC-1918 private** (`10/8`, `172.16/12`, `192.168/16`),
///   **unique-local** IPv6 (`fc00::/7`), unspecified (`0.0.0.0`, `::`), and
///   IPv4-mapped IPv6 forms of the above.
///
/// Mirror/frontend creation is org-admin/operator-only, which bounds the blast
/// radius, but this check is applied at both creation *and* each fetch/probe as
/// defense in depth.
///
/// **Out of scope:** DNS rebinding — the host is resolved and checked here, but
/// a name that resolves benignly now and to an internal address later is not
/// defended against (it would require pinning the resolved address through the
/// connection). The check is on the configured host as resolved at call time.
///
/// **Test/dev escape hatch:** when the `AOS_HUB_ALLOW_LOCAL_REMOTES`
/// environment variable is set, the local/internal address rejection is
/// skipped (the non-HTTP scheme rejection still applies). The integration
/// tests stand up upstream servers on `127.0.0.1`; this lets them run while
/// production — which never sets the variable — keeps the SSRF guard.
///
/// # Errors
///
/// Returns an error when the scheme is not `http(s)`, the URL has no host, DNS
/// resolution fails, or any resolved address is local/internal.
pub fn is_safe_remote_url(raw: &str) -> Result<()> {
    let url = url::Url::parse(raw).map_err(|err| {
        fetch_err(format!(
            "mirror/frontend URL '{raw}' is not a valid URL: {err}"
        ))
    })?;
    match url.scheme() {
        "http" | "https" => {}
        other => {
            return Err(fetch_err(format!(
                "mirror/frontend URL '{raw}' uses unsupported scheme '{other}' \
                 (a network origin must be http(s)://)"
            )));
        }
    }
    // The non-HTTP scheme rejection above always applies; the local/internal
    // address rejection below is the part the test/dev hatch relaxes.
    let allow_local = std::env::var_os("AOS_HUB_ALLOW_LOCAL_REMOTES").is_some();
    if allow_local {
        return Ok(());
    }
    let host = url
        .host_str()
        .ok_or_else(|| fetch_err(format!("mirror/frontend URL '{raw}' has no host")))?;

    // A bracketed/literal IP host is checked directly; a name is resolved and
    // every returned address checked, so a name pointing at an internal IP is
    // rejected too.
    if let Ok(ip) = host.parse::<IpAddr>() {
        if !is_global_ip(ip) {
            return Err(fetch_err(format!(
                "mirror/frontend URL '{raw}' resolves to a local/internal address {ip}"
            )));
        }
        return Ok(());
    }
    let port = url.port_or_known_default().unwrap_or(80);
    let resolved: Vec<IpAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|err| fetch_err(format!("resolving mirror/frontend host '{host}': {err}")))?
        .map(|addr| addr.ip())
        .collect();
    if resolved.is_empty() {
        return Err(fetch_err(format!(
            "mirror/frontend host '{host}' did not resolve to any address"
        )));
    }
    for ip in resolved {
        if !is_global_ip(ip) {
            return Err(fetch_err(format!(
                "mirror/frontend URL '{raw}' resolves to a local/internal address {ip}"
            )));
        }
    }
    Ok(())
}

/// Whether `ip` is a globally routable address (not local/internal).
///
/// Rejects loopback, link-local, private/unique-local, unspecified, and broadcast
/// ranges for both IPv4 and IPv6 (including IPv4-mapped IPv6). The std-stable
/// predicates are combined manually because `Ipv6Addr::is_unique_local` and
/// related helpers are not yet stable.
fn is_global_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_global_ipv4(v4),
        IpAddr::V6(v6) => {
            // Unwrap IPv4-mapped/compatible IPv6 to apply the IPv4 rules.
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_global_ipv4(mapped);
            }
            if let Some(compat) = v6.to_ipv4() {
                return is_global_ipv4(compat);
            }
            is_global_ipv6(v6)
        }
    }
}

/// Whether an IPv4 address is globally routable (not local/internal).
fn is_global_ipv4(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    !(v4.is_loopback()           // 127.0.0.0/8
        || v4.is_private()        // 10/8, 172.16/12, 192.168/16
        || v4.is_link_local()     // 169.254.0.0/16 (cloud metadata)
        || v4.is_unspecified()    // 0.0.0.0
        || v4.is_broadcast()      // 255.255.255.255
        || o[0] == 0) // 0.0.0.0/8
}

/// Whether an IPv6 address is globally routable (not local/internal).
fn is_global_ipv6(v6: Ipv6Addr) -> bool {
    let segs = v6.segments();
    let is_unique_local = (segs[0] & 0xfe00) == 0xfc00; // fc00::/7
    let is_link_local = (segs[0] & 0xffc0) == 0xfe80; // fe80::/10
    !(v6.is_loopback() || v6.is_unspecified() || is_unique_local || is_link_local)
}

/// Join a relative surface path onto a root, rejecting traversal.
///
/// # Errors
///
/// Returns an error for absolute paths or any `..` component.
pub fn safe_join(root: &std::path::Path, relative: &str) -> Result<PathBuf> {
    let rel = std::path::Path::new(relative);
    if rel.is_absolute() {
        bail!("surface path must be relative: '{relative}'");
    }
    for component in rel.components() {
        match component {
            std::path::Component::Normal(_) => {}
            _ => bail!("surface path contains illegal component: '{relative}'"),
        }
    }
    Ok(root.join(rel))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn local_fetch_distinguishes_missing_from_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("HEAD"), b"ref: refs/heads/stable\n").unwrap();
        let fetch = LocalFsFetch::new(dir.path());
        assert!(fetch.fetch("HEAD").await.unwrap().is_some());
        assert!(fetch.fetch("info/refs").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn local_fetch_rejects_symlink_escape() {
        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("secret.txt");
        std::fs::write(&outside, b"keys").unwrap();
        let root = dir.path().join("surface");
        std::fs::create_dir_all(root.join("objects/zz")).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("objects/zz/escape")).unwrap();

        let fetch = LocalFsFetch::new(&root);
        let err = fetch.fetch("objects/zz/escape").await.unwrap_err();
        assert!(is_fetch_error(&err), "got: {err:#}");
        assert!(err.to_string().contains("escapes"), "got: {err:#}");
    }

    #[test]
    fn safe_join_rejects_traversal() {
        let root = std::path::Path::new("/srv/reg");
        assert!(safe_join(root, "objects/ab/cd").is_ok());
        assert!(safe_join(root, "../etc/passwd").is_err());
        assert!(safe_join(root, "/etc/passwd").is_err());
        assert!(safe_join(root, "a/../../b").is_err());
    }

    #[test]
    fn fetch_for_url_dispatches_schemes() {
        assert!(fetch_for_url("file:///srv/reg").is_ok());
        assert!(fetch_for_url("/srv/reg").is_ok());
        assert!(fetch_for_url("https://cdn.example.com/reg").is_ok());
        assert!(fetch_for_url("s3://bucket/prefix").is_err());
    }

    #[tokio::test]
    async fn read_body_capped_rejects_over_cap_body() {
        use axum::routing::get;

        // A tiny upstream that streams more bytes than a deliberately small
        // cap, with no Content-Length so the cap is enforced mid-stream.
        async fn big() -> axum::response::Response {
            use axum::response::IntoResponse as _;
            // 4 KiB body, well over the 1 KiB cap below.
            vec![0u8; 4096].into_response()
        }
        let app = axum::Router::new().route("/big", get(big));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/big", listener.local_addr().unwrap());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = hardened_client();
        let response = client.get(&url).send().await.unwrap();
        let cap = 1024;
        let err = read_body_capped(response, cap, "test fetch")
            .await
            .unwrap_err();
        assert!(is_fetch_error(&err), "got: {err:#}");
        assert!(err.to_string().contains("cap"), "got: {err:#}");

        // A body within the cap is read whole.
        let response = client.get(&url).send().await.unwrap();
        let body = read_body_capped(response, MAX_NAR_BYTES, "test fetch")
            .await
            .unwrap();
        assert_eq!(body.len(), 4096);
    }

    #[test]
    fn is_safe_remote_url_rejects_local_and_non_http() {
        // The escape hatch must be unset for this test (the lib test binary
        // never sets it).
        assert!(std::env::var_os("AOS_HUB_ALLOW_LOCAL_REMOTES").is_none());

        // Non-HTTP schemes and bare paths are rejected outright.
        assert!(is_safe_remote_url("file:///etc/passwd").is_err());
        assert!(is_safe_remote_url("/srv/secret").is_err());
        assert!(is_safe_remote_url("ftp://example.com/x").is_err());

        // Loopback, link-local (cloud metadata), and RFC-1918 literals.
        assert!(is_safe_remote_url("http://127.0.0.1/").is_err());
        assert!(is_safe_remote_url("http://127.0.0.1:8500/v1/").is_err());
        assert!(is_safe_remote_url("http://169.254.169.254/latest/meta-data/").is_err());
        assert!(is_safe_remote_url("http://10.0.0.5/").is_err());
        assert!(is_safe_remote_url("http://172.16.3.4/").is_err());
        assert!(is_safe_remote_url("http://192.168.1.1/").is_err());
        assert!(is_safe_remote_url("http://[::1]/").is_err());
        assert!(is_safe_remote_url("http://[fe80::1]/").is_err());
        assert!(is_safe_remote_url("http://[fc00::1]/").is_err());
        // IPv4-mapped IPv6 form of loopback must not slip through.
        assert!(is_safe_remote_url("http://[::ffff:127.0.0.1]/").is_err());

        // A public literal IP passes (no DNS needed).
        assert!(is_safe_remote_url("https://93.184.216.34/").is_ok());
    }

    #[test]
    fn is_global_ip_classifies_ranges() {
        use std::net::Ipv4Addr;
        assert!(!is_global_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(!is_global_ip(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))));
        assert!(!is_global_ip(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))));
        assert!(!is_global_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1))));
        assert!(!is_global_ip(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))));
        assert!(is_global_ip(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))));
        assert!(is_global_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[test]
    fn fetch_error_classification_survives_context() {
        use anyhow::Context as _;
        let err: anyhow::Error = fetch_err("connection refused");
        let wrapped = Err::<(), _>(err)
            .context("indexing demo")
            .context("outer")
            .unwrap_err();
        assert!(is_fetch_error(&wrapped));
        assert!(!is_fetch_error(&anyhow::anyhow!("parse error")));
    }
}
