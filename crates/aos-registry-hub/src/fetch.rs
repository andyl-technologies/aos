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

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::Arc;
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
/// This is the single client constructor for every outbound, hub-originated
/// fetch — the mirror sync worker, the cache prober, the registry
/// pull-through (reachable unauthenticated), the webhook delivery worker,
/// the deep-validation reads, and [`HttpFetch`]. Centralizing construction
/// here is what lets the SSRF hardening below apply uniformly:
///
/// - **Total-request timeout** of 30 seconds and **connect timeout** of 10
///   seconds, so no outbound request can hang the hub.
/// - **No redirect following** ([`reqwest::redirect::Policy::none`]). These
///   clients fetch from untrusted registry surfaces, which have no
///   legitimate need to redirect the hub elsewhere; following a redirect
///   would let a (validated) upstream bounce the hub into the cloud metadata
///   service or an internal host with a `302 Location:` it never validated.
///   The caller receives the 3xx response and stops.
/// - **A validating DNS resolver** ([`ValidatingResolver`]) that re-runs the
///   global-address check ([`is_global_ip`]) at actual connect time on every
///   resolved address and refuses to hand back any local/internal one. This
///   closes the DNS-rebinding TOCTOU window in [`is_safe_remote_url`]: the
///   address the socket dials is the address that was validated, because the
///   only addresses the connector ever sees are ones this resolver already
///   approved.
pub fn hardened_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .dns_resolver(Arc::new(ValidatingResolver))
        .build()
        // Building only fails when the TLS backend cannot initialize, in
        // which case `Client::new()` would panic identically; fall back
        // to the default client rather than aborting. The fallback loses the
        // resolver and redirect hardening, but `is_safe_remote_url` is still
        // enforced at the call sites, so this is a defense-in-depth gap only.
        .unwrap_or_else(|_| reqwest::Client::new())
}

/// A reqwest DNS resolver that refuses to resolve a name to any
/// local/internal address.
///
/// Installed on [`hardened_client`] so the SSRF address check runs at the
/// moment of connection rather than only at the earlier, separate
/// [`is_safe_remote_url`] resolve. Standard resolution is performed (the
/// blocking `getaddrinfo` is run on a blocking thread), then every returned
/// [`SocketAddr`] is checked with [`is_global_ip`]; if *any* address is
/// local/internal the whole resolution fails, so a name that flips from a
/// public answer at validation time to an internal answer at connect time
/// (DNS rebinding) cannot be reached.
///
/// The test/dev escape hatch ([`allow_local_remotes`]) relaxes the
/// address check here exactly as it does in [`is_safe_remote_url`], so
/// integration tests that point the client at `127.0.0.1` upstreams still
/// connect when running in a debug build.
struct ValidatingResolver;

impl reqwest::dns::Resolve for ValidatingResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_owned();
        Box::pin(async move {
            // Port 0 is a placeholder: reqwest overrides it with the URL's
            // port (or the scheme default) after resolution, so it does not
            // affect which host we look up or the addresses we validate.
            let lookup = tokio::task::spawn_blocking(move || {
                (host.as_str(), 0u16)
                    .to_socket_addrs()
                    .map(|addrs| addrs.collect::<Vec<SocketAddr>>())
                    .map_err(|err| format!("resolving '{host}': {err}"))
            })
            .await
            .map_err(|err| -> Box<dyn std::error::Error + Send + Sync> {
                format!("DNS resolution task failed: {err}").into()
            })?;

            let addrs =
                lookup.map_err(|err| -> Box<dyn std::error::Error + Send + Sync> { err.into() })?;

            if !allow_local_remotes() {
                if let Some(bad) = addrs.iter().find(|addr| !is_global_ip(addr.ip())) {
                    return Err(format!(
                        "refusing to connect: host resolved to a local/internal address {}",
                        bad.ip()
                    )
                    .into());
                }
            }

            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
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
        // The local-FS fetcher guards traversal via `safe_join`; the HTTP
        // fetcher cannot traverse a filesystem, but a hostile `path` could still
        // steer the request to a different URL path or host. Several path
        // segments derive from a remote's own info/refs/channel data during a
        // mirror sync, so validate before interpolating.
        validate_http_surface_path(path)?;
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

/// Whether the SSRF local/internal-address guard is currently relaxed by the
/// test/dev escape hatch.
///
/// The hatch exists only to let integration tests stand up upstream servers
/// on `127.0.0.1`. It is deliberately impossible for it to weaken a release
/// binary: the env var is consulted **only when `debug_assertions` is on**
/// (debug/test builds), so in an optimized production build this function is
/// a compile-time constant `false` and the SSRF guard can never be turned
/// off, regardless of the process environment.
///
/// Even in a debug build the variable must be set to a *truthy* value —
/// merely being present (e.g. `=0`, `=false`, empty) does not enable it, so a
/// stray export cannot silently disarm the guard. Truthy values are `1`,
/// `true`, `yes`, and `on` (case-insensitive).
fn allow_local_remotes() -> bool {
    // Compiled out entirely in release: a production binary never honors the
    // hatch no matter what is in the environment.
    if !cfg!(debug_assertions) {
        return false;
    }
    match std::env::var("AOS_HUB_ALLOW_LOCAL_REMOTES") {
        Ok(value) => {
            let value = value.trim();
            let on = matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            );
            if on {
                // Loud, one-time breadcrumb: this should only ever appear in
                // test/dev logs, never in production (where it is unreachable).
                static WARNED: std::sync::Once = std::sync::Once::new();
                WARNED.call_once(|| {
                    eprintln!(
                        "aos-registry-hub: SSRF local-remote guard RELAXED via \
                         AOS_HUB_ALLOW_LOCAL_REMOTES (debug build only)"
                    );
                });
            }
            on
        }
        Err(_) => false,
    }
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
/// **DNS rebinding:** this check resolves the host once, but the addresses it
/// validates are *not* the addresses reqwest would independently re-resolve at
/// connect time. That residual TOCTOU is closed by [`hardened_client`], whose
/// [`ValidatingResolver`] re-runs [`is_global_ip`] at the actual moment of
/// connection — so even a name that flips from a public answer here to an
/// internal answer later cannot be reached. This function remains a cheap,
/// fail-fast pre-check at configuration and call time.
///
/// **Test/dev escape hatch:** [`allow_local_remotes`] (the
/// `AOS_HUB_ALLOW_LOCAL_REMOTES` variable, honored only in debug builds)
/// skips the local/internal address rejection; the non-HTTP scheme rejection
/// still applies. The integration tests stand up upstream servers on
/// `127.0.0.1`; this lets them run while a release build — where the hatch is
/// compiled out entirely — always keeps the SSRF guard.
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
    if allow_local_remotes() {
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
///
/// Rejects every IANA special-purpose range that is not globally reachable.
/// The `is_shared`/`is_benchmarking`/`is_documentation` std helpers are still
/// unstable (feature `ip`), so the shared-address, benchmarking, protocol-
/// assignment, and documentation ranges are matched explicitly.
fn is_global_ipv4(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    // 100.64.0.0/10 — RFC 6598 carrier-grade NAT shared address space.
    let is_cgnat = o[0] == 100 && (o[1] & 0xc0) == 64;
    // 192.0.0.0/24 — RFC 6890 IETF protocol assignments.
    let is_protocol = o[0] == 192 && o[1] == 0 && o[2] == 0;
    // 198.18.0.0/15 — RFC 2544 benchmarking.
    let is_benchmarking = o[0] == 198 && (o[1] & 0xfe) == 18;
    // Documentation ranges (RFC 5737): 192.0.2.0/24 (TEST-NET-1),
    // 198.51.100.0/24 (TEST-NET-2), 203.0.113.0/24 (TEST-NET-3).
    let is_documentation = (o[0] == 192 && o[1] == 0 && o[2] == 2)
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113);
    !(v4.is_loopback()           // 127.0.0.0/8
        || v4.is_private()        // 10/8, 172.16/12, 192.168/16
        || v4.is_link_local()     // 169.254.0.0/16 (cloud metadata)
        || v4.is_unspecified()    // 0.0.0.0
        || v4.is_broadcast()      // 255.255.255.255
        || o[0] == 0              // 0.0.0.0/8
        || is_cgnat               // 100.64.0.0/10
        || is_protocol            // 192.0.0.0/24
        || is_benchmarking        // 198.18.0.0/15
        || is_documentation) // 192.0.2/24, 198.51.100/24, 203.0.113/24
}

/// Whether an IPv6 address is globally routable (not local/internal).
fn is_global_ipv6(v6: Ipv6Addr) -> bool {
    let segs = v6.segments();
    let is_unique_local = (segs[0] & 0xfe00) == 0xfc00; // fc00::/7
    let is_link_local = (segs[0] & 0xffc0) == 0xfe80; // fe80::/10
    let is_documentation = segs[0] == 0x2001 && segs[1] == 0x0db8; // 2001:db8::/32
    !(v6.is_loopback()
        || v6.is_unspecified()
        || is_unique_local
        || is_link_local
        || is_documentation)
}

/// Validate a relative surface path before interpolating it into an HTTP URL.
///
/// [`HttpFetch::fetch`] builds `"{base}/{path}"`, so a `path` that is absolute,
/// contains a `..` segment, embeds a scheme (`://`), starts a network-path
/// reference (`//host`), or carries control characters could escape the base or
/// repoint the request at a different host. Because several surface segments
/// derive from a remote's own `info/refs`/channel data during a mirror sync,
/// this guard gives the HTTP transport protection equivalent to the local
/// fetcher's [`safe_join`] (which it cannot reuse — there is no filesystem to
/// canonicalize against).
///
/// Legitimate surface paths (`nar/<hash>.nar.zst`, `objects/ab/cdef…`,
/// `channels/stable/00`, `info/refs`, `<hash>.narinfo`) pass unchanged.
///
/// # Errors
///
/// Returns a [`FetchError`] when `path` is empty, absolute (leading `/`),
/// contains a `\` or a control character, embeds `://`, or has any `.`/`..`
/// or empty path segment (which includes a leading `//`).
pub fn validate_http_surface_path(path: &str) -> Result<()> {
    let reject = |reason: &str| {
        Err(fetch_err(format!(
            "refusing HTTP surface path '{path}': {reason}"
        )))
    };
    if path.is_empty() {
        return reject("path is empty");
    }
    if path.starts_with('/') {
        return reject("path is absolute");
    }
    if path.contains('\\') {
        return reject("path contains a backslash");
    }
    if path.contains("://") {
        return reject("path embeds a URL scheme");
    }
    if path.chars().any(|c| c.is_control()) {
        return reject("path contains a control character");
    }
    // Reject `..`/`.`/empty segments. An empty segment covers a leading `//`
    // (network-path reference) and any doubled slash that could collapse the
    // base, and `..` covers traversal toward the host root.
    for segment in path.split('/') {
        if segment.is_empty() {
            return reject("path contains an empty segment (e.g. a leading or doubled '/')");
        }
        if segment == ".." || segment == "." {
            return reject("path contains a '.' or '..' segment");
        }
    }
    Ok(())
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

/// Verify that a write target stays within `root` even through symlinks.
///
/// [`safe_join`] rejects `..` and absolute components in the relative path, but
/// a write through it still *follows symlinks*: a binding-root component that is
/// itself a symlink pointing outside the root would let a `PUT`/mirror copy land
/// outside the surface (the read path guards against this by canonicalizing and
/// `starts_with`-checking the resolved file). This applies the same containment
/// to writes: it canonicalizes the *parent directory* of `target` — which must
/// already exist for an atomic write — and requires it to live under the
/// canonicalized `root`. The target file itself need not exist yet (a fresh
/// object), so only the parent is resolved.
///
/// Call this before creating/writing `target`. When the parent directory does
/// not yet exist, the nearest existing ancestor under the root is resolved
/// instead, so a brand-new `objects/ab/` subtree is still accepted as long as no
/// resolved ancestor escapes the root.
///
/// # Errors
///
/// Returns a [`FetchError`] when `root` cannot be canonicalized, the nearest
/// existing ancestor of `target` cannot be canonicalized, or the resolved
/// ancestor does not start with the canonicalized `root` (a symlink escape).
pub async fn ensure_within_root(root: &std::path::Path, target: &std::path::Path) -> Result<()> {
    // Resolve the nearest *existing* ancestor of the root. On a brand-new
    // binding the root directory may not exist yet (the first publish's
    // `create_dir_all` will make it), so canonicalize the longest prefix that
    // does exist — that is the real, symlink-resolved base the new tree will
    // hang off of.
    let canonical_root = nearest_existing_canonical(root).await?.ok_or_else(|| {
        fetch_err(format!(
            "no existing ancestor for surface root {}",
            root.display()
        ))
    })?;
    // Resolve the nearest existing ancestor of the target the same way. The
    // immediate parent may not exist yet for a fresh subtree; what matters is
    // that the existing portion of the path does not already route through a
    // symlink that leaves the root.
    let resolved = nearest_existing_canonical(target).await?.ok_or_else(|| {
        fetch_err(format!(
            "no existing ancestor for write target {}",
            target.display()
        ))
    })?;
    if !resolved.starts_with(&canonical_root) {
        return Err(fetch_err(format!(
            "write target {} escapes the binding root via symlink",
            target.display()
        )));
    }
    Ok(())
}

/// Canonicalize the nearest existing ancestor of `path` (including `path`
/// itself when it exists), walking up until a component that exists is found.
///
/// Returns `Ok(None)` only when no ancestor at all exists (an empty or
/// fully-absent path), which the callers treat as an error.
///
/// # Errors
///
/// Returns a [`FetchError`] when an existing ancestor cannot be canonicalized
/// for a reason other than absence.
async fn nearest_existing_canonical(path: &std::path::Path) -> Result<Option<PathBuf>> {
    let mut current = Some(path);
    while let Some(dir) = current {
        match tokio::fs::canonicalize(dir).await {
            Ok(canonical) => return Ok(Some(canonical)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                current = dir.parent();
            }
            Err(err) => {
                return Err(fetch_err(format!(
                    "canonicalizing {}: {err}",
                    dir.display()
                )));
            }
        }
    }
    Ok(None)
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

    #[tokio::test]
    async fn ensure_within_root_allows_real_subtree_and_rejects_symlink_escape() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("binding");
        std::fs::create_dir_all(root.join("objects/ab")).unwrap();

        // A normal write under a real binding tree is allowed, including a fresh
        // subtree whose immediate parent does not exist yet.
        let ok = safe_join(&root, "objects/ab/cd").unwrap();
        ensure_within_root(&root, &ok).await.unwrap();
        let fresh = safe_join(&root, "objects/zz/new").unwrap();
        ensure_within_root(&root, &fresh).await.unwrap();

        // A binding-root component that is a symlink pointing outside the root
        // must be refused: `safe_join` admits the path (no `..`), but the
        // canonicalized parent escapes the root.
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("escape")).unwrap();
        let target = safe_join(&root, "escape/loot").unwrap();
        let err = ensure_within_root(&root, &target).await.unwrap_err();
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
    fn validate_http_surface_path_allows_legit_and_rejects_escapes() {
        // Legitimate surface paths pass unchanged.
        for ok in [
            "nar/0a1b2c.nar.zst",
            "objects/ab/cdef0123",
            "channels/stable/00",
            "info/refs",
            "abc123.narinfo",
            "HEAD",
        ] {
            assert!(validate_http_surface_path(ok).is_ok(), "should allow {ok}");
        }
        // Escapes and repointing attempts are rejected.
        for bad in [
            "",
            "/etc/passwd",
            "../secret",
            "objects/../../etc/passwd",
            "//evil.example.com/x",
            "objects//ab",
            "https://evil.example.com/x",
            "objects/ab\\cd",
            "objects/ab/cd\r\nHost: evil",
            "objects/./ab",
        ] {
            assert!(
                validate_http_surface_path(bad).is_err(),
                "should reject {bad:?}"
            );
        }
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
    fn is_global_ipv4_rejects_special_purpose_ranges() {
        use std::net::Ipv4Addr;
        // 100.64.0.0/10 carrier-grade NAT (RFC 6598).
        assert!(!is_global_ipv4(Ipv4Addr::new(100, 64, 0, 1)));
        assert!(!is_global_ipv4(Ipv4Addr::new(100, 127, 255, 255)));
        // Boundaries of the /10 are global on either side.
        assert!(is_global_ipv4(Ipv4Addr::new(100, 63, 255, 255)));
        assert!(is_global_ipv4(Ipv4Addr::new(100, 128, 0, 1)));
        // 192.0.0.0/24 IETF protocol assignments (RFC 6890).
        assert!(!is_global_ipv4(Ipv4Addr::new(192, 0, 0, 1)));
        // 198.18.0.0/15 benchmarking (RFC 2544).
        assert!(!is_global_ipv4(Ipv4Addr::new(198, 18, 0, 1)));
        assert!(!is_global_ipv4(Ipv4Addr::new(198, 19, 255, 255)));
        assert!(is_global_ipv4(Ipv4Addr::new(198, 17, 255, 255)));
        assert!(is_global_ipv4(Ipv4Addr::new(198, 20, 0, 1)));
        // Documentation ranges (RFC 5737).
        assert!(!is_global_ipv4(Ipv4Addr::new(192, 0, 2, 1)));
        assert!(!is_global_ipv4(Ipv4Addr::new(198, 51, 100, 1)));
        assert!(!is_global_ipv4(Ipv4Addr::new(203, 0, 113, 1)));
        // A neighbour outside the documentation /24 is global.
        assert!(is_global_ipv4(Ipv4Addr::new(203, 0, 114, 1)));
    }

    #[test]
    fn is_safe_remote_url_rejects_new_special_ranges() {
        // The hatch must be unset for the literal-IP path to apply its check
        // (the lib test binary never sets it).
        assert!(std::env::var_os("AOS_HUB_ALLOW_LOCAL_REMOTES").is_none());
        assert!(is_safe_remote_url("http://100.64.0.1/").is_err());
        assert!(is_safe_remote_url("http://192.0.0.1/").is_err());
        assert!(is_safe_remote_url("http://198.18.0.1/").is_err());
        assert!(is_safe_remote_url("http://192.0.2.1/").is_err());
        assert!(is_safe_remote_url("http://198.51.100.1/").is_err());
        assert!(is_safe_remote_url("http://203.0.113.1/").is_err());
        // IPv6 documentation range.
        assert!(is_safe_remote_url("http://[2001:db8::1]/").is_err());
    }

    #[tokio::test]
    async fn hardened_client_does_not_follow_redirects() {
        use axum::http::{header, StatusCode};
        use axum::routing::get;

        // A server whose only route 302-redirects to the cloud metadata
        // service. A redirect-following client would chase the `Location`
        // into 169.254.169.254; the hardened client must not.
        async fn redirect() -> axum::response::Response {
            (
                StatusCode::FOUND,
                [(header::LOCATION, "http://169.254.169.254/latest/meta-data/")],
            )
                .into_response()
        }
        use axum::response::IntoResponse as _;
        let app = axum::Router::new().route("/go", get(redirect));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        // A literal-IP host bypasses the validating resolver, so this needs no
        // env hatch: we are exercising the redirect policy, not the resolver.
        let url = format!("http://{}/go", listener.local_addr().unwrap());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = hardened_client();
        let response = client.get(&url).send().await.unwrap();
        // The 3xx is returned verbatim — the client stopped at the redirect
        // rather than following it to the internal target.
        assert_eq!(response.status(), StatusCode::FOUND);
        assert_eq!(
            response
                .headers()
                .get(header::LOCATION)
                .and_then(|v| v.to_str().ok()),
            Some("http://169.254.169.254/latest/meta-data/"),
        );
    }

    #[tokio::test]
    async fn validating_resolver_rejects_non_global_host() {
        // `localhost` resolves to a loopback address. With the escape hatch
        // unset (the lib test binary never sets it), the validating resolver
        // on the hardened client must refuse to connect — proving the SSRF
        // check runs at connect time, not only in `is_safe_remote_url`.
        assert!(std::env::var_os("AOS_HUB_ALLOW_LOCAL_REMOTES").is_none());

        let client = hardened_client();
        let err = client
            .get("http://localhost:80/")
            .send()
            .await
            .expect_err("connecting to a loopback-resolving host must fail");
        // The failure originates in the DNS layer; reqwest surfaces it as a
        // request/connect error.
        assert!(err.is_request() || err.is_connect(), "got: {err:?}");
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
