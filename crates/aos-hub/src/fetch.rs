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

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context as _, Result};
use async_trait::async_trait;

// The pure SSRF/path guards moved to the runtime-agnostic core crate (RFC-0004
// Phase 5) so the Worker shares them; the native DNS pre-check, validating
// resolver, and symlink-escape canonicalization stay here. Re-export the pure
// items so existing `crate::fetch::…` paths (used across the hub) are unchanged.
use aos_hub_core::url_guard::{self, fetch_err};
pub use aos_hub_core::url_guard::{
    is_fetch_error, safe_join, validate_http_surface_path, FetchError,
};

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

/// Typed filesystem failure retained for placement failover classification.
#[derive(Debug, thiserror::Error)]
#[error("{marker}")]
pub(crate) struct LocalFsReadError {
    /// Original IO category, or `None` for a structural containment failure.
    kind: Option<std::io::ErrorKind>,
    /// Fetch-error marker preserved for the legacy indexer's stale classification.
    #[source]
    marker: FetchError,
}

impl LocalFsReadError {
    /// Whether this error is a positively identified transient IO condition.
    #[must_use]
    pub(crate) fn is_retryable(&self) -> bool {
        matches!(
            self.kind,
            Some(
                std::io::ErrorKind::Interrupted
                    | std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::WouldBlock
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::NotConnected
            )
        )
    }
}

/// Wraps a native filesystem IO error without erasing its stable kind.
pub(crate) fn local_fs_io_error(context: &str, error: std::io::Error) -> anyhow::Error {
    anyhow::Error::new(LocalFsReadError {
        kind: Some(error.kind()),
        marker: FetchError(format!("{context}: {error}")),
    })
}

/// Wraps a structural filesystem refusal, which is always terminal.
fn local_fs_structural_error(message: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(LocalFsReadError {
        kind: None,
        marker: FetchError(message.into()),
    })
}

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
///
/// # Literal-IP hosts
///
/// reqwest invokes a custom [`reqwest::dns::Resolve`] **only for DNS names** —
/// a URL whose host is already an IP literal (`http://169.254.169.254/…`,
/// `http://[fd00::1]/…`) is handed straight to the connector and never reaches
/// [`ValidatingResolver`]. The resolver therefore cannot, on its own, stop a
/// hub-originated request to an internal/metadata literal IP. That gap is
/// closed by gating **every** hub-originated request URL through
/// [`is_safe_remote_url`] at its call site before it is issued:
/// [`is_safe_remote_url`] parses the host and, when it is an IP literal, checks
/// it directly with [`is_global_ip`] (the *same* predicate the resolver uses),
/// rejecting loopback/link-local/private/metadata literals. The two mechanisms
/// are complementary — the resolver covers names (and DNS rebinding), the
/// call-site check covers literals — and together they reject every
/// local/internal target uniformly regardless of whether the host is a name or
/// an IP. The `AOS_HUB_ALLOW_LOCAL_REMOTES` debug hatch
/// relaxes both consistently.
pub async fn hardened_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        // Environment-configured proxies would move the actual origin
        // connection outside this process and defeat connect-time DNS pinning.
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .dns_resolver(Arc::new(ValidatingResolver))
        .build()
        .unwrap_or_else(|error| {
            tracing::error!(%error, "hardened outbound HTTP client initialization failed");
            // Continuing with reqwest's defaults would silently re-enable
            // redirects and remove connect-time DNS-rebinding protection.
            // This process cannot safely serve requests without that boundary.
            std::process::abort()
        })
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
/// The test/dev escape hatch (`url_guard::allow_local_remotes`) relaxes the
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

            if !url_guard::allow_local_remotes() {
                let addresses = addrs.iter().map(|address| address.ip()).collect::<Vec<_>>();
                url_guard::validate_resolved_addresses(&addresses).map_err(
                    |error| -> Box<dyn std::error::Error + Send + Sync> {
                        format!("refusing to connect: {error:#}").into()
                    },
                )?;
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

    /// Opens one object stream and reports the version of that exact handle.
    async fn fetch_stream(
        &self,
        path: &str,
        range: Option<(u64, u64)>,
    ) -> Result<Option<aos_hub_core::fetch::StreamedRead>> {
        let Some(bytes) = self.fetch(path).await? else {
            return Ok(None);
        };
        let total = bytes.len() as u64;
        let (bytes, served) = match range {
            Some((start, end)) if start < total => {
                let end = end.min(total.saturating_sub(1));
                (
                    bytes[start as usize..=end as usize].to_vec(),
                    Some((start, end)),
                )
            }
            _ => (bytes, None),
        };
        Ok(Some(aos_hub_core::fetch::StreamedRead {
            body: axum::body::Body::from(bytes),
            total,
            range: served,
            strong_etag: None,
            snapshot_lease_id: None,
        }))
    }

    /// Returns a strong backend version for one object, when available.
    async fn inventory_strong_etag(&self, _path: &str) -> Result<Option<String>> {
        Ok(None)
    }

    /// The byte length of the object at `path`, or `None` when it does not exist.
    ///
    /// Used by the write facade to compute the overwrite quota delta. The default
    /// reads the whole object and measures it; the filesystem fetcher overrides
    /// it with a `metadata` `stat` (which, unlike a full read, does not require
    /// the surface root to already exist — a brand-new managed registry whose
    /// binding directory has never been written probes cleanly as `None`).
    ///
    /// # Errors
    ///
    /// Returns an error for IO/transport failures other than absence.
    async fn size(&self, path: &str) -> Result<Option<u64>> {
        Ok(self.fetch(path).await?.map(|bytes| bytes.len() as u64))
    }

    /// A human-readable description of the source (for health/audit text).
    fn describe(&self) -> String;
}

/// Filesystem-backed surface access for `file://` bindings.
pub struct LocalFsFetch {
    root: PathBuf,
    image_snapshots: Option<std::sync::Arc<crate::image_snapshot::ImageSnapshotStore>>,
    image_snapshot_db: Option<std::sync::Arc<aos_hub_core::db::Database>>,
    lease_image_snapshots: bool,
}

impl LocalFsFetch {
    pub(crate) fn image_digest(path: &str) -> Option<&str> {
        aos_hub_core::keymap::image_object_sha256(path)
    }

    /// Create a fetcher rooted at a surface directory.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            image_snapshots: None,
            image_snapshot_db: None,
            lease_image_snapshots: false,
        }
    }

    /// Attaches the Hub-private immutable image store.
    #[must_use]
    pub fn with_image_snapshots(
        mut self,
        snapshots: std::sync::Arc<crate::image_snapshot::ImageSnapshotStore>,
    ) -> Self {
        self.image_snapshots = Some(snapshots);
        self
    }

    /// Attaches durable in-flight lease storage for snapshot delivery.
    #[must_use]
    pub fn with_image_snapshot_db(
        mut self,
        db: std::sync::Arc<aos_hub_core::db::Database>,
    ) -> Self {
        self.image_snapshot_db = Some(db);
        self
    }

    /// Requires independent durable leases for pre-commit image verification.
    #[must_use]
    pub fn with_image_snapshot_indexing(mut self) -> Self {
        self.lease_image_snapshots = true;
        self
    }

    /// The surface root directory.
    pub fn root(&self) -> &std::path::Path {
        &self.root
    }

    fn metadata_version(metadata: &std::fs::Metadata) -> String {
        use std::os::unix::fs::MetadataExt as _;

        format!(
            "\"fs-{}-{}-{}-{}-{}\"",
            metadata.dev(),
            metadata.ino(),
            metadata.len(),
            metadata.mtime(),
            metadata.mtime_nsec()
        )
    }

    /// Returns a strong version derived from filesystem identity and change metadata.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe path or filesystem read failure.
    pub async fn strong_version(&self, path: &str) -> Result<Option<String>> {
        let full = safe_join(&self.root, path)?;
        if let Some(digest) = Self::image_digest(path) {
            let snapshots = self.image_snapshots.as_ref().context(
                "local filesystem image delivery requires a configured Hub-private snapshot store",
            )?;
            if self.lease_image_snapshots {
                let root = self.root.clone();
                let path = path.to_string();
                let digest = digest.to_string();
                let digest_for_validation = digest.clone();
                let snapshots = std::sync::Arc::clone(snapshots);
                let valid = tokio::task::spawn_blocking(move || {
                    let Some(source) = crate::image_snapshot::open_surface_file(&root, &path)?
                    else {
                        return Ok::<_, anyhow::Error>(false);
                    };
                    snapshots.validate_source(source, &digest_for_validation)?;
                    Ok(true)
                })
                .await
                .context("joining image source validation")??;
                if !valid {
                    return Ok(None);
                }
                return Ok(Some(format!("\"snapshot-sha256-{digest}\"")));
            }
            return Ok((snapshots.open_retained(digest)?.is_some()
                || crate::image_snapshot::open_surface_file(&self.root, path)?.is_some())
            .then(|| format!("\"snapshot-sha256-{digest}\"")));
        }
        match tokio::fs::metadata(full).await {
            Ok(metadata) => Ok(Some(Self::metadata_version(&metadata))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(local_fs_io_error("stat surface object version", error)),
        }
    }

    /// Stream a file from the surface (optionally an inclusive byte `range`),
    /// with the same symlink containment as [`fetch`](Self::fetch).
    ///
    /// Backs the core [`SurfaceFetch::fetch_stream`](aos_hub_core::fetch::SurfaceFetch::fetch_stream)
    /// impl in [`crate::coreports`], so the native hub streams a NAR from disk
    /// (a `tokio` `ReaderStream`) rather than buffering it — the same shared
    /// cache-serve path the Worker uses with its R2 stream.
    ///
    /// # Errors
    ///
    /// Returns an error on a symlink escape or an IO failure other than absence
    /// (an absent file is `Ok(None)`).
    pub(crate) async fn stream_read(
        &self,
        path: &str,
        range: Option<(u64, u64)>,
    ) -> Result<Option<aos_hub_core::fetch::StreamedRead>> {
        use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _};
        use tokio_util::io::ReaderStream;

        let full = safe_join(&self.root, path)?;
        if let Some(digest) = Self::image_digest(path) {
            let snapshots = self.image_snapshots.clone().context(
                "local filesystem image delivery requires a configured Hub-private snapshot store",
            )?;
            let root = self.root.clone();
            let path = path.to_string();
            let digest_owned = digest.to_string();
            let source = tokio::task::spawn_blocking(move || {
                crate::image_snapshot::open_surface_file(&root, &path)
            })
            .await
            .context("joining image source open")??;
            let opened = if let Some(db) = &self.image_snapshot_db {
                Some(
                    snapshots
                        .open_or_publish_leased(
                            source,
                            digest_owned,
                            db,
                            self.lease_image_snapshots,
                        )
                        .await?,
                )
            } else if let Some(file) = snapshots.open_retained(digest)? {
                let size = file.metadata()?.len();
                Some((file, size, None))
            } else {
                match source {
                    Some(source) => {
                        let (file, size) = snapshots.publish_async(source, digest_owned).await?;
                        Some((file, size, None))
                    }
                    None => None,
                }
            };
            let Some((file, total, snapshot_lease_id)) = opened else {
                return Ok(None);
            };
            let mut file = tokio::fs::File::from_std(file);
            let strong_etag = Some(format!("\"snapshot-sha256-{digest}\""));
            return match range {
                Some((start, end)) if start < total => {
                    let end = end.min(total.saturating_sub(1));
                    file.seek(std::io::SeekFrom::Start(start)).await?;
                    Ok(Some(aos_hub_core::fetch::StreamedRead {
                        body: axum::body::Body::from_stream(ReaderStream::new(
                            file.take(end - start + 1),
                        )),
                        total,
                        range: Some((start, end)),
                        strong_etag,
                        snapshot_lease_id,
                    }))
                }
                _ => Ok(Some(aos_hub_core::fetch::StreamedRead {
                    body: axum::body::Body::from_stream(ReaderStream::new(file)),
                    total,
                    range: None,
                    strong_etag,
                    snapshot_lease_id,
                })),
            };
        }
        let root = match tokio::fs::canonicalize(&self.root).await {
            Ok(root) => root,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(local_fs_io_error("canonicalizing surface root", err)),
        };
        let canonical = match tokio::fs::canonicalize(&full).await {
            Ok(canonical) => canonical,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => {
                return Err(local_fs_io_error(
                    &format!("resolving {}", full.display()),
                    err,
                ));
            }
        };
        if !canonical.starts_with(&root) {
            return Err(local_fs_structural_error(format!(
                "surface path '{path}' escapes the surface root via symlink"
            )));
        }
        let mut file = match tokio::fs::File::open(&canonical).await {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => {
                return Err(local_fs_io_error(
                    &format!("opening {}", canonical.display()),
                    err,
                ));
            }
        };
        let metadata = file
            .metadata()
            .await
            .map_err(|err| local_fs_io_error(&format!("stat {}", canonical.display()), err))?;
        let total = metadata.len();
        let strong_etag = Some(Self::metadata_version(&metadata));
        match range {
            Some((start, end)) if start < total => {
                let end = end.min(total.saturating_sub(1));
                file.seek(std::io::SeekFrom::Start(start))
                    .await
                    .map_err(|err| {
                        local_fs_io_error(&format!("seek {}", canonical.display()), err)
                    })?;
                let stream = ReaderStream::new(file.take(end - start + 1));
                Ok(Some(aos_hub_core::fetch::StreamedRead {
                    body: axum::body::Body::from_stream(stream),
                    total,
                    range: Some((start, end)),
                    strong_etag,
                    snapshot_lease_id: None,
                }))
            }
            _ => Ok(Some(aos_hub_core::fetch::StreamedRead {
                body: axum::body::Body::from_stream(ReaderStream::new(file)),
                total,
                range: None,
                strong_etag,
                snapshot_lease_id: None,
            })),
        }
    }
}

#[async_trait]
impl SurfaceFetch for LocalFsFetch {
    async fn fetch(&self, path: &str) -> Result<Option<Vec<u8>>> {
        let full = safe_join(&self.root, path)?;
        // Containment: resolve symlinks and require the real file to live
        // under the real root, so a hostile surface cannot link out of it.
        let root = match tokio::fs::canonicalize(&self.root).await {
            Ok(root) => root,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => {
                return Err(local_fs_io_error(
                    &format!("canonicalizing surface root {}", self.root.display()),
                    err,
                ));
            }
        };
        let canonical = match tokio::fs::canonicalize(&full).await {
            Ok(canonical) => canonical,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => {
                return Err(local_fs_io_error(
                    &format!("resolving {}", full.display()),
                    err,
                ));
            }
        };
        if !canonical.starts_with(&root) {
            return Err(local_fs_structural_error(format!(
                "surface path '{path}' escapes the surface root via symlink"
            )));
        }
        match tokio::fs::read(&canonical).await {
            Ok(bytes) => Ok(Some(bytes)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(local_fs_io_error(
                &format!("reading {}", canonical.display()),
                err,
            )),
        }
    }

    async fn size(&self, path: &str) -> Result<Option<u64>> {
        // `stat` the joined path directly: this neither reads the body nor
        // requires the surface root to already exist (a never-written managed
        // binding probes cleanly as `None`), matching the prior in-facade
        // `std::fs::metadata(&target)` overwrite-delta read. `safe_join` is
        // lexical, so a missing root yields a non-existent target -> `None`.
        let full = safe_join(&self.root, path)?;
        match tokio::fs::metadata(&full).await {
            Ok(meta) => Ok(Some(meta.len())),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(local_fs_io_error(&format!("stat {}", full.display()), err)),
        }
    }

    async fn fetch_stream(
        &self,
        path: &str,
        range: Option<(u64, u64)>,
    ) -> Result<Option<aos_hub_core::fetch::StreamedRead>> {
        self.stream_read(path, range).await
    }

    async fn inventory_strong_etag(&self, path: &str) -> Result<Option<String>> {
        self.strong_version(path).await
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
    pub async fn new(base: impl Into<String>) -> Self {
        Self {
            base: base.into().trim_end_matches('/').to_string(),
            client: hardened_client().await,
        }
    }

    /// Reads a surface object as a version-bound HTTP stream.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe path, transport failure, or malformed response.
    pub async fn stream_read(
        &self,
        path: &str,
        range: Option<(u64, u64)>,
    ) -> Result<Option<aos_hub_core::fetch::StreamedRead>> {
        use reqwest::header;

        validate_http_surface_path(path)?;
        let url = format!("{}/{path}", self.base);
        let mut request = self.client.get(&url);
        if let Some((start, end)) = range {
            let value = if end == u64::MAX {
                format!("bytes={start}-")
            } else {
                format!("bytes={start}-{end}")
            };
            request = request.header(header::RANGE, value);
        }
        let response = request
            .send()
            .await
            .map_err(|error| fetch_err(format!("fetching {url}: {error}")))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !response.status().is_success() {
            return Err(fetch_err(format!(
                "fetching {url}: HTTP {}",
                response.status()
            )));
        }
        let served = if response.status() == reqwest::StatusCode::PARTIAL_CONTENT {
            Some(
                response
                    .headers()
                    .get(header::CONTENT_RANGE)
                    .and_then(|value| value.to_str().ok())
                    .and_then(super::coreports::parse_content_range)
                    .context("HTTP surface 206 has malformed Content-Range")?,
            )
        } else {
            None
        };
        let total = served
            .map(|(_, _, total)| total)
            .or_else(|| response.content_length())
            .context("HTTP surface response has no object length")?;
        let range = served.map(|(start, end, _)| (start, end));
        let strong_etag = response
            .headers()
            .get(header::ETAG)
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .map(str::to_string)
            .filter(|value| aos_hub_core::surface_write::strong_if_match_etag(value).is_ok());
        Ok(Some(aos_hub_core::fetch::StreamedRead {
            body: axum::body::Body::from_stream(response.bytes_stream()),
            total,
            range,
            strong_etag,
            snapshot_lease_id: None,
        }))
    }

    /// Returns the origin's strong HTTP entity tag for one object.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe path or failed HTTP request.
    pub async fn strong_version(&self, path: &str) -> Result<Option<String>> {
        use reqwest::header;

        validate_http_surface_path(path)?;
        let url = format!("{}/{path}", self.base);
        let response = self
            .client
            .head(&url)
            .send()
            .await
            .map_err(|error| fetch_err(format!("fetching {url}: {error}")))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !response.status().is_success() {
            return Err(fetch_err(format!(
                "fetching {url}: HTTP {}",
                response.status()
            )));
        }
        Ok(response
            .headers()
            .get(header::ETAG)
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .map(str::to_string)
            .filter(|value| aos_hub_core::surface_write::strong_if_match_etag(value).is_ok()))
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

    async fn fetch_stream(
        &self,
        path: &str,
        range: Option<(u64, u64)>,
    ) -> Result<Option<aos_hub_core::fetch::StreamedRead>> {
        self.stream_read(path, range).await
    }

    async fn inventory_strong_etag(&self, path: &str) -> Result<Option<String>> {
        self.strong_version(path).await
    }

    fn describe(&self) -> String {
        self.base.clone()
    }
}

/// Constructs a fetcher for an explicitly configured mirror upstream.
///
/// `file://` and bare absolute paths map to [`LocalFsFetch`]; `http://`
/// and `https://` map to [`HttpFetch`].
///
/// # Errors
///
/// Returns an error for unsupported URL schemes.
pub async fn fetch_mirror_upstream(upstream_url: &str) -> Result<Box<dyn SurfaceFetch>> {
    if let Some(path) = upstream_url.strip_prefix("file://") {
        return Ok(Box::new(LocalFsFetch::new(path)));
    }
    if upstream_url.starts_with('/') {
        return Ok(Box::new(LocalFsFetch::new(upstream_url)));
    }
    if upstream_url.starts_with("http://") || upstream_url.starts_with("https://") {
        return Ok(Box::new(HttpFetch::new(upstream_url).await));
    }
    bail!(
        "unsupported mirror upstream URL '{upstream_url}' (expected file://, /path, or http(s)://)"
    );
}

/// Reject a network-origin URL that is local, internal, or non-HTTP — an SSRF
/// guard for operator-configured remote origins.
///
/// A remote origin the hub fetches over the network must be
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
/// Remote-origin configuration is admin-only, which bounds the blast
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
/// **Test/dev escape hatch:** `url_guard::allow_local_remotes` (the
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
    // The test/dev hatch relaxes the local/internal address rejection but never
    // the non-HTTP scheme rejection: enforce the scheme even when it is on.
    if url_guard::allow_local_remotes() {
        url_guard::require_http_scheme(raw)?;
        return Ok(());
    }
    // The pure core guard enforces the http(s) scheme and, for a literal-IP
    // host (v4 or v6), the global-address check. Hostnames are accepted there
    // (it does no DNS); the native pre-check below resolves them and rejects any
    // answer that maps to a local/internal address.
    url_guard::is_safe_remote_url(raw)?;
    // Re-parse for the hostname-resolution pre-check (the URL is already known
    // valid and http(s)). Only a *domain* host needs DNS here — a literal IP
    // host was fully validated against `is_global_ip` by the core guard above
    // (using `url::Host`, which classifies bracketed IPv6 literals correctly).
    let url = url::Url::parse(raw)
        .map_err(|err| fetch_err(format!("remote URL '{raw}' is not valid: {err}")))?;
    let host = match url.host() {
        Some(url::Host::Domain(host)) => host.to_string(),
        // A literal IP (already validated) or a hostless URL: nothing to resolve.
        _ => return Ok(()),
    };
    let port = url.port_or_known_default().unwrap_or(80);
    let resolved: Vec<IpAddr> = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|err| fetch_err(format!("resolving remote host '{host}': {err}")))?
        .map(|addr| addr.ip())
        .collect();
    if resolved.is_empty() {
        return Err(fetch_err(format!(
            "remote host '{host}' did not resolve to any address"
        )));
    }
    for ip in resolved {
        if !url_guard::is_global_ip(ip) {
            return Err(fetch_err(format!(
                "remote URL '{raw}' resolves to a local/internal address {ip}"
            )));
        }
    }
    Ok(())
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

    #[test]
    fn image_snapshot_paths_accept_only_canonical_disk_and_metadata_grammars() {
        let disk = "a".repeat(64);
        let metadata = "b".repeat(64);
        assert_eq!(
            LocalFsFetch::image_digest(&format!("images/sha256/{disk}/aos.img")),
            Some(disk.as_str())
        );
        assert_eq!(
            LocalFsFetch::image_digest(&format!(
                "images/sha256/{disk}/metadata/{metadata}/image-info.json"
            )),
            Some(metadata.as_str())
        );
        for rejected in [
            format!("images/sha256/{disk}/aliases/{metadata}"),
            format!("images/sha256/{disk}/metadata/{metadata}/other.json"),
            format!("images/sha256/{}/disk.img", "A".repeat(64)),
            format!("images/sha256/{disk}/nested/disk.img"),
            format!("images/sha256/{disk}/unsafe..img"),
            format!("images/sha256/{disk}/.hidden"),
            format!("images/sha256/{disk}/non_ascii_é.img"),
        ] {
            assert!(
                LocalFsFetch::image_digest(&rejected).is_none(),
                "{rejected}"
            );
        }
    }

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

    #[tokio::test]
    async fn fetch_mirror_upstream_dispatches_schemes() {
        assert!(fetch_mirror_upstream("file:///srv/reg").await.is_ok());
        assert!(fetch_mirror_upstream("/srv/reg").await.is_ok());
        assert!(fetch_mirror_upstream("https://cdn.example.com/reg")
            .await
            .is_ok());
        assert!(fetch_mirror_upstream("s3://bucket/prefix").await.is_err());
    }

    #[tokio::test]
    async fn read_body_capped_rejects_over_cap_body() {
        use axum::routing::get;

        // A tiny upstream that uses chunked transfer and streams more bytes
        // than a deliberately small cap. There is no trustworthy declared
        // length, so the cap must be enforced mid-stream.
        async fn big() -> axum::response::Response {
            let chunks = futures_util::stream::iter([
                Ok::<_, std::io::Error>(axum::body::Bytes::from(vec![0_u8; 700])),
                Ok(axum::body::Bytes::from(vec![0_u8; 700])),
            ]);
            axum::response::Response::new(axum::body::Body::from_stream(chunks))
        }
        // A lying/malformed peer advertises a body already beyond the cap. The
        // reader must refuse it before it allocates or polls the body stream.
        async fn lying_length() -> axum::response::Response {
            axum::response::Response::builder()
                .header(axum::http::header::CONTENT_LENGTH, "4096")
                .body(axum::body::Body::empty())
                .unwrap()
        }
        let app = axum::Router::new()
            .route("/big", get(big))
            .route("/lying", get(lying_length));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/big", listener.local_addr().unwrap());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = hardened_client().await;
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
        assert_eq!(body.len(), 1400);

        let lying_url = url.replace("/big", "/lying");
        let response = client.get(&lying_url).send().await.unwrap();
        let error = read_body_capped(response, cap, "lying S3 list page")
            .await
            .unwrap_err();
        assert!(error.to_string().contains("4096"), "got: {error:#}");
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
        // A literal-IP host bypasses the validating resolver (reqwest only
        // consults the resolver for DNS names), so this needs no env hatch: we
        // are exercising the redirect policy here, not the resolver. The
        // literal-IP SSRF defense lives at the call sites via
        // `is_safe_remote_url` (see
        // `literal_ip_metadata_host_is_rejected_by_the_call_site_predicate`),
        // which a raw `client.get` in this test deliberately skips.
        let url = format!("http://{}/go", listener.local_addr().unwrap());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = hardened_client().await;
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

        let client = hardened_client().await;
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
    fn hardened_client_ignores_proxy_environment() {
        use std::io::{Read as _, Write as _};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let target = format!("http://{}/", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            for _ in 0..500 {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let mut request = [0_u8; 1024];
                        let _ = stream.read(&mut request);
                        stream
                            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                            .unwrap();
                        return;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("proxy-policy test server failed: {error}"),
                }
            }
            panic!("hardened client did not connect directly to the target");
        });
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "fetch::tests::hardened_client_ignores_proxy_environment_child",
                "--nocapture",
            ])
            .env("AOS_HUB_PROXY_TEST_TARGET", target)
            .env("HTTP_PROXY", "http://127.0.0.1:9")
            .env("HTTPS_PROXY", "http://127.0.0.1:9")
            .env("ALL_PROXY", "http://127.0.0.1:9")
            .env("http_proxy", "http://127.0.0.1:9")
            .env("https_proxy", "http://127.0.0.1:9")
            .env("all_proxy", "http://127.0.0.1:9")
            .env_remove("NO_PROXY")
            .env_remove("no_proxy")
            .output()
            .unwrap();
        server.join().unwrap();
        assert!(
            output.status.success(),
            "child proxy-policy test failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[tokio::test]
    async fn hardened_client_ignores_proxy_environment_child() {
        let Some(target) = std::env::var_os("AOS_HUB_PROXY_TEST_TARGET") else {
            return;
        };
        let response = hardened_client()
            .await
            .get(target.to_string_lossy().as_ref())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn local_image_stream_is_an_identity_bound_snapshot() {
        use http_body_util::BodyExt as _;
        use sha2::Digest as _;

        let root = tempfile::tempdir().unwrap();
        let hub = tempfile::tempdir().unwrap();
        let snapshots = crate::image_snapshot::ImageSnapshotStore::open(hub.path()).unwrap();
        let digest = hex::encode(sha2::Sha256::digest(b"signed-bytes"));
        let path = format!("images/sha256/{digest}/disk.img");
        let full = root.path().join(&path);
        std::fs::create_dir_all(full.parent().unwrap()).unwrap();
        std::fs::write(&full, b"signed-bytes").unwrap();
        let fetch = LocalFsFetch::new(root.path()).with_image_snapshots(Arc::clone(&snapshots));
        let version = fetch.strong_version(&path).await.unwrap().unwrap();
        let read = fetch.stream_read(&path, None).await.unwrap().unwrap();
        assert_eq!(read.strong_etag.as_deref(), Some(version.as_str()));

        // A same-length in-place mutation after publication cannot alter the
        // response snapshot or the token used by subsequent range requests.
        std::fs::write(&full, b"evil--bytes!").unwrap();
        let bytes = read.body.collect().await.unwrap().to_bytes();
        assert_eq!(bytes.as_ref(), b"signed-bytes");
        assert_eq!(fetch.strong_version(&path).await.unwrap().unwrap(), version);
        let second = fetch
            .stream_read(&path, Some((2, 5)))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(second.total, 12);
        assert_eq!(
            second.body.collect().await.unwrap().to_bytes().as_ref(),
            b"gned"
        );
    }

    #[tokio::test]
    async fn local_image_head_and_range_open_snapshot_without_full_response() {
        use http_body_util::BodyExt as _;
        use sha2::Digest as _;

        let root = tempfile::tempdir().unwrap();
        let hub = tempfile::tempdir().unwrap();
        let snapshots = crate::image_snapshot::ImageSnapshotStore::open(hub.path()).unwrap();
        let bytes = vec![0x5a; 8 * 1024 * 1024];
        let digest = hex::encode(sha2::Sha256::digest(&bytes));
        let path = format!("images/sha256/{digest}/large.img");
        let full = root.path().join(&path);
        std::fs::create_dir_all(full.parent().unwrap()).unwrap();
        std::fs::write(&full, &bytes).unwrap();
        let fetch = LocalFsFetch::new(root.path()).with_image_snapshots(Arc::clone(&snapshots));
        let indexed = fetch.stream_read(&path, None).await.unwrap().unwrap();
        assert_eq!(
            indexed.body.collect().await.unwrap().to_bytes().len(),
            bytes.len()
        );

        // The unopened body models HEAD: metadata is available without polling
        // or allocating an image-sized response body.
        let head = fetch
            .stream_read(&path, Some((0, 0)))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(head.total, bytes.len() as u64);
        drop(head.body);
        let range = fetch
            .stream_read(&path, Some((bytes.len() as u64 - 4, u64::MAX)))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(range.body.collect().await.unwrap().to_bytes().len(), 4);
        assert!(snapshots.open_readonly(&digest).is_ok());
    }

    #[test]
    fn literal_ip_metadata_host_is_rejected_by_the_call_site_predicate() {
        // SECURITY regression (SSRF, finding #7): a hub-originated request to a
        // literal-IP internal/metadata host must be refused. reqwest hands an
        // IP-literal host straight to the connector and never consults the
        // `ValidatingResolver` (which only sees DNS names), so the literal-IP
        // defense is `is_safe_remote_url` applied at every call site. This test
        // pins the predicate the call sites rely on: every internal literal —
        // loopback, the cloud-metadata link-local, RFC-1918, and their
        // IPv4-mapped IPv6 / IPv6 forms — is rejected, while a public literal
        // passes. (The hatch is never set in the lib test binary.)
        assert!(std::env::var_os("AOS_HUB_ALLOW_LOCAL_REMOTES").is_none());
        for blocked in [
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1/x.narinfo",
            "http://10.0.0.5/x.narinfo",
            "http://192.168.1.1/x.narinfo",
            "http://[::1]/x.narinfo",
            "http://[fd00::1]/x.narinfo",
            "http://[::ffff:169.254.169.254]/x.narinfo",
        ] {
            assert!(
                is_safe_remote_url(blocked).is_err(),
                "literal-IP internal host must be refused: {blocked}"
            );
        }
        // A public literal still passes, so legitimate IP-addressed caches work.
        assert!(is_safe_remote_url("http://93.184.216.34/x.narinfo").is_ok());
    }
}
