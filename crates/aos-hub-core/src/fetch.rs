//! The surface-read port: how the shared service reaches a registry's bytes.
//!
//! The registry's wire surface (loose git objects, `info/refs`, channel
//! partitions, NARs, …) lives in different stores per deployment — a local
//! filesystem or HTTP origin on the native hub, an R2 bucket on the Cloudflare
//! Worker. The shared service (the facade and the `GitService` methods) reads it
//! through two ports so the read logic is written once:
//!
//! - [`SurfaceFetch`] — read one surface path (the RFC's "Blobs" port, read
//!   side: the facade streams objects through it and the git log/diff walk
//!   commits through it), and [`list_page`](SurfaceFetch::list_page) the
//!   surface in bounded pages for storage migration and cache re-scan.
//! - [`SurfaceProvider`] — open a [`SurfaceFetch`] for an explicitly selected
//!   physical placement. The native hub resolves its binding and prefix to a
//!   filesystem or object-store reader; the Worker resolves the same record to
//!   bound R2 or an external S3-compatible origin. Every resolution requires an
//!   explicit placement; there is no resource-global binding fallback.
//!
//! Both carry the same target-conditional bound as the rest of the core ports
//! ([`BackendBounds`]): `Send + Sync` natively, unbounded on the single-threaded
//! wasm32 Worker (whose R2 futures are `?Send`).

use std::collections::BTreeMap;

use anyhow::{bail, Context as _, Result};
use futures_util::TryStreamExt as _;
use sha2::{Digest as _, Sha256};

use crate::backend::BackendBounds;
use crate::db::SurfacePlacementRecord;

/// Maximum object keys accepted from one physical placement or one cache-wide scan.
pub const MAX_SURFACE_LIST_OBJECTS: usize = 1_000_000;

/// Maximum aggregate UTF-8 key bytes accepted by one physical or cache-wide scan.
pub const MAX_SURFACE_LIST_PATH_BYTES: usize = 256 * 1024 * 1024;

/// Maximum backend pages accepted from one paginated surface listing.
pub const MAX_SURFACE_LIST_PAGES: usize = 1_024;

/// Maximum keys one listing page may return to shared code.
pub const MAX_SURFACE_LIST_PAGE_OBJECTS: usize = 1_000;

/// Maximum bytes accepted for an opaque backend listing cursor.
pub const MAX_SURFACE_LIST_CURSOR_BYTES: usize = 4 * 1024;

/// Maximum narinfo body accepted by the inventory parser.
pub const MAX_CACHE_NARINFO_BYTES: usize = 256 * 1024;

/// Maximum object keys retained by a Worker inventory operation.
///
/// Inventory currently crosses the storage port as an owned path vector and is
/// then indexed into bounded maps. This ceiling keeps those simultaneous
/// structures comfortably inside the Worker isolate memory limit. Native
/// deployments retain the larger general-purpose ceiling above.
pub const WORKER_MAX_SURFACE_LIST_OBJECTS: usize = 50_000;

/// Maximum aggregate key bytes retained by a Worker inventory operation.
pub const WORKER_MAX_SURFACE_LIST_PATH_BYTES: usize = 8 * 1024 * 1024;

/// Maximum keys retained in one Worker listing page.
pub const WORKER_MAX_SURFACE_LIST_PAGE_OBJECTS: usize = 256;

/// Maximum backend pages traversed by one Worker enumeration.
pub const WORKER_MAX_SURFACE_LIST_PAGES: usize = 256;

/// Maximum bytes accepted for a Worker backend cursor.
pub const WORKER_MAX_SURFACE_LIST_CURSOR_BYTES: usize = 1024;

/// One bounded, ordered page returned by [`SurfaceFetch::list_page`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurfaceListPage {
    /// Strictly increasing surface-relative object keys.
    pub paths: Vec<String>,
    /// Provider-observed metadata keyed by a listed path.
    ///
    /// Backends may omit this map. Entries are reusable only when their strong
    /// version identifiers match earlier byte-verified placement evidence.
    pub evidence: BTreeMap<String, SurfaceListedEvidence>,
    /// Opaque continuation cursor, or `None` when enumeration is complete.
    pub next_cursor: Option<String>,
}

/// Provider metadata returned atomically with one listing entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurfaceListedEvidence {
    /// Length of the listed representation in bytes.
    pub size: i64,
    /// Provider-issued strong entity tag for the listed representation.
    pub strong_etag: String,
}

impl SurfaceListPage {
    /// Validates the page before shared code retains or processes it.
    ///
    /// # Errors
    ///
    /// Returns an error for an oversized page or cursor, empty/unsorted keys,
    /// or a cursor repeated by the backend.
    pub fn validate(&self, requested_limit: usize, prior_cursor: Option<&str>) -> Result<()> {
        let cursor_limit = if cfg!(target_arch = "wasm32") {
            WORKER_MAX_SURFACE_LIST_CURSOR_BYTES
        } else {
            MAX_SURFACE_LIST_CURSOR_BYTES
        };
        if requested_limit == 0 || self.paths.len() > requested_limit {
            bail!("surface listing returned more keys than requested");
        }
        if self.evidence.iter().any(|(path, evidence)| {
            self.paths.binary_search(path).is_err()
                || evidence.size < 0
                || crate::surface_write::strong_if_match_etag(&evidence.strong_etag).is_err()
        }) {
            bail!("surface listing returned invalid provider evidence");
        }
        if self
            .next_cursor
            .as_ref()
            .is_some_and(|cursor| cursor.is_empty() || cursor.len() > cursor_limit)
        {
            bail!("surface listing returned an invalid continuation cursor");
        }
        if self.next_cursor.is_some() && self.next_cursor.as_deref() == prior_cursor {
            bail!("surface listing returned a repeated continuation cursor");
        }
        let mut prior: Option<&str> = None;
        for path in &self.paths {
            if path.is_empty()
                || path.len() > cursor_limit
                || prior.is_some_and(|value| value >= path.as_str())
            {
                bail!("surface listing page keys are not strictly increasing");
            }
            prior = Some(path);
        }
        if self.paths.is_empty() && self.next_cursor.is_some() {
            bail!("surface listing returned an empty non-terminal page");
        }
        Ok(())
    }
}

/// Tracks fail-closed object-count and key-byte bounds while enumerating a surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SurfaceListingBudget {
    object_count: usize,
    path_bytes: usize,
    max_objects: usize,
    max_path_bytes: usize,
}

impl Default for SurfaceListingBudget {
    fn default() -> Self {
        #[cfg(target_arch = "wasm32")]
        let (max_objects, max_path_bytes) = (
            WORKER_MAX_SURFACE_LIST_OBJECTS,
            WORKER_MAX_SURFACE_LIST_PATH_BYTES,
        );
        #[cfg(not(target_arch = "wasm32"))]
        let (max_objects, max_path_bytes) = (MAX_SURFACE_LIST_OBJECTS, MAX_SURFACE_LIST_PATH_BYTES);
        Self {
            object_count: 0,
            path_bytes: 0,
            max_objects,
            max_path_bytes,
        }
    }
}

impl SurfaceListingBudget {
    /// Creates a budget with explicit platform limits.
    #[must_use]
    pub const fn with_limits(max_objects: usize, max_path_bytes: usize) -> Self {
        Self {
            object_count: 0,
            path_bytes: 0,
            max_objects,
            max_path_bytes,
        }
    }

    /// Accounts for one listed key.
    ///
    /// # Errors
    ///
    /// Returns an error when the object-count or aggregate key-byte bound would
    /// be exceeded, including integer overflow.
    pub fn record(&mut self, path: &str) -> Result<()> {
        self.object_count = self
            .object_count
            .checked_add(1)
            .context("surface listing object count overflowed")?;
        self.path_bytes = self
            .path_bytes
            .checked_add(path.len())
            .context("surface listing path bytes overflowed")?;
        if self.object_count > self.max_objects {
            bail!(
                "surface listing exceeded the {} object limit",
                self.max_objects
            );
        }
        if self.path_bytes > self.max_path_bytes {
            bail!(
                "surface listing exceeded the {} byte key limit",
                self.max_path_bytes
            );
        }
        Ok(())
    }
}

/// A streaming read of a surface object: the body, the object's total size, and
/// the served byte range (`None` = the whole object was served).
///
/// The body is an [`axum::body::Body`] — a stream — so the *same* shared serve
/// path streams on both shells: the native hub wraps a `tokio` file
/// `ReaderStream`, the Worker wraps an R2 ranged-GET stream. Neither buffers a
/// NAR into memory.
pub struct StreamedRead {
    /// The (streaming) response body for the object or the requested range.
    pub body: axum::body::Body,
    /// The object's full byte length (the `Content-Range` denominator).
    pub total: u64,
    /// The inclusive `(start, end)` byte range actually served, or `None` for a
    /// whole-object read (a `200` rather than a `206`).
    pub range: Option<(u64, u64)>,
    /// Strong identity for the exact object handle or immutable snapshot that produced `body`.
    ///
    /// Signed-image delivery requires this value and compares it with the
    /// version observed while hashing the object. A content-derived token is
    /// valid only when derived from the actual response snapshot, never from
    /// expected catalog metadata.
    pub strong_etag: Option<String>,
    /// Exact native snapshot lease acquired for pre-commit verification.
    pub snapshot_lease_id: Option<String>,
}

/// Placement-scoped identity evidence collected from one physical object.
///
/// The SHA-256 digest and size are derived from the bytes returned by that
/// placement. `strong_etag` is populated only when the backend returned a
/// strong entity tag; callers must not synthesize one from a hash or key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurfaceObjectEvidence {
    /// SHA-256 of the physical bytes observed at this placement.
    pub sha256: [u8; 32],
    /// Length of the physical object in bytes.
    pub size: i64,
    /// Backend-issued strong entity tag, if the backend exposes one.
    pub strong_etag: Option<String>,
}

/// One exact ranged object chunk used by resumable provider inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurfaceInventoryChunk {
    /// Exact bytes in the requested inclusive range.
    pub bytes: Vec<u8>,
    /// Full object size observed by the same ranged response.
    pub total: u64,
    /// Inclusive byte range served by the provider.
    pub range: (u64, u64),
    /// Provider-issued strong entity tag for this object snapshot.
    pub strong_etag: String,
}

/// Read access to a registry surface by relative path (the "Blobs" read port).
///
/// Mirrors the native hub's surface reader so the relocated read logic (facade,
/// git walk) is single-source across both deployments.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait SurfaceFetch: BackendBounds {
    /// Fetch one surface path.
    ///
    /// Returns `Ok(None)` when the path definitively does not exist (missing
    /// object, HTTP 404, absent R2 key) — a meaningful state for channel
    /// partition probing — and an error for transport failures.
    ///
    /// # Errors
    ///
    /// Returns an error for IO/transport failures other than absence.
    async fn fetch(&self, path: &str) -> Result<Option<Vec<u8>>>;

    /// Stream one surface path, optionally just the inclusive byte `range`.
    ///
    /// The streaming counterpart of [`fetch`](Self::fetch) and the single read
    /// path the shared cache facade serves NAR/narinfo through, so the native hub
    /// and the Worker stream identically. Returns `Ok(None)` when the path does
    /// not exist.
    ///
    /// The provided default buffers via [`fetch`](Self::fetch) and wraps the
    /// (optionally sliced) bytes in a one-chunk body — correct on any store. An
    /// implementation whose store streams natively (a filesystem `ReaderStream`,
    /// an R2 ranged GET) **should override this** so a large NAR never lands in
    /// memory.
    ///
    /// # Errors
    ///
    /// Returns an error for IO/transport failures other than absence.
    async fn fetch_stream(
        &self,
        path: &str,
        range: Option<(u64, u64)>,
    ) -> Result<Option<StreamedRead>> {
        let Some(bytes) = self.fetch(path).await? else {
            return Ok(None);
        };
        let total = bytes.len() as u64;
        match range {
            Some((start, end)) if start <= end && start < total => {
                let end = end.min(total.saturating_sub(1));
                let slice = bytes[start as usize..=end as usize].to_vec();
                Ok(Some(StreamedRead {
                    body: axum::body::Body::from(slice),
                    total,
                    range: Some((start, end)),
                    strong_etag: None,
                    snapshot_lease_id: None,
                }))
            }
            _ => Ok(Some(StreamedRead {
                body: axum::body::Body::from(bytes),
                total,
                range: None,
                strong_etag: None,
                snapshot_lease_id: None,
            })),
        }
    }

    /// The byte length of the object at `path`, or `None` when it does not exist.
    ///
    /// Used by the write facade to compute the *overwrite delta* charged against
    /// an org's storage quota: a `Some(old)` means the path already holds `old`
    /// bytes, so a `PUT` of `new` bytes charges `new - old`; a `None` charges the
    /// full new size as a brand-new object.
    ///
    /// The provided default reads the whole object and measures it, so an
    /// implementation that already pays for the full fetch loses nothing; an
    /// implementation whose store exposes object metadata cheaply (a filesystem
    /// `stat`, an R2 `head`) should override this to avoid streaming the body
    /// just to learn its length.
    ///
    /// # Errors
    ///
    /// Returns an error for IO/transport failures other than absence.
    async fn size(&self, path: &str) -> Result<Option<u64>> {
        Ok(self.fetch(path).await?.map(|bytes| bytes.len() as u64))
    }

    /// Reads one small semantic object without trusting its body size.
    ///
    /// The declared size is checked before body allocation, then the streamed
    /// body is independently capped and required to match that declaration.
    ///
    /// # Errors
    ///
    /// Returns an error when metadata or body transport fails, the declared or
    /// streamed size exceeds `max_bytes`, or the object changes while read.
    async fn fetch_bounded(&self, path: &str, max_bytes: usize) -> Result<Option<Vec<u8>>> {
        let Some(declared) = self.size(path).await? else {
            return Ok(None);
        };
        let declared = usize::try_from(declared).context("surface object size is too large")?;
        if declared > max_bytes {
            bail!("surface object '{path}' exceeds the {max_bytes} byte semantic limit");
        }
        let Some(read) = self.fetch_stream(path, None).await? else {
            bail!("surface object '{path}' disappeared after its metadata read");
        };
        if read.total != declared as u64 {
            bail!("surface object '{path}' changed after its metadata read");
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(declared)
            .context("allocating bounded surface object")?;
        let mut stream = read.body.into_data_stream();
        while let Some(chunk) = stream.try_next().await? {
            let next = bytes
                .len()
                .checked_add(chunk.len())
                .context("surface object body size overflowed")?;
            if next > max_bytes || next > declared {
                bail!("surface object '{path}' exceeded its declared or semantic size");
            }
            bytes.extend_from_slice(&chunk);
        }
        if bytes.len() != declared {
            bail!("surface object '{path}' did not match its declared size");
        }
        Ok(Some(bytes))
    }

    /// Enumerates one ordered page of surface-relative object paths.
    ///
    /// Returns the logical paths [`fetch`](Self::fetch) accepts (e.g.
    /// `objects/ab/cd…`, `nar/…`, `<hash>.narinfo`, `nix-cache-info`), walking
    /// the whole surface. The store (the bucket, the source of truth) is
    /// authoritative; this is how the hub re-derives what it holds when it
    /// cannot enumerate from the derived relational index alone:
    ///
    /// - **Storage migration** copies every listed object to the new backend.
    /// - **Cache re-scan** rebuilds the `cache_objects` index from the
    ///   narinfos it lists, reconciling drift after a direct (`apr`-presigned)
    ///   upload that bypassed the facade write-through.
    ///
    /// `cursor` is the opaque value returned by the preceding page. Keys within
    /// a page must be strictly increasing and a backend must never return an
    /// empty non-terminal page. The default errors, so an HTTP-only origin with
    /// no index need not implement enumeration.
    ///
    /// # Errors
    ///
    /// Returns an error when the store cannot enumerate, or on IO/transport
    /// failure.
    async fn list_page(&self, _cursor: Option<&str>, _limit: usize) -> Result<SurfaceListPage> {
        anyhow::bail!(
            "this surface ({}) does not support listing",
            self.describe()
        )
    }

    /// Returns a backend-issued strong entity tag for one object, when available.
    ///
    /// Implementations must return `None` for weak tags. A backend may return
    /// a digest of bytes it actually snapshotted, but must not synthesize a tag
    /// from the object key, expected database hash, or size.
    ///
    /// # Errors
    ///
    /// Returns an error for metadata transport failures.
    async fn inventory_strong_etag(&self, _path: &str) -> Result<Option<String>> {
        Ok(None)
    }

    /// Returns the backend-observed object size without consuming its body.
    ///
    /// # Errors
    ///
    /// Returns an error for metadata transport failure or a size too large to
    /// represent in the shared database contract.
    async fn inventory_size(&self, path: &str) -> Result<Option<i64>> {
        self.fetch_stream(path, None)
            .await?
            .map(|read| i64::try_from(read.total).context("surface object size exceeds i64"))
            .transpose()
    }

    /// Streams one object and derives placement-scoped inventory evidence.
    ///
    /// The default deliberately hashes the streamed bytes and separately asks
    /// the backend for a real strong tag. Returning an expected database hash
    /// as if it were observed is forbidden.
    ///
    /// # Errors
    ///
    /// Returns an error for transport failure or an object too large to model.
    async fn inventory_evidence(&self, path: &str) -> Result<Option<SurfaceObjectEvidence>> {
        self.inventory_evidence_bounded(path, u64::MAX).await
    }

    /// Streams one object without reading beyond an accepted byte ceiling.
    ///
    /// Implementations reject an oversized declaration before consuming the
    /// body and abort as soon as a broken transport exceeds either its declared
    /// length or `maximum_bytes`.
    ///
    /// # Errors
    ///
    /// Returns an error for transport failure, an oversized declaration or
    /// stream, a length mismatch, or an object too large to model.
    async fn inventory_evidence_bounded(
        &self,
        path: &str,
        maximum_bytes: u64,
    ) -> Result<Option<SurfaceObjectEvidence>> {
        let before_etag = self.inventory_strong_etag(path).await?;
        let Some(read) = self.fetch_stream(path, None).await? else {
            return Ok(None);
        };
        let expected_size = read.total;
        if expected_size > maximum_bytes {
            anyhow::bail!(
                "surface object '{path}' declares {expected_size} bytes, exceeding the {maximum_bytes}-byte inventory limit"
            );
        }
        let mut stream = read.body.into_data_stream();
        let mut hasher = Sha256::new();
        let mut observed_size = 0_u64;
        while let Some(chunk) = stream.try_next().await? {
            observed_size = observed_size
                .checked_add(chunk.len() as u64)
                .ok_or_else(|| anyhow::anyhow!("surface object '{path}' size overflowed"))?;
            if observed_size > expected_size || observed_size > maximum_bytes {
                anyhow::bail!(
                    "surface object '{path}' exceeded its bounded inventory length while streaming"
                );
            }
            hasher.update(&chunk);
        }
        if observed_size != expected_size {
            anyhow::bail!(
                "surface object '{path}' changed while inventory streamed it: expected {expected_size} bytes, observed {observed_size}"
            );
        }
        let after_etag = self.inventory_strong_etag(path).await?;
        if before_etag != after_etag {
            anyhow::bail!("surface object '{path}' changed while inventory observed it");
        }
        let size = i64::try_from(observed_size)
            .map_err(|_| anyhow::anyhow!("surface object '{path}' is too large"))?;
        Ok(Some(SurfaceObjectEvidence {
            sha256: hasher.finalize().into(),
            size,
            strong_etag: after_etag,
        }))
    }

    /// Reads one exact bounded range for resumable provider inventory hashing.
    ///
    /// The default uses the provider's streaming range implementation and
    /// rejects a response whose total, served range, strong identity, or byte
    /// count differs from the request. Production placement adapters override
    /// [`fetch_stream`](Self::fetch_stream), so this never requires retaining a
    /// complete large object in the Worker or native Hub.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid range, transport failure, missing strong
    /// entity tag, response identity mismatch, or a body exceeding the exact
    /// requested range.
    async fn inventory_chunk_bounded(
        &self,
        path: &str,
        offset: u64,
        expected_total: u64,
        maximum_bytes: u64,
    ) -> Result<Option<SurfaceInventoryChunk>> {
        if maximum_bytes == 0 || offset >= expected_total {
            bail!("surface inventory chunk range is invalid");
        }
        let end = offset
            .checked_add(maximum_bytes.saturating_sub(1))
            .context("surface inventory chunk range overflowed")?
            .min(expected_total.saturating_sub(1));
        let expected_len = end
            .checked_sub(offset)
            .and_then(|length| length.checked_add(1))
            .context("surface inventory chunk length overflowed")?;
        let Some(read) = self.fetch_stream(path, Some((offset, end))).await? else {
            return Ok(None);
        };
        if read.total != expected_total || read.range != Some((offset, end)) {
            bail!("surface inventory chunk response range or total changed");
        }
        let strong_etag = crate::surface_write::strong_if_match_etag(
            &read
                .strong_etag
                .context("surface inventory chunk has no strong entity tag")?,
        )?;

        let mut stream = read.body.into_data_stream();
        let mut bytes = Vec::with_capacity(
            usize::try_from(expected_len).context("surface inventory chunk exceeds usize")?,
        );
        while let Some(chunk) = stream.try_next().await? {
            let next_len = bytes
                .len()
                .checked_add(chunk.len())
                .context("surface inventory chunk size overflowed")?;
            if u64::try_from(next_len)? > expected_len {
                bail!("surface inventory chunk exceeded its requested range");
            }
            bytes.extend_from_slice(&chunk);
        }
        if u64::try_from(bytes.len())? != expected_len {
            bail!("surface inventory chunk did not fill its requested range");
        }
        Ok(Some(SurfaceInventoryChunk {
            bytes,
            total: read.total,
            range: (offset, end),
            strong_etag,
        }))
    }

    /// A human-readable description of the source (for health/audit text).
    fn describe(&self) -> String;
}

/// Fetches an absolute origin URL's body as a stream (the authenticated-origin
/// proxy-read port).
///
/// When a cache is backed by a *private external* origin and its serving
/// route is configured to proxy reads rather than redirect them,
/// the hub fetches the (presigned) origin URL itself and streams the body
/// through the shared cache serve path, so the origin endpoint is never exposed
/// to the client. This is the read sibling of the presign path: same signed URL,
/// but the hub is the fetcher.
///
/// Like the other core ports it carries [`BackendBounds`]: the native hub uses a
/// streaming `reqwest` GET (`Send + Sync`); the Worker uses its authenticated,
/// fixed-origin gateway client (`?Send`). The `range`, when given, is forwarded to the origin as a
/// `Range: bytes=start-end` request header so the origin serves only those bytes.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait OriginFetch: BackendBounds {
    /// `GET` `url`, optionally just the inclusive byte `range`, and stream the body.
    ///
    /// Returns `Ok(None)` when the origin responds `404`. The returned
    /// [`StreamedRead::range`] reflects what the origin actually served (`Some`
    /// when it answered `206 Partial Content`, `None` for a whole-object `200`),
    /// and [`StreamedRead::total`] is the object's full length (parsed from
    /// `Content-Range` on a `206`, else `Content-Length`).
    ///
    /// # Errors
    ///
    /// Returns an error for transport failures or a non-404 error status.
    async fn get_stream(
        &self,
        url: &str,
        range: Option<(u64, u64)>,
    ) -> Result<Option<StreamedRead>>;
}

/// Resolves a [`SurfaceFetch`] for one explicit physical placement.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait SurfaceProvider: BackendBounds {
    /// Opens a reader rooted at one explicit physical placement.
    ///
    /// Selection remains in shared topology logic; adapters only translate the
    /// selected binding and prefix into a concrete backend reader.
    ///
    /// # Errors
    ///
    /// Returns an error when the placement's binding cannot be resolved or the
    /// runtime does not support its backend kind.
    async fn placement_fetcher(
        &self,
        placement: &SurfacePlacementRecord,
    ) -> Result<Box<dyn SurfaceFetch>>;

    /// Opens a reader at one immutable durable-work physical address.
    ///
    /// Implementations may reopen the exact frozen binding revision, but must
    /// not consult current write authority or substitute a current placement.
    /// The frozen prefix is the only permitted backend address.
    ///
    /// # Errors
    ///
    /// Returns an error when the frozen fence is malformed, its exact binding
    /// version/revision is unavailable, or the runtime cannot address it.
    async fn frozen_placement_fetcher(
        &self,
        access: &crate::surface_write::FrozenSurfaceAccess,
    ) -> Result<Box<dyn SurfaceFetch>> {
        let _ = access;
        anyhow::bail!("this provider does not support frozen placement reads")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct DeclaredFetch {
        declared: u64,
        body: Vec<u8>,
        body_reads: AtomicUsize,
    }

    struct InconsistentStream {
        declared: u64,
        body: Vec<u8>,
    }

    struct ExactRangeFetch {
        body: Vec<u8>,
    }

    #[async_trait::async_trait]
    impl SurfaceFetch for DeclaredFetch {
        async fn fetch(&self, _path: &str) -> Result<Option<Vec<u8>>> {
            self.body_reads.fetch_add(1, Ordering::SeqCst);
            Ok(Some(self.body.clone()))
        }

        async fn size(&self, _path: &str) -> Result<Option<u64>> {
            Ok(Some(self.declared))
        }

        fn describe(&self) -> String {
            "declared-test".into()
        }
    }

    #[async_trait::async_trait]
    impl SurfaceFetch for InconsistentStream {
        async fn fetch(&self, _path: &str) -> Result<Option<Vec<u8>>> {
            Ok(Some(self.body.clone()))
        }

        async fn fetch_stream(
            &self,
            _path: &str,
            _range: Option<(u64, u64)>,
        ) -> Result<Option<StreamedRead>> {
            Ok(Some(StreamedRead {
                body: axum::body::Body::from(self.body.clone()),
                total: self.declared,
                range: None,
                strong_etag: Some("stream-version".into()),
                snapshot_lease_id: None,
            }))
        }

        fn describe(&self) -> String {
            "inconsistent-stream-test".into()
        }
    }

    #[async_trait::async_trait]
    impl SurfaceFetch for ExactRangeFetch {
        async fn fetch(&self, _path: &str) -> Result<Option<Vec<u8>>> {
            Ok(Some(self.body.clone()))
        }

        async fn fetch_stream(
            &self,
            _path: &str,
            range: Option<(u64, u64)>,
        ) -> Result<Option<StreamedRead>> {
            let (start, end) = range.context("range test requires a range")?;
            Ok(Some(StreamedRead {
                body: axum::body::Body::from(self.body[start as usize..=end as usize].to_vec()),
                total: self.body.len() as u64,
                range: Some((start, end)),
                strong_etag: Some("range-version".into()),
                snapshot_lease_id: None,
            }))
        }

        fn describe(&self) -> String {
            "exact-range-test".into()
        }
    }

    #[test]
    fn listing_budget_rejects_count_and_key_byte_overflow() {
        let mut count = SurfaceListingBudget::with_limits(1, 32);
        count.record("first").unwrap();
        assert!(count.record("next").is_err());

        let mut bytes = SurfaceListingBudget::with_limits(10, 1);
        bytes.record("x").unwrap();
        assert!(bytes.record("y").is_err());

        let worker = SurfaceListingBudget::with_limits(
            WORKER_MAX_SURFACE_LIST_OBJECTS,
            WORKER_MAX_SURFACE_LIST_PATH_BYTES,
        );
        assert_eq!(worker.max_objects, WORKER_MAX_SURFACE_LIST_OBJECTS);
        assert_eq!(worker.max_path_bytes, WORKER_MAX_SURFACE_LIST_PATH_BYTES);
    }

    #[test]
    fn listing_page_rejects_oversized_repeated_and_unordered_state() {
        let valid = SurfaceListPage {
            paths: vec!["a".into(), "b".into()],
            evidence: Default::default(),
            next_cursor: Some("cursor-2".into()),
        };
        assert!(valid.validate(2, Some("cursor-1")).is_ok());
        assert!(valid.validate(1, Some("cursor-1")).is_err());
        assert!(valid.validate(2, Some("cursor-2")).is_err());

        let mut invalid_evidence = valid.clone();
        invalid_evidence.evidence.insert(
            "outside-page".into(),
            SurfaceListedEvidence {
                size: 1,
                strong_etag: "version-1".into(),
            },
        );
        assert!(invalid_evidence.validate(2, Some("cursor-1")).is_err());

        let unordered = SurfaceListPage {
            paths: vec!["b".into(), "a".into()],
            evidence: Default::default(),
            next_cursor: None,
        };
        assert!(unordered.validate(2, None).is_err());

        let empty_non_terminal = SurfaceListPage {
            paths: Vec::new(),
            evidence: Default::default(),
            next_cursor: Some("cursor".into()),
        };
        assert!(empty_non_terminal.validate(2, None).is_err());
    }

    #[tokio::test]
    async fn bounded_fetch_rejects_metadata_before_body_and_stream_mismatch() {
        let oversized = DeclaredFetch {
            declared: 5,
            body: vec![0; 5],
            body_reads: AtomicUsize::new(0),
        };
        assert!(oversized.fetch_bounded("x", 4).await.is_err());
        assert_eq!(oversized.body_reads.load(Ordering::SeqCst), 0);

        let changed = DeclaredFetch {
            declared: 4,
            body: vec![0; 5],
            body_reads: AtomicUsize::new(0),
        };
        assert!(changed.fetch_bounded("x", 4).await.is_err());
        assert_eq!(changed.body_reads.load(Ordering::SeqCst), 1);

        let exact = DeclaredFetch {
            declared: 4,
            body: vec![7; 4],
            body_reads: AtomicUsize::new(0),
        };
        assert_eq!(exact.fetch_bounded("x", 4).await.unwrap(), Some(vec![7; 4]));
    }

    #[tokio::test]
    async fn inventory_chunk_requires_and_returns_one_exact_strong_range() {
        let fetch = ExactRangeFetch {
            body: b"abcdefgh".to_vec(),
        };
        let chunk = fetch
            .inventory_chunk_bounded("object", 2, 8, 3)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(chunk.bytes, b"cde");
        assert_eq!(chunk.range, (2, 4));
        assert_eq!(chunk.total, 8);
        assert_eq!(chunk.strong_etag, "\"range-version\"");

        let mismatched = InconsistentStream {
            declared: 8,
            body: b"abc".to_vec(),
        };
        assert!(mismatched
            .inventory_chunk_bounded("object", 2, 8, 3)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn bounded_inventory_rejects_declared_and_streamed_oversize() {
        let declared = InconsistentStream {
            declared: 5,
            body: vec![0; 5],
        };
        assert!(declared.inventory_evidence_bounded("x", 4).await.is_err());

        let streamed = InconsistentStream {
            declared: 4,
            body: vec![0; 5],
        };
        assert!(streamed.inventory_evidence_bounded("x", 4).await.is_err());

        let exact = InconsistentStream {
            declared: 4,
            body: vec![7; 4],
        };
        let evidence = exact
            .inventory_evidence_bounded("x", 4)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(evidence.size, 4);
        let expected: [u8; 32] = Sha256::digest([7; 4]).into();
        assert_eq!(evidence.sha256, expected);
    }
}
