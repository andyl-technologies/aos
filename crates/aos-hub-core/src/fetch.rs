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
//!   commits through it), and [`list`](SurfaceFetch::list) the whole surface —
//!   the enumeration storage migration and the cache re-scan walk, treating the
//!   store as the source of truth.
//! - [`SurfaceProvider`] — resolve the [`SurfaceFetch`] for a given registry.
//!   The native hub picks a filesystem or HTTP fetcher per the registry's
//!   storage binding; the Worker returns an R2-backed fetcher scoped to the
//!   registry's prefix.
//!
//! Both carry the same target-conditional bound as the rest of the core ports
//! ([`BackendBounds`]): `Send + Sync` natively, unbounded on the single-threaded
//! wasm32 Worker (whose R2 futures are `?Send`).

use anyhow::Result;

use crate::backend::BackendBounds;
use crate::db::RegistryRecord;

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
                }))
            }
            _ => Ok(Some(StreamedRead {
                body: axum::body::Body::from(bytes),
                total,
                range: None,
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

    /// Enumerate every surface-relative object path under this reader's scope.
    ///
    /// Returns the logical paths [`fetch`](Self::fetch) accepts (e.g.
    /// `objects/ab/cd…`, `nar/…`, `<hash>.narinfo`, `nix-cache-info`), walking
    /// the whole surface. The store (the bucket, the source of truth) is
    /// authoritative; this is how the hub re-derives what it holds when it
    /// cannot enumerate from D1 alone:
    ///
    /// - **Storage migration** copies every listed object to the new backend.
    /// - **Cache re-scan** rebuilds the `cache_objects` D1 index from the
    ///   narinfos it lists, reconciling drift after a direct (`apr`-presigned)
    ///   upload that bypassed the facade write-through.
    ///
    /// Order is unspecified. The default errors, so a reader whose store cannot
    /// enumerate (a test double, an HTTP-only origin with no index) need not
    /// implement it — callers that require listing surface a clear error.
    ///
    /// # Errors
    ///
    /// Returns an error when the store cannot enumerate, or on IO/transport
    /// failure.
    async fn list(&self) -> Result<Vec<String>> {
        anyhow::bail!(
            "this surface ({}) does not support listing",
            self.describe()
        )
    }

    /// A human-readable description of the source (for health/audit text).
    fn describe(&self) -> String;
}

/// Fetches an absolute origin URL's body as a stream (the authenticated-origin
/// proxy-read port).
///
/// When a cache is backed by a *private external* origin and its serving
/// frontend is configured to **proxy** reads (rather than `302`-redirect them),
/// the hub fetches the (presigned) origin URL itself and streams the body
/// through the shared cache serve path, so the origin endpoint is never exposed
/// to the client. This is the read sibling of the presign path: same signed URL,
/// but the hub is the fetcher.
///
/// Like the other core ports it carries [`BackendBounds`]: the native hub uses a
/// streaming `reqwest` GET (`Send + Sync`); the Worker uses the global Fetch API
/// (`?Send`). The `range`, when given, is forwarded to the origin as a
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

/// Resolves the [`SurfaceFetch`] for a registry (the per-registry store seam).
///
/// The native hub inspects the registry's storage binding to choose a
/// filesystem or HTTP fetcher; the Worker returns an R2-backed fetcher scoped to
/// the registry's prefix. Keeping this a port lets the `GitService` methods and
/// the facade in [`crate::service`] obtain a reader without knowing the store.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait SurfaceProvider: BackendBounds {
    /// Build the surface reader for `registry`.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry's store cannot be resolved (e.g. an
    /// unknown or unreadable storage binding).
    async fn fetcher(&self, registry: &RegistryRecord) -> Result<Box<dyn SurfaceFetch>>;

    /// Build the surface reader for a managed [`Cache`](crate::db::Cache).
    ///
    /// The cache analog of [`fetcher`](Self::fetcher): the native hub roots a
    /// filesystem reader at the cache's binding root + prefix; the Worker scopes
    /// an R2 reader to the cache's prefix. The provided default errors, so a
    /// provider that does not host caches (e.g. a test double) need not override
    /// it.
    ///
    /// # Errors
    ///
    /// Returns an error when the provider does not serve caches, or when the
    /// cache's store cannot be resolved.
    async fn cache_fetcher(&self, cache: &crate::db::Cache) -> Result<Box<dyn SurfaceFetch>> {
        let _ = cache;
        anyhow::bail!("this surface provider does not serve caches")
    }
}
