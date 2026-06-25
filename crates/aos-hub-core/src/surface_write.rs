//! The surface-write port: how the shared service mutates a registry's bytes.
//!
//! This is the write sibling of [`crate::fetch`]. The read port
//! ([`SurfaceFetch`](crate::fetch::SurfaceFetch)) lets the facade and the git
//! walk *read* a registry's wire surface from whatever store backs the
//! deployment; this port lets the shared console *write* to it — the
//! git-backed configuration change-request flow commits a draft to
//! `refs/hub/changes/<id>` and writes the loose blob/tree/commit objects it
//! references.
//!
//! - [`SurfaceWrite`] — atomically write or delete one surface path. This is
//!   the RFC's "Blobs" port, write side: the loose-object and ref writes the
//!   git-backed change-request flow performs go through it.
//! - [`SurfaceWriteProvider`] — resolve the [`SurfaceWrite`] for a given
//!   registry. The native hub returns a filesystem writer rooted at the
//!   registry's storage binding; the Worker returns an R2-backed writer scoped
//!   to the registry's prefix.
//!
//! Both carry the same target-conditional bound as the rest of the core ports
//! ([`BackendBounds`]): `Send + Sync` natively, unbounded on the
//! single-threaded wasm32 Worker (whose R2 futures are `?Send`).
//!
//! # Path semantics
//!
//! Every `path` is a **logical, registry-relative surface path** — the same
//! space the read port uses (`objects/ab/cdef…`, `refs/hub/changes/<id>`),
//! never a host filesystem path or an R2 key. The implementation owns the
//! mapping to its store and is responsible for path safety: the native writer
//! rejects `..`/absolute components lexically and then symlink-canonicalizes the
//! parent and requires it to stay under the storage root (the same containment
//! the read port enforces), and the R2 writer maps through the flat key space
//! where traversal is not expressible.

use anyhow::Result;

use crate::backend::BackendBounds;
use crate::db::RegistryRecord;

/// One multipart-upload part's identity: its 1-based `part_number` and the
/// backend's entity tag.
///
/// `etag` is the value the backend returns for an uploaded part and requires
/// back at completion (S3/R2 multipart); a backend with no native etag (local
/// disk) returns and accepts an empty string. It is opaque to the hub and the
/// client, which only carry it through the wire protocol and echo the full,
/// ordered set back at [`complete`](SurfaceWrite::complete_multipart).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartTag {
    /// 1-based, contiguous part index.
    pub part_number: u32,
    /// Backend-returned entity tag (empty when the backend has none).
    pub etag: String,
}

/// Write access to a registry surface by relative path (the "Blobs" write
/// port).
///
/// The git-backed configuration change-request flow writes its loose objects
/// and draft ref through this port, so the same write logic is single-source
/// across the native hub and the Cloudflare Worker.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait SurfaceWrite: BackendBounds {
    /// Atomically write `bytes` to the surface at the logical `path`.
    ///
    /// The write MUST be atomic with respect to a concurrent reader: a reader
    /// fetching `path` while this runs sees either the old contents (or
    /// absence) or the complete new contents, never a half-written object. The
    /// native filesystem implementation achieves this with a temp-file write
    /// followed by a rename; an object store whose puts are atomic per-object
    /// (R2) needs no temp step.
    ///
    /// `path` is a logical, registry-relative surface path (`objects/ab/cd…`,
    /// `refs/hub/changes/<id>`); the implementation maps it to its store and is
    /// responsible for rejecting any path that would escape the registry's
    /// space.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry has no writable storage root, when
    /// `path` is rejected as unsafe (traversal/symlink escape), or on any IO or
    /// transport failure.
    async fn write(&self, path: &str, bytes: &[u8]) -> Result<()>;

    /// Idempotently delete the surface object at the logical `path`.
    ///
    /// Deleting an absent path is **not** an error: the call returns `Ok(())`
    /// so a retry or a redundant cleanup is harmless.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry has no writable storage root, when
    /// `path` is rejected as unsafe, or on any IO or transport failure other
    /// than the object being absent.
    async fn delete(&self, path: &str) -> Result<()>;

    /// Begin a multipart upload targeting the logical `path`, returning the
    /// backend's opaque upload id.
    ///
    /// The id, paired with `path`, reconstructs the in-progress upload on every
    /// later [`upload_part`](Self::upload_part) /
    /// [`complete_multipart`](Self::complete_multipart) / [`abort_multipart`](Self::abort_multipart)
    /// call. This is what lets a *stateless* host drive a multipart upload: the
    /// Cloudflare Worker handles each request in a fresh isolate and holds no
    /// cross-request state, so the backend (R2/S3 upload id, or a hub-minted id
    /// for local disk) owns the in-flight assembly and the protocol carries the
    /// id. Large objects therefore upload as several sub-cap parts, one per
    /// request, with memory bounded to a single part.
    ///
    /// # Errors
    ///
    /// Returns an error when the backend does not support multipart, the store
    /// is not writable, `path` is unsafe, or on a transport failure.
    async fn create_multipart(&self, path: &str) -> Result<String> {
        let _ = path;
        anyhow::bail!("multipart upload not supported by this backend")
    }

    /// Upload one part (`part_number`, 1-based and contiguous) of the
    /// in-progress upload `upload_id` for `path`, returning its [`PartTag`].
    ///
    /// Every part except the last MUST meet the backend's minimum part size
    /// (R2/S3: 5 MiB). The caller streams one sub-cap part per request, so peak
    /// memory is one part regardless of the final object size.
    ///
    /// # Errors
    ///
    /// Returns an error when the backend does not support multipart, the
    /// `upload_id` is unknown/expired, the part violates the size minimum, or on
    /// a transport failure.
    async fn upload_part(
        &self,
        path: &str,
        upload_id: &str,
        part_number: u32,
        bytes: &[u8],
    ) -> Result<PartTag> {
        let _ = (path, upload_id, part_number, bytes);
        anyhow::bail!("multipart upload not supported by this backend")
    }

    /// Finalize the upload `upload_id` for `path`, assembling `parts` (which the
    /// implementation orders by `part_number`) into the object — atomically with
    /// respect to a concurrent reader, the same guarantee as [`write`](Self::write).
    ///
    /// # Errors
    ///
    /// Returns an error when the backend does not support multipart, a part is
    /// missing or out of order, an `etag` does not match, or on a transport
    /// failure.
    async fn complete_multipart(
        &self,
        path: &str,
        upload_id: &str,
        parts: &[PartTag],
    ) -> Result<()> {
        let _ = (path, upload_id, parts);
        anyhow::bail!("multipart upload not supported by this backend")
    }

    /// Abort the upload `upload_id` for `path`, freeing any backend-held state.
    ///
    /// Best-effort and idempotent: aborting an unknown or already-completed
    /// upload is not an error, so a retry or redundant cleanup is harmless.
    ///
    /// # Errors
    ///
    /// Returns an error only on a transport failure the backend deems fatal.
    async fn abort_multipart(&self, path: &str, upload_id: &str) -> Result<()> {
        let _ = (path, upload_id);
        Ok(())
    }
}

/// Resolves the [`SurfaceWrite`] for a registry (the per-registry store seam).
///
/// The write sibling of [`SurfaceProvider`](crate::fetch::SurfaceProvider):
/// the native hub returns a filesystem writer rooted at the registry's storage
/// binding (the same root the read fetcher uses), and the Worker returns an
/// R2-backed writer scoped to the registry's prefix. Keeping this a port lets
/// the shared console's git-backed change-request handlers obtain a writer
/// without knowing the store.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait SurfaceWriteProvider: BackendBounds {
    /// Build the surface writer for `registry`.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry's writable store cannot be resolved
    /// (e.g. a registration-only registry with no storage binding, or an
    /// unreadable binding).
    async fn writer(&self, registry: &RegistryRecord) -> Result<Box<dyn SurfaceWrite>>;

    /// Build the surface writer for a managed [`Cache`](crate::db::Cache).
    ///
    /// The cache analog of [`writer`](Self::writer): the native hub roots a
    /// filesystem writer at the cache's binding root + prefix; the Worker scopes
    /// an R2 writer to the cache's prefix. The provided default errors, so a
    /// provider that does not host caches need not override it.
    ///
    /// # Errors
    ///
    /// Returns an error when the provider does not serve caches, or when the
    /// cache's writable store cannot be resolved.
    async fn cache_writer(&self, cache: &crate::db::Cache) -> Result<Box<dyn SurfaceWrite>> {
        let _ = cache;
        anyhow::bail!("this surface write provider does not serve caches")
    }
}
