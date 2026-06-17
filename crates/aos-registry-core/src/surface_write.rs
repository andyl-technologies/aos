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
}
