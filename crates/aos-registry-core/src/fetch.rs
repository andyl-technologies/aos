//! The surface-read port: how the shared service reaches a registry's bytes.
//!
//! The registry's wire surface (loose git objects, `info/refs`, channel
//! partitions, NARs, …) lives in different stores per deployment — a local
//! filesystem or HTTP origin on the native hub, an R2 bucket on the Cloudflare
//! Worker. The shared service (the facade and the `GitService` methods) reads it
//! through two ports so the read logic is written once:
//!
//! - [`SurfaceFetch`] — read one surface path. This is the RFC's "Blobs" port,
//!   read side: the facade streams objects through it and the git log/diff walk
//!   commits through it. (Write/list — for mirror sync — are deferred.)
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

    /// A human-readable description of the source (for health/audit text).
    fn describe(&self) -> String;
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
}
