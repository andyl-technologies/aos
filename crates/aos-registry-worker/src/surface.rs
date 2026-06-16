//! The R2-backed [`SurfaceProvider`] for the shared service (wasm32-only).
//!
//! The shared [`RpcService`](aos_registry_core::service::RpcService) reads a
//! registry's wire surface (loose git objects, `info/refs`, channel partitions,
//! NARs, …) through the [`SurfaceProvider`]/[`SurfaceFetch`] ports
//! ([`aos_registry_core::fetch`]). On the Cloudflare Worker that surface lives
//! in the hub-owned R2 bucket, with each registry occupying a *prefix*
//! (RFC-0004 "Storage": registries as prefixes in a shared bucket). This module
//! supplies the Worker's concrete fetcher: it resolves the per-registry prefix
//! from the [`RegistryRecord`] and reads R2 keys `{prefix}{path}` via the same
//! [`crate::keymap::r2_key`] mapping and `bucket.get(...).execute()` access the
//! read-path [`facade`](crate::facade) uses, so the RPC `GitService` reads and
//! the facade cannot drift.
//!
//! The R2 bucket handle is not `Send`/`Sync`, but on the single-threaded Worker
//! the core ports drop those bounds (the wasm32 `BackendBounds` is unbounded),
//! so an `Rc`-free owned [`worker::Bucket`] satisfies the trait directly.

use anyhow::Result;
use async_trait::async_trait;
use worker::Bucket;

use aos_registry_core::db::RegistryRecord;
use aos_registry_core::fetch::{SurfaceFetch, SurfaceProvider};

use crate::keymap;

/// A [`SurfaceProvider`] that serves every registry from one R2 bucket.
///
/// Holds the hub-owned bucket binding; [`fetcher`](SurfaceProvider::fetcher)
/// scopes a reader to the requested registry's prefix.
pub struct R2SurfaceProvider {
    bucket: Bucket,
}

impl R2SurfaceProvider {
    /// Wrap a bound R2 bucket (`env.bucket(binding)`) as a surface provider.
    #[must_use]
    pub fn new(bucket: Bucket) -> R2SurfaceProvider {
        R2SurfaceProvider { bucket }
    }
}

#[async_trait(?Send)]
impl SurfaceProvider for R2SurfaceProvider {
    async fn fetcher(&self, registry: &RegistryRecord) -> Result<Box<dyn SurfaceFetch>> {
        Ok(Box::new(R2SurfaceFetch {
            bucket: self.bucket.clone(),
            prefix: registry.prefix.clone(),
        }))
    }
}

/// A [`SurfaceFetch`] reading one registry's prefix from an R2 bucket.
struct R2SurfaceFetch {
    bucket: Bucket,
    prefix: String,
}

#[async_trait(?Send)]
impl SurfaceFetch for R2SurfaceFetch {
    async fn fetch(&self, path: &str) -> Result<Option<Vec<u8>>> {
        let key = keymap::r2_key(&self.prefix, path);
        let object = self
            .bucket
            .get(&key)
            .execute()
            .await
            .map_err(|err| anyhow::anyhow!("R2 get {key}: {err}"))?;
        let Some(object) = object else {
            return Ok(None);
        };
        // A zero-length object (legal for some pointers) has no body stream;
        // treat it as present-but-empty rather than a miss.
        let Some(body) = object.body() else {
            return Ok(Some(Vec::new()));
        };
        let bytes = body
            .bytes()
            .await
            .map_err(|err| anyhow::anyhow!("R2 read body {key}: {err}"))?;
        Ok(Some(bytes))
    }

    fn describe(&self) -> String {
        format!("r2://{}", self.prefix)
    }
}
