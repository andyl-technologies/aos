//! The R2-backed [`SurfaceProvider`] for the shared service (wasm32-only).
//!
//! The shared [`RpcService`](aos_registry_core::service::RpcService) reads a
//! registry's wire surface (loose git objects, `info/refs`, channel partitions,
//! NARs, …) through the [`SurfaceProvider`]/[`SurfaceFetch`] ports
//! ([`aos_registry_core::fetch`]). On the Cloudflare Worker that surface lives
//! in the hub-owned R2 bucket, with each registry occupying a *prefix*
//! (RFC-0004 "Storage": registries as prefixes in a shared bucket). This module
//! supplies the Worker's concrete fetcher: it resolves the per-registry prefix
//! from the [`RegistryRecord`] and reads R2 keys `{prefix}{path}` via the
//! [`crate::keymap::r2_key`] mapping and `bucket.get(...).execute()`. The shared
//! machine-surface facade
//! ([`aos_registry_core::service::RpcService::facade_fetch`]) and the RPC
//! `GitService` reads both read through this one provider, so they cannot drift.
//!
//! The R2 bucket handle is not `Send`/`Sync`, but on the single-threaded Worker
//! the core ports drop those bounds (the wasm32 `BackendBounds` is unbounded),
//! so an `Rc`-free owned [`worker::Bucket`] satisfies the trait directly.

use anyhow::Result;
use async_trait::async_trait;
use worker::Bucket;

use aos_registry_core::db::RegistryRecord;
use aos_registry_core::fetch::{SurfaceFetch, SurfaceProvider};
use aos_registry_core::surface_write::{SurfaceWrite, SurfaceWriteProvider};

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

    async fn size(&self, path: &str) -> Result<Option<u64>> {
        let key = keymap::r2_key(&self.prefix, path);
        // R2 `head` returns object metadata (including the size) without
        // streaming the body — the cheap path for the write facade's overwrite
        // quota delta. An absent key is `Ok(None)`.
        let object = self
            .bucket
            .head(&key)
            .await
            .map_err(|err| anyhow::anyhow!("R2 head {key}: {err}"))?;
        Ok(object.map(|object| u64::from(object.size())))
    }

    fn describe(&self) -> String {
        format!("r2://{}", self.prefix)
    }
}

/// A [`SurfaceWriteProvider`] that writes every registry into one R2 bucket.
///
/// The write sibling of [`R2SurfaceProvider`]: holds the hub-owned bucket
/// binding and scopes a [`R2Write`] to the requested registry's prefix. The
/// shared git-backed change-request flow ([`aos_registry_core::gitwrite`]) uses
/// it to write loose objects and draft refs.
pub struct R2SurfaceWriteProvider {
    bucket: Bucket,
}

impl R2SurfaceWriteProvider {
    /// Wrap a bound R2 bucket (`env.bucket(binding)`) as a surface write
    /// provider.
    #[must_use]
    pub fn new(bucket: Bucket) -> R2SurfaceWriteProvider {
        R2SurfaceWriteProvider { bucket }
    }
}

#[async_trait(?Send)]
impl SurfaceWriteProvider for R2SurfaceWriteProvider {
    async fn writer(&self, registry: &RegistryRecord) -> Result<Box<dyn SurfaceWrite>> {
        Ok(Box::new(R2Write {
            bucket: self.bucket.clone(),
            prefix: registry.prefix.clone(),
        }))
    }
}

/// A [`SurfaceWrite`] writing one registry's prefix into an R2 bucket.
///
/// Logical surface paths map to R2 keys through the same
/// [`crate::keymap::r2_key`] mapping the read side
/// ([`R2SurfaceFetch`]) uses, so a draft written here is read back by the same
/// key. R2 puts are atomic per object, so no temp-file + rename dance is needed;
/// R2 keys are a flat namespace, so there is no traversal/symlink escape to
/// guard against (the key map normalizes the prefix join).
struct R2Write {
    bucket: Bucket,
    prefix: String,
}

#[async_trait(?Send)]
impl SurfaceWrite for R2Write {
    async fn write(&self, path: &str, bytes: &[u8]) -> Result<()> {
        let key = keymap::r2_key(&self.prefix, path);
        self.bucket
            .put(&key, bytes.to_vec())
            .execute()
            .await
            .map_err(|err| anyhow::anyhow!("R2 put {key}: {err}"))?;
        Ok(())
    }

    async fn delete(&self, path: &str) -> Result<()> {
        let key = keymap::r2_key(&self.prefix, path);
        // R2 delete of an absent key is a no-op, so this is naturally
        // idempotent.
        self.bucket
            .delete(&key)
            .await
            .map_err(|err| anyhow::anyhow!("R2 delete {key}: {err}"))?;
        Ok(())
    }
}
