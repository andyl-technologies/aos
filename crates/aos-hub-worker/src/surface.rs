//! The R2-backed [`SurfaceProvider`] for the shared service (wasm32-only).
//!
//! The shared [`RpcService`](aos_hub_core::service::RpcService) reads a
//! registry's wire surface (loose git objects, `info/refs`, channel partitions,
//! NARs, …) through the [`SurfaceProvider`]/[`SurfaceFetch`] ports
//! ([`aos_hub_core::fetch`]). On the Cloudflare Worker that surface lives
//! in the hub-owned R2 bucket, with each registry occupying a *prefix*
//! (RFC-0004 "Storage": registries as prefixes in a shared bucket). This module
//! supplies the Worker's concrete fetcher: it resolves the per-registry prefix
//! from the [`RegistryRecord`] and reads R2 keys `{prefix}{path}` via the
//! [`crate::keymap::r2_key`] mapping and `bucket.get(...).execute()`. The shared
//! machine-surface facade
//! ([`aos_hub_core::service::RpcService::facade_fetch`]) and the RPC
//! `GitService` reads both read through this one provider, so they cannot drift.
//!
//! The R2 bucket handle is not `Send`/`Sync`, but on the single-threaded Worker
//! the core ports drop those bounds (the wasm32 `BackendBounds` is unbounded),
//! so an `Rc`-free owned [`worker::Bucket`] satisfies the trait directly.

use anyhow::Result;
use async_trait::async_trait;
use worker::Bucket;

use aos_hub_core::db::RegistryRecord;
use aos_hub_core::fetch::{OriginFetch, StreamedRead, SurfaceFetch, SurfaceProvider};
use aos_hub_core::surface_write::{SurfaceWrite, SurfaceWriteProvider};

use crate::keymap;

/// Whether an R2 error message names a transient, retryable condition.
///
/// Cloudflare R2 surfaces error `10001` ("We encountered an internal error.
/// Please try again.") for transient server-side faults, which it explicitly
/// asks callers to retry. A missing object is not an error (it returns
/// `Ok(None)`), so this never matches a 404-equivalent.
fn is_transient_r2(message: &str) -> bool {
    message.contains("(10001)") || message.contains("Please try again")
}

/// Run an R2 `get`, retrying a few times on a transient R2 internal error
/// ([`is_transient_r2`]).
///
/// A missing object (`Ok(None)`) and a non-transient error return immediately;
/// only a transient `10001`-class fault is retried (up to three attempts total),
/// so a brief R2 hiccup does not, for example, mark a registry's index `failed`.
///
/// # Errors
///
/// Returns an error if a non-transient error occurs or every attempt fails (the
/// last error is reported, prefixed with the key).
async fn r2_get(bucket: &Bucket, key: &str) -> Result<Option<worker::Object>> {
    let mut attempt = 0u32;
    loop {
        match bucket.get(key).execute().await {
            Ok(object) => return Ok(object),
            Err(err) if attempt < 2 && is_transient_r2(&err.to_string()) => attempt += 1,
            Err(err) => return Err(anyhow::anyhow!("R2 get {key}: {err}")),
        }
    }
}

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

    async fn cache_fetcher(
        &self,
        cache: &aos_hub_core::db::Cache,
    ) -> Result<Box<dyn SurfaceFetch>> {
        Ok(Box::new(R2SurfaceFetch {
            bucket: self.bucket.clone(),
            prefix: cache.prefix.clone(),
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
        let object = r2_get(&self.bucket, &key).await?;
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

    async fn fetch_stream(
        &self,
        path: &str,
        range: Option<(u64, u64)>,
    ) -> Result<Option<aos_hub_core::fetch::StreamedRead>> {
        use futures_util::{StreamExt as _, TryStreamExt as _};

        let key = keymap::r2_key(&self.prefix, path);
        // NOTE: we deliberately do *not* push the byte range into the R2 `get`
        // (`GetOptionsBuilder::range`). workers-rs 0.4.x serializes every `Range`
        // variant with an explicit `suffix: undefined` property, and the runtime's
        // R2 binding rejects the *presence* of the `suffix` key alongside `offset`
        // ("Suffix is incompatible with offset"), so a pushed-down range errors on
        // workerd. Instead we open the whole-object stream and trim it chunk by
        // chunk below — the isolate still never holds the whole object in memory
        // (it streams through, dropping pre-`start` bytes and stopping at the
        // range end), so the memory-safety property the streaming path guarantees
        // is preserved; only the discarded pre-`start` bytes cross R2→isolate
        // (nil for the whole-object and prefix reads nix actually issues).
        let object = r2_get(&self.bucket, &key).await?;
        let Some(object) = object else {
            return Ok(None);
        };
        let total = object.size();
        // The inclusive range actually served (clamped to the object), or `None`
        // for a whole-object read.
        let served = match range {
            Some((start, end)) if start < total => Some((start, end.min(total.saturating_sub(1)))),
            _ => None,
        };
        let Some(body) = object.body() else {
            // A bodyless R2 object is zero-length, so there is nothing to range
            // over — serve a whole-object empty body (`range: None`) regardless of
            // what was requested, so `cache_serve` emits `Content-Length: 0`
            // rather than a positive length against an empty body.
            return Ok(Some(aos_hub_core::fetch::StreamedRead {
                body: axum::body::Body::empty(),
                total,
                range: None,
            }));
        };
        let stream = body
            .stream()
            .map_err(|err| anyhow::anyhow!("R2 stream {key}: {err}"))?
            .map_err(|err| std::io::Error::other(err.to_string()));
        // Trim the whole-object stream to the served byte range without buffering:
        // `skip` leading bytes are dropped (splitting a straddling chunk) and at
        // most `remaining` bytes are emitted (truncating the final chunk, then
        // ending the stream). For a whole-object read both bounds are wide open.
        let (skip, remaining) = match served {
            Some((start, end)) => (start, end - start + 1),
            None => (0, u64::MAX),
        };
        let trimmed = futures_util::stream::try_unfold(
            (stream.boxed_local(), skip, remaining),
            |(mut stream, mut skip, mut remaining)| async move {
                if remaining == 0 {
                    return Ok(None);
                }
                loop {
                    match stream.next().await {
                        None => return Ok(None),
                        Some(Err(err)) => return Err(err),
                        Some(Ok(mut chunk)) => {
                            if skip > 0 {
                                // `skip as usize` is sound on wasm32 (32-bit
                                // usize) because `.min(chunk.len())` bounds it
                                // below `usize::MAX` before the cast.
                                let drop = (skip as usize).min(chunk.len());
                                chunk.drain(..drop);
                                skip -= drop as u64;
                                if chunk.is_empty() {
                                    continue;
                                }
                            }
                            // Compare/clamp in `u64`: `remaining` can exceed
                            // `u32::MAX` for a multi-GiB range, so `remaining as
                            // usize` on wasm32 would truncate the high bits and
                            // wrongly truncate the chunk. `chunk.len()` fits a
                            // u32, so the *bounded* `take` casts back safely.
                            let take = remaining.min(chunk.len() as u64) as usize;
                            chunk.truncate(take);
                            remaining -= take as u64;
                            return Ok(Some((chunk, (stream, skip, remaining))));
                        }
                    }
                }
            },
        );
        // `axum::body::Body::from_stream` requires `Send`; the R2 `ByteStream` is
        // `!Send`. `SendWrapper` makes it `Send` (sound on the single-threaded
        // Worker), so the *same* `StreamedRead` the native file path returns
        // flows through the shared `cache_serve` and the streaming bridge.
        let body = axum::body::Body::from_stream(send_wrapper::SendWrapper::new(trimmed));
        Ok(Some(aos_hub_core::fetch::StreamedRead {
            body,
            total,
            range: served,
        }))
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

/// A [`OriginFetch`] over the Workers global Fetch API.
///
/// The Worker counterpart of the native `ReqwestOriginFetch`: it streams a
/// private external origin's bytes through the isolate (the proxy-read
/// alternative to a `302` presigned redirect), forwarding a byte range as a
/// `Range` request header and re-deriving the served range/total from the
/// origin's `Content-Range`/`Content-Length` response headers. The body is the
/// `worker::Response` `ByteStream`, `SendWrapper`-wrapped into the axum body
/// exactly like the R2 read path, so a large NAR never buffers in the isolate.
pub struct WorkerOriginFetch;

#[async_trait(?Send)]
impl OriginFetch for WorkerOriginFetch {
    async fn get_stream(
        &self,
        url: &str,
        range: Option<(u64, u64)>,
    ) -> Result<Option<StreamedRead>> {
        use futures_util::TryStreamExt as _;
        use worker::{Fetch, Headers, Method, Request, RequestInit};

        let mut headers = Headers::new();
        if let Some((start, end)) = range {
            let spec = if end == u64::MAX {
                format!("bytes={start}-")
            } else {
                format!("bytes={start}-{end}")
            };
            headers
                .set("Range", &spec)
                .map_err(|err| anyhow::anyhow!("origin set Range: {err}"))?;
        }
        let mut init = RequestInit::new();
        init.with_method(Method::Get).with_headers(headers);
        let request = Request::new_with_init(url, &init)
            .map_err(|err| anyhow::anyhow!("origin build request {url}: {err}"))?;
        let mut response = Fetch::Request(request)
            .send()
            .await
            .map_err(|err| anyhow::anyhow!("origin GET {url}: {err}"))?;
        let status = response.status_code();
        if status == 404 {
            return Ok(None);
        }
        if !(200..300).contains(&status) {
            anyhow::bail!("origin GET {url}: status {status}");
        }
        // A `206` carries the served range + total in `Content-Range`; a `200`
        // carries the size in `Content-Length` and serves the whole object.
        let served;
        let total;
        if status == 206 {
            let cr = response
                .headers()
                .get("content-range")
                .ok()
                .flatten()
                .and_then(|v| parse_content_range(&v))
                .ok_or_else(|| anyhow::anyhow!("origin 206 without a parseable Content-Range"))?;
            // Trust nothing from the origin: a malformed range (`end < start` or
            // `end >= total`) would underflow/overflow the downstream
            // `Content-Length` arithmetic. Enforce `fetch_stream`'s invariant.
            if cr.0 > cr.1 || cr.1 >= cr.2 {
                anyhow::bail!("origin malformed Content-Range bytes {}-{}/{}", cr.0, cr.1, cr.2);
            }
            served = Some((cr.0, cr.1));
            total = cr.2;
        } else {
            served = None;
            total = response
                .headers()
                .get("content-length")
                .ok()
                .flatten()
                .and_then(|v| v.parse::<u64>().ok())
                .ok_or_else(|| anyhow::anyhow!("origin 200 without a Content-Length"))?;
        }
        let stream = response
            .stream()
            .map_err(|err| anyhow::anyhow!("origin stream {url}: {err}"))?
            .map_err(|err| std::io::Error::other(err.to_string()));
        let body = axum::body::Body::from_stream(send_wrapper::SendWrapper::new(stream));
        Ok(Some(StreamedRead {
            body,
            total,
            range: served,
        }))
    }
}

/// Parse a `Content-Range: bytes START-END/TOTAL` value into `(start, end, total)`.
///
/// Returns `None` for an unsatisfiable (`bytes */TOTAL`) or malformed value.
fn parse_content_range(value: &str) -> Option<(u64, u64, u64)> {
    let rest = value.trim().strip_prefix("bytes ")?;
    let (range, total) = rest.split_once('/')?;
    let (start, end) = range.split_once('-')?;
    Some((
        start.trim().parse().ok()?,
        end.trim().parse().ok()?,
        total.trim().parse().ok()?,
    ))
}

/// A [`SurfaceWriteProvider`] that writes every registry into one R2 bucket.
///
/// The write sibling of [`R2SurfaceProvider`]: holds the hub-owned bucket
/// binding and scopes a [`R2Write`] to the requested registry's prefix. The
/// shared git-backed change-request flow ([`aos_hub_core::gitwrite`]) uses
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

    async fn cache_writer(
        &self,
        cache: &aos_hub_core::db::Cache,
    ) -> Result<Box<dyn SurfaceWrite>> {
        Ok(Box::new(R2Write {
            bucket: self.bucket.clone(),
            prefix: cache.prefix.clone(),
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
