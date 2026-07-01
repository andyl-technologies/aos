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

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use worker::Bucket;

use aos_hub_core::auth::seal::SecretSealer;
use aos_hub_core::db::{Cache, Database, RegistryRecord};
use aos_hub_core::fetch::{OriginFetch, StreamedRead, SurfaceFetch, SurfaceProvider};
use aos_hub_core::s3surface::{Method as S3Method, S3Surface};
use aos_hub_core::surface_write::{PartTag, SurfaceWrite, SurfaceWriteProvider};

use crate::keymap;

/// Resolve a registry's storage binding into an external [`S3Surface`], or
/// `Ok(None)` when the registry has no binding (or its binding is not an
/// S3-compatible object store).
///
/// A managed registry with an `s3`/`r2` binding serves its surface from an
/// external object store rather than the hub-owned R2 bucket; this loads the
/// binding row from D1 and resolves it (unsealing private credentials) against
/// the registry's `prefix`. Registries with no binding (`file://`/`http`
/// phase-1 rows, or a non-object-store binding) return `Ok(None)` so the caller
/// keeps the default R2 path.
///
/// # Errors
///
/// Returns an error if the D1 lookup of the binding fails, or if resolving the
/// binding fails (missing endpoint, malformed or un-unsealable credentials).
async fn registry_s3_surface(
    db: &Database,
    sealer: &dyn SecretSealer,
    registry: &RegistryRecord,
) -> Result<Option<S3Surface>> {
    let Some(id) = registry.storage_binding_id else {
        return Ok(None);
    };
    let Some(binding) = db.storage_binding(id).await? else {
        return Ok(None);
    };
    // The instance-default binding *is* the hub's own bound R2 bucket
    // (`REGISTRY_BUCKET`): read it directly via `env.bucket` (the `Ok(None)`
    // fallthrough), not over the R2 S3 API — the Worker has no credentials or
    // public-read path to its own bucket through that endpoint, so an S3 fetch
    // 400s. Only genuinely external bindings serve their surface over S3.
    if binding.is_instance_default {
        return Ok(None);
    }
    S3Surface::from_binding(&binding, &registry.prefix, sealer)
}

/// Resolve a cache's storage binding into an external [`S3Surface`], or
/// `Ok(None)` when the binding is not an S3-compatible object store.
///
/// The cache counterpart of [`registry_s3_surface`], scoped to the cache's
/// `prefix`. A cache always names a binding (`Cache::storage_binding_id` is
/// non-optional); a binding whose kind is not `s3`/`r2` (e.g. the hub-owned R2
/// bucket) yields `Ok(None)`.
///
/// # Errors
///
/// Returns an error if the D1 lookup of the binding fails, or if resolving the
/// binding fails (missing endpoint, malformed or un-unsealable credentials).
async fn cache_s3_surface(
    db: &Database,
    sealer: &dyn SecretSealer,
    cache: &Cache,
) -> Result<Option<S3Surface>> {
    // A binding-less (default-storage) cache has no external origin — it is
    // served from the deployment R2 bucket by prefix (the fallthrough path).
    let Some(binding_id) = cache.storage_binding_id else {
        return Ok(None);
    };
    let Some(binding) = db.storage_binding(binding_id).await? else {
        return Ok(None);
    };
    // Instance-default binding → the hub's bound R2 bucket (read via `env.bucket`,
    // the `Ok(None)` fallthrough), not the R2 S3 API. See `registry_s3_surface`.
    if binding.is_instance_default {
        return Ok(None);
    }
    S3Surface::from_binding(&binding, &cache.prefix, sealer)
}

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
async fn r2_get(bucket: &Bucket, key: &str) -> Result<Option<wasm_bindgen::JsValue>> {
    // Call the R2 binding's `get` method directly with *only* the key, rather
    // than via worker-rs `Bucket::get(key).execute()`. The 0.8 `GetOptionsBuilder`
    // always serializes an options object whose `onlyIf`/`range` keys are present
    // and set to JS `undefined` even when unset (`js_object!` does an
    // unconditional `Reflect::set`), and the current workerd/R2 rejects those
    // present-but-`undefined` option keys by failing the GET with a *persistent*
    // `10001` "internal error" — the same class of 0.8 R2 option-serialization
    // bug worked around in [`R2SurfaceFetch::list`] (unset `cursor`) and the
    // ranged read in [`R2SurfaceFetch::fetch_stream`] (`suffix: undefined`).
    // Passing no options object at all avoids it; the returned value is the raw
    // R2 object (or `null`/`undefined` for a miss), read via `js_sys` since
    // worker-rs `Object` has no public constructor from a `JsValue`.
    use js_sys::{Function, Promise, Reflect};
    use wasm_bindgen::{JsCast, JsValue};
    use wasm_bindgen_futures::JsFuture;

    let jsbucket: &JsValue = bucket.as_ref();
    let get_fn: Function = Reflect::get(jsbucket, &JsValue::from_str("get"))
        .map_err(|e| anyhow::anyhow!("R2 get {key}: get method: {e:?}"))?
        .dyn_into()
        .map_err(|e| anyhow::anyhow!("R2 get {key}: get is not a function: {e:?}"))?;
    let mut attempt = 0u32;
    loop {
        let promise: Promise = get_fn
            .call1(jsbucket, &JsValue::from_str(key))
            .map_err(|e| anyhow::anyhow!("R2 get {key}: call: {e:?}"))?
            .dyn_into()
            .map_err(|e| anyhow::anyhow!("R2 get {key}: get did not return a promise: {e:?}"))?;
        match JsFuture::from(promise).await {
            Ok(v) if v.is_null() || v.is_undefined() => return Ok(None),
            Ok(v) => return Ok(Some(v)),
            Err(e) if attempt < 2 && is_transient_r2(&format!("{e:?}")) => attempt += 1,
            Err(e) => return Err(anyhow::anyhow!("R2 get {key}: {e:?}")),
        }
    }
}

/// Adapt an R2 object's `body` ([`web_sys::ReadableStream`]-shaped `JsValue`)
/// into a byte-chunk stream by driving its default reader.
///
/// Mirrors what worker-rs `ByteStream` does internally, but over the raw
/// `JsValue` body of the object [`r2_get`] returns (worker-rs `ObjectBody` is
/// only reachable from a `worker::Object`, which has no public constructor). Each
/// `reader.read()` yields `{ done, value: Uint8Array }`; `done` ends the stream.
fn r2_body_stream(
    body: wasm_bindgen::JsValue,
) -> impl futures_util::Stream<Item = std::result::Result<Vec<u8>, std::io::Error>> {
    use js_sys::{Function, Promise, Reflect, Uint8Array};
    use wasm_bindgen::{JsCast, JsValue};
    use wasm_bindgen_futures::JsFuture;

    let reader = Reflect::get(&body, &JsValue::from_str("getReader"))
        .ok()
        .and_then(|f| f.dyn_into::<Function>().ok())
        .and_then(|f| f.call0(&body).ok());
    futures_util::stream::try_unfold(reader, move |reader| async move {
        let Some(reader) = reader else {
            return Err(std::io::Error::other("R2 body: getReader unavailable"));
        };
        let read_fn: Function = Reflect::get(&reader, &JsValue::from_str("read"))
            .map_err(|e| std::io::Error::other(format!("R2 read method: {e:?}")))?
            .dyn_into()
            .map_err(|e| std::io::Error::other(format!("R2 read not a function: {e:?}")))?;
        let promise: Promise = read_fn
            .call0(&reader)
            .map_err(|e| std::io::Error::other(format!("R2 read call: {e:?}")))?
            .dyn_into()
            .map_err(|e| std::io::Error::other(format!("R2 read not a promise: {e:?}")))?;
        let result = JsFuture::from(promise)
            .await
            .map_err(|e| std::io::Error::other(format!("R2 read: {e:?}")))?;
        let done = Reflect::get(&result, &JsValue::from_str("done"))
            .ok()
            .and_then(|d| d.as_bool())
            .unwrap_or(true);
        if done {
            return Ok(None);
        }
        let value = Reflect::get(&result, &JsValue::from_str("value"))
            .map_err(|e| std::io::Error::other(format!("R2 read value: {e:?}")))?;
        let chunk = value.unchecked_into::<Uint8Array>().to_vec();
        Ok(Some((chunk, Some(reader))))
    })
}

/// A [`SurfaceProvider`] that serves every registry from one R2 bucket, or from
/// an external S3/R2 origin when the resource names an `s3`/`r2` storage
/// binding.
///
/// Holds the hub-owned bucket binding plus the shared [`Database`] and
/// [`SecretSealer`] needed to resolve a per-resource storage binding;
/// [`fetcher`](SurfaceProvider::fetcher) scopes a reader to the requested
/// registry's prefix — proxying to the external origin via signed URLs when the
/// binding is external ([`S3SurfaceFetch`]), else reading the hub R2 bucket
/// ([`R2SurfaceFetch`]).
pub struct R2SurfaceProvider {
    bucket: Bucket,
    db: Arc<Database>,
    sealer: Arc<dyn SecretSealer>,
}

impl R2SurfaceProvider {
    /// Wrap a bound R2 bucket (`env.bucket(binding)`) as a surface provider,
    /// with the D1 [`Database`] and [`SecretSealer`] used to resolve external
    /// S3/R2 storage bindings.
    #[must_use]
    pub fn new(
        bucket: Bucket,
        db: Arc<Database>,
        sealer: Arc<dyn SecretSealer>,
    ) -> R2SurfaceProvider {
        R2SurfaceProvider { bucket, db, sealer }
    }
}

#[async_trait(?Send)]
impl SurfaceProvider for R2SurfaceProvider {
    async fn fetcher(&self, registry: &RegistryRecord) -> Result<Box<dyn SurfaceFetch>> {
        if let Some(surface) = registry_s3_surface(&self.db, self.sealer.as_ref(), registry).await?
        {
            return Ok(Box::new(S3SurfaceFetch { surface }));
        }
        Ok(Box::new(R2SurfaceFetch {
            bucket: self.bucket.clone(),
            prefix: registry.prefix.clone(),
        }))
    }

    async fn cache_fetcher(
        &self,
        cache: &aos_hub_core::db::Cache,
    ) -> Result<Box<dyn SurfaceFetch>> {
        if let Some(surface) = cache_s3_surface(&self.db, self.sealer.as_ref(), cache).await? {
            return Ok(Box::new(S3SurfaceFetch { surface }));
        }
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
        use js_sys::{Function, Promise, Reflect, Uint8Array};
        use wasm_bindgen::{JsCast, JsValue};
        use wasm_bindgen_futures::JsFuture;

        let key = keymap::r2_key(&self.prefix, path);
        let Some(object) = r2_get(&self.bucket, &key).await? else {
            return Ok(None);
        };
        // Read the whole object via the R2 object's `arrayBuffer()`. A zero-length
        // object yields an empty buffer (present-but-empty, not a miss), so legal
        // empty pointers still resolve to `Some(vec![])`.
        let array_buffer: Function = Reflect::get(&object, &JsValue::from_str("arrayBuffer"))
            .map_err(|e| anyhow::anyhow!("R2 get {key}: arrayBuffer method: {e:?}"))?
            .dyn_into()
            .map_err(|e| anyhow::anyhow!("R2 get {key}: arrayBuffer not a function: {e:?}"))?;
        let promise: Promise = array_buffer
            .call0(&object)
            .map_err(|e| anyhow::anyhow!("R2 read body {key}: arrayBuffer call: {e:?}"))?
            .dyn_into()
            .map_err(|e| anyhow::anyhow!("R2 read body {key}: not a promise: {e:?}"))?;
        let buffer = JsFuture::from(promise)
            .await
            .map_err(|e| anyhow::anyhow!("R2 read body {key}: {e:?}"))?;
        Ok(Some(Uint8Array::new(&buffer).to_vec()))
    }

    async fn list(&self) -> Result<Vec<String>> {
        // List every key under the registry/cache's R2 prefix, paging through the
        // cursor, and re-home each to a surface-relative path so the migration
        // copy and the cache re-scan speak the same logical paths the rest of the
        // ports do.
        //
        // We call the R2 binding's `list` directly rather than via
        // `worker::Bucket::list()`: the worker-rs 0.8 `ListOptionsBuilder` always
        // serializes the unset `cursor` as JS `null`, and the current workerd
        // rejects a non-string `cursor` on `R2ListOptions` ("Incorrect type for
        // the 'cursor' field … not of type 'string'"), so every list 500s. Here
        // we build the options object ourselves and OMIT `cursor` until we have a
        // real one.
        use js_sys::{Array, Function, Object, Promise, Reflect};
        use wasm_bindgen::{JsCast, JsValue};
        use wasm_bindgen_futures::JsFuture;

        let jserr = |ctx: &str, e: JsValue| anyhow::anyhow!("R2 list: {ctx}: {e:?}");
        let listing_prefix = keymap::r2_key(&self.prefix, "");
        let bucket: &JsValue = self.bucket.as_ref();
        let list_fn: Function = Reflect::get(bucket, &JsValue::from_str("list"))
            .map_err(|e| jserr("get list method", e))?
            .dyn_into()
            .map_err(|e| jserr("list is not a function", e))?;

        let mut keys = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let opts = Object::new();
            Reflect::set(
                &opts,
                &JsValue::from_str("prefix"),
                &JsValue::from_str(&listing_prefix),
            )
            .map_err(|e| jserr("set prefix", e))?;
            Reflect::set(
                &opts,
                &JsValue::from_str("limit"),
                &JsValue::from_f64(1000.0),
            )
            .map_err(|e| jserr("set limit", e))?;
            if let Some(c) = &cursor {
                Reflect::set(&opts, &JsValue::from_str("cursor"), &JsValue::from_str(c))
                    .map_err(|e| jserr("set cursor", e))?;
            }
            let promise: Promise = list_fn
                .call1(bucket, &opts)
                .map_err(|e| jserr(&format!("calling list({listing_prefix})"), e))?
                .dyn_into()
                .map_err(|e| jserr("list did not return a promise", e))?;
            let result = JsFuture::from(promise)
                .await
                .map_err(|e| jserr(&format!("awaiting list({listing_prefix})"), e))?;

            let objects: Array = Reflect::get(&result, &JsValue::from_str("objects"))
                .map_err(|e| jserr("get objects", e))?
                .dyn_into()
                .map_err(|e| jserr("objects is not an array", e))?;
            for object in objects.iter() {
                let key = Reflect::get(&object, &JsValue::from_str("key"))
                    .ok()
                    .and_then(|k| k.as_string())
                    .unwrap_or_default();
                if let Some(rel) = keymap::relative_key(&self.prefix, &key) {
                    if !rel.is_empty() {
                        keys.push(rel);
                    }
                }
            }
            let truncated = Reflect::get(&result, &JsValue::from_str("truncated"))
                .ok()
                .and_then(|t| t.as_bool())
                .unwrap_or(false);
            if !truncated {
                break;
            }
            cursor = Reflect::get(&result, &JsValue::from_str("cursor"))
                .ok()
                .and_then(|c| c.as_string());
            if cursor.is_none() {
                break;
            }
        }
        Ok(keys)
    }

    async fn fetch_stream(
        &self,
        path: &str,
        range: Option<(u64, u64)>,
    ) -> Result<Option<aos_hub_core::fetch::StreamedRead>> {
        use futures_util::StreamExt as _;

        let key = keymap::r2_key(&self.prefix, path);
        // NOTE: we deliberately do *not* push the byte range into the R2 `get`
        // (`GetOptionsBuilder::range`). workers-rs serializes every `Range`
        // variant with an explicit `suffix: undefined` property (still true in
        // 0.8.5 — `r2::builder::Range`'s `OffsetWithLength` arm emits
        // `"suffix" => JsValue::UNDEFINED`), and the runtime's R2 binding rejects
        // the *presence* of the `suffix` key alongside `offset` ("Suffix is
        // incompatible with offset"), so a pushed-down range errors on
        // workerd. Instead we open the whole-object stream and trim it chunk by
        // chunk below — the isolate still never holds the whole object in memory
        // (it streams through, dropping pre-`start` bytes and stopping at the
        // range end), so the memory-safety property the streaming path guarantees
        // is preserved; only the discarded pre-`start` bytes cross R2→isolate
        // (nil for the whole-object and prefix reads nix actually issues).
        let Some(object) = r2_get(&self.bucket, &key).await? else {
            return Ok(None);
        };
        // Read `size` and `body` off the raw R2 object via `js_sys` (worker-rs
        // `Object` is unreachable here — see `r2_get`).
        let total = js_sys::Reflect::get(&object, &wasm_bindgen::JsValue::from_str("size"))
            .ok()
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0) as u64;
        // The inclusive range actually served (clamped to the object), or `None`
        // for a whole-object read.
        let served = match range {
            Some((start, end)) if start < total => Some((start, end.min(total.saturating_sub(1)))),
            _ => None,
        };
        let body_js = js_sys::Reflect::get(&object, &wasm_bindgen::JsValue::from_str("body"))
            .unwrap_or(wasm_bindgen::JsValue::UNDEFINED);
        if body_js.is_null() || body_js.is_undefined() {
            // A bodyless R2 object is zero-length, so there is nothing to range
            // over — serve a whole-object empty body (`range: None`) regardless of
            // what was requested, so `cache_serve` emits `Content-Length: 0`
            // rather than a positive length against an empty body.
            return Ok(Some(aos_hub_core::fetch::StreamedRead {
                body: axum::body::Body::empty(),
                total,
                range: None,
            }));
        }
        let stream = r2_body_stream(body_js);
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

/// A [`SurfaceFetch`] reading one resource's surface from an external
/// S3-compatible origin via per-object signed URLs.
///
/// The external-binding counterpart of [`R2SurfaceFetch`]: instead of an R2
/// `get`/`head`, each operation mints a short-lived presigned URL with
/// [`S3Surface::object_url`] and drives it over the Workers global Fetch API,
/// streaming bodies through the isolate exactly like [`WorkerOriginFetch`] (so a
/// large NAR never buffers). A presigned URL signs only the `Host` header, so a
/// `Range` request header may be added freely on the streaming path.
struct S3SurfaceFetch {
    surface: S3Surface,
}

#[async_trait(?Send)]
impl SurfaceFetch for S3SurfaceFetch {
    async fn fetch(&self, path: &str) -> Result<Option<Vec<u8>>> {
        use worker::Fetch;

        let now = aos_hub_core::clock::now_unix_secs();
        let url = self.surface.object_url(S3Method::Get, path, now)?;
        let mut response = Fetch::Url(
            url.parse()
                .map_err(|err| anyhow::anyhow!("s3 parse GET url: {err}"))?,
        )
        .send()
        .await
        .map_err(|err| anyhow::anyhow!("s3 GET {}: {err}", self.surface.describe()))?;
        let status = response.status_code();
        if status == 404 {
            return Ok(None);
        }
        if !(200..300).contains(&status) {
            anyhow::bail!("s3 GET {}: status {status}", self.surface.describe());
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|err| anyhow::anyhow!("s3 read body {}: {err}", self.surface.describe()))?;
        Ok(Some(bytes))
    }

    async fn list(&self) -> Result<Vec<String>> {
        use worker::Fetch;

        let mut keys = Vec::new();
        let mut continuation: Option<String> = None;
        loop {
            let now = aos_hub_core::clock::now_unix_secs();
            let url = self.surface.list_url(continuation.as_deref(), now)?;
            let mut response = Fetch::Url(
                url.parse()
                    .map_err(|err| anyhow::anyhow!("s3 parse list url: {err}"))?,
            )
            .send()
            .await
            .map_err(|err| anyhow::anyhow!("s3 list {}: {err}", self.surface.describe()))?;
            let status = response.status_code();
            if !(200..300).contains(&status) {
                anyhow::bail!("s3 list {}: status {status}", self.surface.describe());
            }
            let body = response.text().await.map_err(|err| {
                anyhow::anyhow!("s3 list body {}: {err}", self.surface.describe())
            })?;
            let (page_keys, next) = aos_hub_core::s3surface::parse_list_objects_v2(&body);
            for key in page_keys {
                if let Some(rel) = self.surface.relative_from_key(&key) {
                    if !rel.is_empty() {
                        keys.push(rel);
                    }
                }
            }
            match next {
                Some(token) => continuation = Some(token),
                None => break,
            }
        }
        Ok(keys)
    }

    async fn fetch_stream(
        &self,
        path: &str,
        range: Option<(u64, u64)>,
    ) -> Result<Option<StreamedRead>> {
        use futures_util::TryStreamExt as _;
        use worker::{Fetch, Headers, Method, Request, RequestInit};

        let now = aos_hub_core::clock::now_unix_secs();
        let url = self.surface.object_url(S3Method::Get, path, now)?;

        // The presigned URL signs only the Host header, so a `Range` request
        // header travels unsigned and the origin honors it as a normal byte
        // range — the served range/total are re-derived from the response.
        let headers = Headers::new();
        if let Some((start, end)) = range {
            let spec = if end == u64::MAX {
                format!("bytes={start}-")
            } else {
                format!("bytes={start}-{end}")
            };
            headers
                .set("Range", &spec)
                .map_err(|err| anyhow::anyhow!("s3 set Range: {err}"))?;
        }
        let mut init = RequestInit::new();
        init.with_method(Method::Get).with_headers(headers);
        let request = Request::new_with_init(&url, &init)
            .map_err(|err| anyhow::anyhow!("s3 build request: {err}"))?;
        let mut response = Fetch::Request(request)
            .send()
            .await
            .map_err(|err| anyhow::anyhow!("s3 GET {}: {err}", self.surface.describe()))?;
        let status = response.status_code();
        if status == 404 {
            return Ok(None);
        }
        if !(200..300).contains(&status) {
            anyhow::bail!("s3 GET {}: status {status}", self.surface.describe());
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
                .ok_or_else(|| anyhow::anyhow!("s3 206 without a parseable Content-Range"))?;
            // Trust nothing from the origin: a malformed range would
            // underflow/overflow the downstream `Content-Length` arithmetic.
            if cr.0 > cr.1 || cr.1 >= cr.2 {
                anyhow::bail!(
                    "s3 malformed Content-Range bytes {}-{}/{}",
                    cr.0,
                    cr.1,
                    cr.2
                );
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
                .ok_or_else(|| anyhow::anyhow!("s3 200 without a Content-Length"))?;
        }
        let stream = response
            .stream()
            .map_err(|err| anyhow::anyhow!("s3 stream {}: {err}", self.surface.describe()))?
            .map_err(|err| std::io::Error::other(err.to_string()));
        // The `worker::Response` `ByteStream` is `!Send`; `SendWrapper` makes it
        // `Send` (sound on the single-threaded Worker) so the same
        // `StreamedRead` the R2/native paths return flows through `cache_serve`.
        let body = axum::body::Body::from_stream(send_wrapper::SendWrapper::new(stream));
        Ok(Some(StreamedRead {
            body,
            total,
            range: served,
        }))
    }

    async fn size(&self, path: &str) -> Result<Option<u64>> {
        use worker::{Fetch, Method, Request, RequestInit};

        let now = aos_hub_core::clock::now_unix_secs();
        let url = self.surface.object_url(S3Method::Head, path, now)?;
        let mut init = RequestInit::new();
        init.with_method(Method::Head);
        let request = Request::new_with_init(&url, &init)
            .map_err(|err| anyhow::anyhow!("s3 build HEAD request: {err}"))?;
        let response = Fetch::Request(request)
            .send()
            .await
            .map_err(|err| anyhow::anyhow!("s3 HEAD {}: {err}", self.surface.describe()))?;
        let status = response.status_code();
        if status == 404 {
            return Ok(None);
        }
        if !(200..300).contains(&status) {
            anyhow::bail!("s3 HEAD {}: status {status}", self.surface.describe());
        }
        let len = response
            .headers()
            .get("content-length")
            .ok()
            .flatten()
            .and_then(|v| v.parse::<u64>().ok())
            .ok_or_else(|| anyhow::anyhow!("s3 HEAD without a Content-Length"))?;
        Ok(Some(len))
    }

    fn describe(&self) -> String {
        self.surface.describe()
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

        let headers = Headers::new();
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
                anyhow::bail!(
                    "origin malformed Content-Range bytes {}-{}/{}",
                    cr.0,
                    cr.1,
                    cr.2
                );
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

/// A [`SurfaceWriteProvider`] that writes every registry into one R2 bucket, or
/// into an external S3/R2 origin when the resource names an `s3`/`r2` binding.
///
/// The write sibling of [`R2SurfaceProvider`]: holds the hub-owned bucket
/// binding plus the shared [`Database`] and [`SecretSealer`] for resolving an
/// external binding, and scopes a writer to the requested registry's prefix —
/// signed `PUT`/`DELETE` against the external origin ([`S3Write`]) when the
/// binding is external, else the hub R2 bucket ([`R2Write`]). The shared
/// git-backed change-request flow ([`aos_hub_core::gitwrite`]) uses it to write
/// loose objects and draft refs.
pub struct R2SurfaceWriteProvider {
    bucket: Bucket,
    db: Arc<Database>,
    sealer: Arc<dyn SecretSealer>,
}

impl R2SurfaceWriteProvider {
    /// Wrap a bound R2 bucket (`env.bucket(binding)`) as a surface write
    /// provider, with the D1 [`Database`] and [`SecretSealer`] used to resolve
    /// external S3/R2 storage bindings.
    #[must_use]
    pub fn new(
        bucket: Bucket,
        db: Arc<Database>,
        sealer: Arc<dyn SecretSealer>,
    ) -> R2SurfaceWriteProvider {
        R2SurfaceWriteProvider { bucket, db, sealer }
    }
}

#[async_trait(?Send)]
impl SurfaceWriteProvider for R2SurfaceWriteProvider {
    async fn writer(&self, registry: &RegistryRecord) -> Result<Box<dyn SurfaceWrite>> {
        if let Some(surface) = registry_s3_surface(&self.db, self.sealer.as_ref(), registry).await?
        {
            return Ok(Box::new(S3Write { surface }));
        }
        Ok(Box::new(R2Write {
            bucket: self.bucket.clone(),
            prefix: registry.prefix.clone(),
        }))
    }

    async fn cache_writer(&self, cache: &aos_hub_core::db::Cache) -> Result<Box<dyn SurfaceWrite>> {
        if let Some(surface) = cache_s3_surface(&self.db, self.sealer.as_ref(), cache).await? {
            return Ok(Box::new(S3Write { surface }));
        }
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
        // Call the R2 binding's `put` directly with only `(key, value)`, rather
        // than via worker-rs `Bucket::put(key, value).execute()`. The 0.8
        // `PutOptionsBuilder` serializes an options object whose keys (notably
        // `md5`) are present and set via an unconditional `Reflect::set`, and the
        // current workerd/R2 rejects the wrong-typed value ("Incorrect type for
        // the 'md5' field on 'PutOptions'"), failing every write with a 500 —
        // the same class of 0.8 R2 option-serialization bug bypassed for the
        // read path in [`r2_get`]. Passing no options object avoids it.
        use js_sys::{Function, Promise, Reflect, Uint8Array};
        use wasm_bindgen::{JsCast, JsValue};
        use wasm_bindgen_futures::JsFuture;

        let jsbucket: &JsValue = self.bucket.as_ref();
        let put_fn: Function = Reflect::get(jsbucket, &JsValue::from_str("put"))
            .map_err(|e| anyhow::anyhow!("R2 put {key}: put method: {e:?}"))?
            .dyn_into()
            .map_err(|e| anyhow::anyhow!("R2 put {key}: put is not a function: {e:?}"))?;
        let value = Uint8Array::from(bytes);
        let promise: Promise = put_fn
            .call2(jsbucket, &JsValue::from_str(&key), value.as_ref())
            .map_err(|e| anyhow::anyhow!("R2 put {key}: call: {e:?}"))?
            .dyn_into()
            .map_err(|e| anyhow::anyhow!("R2 put {key}: put did not return a promise: {e:?}"))?;
        JsFuture::from(promise)
            .await
            .map_err(|e| anyhow::anyhow!("R2 put {key}: {e:?}"))?;
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

    async fn create_multipart(&self, path: &str) -> Result<String> {
        use wasm_bindgen::JsValue;
        use wasm_bindgen_futures::JsFuture;
        let key = keymap::r2_key(&self.prefix, path);
        let jsbucket: &JsValue = self.bucket.as_ref();
        // bucket.createMultipartUpload(key) -> Promise<R2MultipartUpload>. Call
        // via js_sys with no options object: worker-rs 0.8.5's multipart builders
        // share the option-serialization bug bypassed for r2_get / the put path.
        let create = js_method(jsbucket, "createMultipartUpload")?;
        let promise = js_promise(
            create.call1(jsbucket, &JsValue::from_str(&key)),
            &key,
            "createMultipartUpload",
        )?;
        let mp = JsFuture::from(promise)
            .await
            .map_err(|e| anyhow::anyhow!("R2 createMultipartUpload {key}: {e:?}"))?;
        js_sys::Reflect::get(&mp, &JsValue::from_str("uploadId"))
            .ok()
            .and_then(|v| v.as_string())
            .ok_or_else(|| {
                anyhow::anyhow!("R2 createMultipartUpload {key}: result has no uploadId")
            })
    }

    async fn upload_part(
        &self,
        path: &str,
        upload_id: &str,
        part_number: u32,
        bytes: &[u8],
    ) -> Result<PartTag> {
        use js_sys::Uint8Array;
        use wasm_bindgen::JsValue;
        use wasm_bindgen_futures::JsFuture;
        let key = keymap::r2_key(&self.prefix, path);
        let mp = self.resume_multipart(&key, upload_id)?;
        let upload = js_method(&mp, "uploadPart")?;
        let value = Uint8Array::from(bytes);
        let promise = js_promise(
            upload.call2(&mp, &JsValue::from(part_number), value.as_ref()),
            &key,
            "uploadPart",
        )?;
        let uploaded = JsFuture::from(promise)
            .await
            .map_err(|e| anyhow::anyhow!("R2 uploadPart {key} #{part_number}: {e:?}"))?;
        let etag = js_sys::Reflect::get(&uploaded, &JsValue::from_str("etag"))
            .ok()
            .and_then(|v| v.as_string())
            .ok_or_else(|| anyhow::anyhow!("R2 uploadPart {key} #{part_number}: no etag"))?;
        Ok(PartTag { part_number, etag })
    }

    async fn complete_multipart(
        &self,
        path: &str,
        upload_id: &str,
        parts: &[PartTag],
    ) -> Result<()> {
        use wasm_bindgen::JsValue;
        use wasm_bindgen_futures::JsFuture;
        let key = keymap::r2_key(&self.prefix, path);
        let mp = self.resume_multipart(&key, upload_id)?;
        // R2.complete expects [{ partNumber, etag }, ...]; order by part number.
        let mut sorted: Vec<&PartTag> = parts.iter().collect();
        sorted.sort_by_key(|p| p.part_number);
        let arr = js_sys::Array::new();
        for p in sorted {
            let obj = js_sys::Object::new();
            js_sys::Reflect::set(
                &obj,
                &JsValue::from_str("partNumber"),
                &JsValue::from(p.part_number),
            )
            .map_err(|e| anyhow::anyhow!("R2 complete {key}: build part: {e:?}"))?;
            js_sys::Reflect::set(
                &obj,
                &JsValue::from_str("etag"),
                &JsValue::from_str(&p.etag),
            )
            .map_err(|e| anyhow::anyhow!("R2 complete {key}: build part: {e:?}"))?;
            arr.push(&obj);
        }
        let complete = js_method(&mp, "complete")?;
        let promise = js_promise(complete.call1(&mp, arr.as_ref()), &key, "complete")?;
        JsFuture::from(promise)
            .await
            .map_err(|e| anyhow::anyhow!("R2 complete {key}: {e:?}"))?;
        Ok(())
    }

    async fn abort_multipart(&self, path: &str, upload_id: &str) -> Result<()> {
        use wasm_bindgen_futures::JsFuture;
        let key = keymap::r2_key(&self.prefix, path);
        // Best-effort: a resume/abort failure (e.g. an already-completed or
        // unknown upload) is not fatal.
        let Ok(mp) = self.resume_multipart(&key, upload_id) else {
            return Ok(());
        };
        if let Ok(abort) = js_method(&mp, "abort") {
            if let Ok(promise) = js_promise(abort.call0(&mp), &key, "abort") {
                let _ = JsFuture::from(promise).await;
            }
        }
        Ok(())
    }
}

impl R2Write {
    /// Reconstruct an in-progress R2 multipart upload from `(key, upload_id)`.
    ///
    /// `bucket.resumeMultipartUpload(key, uploadId)` returns the
    /// `R2MultipartUpload` handle synchronously (no `Promise`), so a fresh Worker
    /// isolate can drive `uploadPart`/`complete`/`abort` against an upload begun
    /// in an earlier request — the statelessness the multipart protocol relies on.
    fn resume_multipart(&self, key: &str, upload_id: &str) -> Result<wasm_bindgen::JsValue> {
        use wasm_bindgen::JsValue;
        let jsbucket: &JsValue = self.bucket.as_ref();
        let resume = js_method(jsbucket, "resumeMultipartUpload")?;
        resume
            .call2(
                jsbucket,
                &JsValue::from_str(key),
                &JsValue::from_str(upload_id),
            )
            .map_err(|e| anyhow::anyhow!("R2 resumeMultipartUpload {key}: {e:?}"))
    }
}

/// Reflect method `name` off the JS object `obj` as a callable `Function`.
fn js_method(obj: &wasm_bindgen::JsValue, name: &str) -> Result<js_sys::Function> {
    use wasm_bindgen::JsCast;
    js_sys::Reflect::get(obj, &wasm_bindgen::JsValue::from_str(name))
        .map_err(|e| anyhow::anyhow!("missing JS method {name}: {e:?}"))?
        .dyn_into::<js_sys::Function>()
        .map_err(|e| anyhow::anyhow!("JS {name} is not a function: {e:?}"))
}

/// Coerce a JS call result into a `Promise`, tagging errors with `key`/`op`.
fn js_promise(
    result: std::result::Result<wasm_bindgen::JsValue, wasm_bindgen::JsValue>,
    key: &str,
    op: &str,
) -> Result<js_sys::Promise> {
    use wasm_bindgen::JsCast;
    result
        .map_err(|e| anyhow::anyhow!("R2 {op} {key}: call: {e:?}"))?
        .dyn_into::<js_sys::Promise>()
        .map_err(|e| anyhow::anyhow!("R2 {op} {key}: did not return a promise: {e:?}"))
}

/// A [`SurfaceWrite`] writing one resource's surface to an external
/// S3-compatible origin via per-object signed URLs.
///
/// The external-binding counterpart of [`R2Write`]: each operation mints a
/// short-lived presigned `PUT`/`DELETE` URL with [`S3Surface::object_url`] and
/// drives it over the Workers global Fetch API. A `DELETE` is idempotent — a
/// `404`/`204` (absent key) is treated as success — matching the R2 path's
/// no-op delete.
struct S3Write {
    surface: S3Surface,
}

#[async_trait(?Send)]
impl SurfaceWrite for S3Write {
    async fn write(&self, path: &str, bytes: &[u8]) -> Result<()> {
        use worker::{Fetch, Method, Request, RequestInit};

        let now = aos_hub_core::clock::now_unix_secs();
        let url = self.surface.object_url(S3Method::Put, path, now)?;
        let body: worker::wasm_bindgen::JsValue = js_sys::Uint8Array::from(bytes).into();
        let mut init = RequestInit::new();
        init.with_method(Method::Put).with_body(Some(body));
        let request = Request::new_with_init(&url, &init)
            .map_err(|err| anyhow::anyhow!("s3 build PUT request: {err}"))?;
        let response = Fetch::Request(request)
            .send()
            .await
            .map_err(|err| anyhow::anyhow!("s3 PUT {}: {err}", self.surface.describe()))?;
        let status = response.status_code();
        if !(200..300).contains(&status) {
            anyhow::bail!("s3 PUT {}: status {status}", self.surface.describe());
        }
        Ok(())
    }

    async fn delete(&self, path: &str) -> Result<()> {
        use worker::{Fetch, Method, Request, RequestInit};

        let now = aos_hub_core::clock::now_unix_secs();
        let url = self.surface.object_url(S3Method::Delete, path, now)?;
        let mut init = RequestInit::new();
        init.with_method(Method::Delete);
        let request = Request::new_with_init(&url, &init)
            .map_err(|err| anyhow::anyhow!("s3 build DELETE request: {err}"))?;
        let response = Fetch::Request(request)
            .send()
            .await
            .map_err(|err| anyhow::anyhow!("s3 DELETE {}: {err}", self.surface.describe()))?;
        let status = response.status_code();
        // Idempotent: deleting an absent object (404) succeeds, as does a 204
        // No Content or any other 2xx the origin returns.
        if status == 404 || (200..300).contains(&status) {
            return Ok(());
        }
        anyhow::bail!("s3 DELETE {}: status {status}", self.surface.describe());
    }
}
