//! The R2-backed machine-path facade (wasm32-only).
//!
//! Serves a registry's machine surface — `HEAD`, `info/refs`, `objects/**`,
//! `channels/**`, `releases/**`, `nix-cache-info`, `*.narinfo`, `nar/**`, and
//! the `web/`/`browse/` files — straight from the hub's R2 bucket binding. R2
//! native bindings give a **zero-egress facade** (RFC-0004 "R2 via native
//! bindings gives a zero-egress facade, which is why R2 is the flagship
//! deployment"): the Worker reads the object in-process and streams it back, so
//! the bytes never leave Cloudflare's edge and never transit a billed egress
//! path.
//!
//! Each response carries the per-object `Cache-Control` and `Content-Type` from
//! the pure [`crate::keymap`] classification — the same immutable/60-second
//! split `apr origin upload` writes — so the surface is byte-and-header
//! faithful to what `apm`, stock git, and Nix expect. A miss is a plain `404`.

use worker::{Headers, Response, Result};

use crate::keymap;
use crate::model::Registry;

/// Serve one machine path for a registry from the R2 bucket.
///
/// The object key is `{registry.prefix}{path}` ([`keymap::r2_key`]); on a hit
/// the body is returned with the path's cache class and content type, on a miss
/// a `404`. Returns `404` for any non-machine path (the human `/-/` namespace
/// and unknown paths are handled by the router, not the facade).
///
/// # Errors
///
/// Returns an error if R2 access fails or a response header cannot be built;
/// the caller maps that to a `502`/`500`.
pub async fn serve(bucket: &worker::Bucket, registry: &Registry, path: &str) -> Result<Response> {
    if !keymap::is_machine_path(path) {
        return Response::error("Not Found", 404);
    }

    let key = keymap::r2_key(&registry.prefix, path);
    let object = bucket.get(&key).execute().await?;
    let Some(object) = object else {
        return Response::error("Not Found", 404);
    };
    let Some(body) = object.body() else {
        // A zero-length object (legal for some pointers) has no body stream.
        return empty_response(path);
    };

    let bytes = body.bytes().await?;
    let headers = machine_headers(path)?;
    Ok(Response::from_bytes(bytes)?.with_headers(headers))
}

/// Build the `Content-Type`/`Cache-Control` headers for a machine path.
fn machine_headers(path: &str) -> Result<Headers> {
    let mut headers = Headers::new();
    headers.set("content-type", keymap::content_type(path))?;
    headers.set("cache-control", keymap::cache_control(path))?;
    Ok(headers)
}

/// An empty (zero-byte) body with the path's machine headers.
fn empty_response(path: &str) -> Result<Response> {
    let headers = machine_headers(path)?;
    Ok(Response::from_bytes(Vec::new())?.with_headers(headers))
}
