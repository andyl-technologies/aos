//! The machine-path *write* facade: authenticated surface uploads.
//!
//! This is the upload half of the byte-faithful facade
//! ([`crate::compat`] serves reads). A managed registry's on-disk surface
//! is published by writing each relative file path of the static origin
//! under the registry's canonical URL, exactly as `apr origin upload` and
//! `apr cache generate --upload-url` already write to any generic binary
//! cache. The hub is therefore a drop-in upload target — *"like magic"* —
//! requiring no client changes.
//!
//! # Discovered upload wire protocol
//!
//! The producer CLIs upload a registry surface through
//! `aos_cache::backend::CacheBackend::put_static_file`
//! (`crates/aos-package/src/registry/static_upload.rs`). For an HTTP(S)
//! destination this lands in [`aos_cache::backend::http::HttpBackend`],
//! which has **two modes** selected by whether an AOS provisioning token
//! was supplied:
//!
//! - **AOS mode** (`--token aos_…`, sets `is_aos = true`): the token is
//!   exchanged for a JWT at `/oauth2/token`, and `put_static_file`
//!   *bails out* — `"generic static-file upload is not supported by the
//!   AOS server API"`. The AOS server API (`/query-missing`,
//!   `/upload-pack`, `PUT /{view}/store/{hash}`) is a NAR-import protocol,
//!   **not** a static-file surface protocol. ORIGIN/static upload does not
//!   use it.
//! - **Generic mode** (no `--token`; a Bearer is instead carried in
//!   `--header "Authorization: Bearer <jwt>"`, so `is_aos = false`): each
//!   file is a single request:
//!
//!   ```text
//!   PUT  {base_url}/{relative_path}
//!   Authorization: Bearer <jwt>          (from --header, attached to every request)
//!   Content-Type:  <per-file>            (text/x-nix-narinfo, application/zstd, …)
//!   Cache-Control: <per-file>            (immutable for objects/NARs, revalidate for pointers)
//!   <file bytes as the body>
//!
//!   HEAD {base_url}/{relative_path}      (query_missing in generic mode probes existence)
//!   ```
//!
//!   A `2xx` is success; a `>= 400` status is an upload failure.
//!
//! So the *minimal* set of endpoints the hub must expose for an
//! origin/static upload to `http://hub/{canonical-registry-path}` to
//! succeed is: an **authenticated `PUT`** of every relative surface path
//! (`HEAD`, `info/refs`, `objects/**`, `releases/**`, `channels/**`,
//! `nix-cache-info`, `*.narinfo`, `nar/**`), plus an optional `HEAD` so an
//! uploader can skip files it has already pushed. The hub does **not**
//! implement `/query-missing` or `/upload-pack` for the static surface:
//! the investigation confirms origin upload never reaches them (they are
//! `is_aos`-only, and the static surface is not a NAR-import surface).
//!
//! The uploader thus authenticates with a JWT (the same HS256 access
//! token [`crate::auth::jwt`] mints), obtained either directly or by
//! exchanging a provisioning secret at `/oauth2/token` and then passing
//! the result through `--header`. The facade requires
//! [`Permission::Publish`] on the registry's canonical [`Scope`].
//!
//! # Publish lease
//!
//! Writes within one publish pipeline land immutable-first (objects, NARs)
//! and then flip mutable pointers (`HEAD`, `info/refs`, `channels/**`,
//! `nix-cache-info`). To keep two concurrent publishers from interleaving
//! their pointer flips, the first mutable-pointer write of a pipeline
//! acquires an in-memory, per-registry [`PublishLease`] held by the
//! writing token. While the lease is held and unexpired, a *different*
//! token's mutable-pointer write is rejected `409 Conflict`; immutable
//! object writes never need the lease. The invariant: **only the lease
//! holder flips a registry's pointers** for the lease's lifetime. The
//! lease is process-local (phase 1/2 is single-process); a cross-process
//! lease is a later phase.
//!
//! # Index-after-flip
//!
//! A successful mutable-pointer write re-indexes the registry from its
//! binding root (a [`crate::fetch::LocalFsFetch`] over
//! [`crate::db::Database::registry_surface_root`]), so a publish becomes
//! visible on the browse pages and read facade without an external poll.
//! Re-index runs inline for the pointers that complete a publish
//! (`info/refs`, `nix-cache-info`) so a caller — or a test — observes a
//! consistent index the moment the final pointer write returns `200`.

use std::collections::HashMap;
use std::sync::Mutex;

use axum::body::Bytes;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::db::RegistryRecord;
use crate::domain::{Permission, Scope};
use crate::fetch::{safe_join, LocalFsFetch};
use crate::server::AppState;

/// Maximum surface-file upload size accepted by a single `PUT` (256 MiB).
///
/// Generously sized for release packs while still bounding a single
/// request; a body past this cap is rejected `413 Payload Too Large`.
pub const MAX_UPLOAD_BYTES: usize = 256 * 1024 * 1024;

/// Grace period, in seconds, after which an idle [`PublishLease`] expires
/// and another token may take it.
///
/// A publish pipeline holds the lease only as long as it is actively
/// writing pointers; this bounds how long a crashed or abandoned
/// publisher can block another from flipping the same registry's
/// pointers.
pub const LEASE_TTL_SECS: i64 = 300;

/// One registry's in-memory publish lease.
///
/// Held by the token that first flips a mutable pointer in a publish
/// pipeline; a different token's mutable write is blocked until the lease
/// expires (see [`LEASE_TTL_SECS`]).
#[derive(Debug, Clone)]
pub struct PublishLease {
    /// The `sub` (token id) of the JWT that holds the lease.
    holder_token_id: String,
    /// Unix time after which the lease is considered abandoned.
    deadline: i64,
}

/// Process-local map of `registry_id -> `[`PublishLease`].
///
/// Lives in [`AppState`]; guarded by a `Mutex` because publish writes are
/// rare and short. A multi-process deployment needs a shared lease store,
/// noted as a later phase in the [module docs](self).
#[derive(Debug, Default)]
pub struct LeaseMap {
    leases: Mutex<HashMap<i64, PublishLease>>,
}

impl LeaseMap {
    /// Builds an empty lease map.
    #[must_use]
    pub fn new() -> LeaseMap {
        LeaseMap::default()
    }

    /// Acquire or refresh the lease for `registry_id` on behalf of
    /// `token_id`, or report the conflicting holder.
    ///
    /// Returns `Ok(())` when `token_id` already holds the lease (the
    /// deadline is refreshed) or no live lease exists (a new one is
    /// taken). Returns `Err(holder)` with the conflicting token id when a
    /// *different* token holds an unexpired lease.
    fn acquire(&self, registry_id: i64, token_id: &str, now: i64) -> Result<(), String> {
        let mut leases = self.leases.lock().unwrap_or_else(|p| p.into_inner());
        match leases.get(&registry_id) {
            Some(lease) if lease.deadline > now && lease.holder_token_id != token_id => {
                Err(lease.holder_token_id.clone())
            }
            _ => {
                leases.insert(
                    registry_id,
                    PublishLease {
                        holder_token_id: token_id.to_string(),
                        deadline: now + LEASE_TTL_SECS,
                    },
                );
                Ok(())
            }
        }
    }
}

/// Whether a surface-relative path is a *mutable pointer* (vs. an
/// immutable content-addressed object).
///
/// Mirrors the producer's classification
/// (`StaticOriginClass` in `static_upload.rs` and
/// [`crate::compat::cache_control`]): `HEAD`, `info/refs`,
/// `objects/info/**`, `channels/**`, and `nix-cache-info` are pointers
/// rewritten on each publish; everything else (loose objects, release
/// packs, narinfos, NARs) is content-addressed and immutable. Only
/// pointer writes take the publish lease and trigger a re-index.
fn is_mutable_pointer(path: &str) -> bool {
    path == "HEAD"
        || path == "info/refs"
        || path == "nix-cache-info"
        || path.starts_with("objects/info/")
        || path.starts_with("channels/")
}

/// Whether a successful write of `path` should trigger a re-index.
///
/// The two pointers that *complete* a publish — `info/refs` (the git
/// surface) and `nix-cache-info` (the cache surface) — drive a re-index;
/// they are written last in the producer's phase-major order, so by the
/// time they land the objects they reference are already present. The
/// re-index runs inline so the index is consistent the instant the write
/// returns.
fn triggers_reindex(path: &str) -> bool {
    path == "info/refs" || path == "nix-cache-info"
}

/// Resolve a managed registry by slug, requiring it be writable (have a
/// storage binding root), or return the denial response.
///
/// Phase-1 unowned `file://`/`http` registries have no storage binding and
/// are **not** writable through the facade — a `PUT` to one is
/// `405 Method Not Allowed` (the resource exists but the verb is
/// unsupported), and a missing slug is `404`.
fn resolve_writable(
    state: &AppState,
    slug: &str,
) -> Result<(RegistryRecord, std::path::PathBuf), Box<Response>> {
    let registry = match state.db.registry_by_slug(slug) {
        Ok(Some(registry)) => registry,
        Ok(None) => return Err(Box::new(StatusCode::NOT_FOUND.into_response())),
        Err(err) => return Err(Box::new(internal(err))),
    };
    // A managed registry has a storage binding; that is what makes it
    // writable. Unowned phase-1 registries (no binding) are read-only.
    if registry.storage_binding_id.is_none() {
        return Err(Box::new(
            (
                StatusCode::METHOD_NOT_ALLOWED,
                "registry has no storage binding; uploads are not supported",
            )
                .into_response(),
        ));
    }
    match state.db.registry_surface_root(registry.id) {
        Ok(Some(root)) => Ok((registry, root)),
        Ok(None) => Err(Box::new(
            (
                StatusCode::METHOD_NOT_ALLOWED,
                "registry surface is not locally writable",
            )
                .into_response(),
        )),
        Err(err) => Err(Box::new(internal(err))),
    }
}

/// Authorize a write: require a Bearer JWT granting [`Permission::Publish`]
/// on the registry's canonical scope, returning the token id on success.
///
/// `401` when the `Authorization: Bearer <jwt>` header is missing or the
/// JWT does not verify; `403` when it verifies but does not grant
/// `Publish` on the registry scope.
fn authorize_publish(
    state: &AppState,
    registry: &RegistryRecord,
    headers: &HeaderMap,
) -> Result<String, Box<Response>> {
    let value = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            Box::new((StatusCode::UNAUTHORIZED, "missing Authorization header").into_response())
        })?;
    let token = value.strip_prefix("Bearer ").ok_or_else(|| {
        Box::new(
            (
                StatusCode::UNAUTHORIZED,
                "Authorization header must start with Bearer",
            )
                .into_response(),
        )
    })?;
    let claims = state
        .auth
        .jwt_keys
        .verify(token)
        .map_err(|_| Box::new((StatusCode::UNAUTHORIZED, "invalid token").into_response()))?;
    let scope = Scope::parse(&registry.slug);
    if crate::auth::extract::token_allows(&claims, Permission::Publish, &scope) {
        Ok(claims.sub)
    } else {
        Err(Box::new(
            (StatusCode::FORBIDDEN, "insufficient permission").into_response(),
        ))
    }
}

/// Handle a `PUT` of one surface path for a managed registry.
///
/// Validates the path, authorizes [`Permission::Publish`], enforces the
/// publish lease for mutable pointers, writes the body atomically under
/// the binding root, and re-indexes inline when the write completes a
/// publish. Returns `201 Created` (new file) or `200 OK` (overwrite) with
/// a small `{"path": …}` JSON body.
///
/// # Errors
///
/// Surfaces, as the HTTP status: `401`/`403` on auth failure, `404`/`405`
/// for a missing or non-writable registry, `400` for a path that is not a
/// machine path or escapes the surface root, `409` when another token
/// holds the publish lease, `413` for an oversized body, and `500` on an
/// IO or database failure.
pub async fn put_machine_path(
    state: &AppState,
    slug: &str,
    path: &str,
    headers: &HeaderMap,
    body: Bytes,
) -> Response {
    let (registry, root) = match resolve_writable(state, slug) {
        Ok(pair) => pair,
        Err(deny) => return *deny,
    };
    let token_id = match authorize_publish(state, &registry, headers) {
        Ok(token_id) => token_id,
        Err(deny) => return *deny,
    };

    if !crate::compat::is_machine_path(path) {
        return (StatusCode::BAD_REQUEST, "not a machine path").into_response();
    }
    if body.len() > MAX_UPLOAD_BYTES {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }

    let mutable = is_mutable_pointer(path);
    if mutable {
        if let Err(holder) = state.leases.acquire(registry.id, &token_id, unix_now()) {
            tracing::warn!(
                slug = %registry.slug,
                %path,
                held_by = %holder,
                "publish lease conflict"
            );
            return (
                StatusCode::CONFLICT,
                "another publisher holds the registry publish lease",
            )
                .into_response();
        }
    }

    let target = match safe_join(&root, path) {
        Ok(target) => target,
        Err(_) => return (StatusCode::BAD_REQUEST, "unsafe surface path").into_response(),
    };
    let existed = target.exists();
    if let Err(err) = write_atomic(&target, &body).await {
        return internal(err);
    }

    // A pointer that completes a publish re-indexes inline so the index is
    // consistent the instant this write returns.
    if mutable && triggers_reindex(path) {
        if let Err(err) = reindex(state, &registry, &root).await {
            // The bytes landed; a failed re-index is logged, and the index
            // is marked stale/failed by `index_and_record`, but the upload
            // itself succeeded.
            tracing::warn!(
                slug = %registry.slug,
                error = %format!("{err:#}"),
                "re-index after pointer flip failed"
            );
        }
    }

    let status = if existed {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    (status, Json(serde_json::json!({ "path": path }))).into_response()
}

/// Handle a `HEAD` of one surface path for a managed registry.
///
/// Lets an uploader skip files it has already pushed: `200` when the file
/// exists, `404` when it does not. Authorization matches [`put_machine_path`]
/// (a probe reveals surface contents, so it requires `Publish`).
///
/// # Errors
///
/// Surfaces, as the HTTP status: `401`/`403` on auth failure, `404`/`405`
/// for a missing or non-writable registry, and `500` on a database failure.
pub async fn head_machine_path(
    state: &AppState,
    slug: &str,
    path: &str,
    headers: &HeaderMap,
) -> Response {
    let (registry, root) = match resolve_writable(state, slug) {
        Ok(pair) => pair,
        Err(deny) => return *deny,
    };
    if let Err(deny) = authorize_publish(state, &registry, headers) {
        return *deny;
    }
    if !crate::compat::is_machine_path(path) {
        return (StatusCode::BAD_REQUEST, "not a machine path").into_response();
    }
    match safe_join(&root, path) {
        Ok(target) if target.is_file() => StatusCode::OK.into_response(),
        Ok(_) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => (StatusCode::BAD_REQUEST, "unsafe surface path").into_response(),
    }
}

/// Re-index a managed registry from its binding root.
///
/// Managed registries index from their local surface, not an HTTP source,
/// so the fetcher is a [`LocalFsFetch`] over the resolved root rather than
/// the (empty) `source_url`.
async fn reindex(
    state: &AppState,
    registry: &RegistryRecord,
    root: &std::path::Path,
) -> anyhow::Result<()> {
    let fetch = LocalFsFetch::new(root);
    crate::indexer::index_and_record(&state.db, &fetch, registry).await?;
    Ok(())
}

/// Write `bytes` to `target` atomically: create the parent directory, write
/// to a sibling temp file, then rename over `target`.
///
/// The rename keeps a concurrent reader (the read facade, the indexer) from
/// ever observing a half-written file.
async fn write_atomic(target: &std::path::Path, bytes: &[u8]) -> anyhow::Result<()> {
    use anyhow::Context as _;
    if let Some(parent) = target.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let tmp = target.with_extension(format!("tmp-{}", uuid::Uuid::new_v4()));
    tokio::fs::write(&tmp, bytes)
        .await
        .with_context(|| format!("writing {}", tmp.display()))?;
    tokio::fs::rename(&tmp, target)
        .await
        .with_context(|| format!("renaming into {}", target.display()))?;
    Ok(())
}

/// Current Unix time in seconds.
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Map an internal error into a `500` with a terse body.
fn internal(err: anyhow::Error) -> Response {
    tracing::error!(error = %format!("{err:#}"), "facade write failed");
    (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_mutable_pointers() {
        for pointer in [
            "HEAD",
            "info/refs",
            "nix-cache-info",
            "objects/info/packs",
            "channels/stable/00",
        ] {
            assert!(is_mutable_pointer(pointer), "{pointer}");
        }
        for immutable in [
            "objects/ab/cd",
            "releases/1/0/0/objects/pack/p.pack",
            "abc123.narinfo",
            "nar/x.nar.zst",
        ] {
            assert!(!is_mutable_pointer(immutable), "{immutable}");
        }
    }

    #[test]
    fn only_completing_pointers_trigger_reindex() {
        assert!(triggers_reindex("info/refs"));
        assert!(triggers_reindex("nix-cache-info"));
        assert!(!triggers_reindex("HEAD"));
        assert!(!triggers_reindex("channels/stable/00"));
        assert!(!triggers_reindex("objects/ab/cd"));
    }

    #[test]
    fn lease_is_held_by_first_token_until_expiry() {
        let leases = LeaseMap::new();
        // First token takes the lease.
        assert!(leases.acquire(1, "token-a", 1000).is_ok());
        // Same token refreshes it.
        assert!(leases.acquire(1, "token-a", 1010).is_ok());
        // A different token is blocked while the lease is live.
        assert_eq!(leases.acquire(1, "token-b", 1020), Err("token-a".into()));
        // A different registry is independent.
        assert!(leases.acquire(2, "token-b", 1020).is_ok());
        // After the last refresh's deadline passes, the other token may
        // take it (the refresh at t=1010 set the deadline to 1010 + TTL).
        assert!(leases
            .acquire(1, "token-b", 1010 + LEASE_TTL_SECS + 1)
            .is_ok());
    }

    #[tokio::test]
    async fn write_atomic_creates_parents_and_file() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("objects/ab/cd");
        write_atomic(&target, b"payload").await.unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"payload");
        // No stray temp files remain beside it.
        let siblings: Vec<_> = std::fs::read_dir(target.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(siblings, vec!["cd".to_string()]);
    }
}
