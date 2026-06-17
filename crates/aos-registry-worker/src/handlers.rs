//! The worker-local `GET /_init` D1 schema setup (wasm32-only).
//!
//! Every request surface — the `aos.registry.v1` RPC methods, the machine-path
//! facade, and the no-JS browse UI + JSON read API — is served by the shared
//! router ([`aos_registry_core::connect::router`]) over
//! [`aos_registry_core::web`], single-sourced with the native hub. The only
//! path that stays worker-local is the one-shot schema bootstrap:
//!
//! ```text
//! /_init   apply the shared D1 schema + bootstrap the root admin (one-shot)
//! ```
//!
//! `_init` is also the Worker's **install-time root bootstrap** (RFC-0004's sole
//! non-API mutation path): when `HUB_ROOT_EMAIL` + `HUB_ROOT_PASSWORD` are
//! configured it creates that first credential idempotently via the shared
//! in-process DB calls, mirroring the native hub's `user set-password` install
//! step. The first user with a password logs in and creates orgs (becoming
//! their admin); everything after is API/WebUI only.
//!
//! This module also re-exports the Wrangler binding names ([`bindings`]) the
//! `fetch`/`scheduled` entry points, the README, and `wrangler.toml` agree on.

use worker::{Env, Response, Result};

/// Binding names the Worker expects in `wrangler.toml`.
const D1_BINDING: &str = "REGISTRY_DB";
const R2_BINDING: &str = "REGISTRY_BUCKET";

/// Apply the canonical D1 schema (a one-shot operational convenience).
///
/// This is the production schema-setup path: request `GET /_init` once after
/// `wrangler deploy` (there is no separate `wrangler d1 migrations` step — a
/// hand-maintained migration file would diverge from core's `MIGRATIONS`).
///
/// It runs the **shared** schema: constructing
/// [`aos_registry_core::db::Database`] over the [`D1Backend`](crate::d1backend::D1Backend)
/// applies the exact `MIGRATIONS` the native hub uses (RFC-0004 Phase 5 — the
/// Worker and the native hub share one `Database`), rather than a Worker-local
/// read-only schema subset.
///
/// After the schema, it runs the **install-time root bootstrap**
/// ([`bootstrap_root`]): when `HUB_ROOT_EMAIL` + `HUB_ROOT_PASSWORD` are
/// configured, the first admin credential is created idempotently. This is the
/// Worker's equivalent of the native hub's `user set-password` install step and
/// the only sanctioned non-API mutation.
///
/// # Errors
///
/// Returns an error if the D1 binding is missing, applying the migrations
/// fails, or the root bootstrap fails.
pub async fn init_schema(env: &Env) -> Result<Response> {
    use aos_registry_core::db::Database;

    let db_handle = env.d1(D1_BINDING)?;
    let db = Database::with_backend(Box::new(crate::d1backend::D1Backend::new(db_handle)))
        .await
        .map_err(|err| worker::Error::RustError(format!("applying D1 migrations: {err:#}")))?;

    let bootstrap = bootstrap_root(&db, env)
        .await
        .map_err(|err| worker::Error::RustError(format!("root bootstrap: {err:#}")))?;
    Response::ok(format!("schema applied{bootstrap}"))
}

/// Create the configured root admin credential, idempotently.
///
/// Reads `HUB_ROOT_EMAIL` (`[vars]`) and `HUB_ROOT_PASSWORD` (a secret). When
/// both are set and that user does not yet have a password, it creates the user
/// (if absent) and sets the password via the shared in-process DB calls
/// (`find_or_create_user` + `hash_password` + `set_user_password`) — the same
/// path the native hub's `user set-password` uses. It is idempotent: re-running
/// `_init` after the root exists is a no-op, so it never resets a password the
/// admin later changed. Returns a short status suffix for the `_init` response.
///
/// # Errors
///
/// Returns an error only if a DB call or the password hash fails.
async fn bootstrap_root(db: &aos_registry_core::db::Database, env: &Env) -> anyhow::Result<String> {
    let email = env
        .var("HUB_ROOT_EMAIL")
        .ok()
        .map(|v| v.to_string())
        .filter(|s| !s.is_empty());
    let Some(email) = email else {
        return Ok(String::new()); // not configured: schema-only init
    };
    let email = email.trim().to_lowercase();

    let password = env
        .secret("HUB_ROOT_PASSWORD")
        .ok()
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty());
    let Some(password) = password else {
        return Ok(format!(
            "; HUB_ROOT_EMAIL set but HUB_ROOT_PASSWORD missing — root '{email}' not created"
        ));
    };

    // Idempotent: `user_for_password` returns `Some` only when a password is
    // already set, so a re-run never overwrites it.
    if db.user_for_password(&email).await?.is_some() {
        return Ok(format!("; root '{email}' already provisioned"));
    }

    let user_id = db.find_or_create_user(&email).await?;
    let hash = aos_registry_core::auth::password::hash_password(&password)?;
    db.set_user_password(user_id, &hash).await?;
    Ok(format!("; root '{email}' provisioned (user id {user_id})"))
}

/// Re-export the binding names so the README/wrangler config and tests agree.
pub mod bindings {
    /// The D1 database binding name (`wrangler.toml` `[[d1_databases]]`).
    pub const D1: &str = super::D1_BINDING;
    /// The R2 bucket binding name (`wrangler.toml` `[[r2_buckets]]`).
    pub const R2: &str = super::R2_BINDING;
    /// The KV namespace binding name for sessions (`[[kv_namespaces]]`).
    pub const KV_SESSIONS: &str = "SESSIONS";
}
