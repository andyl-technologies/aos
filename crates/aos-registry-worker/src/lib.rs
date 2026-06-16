//! The Cloudflare Workers read-path target for the AOS registry hub (RFC-0004).
//!
//! RFC-0004 specifies a Cloudflare Workers deployment of the registry hub —
//! `wasm32-unknown-unknown` via `workers-rs`, with D1 as the sqlite backend, R2
//! as a zero-egress facade, KV for sessions, and Cron Triggers driving the
//! indexer ("Architecture and runtime targets"). The native hub is a sync
//! axum + tokio + rusqlite binary that cannot compile to wasm32, so this is a
//! **separate Worker crate** implementing the RFC's phase-1 Cloudflare
//! deployment: **read the index + serve the facade**. It deliberately reuses
//! the pure, shared crates rather than porting the native hub:
//!
//! - [`aos_registry_surface`] — the wasm-clean reader (objects, tags, refs,
//!   Ed25519 verification) the native hub indexer and `apm` already run, reused
//!   verbatim in the Cron indexer ([`indexer`]).
//! - [`aos_registry_core`] — the shared `Database` (schema `MIGRATIONS` + read
//!   queries) the native hub runs, driven over the D1 [`d1backend`] so the
//!   Worker's read path and indexer cannot drift from the hub's.
//! - The native hub's facade classification — [`keymap`] is a faithful copy of
//!   `compat::{is_machine_path, cache_control, content_type}`.
//!
//! # What is and isn't here (yet)
//!
//! This crate is mid-migration to **full native parity** (RFC-0004 Phase 5,
//! `docs/rfcs/0004-registry-hub/10-unified-runtime.md`). The data layer is
//! shared with the native hub (`aos_registry_core::Database` over the D1
//! [`d1backend`]), and the **entire `aos.registry.v1` RPC surface is now served
//! by the *same* shared Connect-JSON `axum` router the native hub mounts**
//! ([`aos_registry_core::connect::router`]) — bridged to the Workers runtime by
//! [`bridge`] over the Worker's [`RpcService`](aos_registry_core::service)
//! (D1 backend, R2 [`surface`] provider, D1-backed [`workerlimit`]). So the
//! write/publish path, authentication (tokens/sessions/SSO/device-flow),
//! private-registry access control, and IAM/config/webhook/publish RPCs all run
//! here, single-sourced with the native hub. The `connectrpc` server runtime
//! cannot target wasm, which is why the transport is **Connect-JSON** (plain
//! JSON over HTTP — `POST /aos.registry.v1.{Service}/{Method}`) over ordinary
//! `axum` handlers, with no `connectrpc` runtime on the registry path.
//!
//! Still worker-local (not yet lifted into `core`): the R2 machine facade
//! ([`facade`]), the D1-backed browse UI ([`render`]) and simple-JSON read API
//! ([`handlers`]), and the Cron-trigger indexer ([`indexer`]). The `fetch`
//! handler routes `/aos.registry.v1.*` to the shared router and everything else
//! to this read path; moving the facade + browse into the shared router (so this
//! crate's read handlers also delete) is the remaining Phase 5 step. The
//! producer console likewise awaits its move into `core`. See `README.md` and
//! the RFC.
//!
//! # Module map
//!
//! Pure, native-testable (compile on every target):
//!
//! - [`keymap`] — R2 key mapping and the facade cache/content classification.
//! - [`model`] — serde data models shared by the D1 layer, JSON API, and
//!   renderer.
//! - [`render`] — the no-JS HTML browse pages.
//! - [`indexlogic`] — the Cron indexer's pure verification decisions (partition
//!   target checks, channel anti-rollback floors, href-scheme safety), factored
//!   out of the wasm-only [`indexer`] so they are unit-tested natively against
//!   the same rules the native hub indexer enforces.
//!
//! Worker glue (wasm32-only, gated behind `#[cfg(target_arch = "wasm32")]`):
//!
//! - `d1backend` — the [`aos_registry_core::backend::Backend`] over D1.
//! - `reads` — the read access layer driving `core::Database` over `d1backend`,
//!   projecting onto the [`model`] types the renderer and JSON API consume.
//! - `facade` — the R2 machine-path facade handler.
//! - `handlers` — the read-path `fetch` request dispatch.
//! - `indexer` — the Cron-trigger indexer over R2 + D1.
//! - `bridge` — the hand-rolled `worker`⇄`axum` bridge that runs the shared
//!   Connect-JSON router for the RPC surface (no `axum-cloudflare-adapter`).
//! - `surface` — the R2-backed [`aos_registry_core::fetch::SurfaceProvider`]
//!   the shared git/facade read logic uses.
//! - `workerlimit` — the D1-backed [`aos_registry_core::ratelimit::RateLimiter`].
//!
//! # Build and deploy
//!
//! ```text
//! cargo build -p aos-registry-worker --target wasm32-unknown-unknown   # compile check
//! wrangler deploy                                                       # deploy (needs an account)
//! ```
//!
//! The native workspace build only compiles the pure modules; the Worker glue
//! is wasm-only, exactly like the sibling `aos-registry-spa` crate, so adding
//! this crate to the workspace members never breaks the native build.

pub mod indexlogic;
pub mod keymap;
pub mod model;
pub mod render;

#[cfg(target_arch = "wasm32")]
pub mod bridge;
#[cfg(target_arch = "wasm32")]
pub mod d1backend;
#[cfg(target_arch = "wasm32")]
pub mod facade;
#[cfg(target_arch = "wasm32")]
pub mod handlers;
#[cfg(target_arch = "wasm32")]
pub mod indexer;
#[cfg(target_arch = "wasm32")]
pub mod reads;
#[cfg(target_arch = "wasm32")]
pub mod surface;
#[cfg(target_arch = "wasm32")]
pub mod workerlimit;

#[cfg(target_arch = "wasm32")]
mod entry {
    //! The Workers runtime entry points: the `fetch` and `scheduled` handlers.
    //!
    //! The `fetch` handler dispatches by path. The `aos.registry.v1.*` RPC
    //! surface (RFC-0004 Phase 5 step 4e) is served by the **same** shared
    //! Connect-JSON `axum` router the native hub mounts
    //! ([`aos_registry_core::connect::router`]), built per request over the
    //! Worker's D1/R2 bindings ([`service_from`]) and bridged to the Workers
    //! runtime by [`crate::bridge`]. Every other path keeps the existing read
    //! path ([`crate::handlers::handle`]): the R2 facade, the browse UI, and the
    //! JSON read API.

    use std::sync::Arc;

    use worker::{Context, Env, Request, Response, Result, ScheduleContext, ScheduledEvent};

    use aos_registry_core::auth::jwt::JwtKeys;
    use aos_registry_core::db::Database;
    use aos_registry_core::service::RpcService;

    /// The route prefix that selects the shared RPC router.
    ///
    /// Every Connect-JSON method is `POST /aos.registry.v1.{Service}/{Method}`,
    /// so a path with this prefix is dispatched to the shared router; anything
    /// else falls through to the read path.
    const RPC_PREFIX: &str = "/aos.registry.v1.";

    /// The Wrangler secret holding the HS256 JWT signing secret.
    const HUB_JWT_SECRET: &str = "HUB_JWT_SECRET";
    /// The Wrangler `[vars]` entry holding the hub's externally-reachable URL.
    const HUB_EXTERNAL_URL: &str = "HUB_EXTERNAL_URL";

    /// Construct the shared [`RpcService`] over the Worker's D1/R2 bindings.
    ///
    /// Attaches a non-migrating [`Database`] over the D1 [`crate::d1backend`]
    /// (the schema is applied once via `GET /_init`), reads the JWT secret and
    /// external URL from the Wrangler secret/var, and wires the Worker's
    /// D1-backed rate limiter ([`crate::workerlimit`]) and R2-backed surface
    /// provider ([`crate::surface`]).
    ///
    /// # Errors
    ///
    /// Returns an error if a binding is missing, the `HUB_JWT_SECRET` secret or
    /// `HUB_EXTERNAL_URL` var is absent, or the rate-limiter table cannot be
    /// ensured.
    async fn service_from(env: &Env) -> Result<Arc<RpcService>> {
        let db = Arc::new(Database::attach(Box::new(crate::d1backend::D1Backend::new(
            env.d1(crate::handlers::bindings::D1)?,
        ))));

        let secret = env.secret(HUB_JWT_SECRET)?.to_string();
        if secret.is_empty() {
            return Err(worker::Error::RustError(format!(
                "{HUB_JWT_SECRET} secret is empty; set it with `wrangler secret put {HUB_JWT_SECRET}`"
            )));
        }
        let jwt_keys = JwtKeys::from_secret(secret.as_bytes());

        let external_url = env.var(HUB_EXTERNAL_URL)?.to_string();

        // The limiter drives its own D1 counter table over a second D1 backend
        // handle (the binding is cheap to re-resolve and D1 handles are owned).
        let ratelimit = crate::workerlimit::D1RateLimiter::create(crate::d1backend::D1Backend::new(
            env.d1(crate::handlers::bindings::D1)?,
        ))
        .await
        .map_err(|err| worker::Error::RustError(format!("rate limiter init: {err:#}")))?;

        let surface =
            crate::surface::R2SurfaceProvider::new(env.bucket(crate::handlers::bindings::R2)?);

        Ok(Arc::new(RpcService::new(
            db,
            jwt_keys,
            external_url,
            Arc::new(ratelimit),
            Arc::new(surface),
        )))
    }

    /// The HTTP entry point: the shared RPC router or the read path.
    ///
    /// A request whose path begins with [`RPC_PREFIX`] is dispatched through the
    /// shared Connect-JSON router (full write/auth/RPC parity with the native
    /// hub); everything else delegates to [`crate::handlers::handle`] (facade,
    /// browse UI, JSON read API). A handler error is logged and returned as a
    /// `500` so a binding/back-end failure never panics the isolate.
    #[worker::event(fetch, respond_with_errors)]
    async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
        // Peek the path without consuming the body (`url()` borrows `&self`).
        let is_rpc = req
            .url()
            .map(|url| url.path().starts_with(RPC_PREFIX))
            .unwrap_or(false);

        if is_rpc {
            let service = service_from(&env).await?;
            let router = aos_registry_core::connect::router(service);
            return crate::bridge::dispatch(router, req).await;
        }

        crate::handlers::handle(req, env).await
    }

    /// The Cron-triggered indexer: re-walk every public registry's R2 surface
    /// into D1, reusing the pure verifier.
    ///
    /// Bound to a Cron schedule in `wrangler.toml`; mirrors the native hub's
    /// scheduled re-index. Failures of an individual registry are logged and do
    /// not abort the run (see [`crate::indexer::index_all`]).
    #[worker::event(scheduled)]
    async fn scheduled(_event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
        let db = match env.d1(crate::handlers::bindings::D1) {
            Ok(db) => db,
            Err(err) => {
                worker::console_error!("scheduled: D1 binding missing: {err}");
                return;
            }
        };
        let bucket = match env.bucket(crate::handlers::bindings::R2) {
            Ok(bucket) => bucket,
            Err(err) => {
                worker::console_error!("scheduled: R2 binding missing: {err}");
                return;
            }
        };
        // Drive the indexer's D1 access through the shared D1Backend (f64 binds,
        // NULL-tolerant reads), the same engine the read path uses.
        let backend = crate::d1backend::D1Backend::new(db);
        if let Err(err) = crate::indexer::index_all(&backend, &bucket).await {
            worker::console_error!("scheduled index failed: {err:#}");
        }
    }
}
