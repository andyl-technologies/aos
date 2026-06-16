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
//! - The native hub's sqlite-dialect SQL — D1 *is* sqlite, so the schema and
//!   read queries ([`sql`]) are the native strings unchanged.
//! - The native hub's facade classification — [`keymap`] is a faithful copy of
//!   `compat::{is_machine_path, cache_control, content_type}`.
//!
//! # What is and isn't here
//!
//! Ported (the read path): the R2 machine facade ([`facade`]), the D1-backed
//! browse UI ([`render`]) and JSON read API ([`handlers`]), and the
//! Cron-trigger indexer ([`indexer`]). **Not ported** (native-only for now):
//! the write/publish path, the producer console, all authentication
//! (tokens/sessions/SSO/device-flow), private-registry access control, and full
//! `aos.registry.v1` Connect framing. The Worker serves `public` registries
//! anonymously; the JSON API is a simple JSON shape, not a Connect envelope.
//! See `README.md` for the full deferred list and the deploy/validate gap.
//!
//! # Module map
//!
//! Pure, native-testable (compile on every target):
//!
//! - [`sql`] — the D1 schema and read queries, validated offline against a real
//!   sqlite engine.
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
//! - `handlers` — the `fetch` request dispatch.
//! - `indexer` — the Cron-trigger indexer over R2 + D1.
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
pub mod sql;

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
mod entry {
    //! The Workers runtime entry points: the `fetch` and `scheduled` handlers.

    use worker::{Context, Env, Request, Response, Result, ScheduleContext, ScheduledEvent};

    /// The HTTP read path: facade, browse UI, and JSON API.
    ///
    /// Delegates to [`crate::handlers::handle`]; a handler error is logged and
    /// returned as a `500` so a binding/back-end failure never panics the
    /// isolate.
    #[worker::event(fetch, respond_with_errors)]
    async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
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
