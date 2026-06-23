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
//! - [`aos_hub_core`] — the shared `Database` (schema `MIGRATIONS` + read
//!   queries) the native hub runs, driven over the D1 [`d1backend`] so the
//!   Worker's read path and indexer cannot drift from the hub's.
//! - The native hub's facade classification — [`keymap`] is a faithful copy of
//!   `compat::{is_machine_path, cache_control, content_type}`.
//!
//! # What is and isn't here (yet)
//!
//! The data layer is shared with the native hub
//! (`aos_hub_core::Database` over the D1 [`d1backend`]), and the **entire
//! request surface is now served by the *same* shared `axum` router the native
//! hub's RPC path mounts** ([`aos_hub_core::connect::router`]) — bridged to
//! the Workers runtime by [`bridge`] over the Worker's
//! [`RpcService`](aos_hub_core::service) (D1 backend, R2 [`surface`]
//! provider, D1-backed [`workerlimit`]). One router serves three surfaces:
//!
//! - the `aos.registry.v1` RPC surface (`POST
//!   /aos.registry.v1.{Service}/{Method}`) — the write/publish path,
//!   authentication (tokens/sessions/SSO/device-flow), private-registry access
//!   control, and IAM/config/webhook/publish RPCs;
//! - the machine-path facade (`GET`/`HEAD` `/{slug}/{*path}`), delegating to
//!   [`aos_hub_core::service::RpcService::facade_fetch`] over the R2
//!   [`surface`] provider;
//! - the no-JS browse UI and JSON read API (the hub home `/`, the
//!   `/{slug}/-/…` pages, and `/{slug}/-/api/…`), served by
//!   [`aos_hub_core::web`] from the same `RpcService` read methods.
//!
//! All three are single-sourced with the native hub, so the Worker and the hub
//! cannot drift. The `connectrpc` server runtime cannot target wasm, which is
//! why the RPC transport is **Connect-JSON** (plain JSON over HTTP) over
//! ordinary `axum` handlers, with no `connectrpc` runtime on the registry path.
//!
//! The producer console (RFC-0004 Phase 5, console-dedup stage C) is served by
//! the same shared router too: the Worker builds a
//! [`ConsoleDeps`](aos_hub_core::web::console::ConsoleDeps) over its console
//! ports ([`consoleports`]) and merges
//! [`console_router`](aos_hub_core::web::console::console_router) onto the
//! RPC/facade/browse router, so the console runs identical code on both shells.
//! As of stage H3 that includes the git-backed config/change-request flow
//! (`/{slug}/-/settings/config`, `/{slug}/-/changes`): its base-commit reads go
//! through the R2 [`surface`] read provider and its draft-object writes through
//! the R2 [`surface::R2SurfaceWriteProvider`] write provider, so **every** flat
//! console route is mounted on the Worker. The only console code that stays
//! native is the hub's nested-canonical fallback for slugs with slashes.
//!
//! Worker-local: only the Cron-trigger indexer ([`indexer`]). The `fetch`
//! handler bridges every request to the shared router; there is no schema-init
//! endpoint — migrations are CLI-driven over D1 (`aos-hub init --target
//! d1:<name>`). See `README.md` and the RFC.
//!
//! # Module map
//!
//! Pure, native-testable (compile on every target):
//!
//! - [`keymap`] — R2 key mapping and the facade cache/content classification.
//!
//! The Cron indexer no longer carries a bespoke `Registry` row model or a
//! `indexlogic` rules module: it projects the core
//! [`RegistryRecord`](aos_hub_core::db::RegistryRecord) from D1 and runs the
//! shared [`aos_hub_core::indexer`] (the partition target checks, the
//! channel anti-rollback floor, and the snapshot write all live there now), so
//! the Worker's Cron index is byte-identical to the native hub's (RFC-0004
//! Phase 5).
//!
//! Worker glue (wasm32-only, gated behind `#[cfg(target_arch = "wasm32")]`):
//!
//! - `d1backend` — the [`aos_hub_core::backend::Backend`] over D1.
//! - `handlers` — the Wrangler binding names.
//! - `indexer` — the Cron-trigger indexer: lists public registries from D1 and
//!   runs the shared [`aos_hub_core::indexer`] over each registry's R2
//!   [`surface`] fetcher.
//! - `bridge` — the hand-rolled `worker`⇄`axum` bridge that runs the shared
//!   Connect-JSON router for the RPC surface (no `axum-cloudflare-adapter`).
//! - `surface` — the R2-backed [`aos_hub_core::fetch::SurfaceProvider`]
//!   the shared git/facade read logic uses.
//! - `workerlimit` — the D1-backed [`aos_hub_core::ratelimit::RateLimiter`].
//! - `consoleports` — the Worker's console ports: the logging mailer, the
//!   Fetch-API OIDC [`HttpClient`](aos_hub_core::web::console::ports::HttpClient),
//!   and the Cron-deferring [`Reindexer`](aos_hub_core::reindex::Reindexer)
//!   over which the shared
//!   [`advance_channel`](aos_hub_core::signing::advance_channel) signs a
//!   hosted-key channel advance onto the R2 surface.
//!
//! # Build and deploy
//!
//! ```text
//! cargo build -p aos-hub-worker --target wasm32-unknown-unknown   # compile check
//! wrangler deploy                                                       # deploy (needs an account)
//! ```
//!
//! The native workspace build only compiles the pure modules; the Worker glue
//! is wasm-only, exactly like the sibling `aos-registry-spa` crate, so adding
//! this crate to the workspace members never breaks the native build.

pub mod keymap;

#[cfg(target_arch = "wasm32")]
pub mod bridge;
#[cfg(target_arch = "wasm32")]
pub mod consoleports;
#[cfg(target_arch = "wasm32")]
pub mod d1backend;
#[cfg(target_arch = "wasm32")]
pub mod handlers;
#[cfg(target_arch = "wasm32")]
pub mod indexer;
#[cfg(target_arch = "wasm32")]
pub mod surface;
#[cfg(target_arch = "wasm32")]
pub mod tracinglog;
#[cfg(target_arch = "wasm32")]
pub mod workerlease;
#[cfg(target_arch = "wasm32")]
pub mod workerlimit;

#[cfg(target_arch = "wasm32")]
mod entry {
    //! The Workers runtime entry points: the `fetch` and `scheduled` handlers.
    //!
    //! The `fetch` handler bridges **every** request to the shared `axum` router
    //! ([`aos_hub_core::connect::router`]), built per request over the
    //! Worker's D1/R2 bindings ([`service_from`]) and bridged to the Workers
    //! runtime by [`crate::bridge`]. That one router serves the
    //! `aos.registry.v1.*` RPC surface, the machine-path facade, and the no-JS
    //! browse UI + JSON read API ([`aos_hub_core::web`]), all single-sourced
    //! with the native hub.

    use std::sync::Arc;

    use wasm_bindgen::JsCast;
    use worker::{Context, Env, Request, Response, Result, ScheduleContext, ScheduledEvent};

    use aos_hub_core::auth::jwt::JwtKeys;
    use aos_hub_core::db::Database;
    use aos_hub_core::ratelimit::RateLimiter;
    use aos_hub_core::service::RpcService;
    use aos_hub_core::web::console::{console_router, ConsoleDeps};
    use axum::Router;

    use crate::consoleports::{
        sealer_from_secret, WorkerHttpClient, WorkerMailer, WorkerReindexer,
    };

    /// The Wrangler secret holding the HS256 JWT signing secret.
    const HUB_JWT_SECRET: &str = "HUB_JWT_SECRET";
    /// The Wrangler secret holding the at-rest secret-sealing key.
    ///
    /// Hashed to a 256-bit AES-GCM instance key (see
    /// [`sealer_from_secret`](crate::consoleports::sealer_from_secret)); the
    /// console's OIDC token exchange unseals a tenant's client secret with it.
    const HUB_SEAL_KEY: &str = "HUB_SEAL_KEY";
    /// The Wrangler `[vars]` entry holding the hub's externally-reachable URL.
    const HUB_EXTERNAL_URL: &str = "HUB_EXTERNAL_URL";
    /// Optional `[vars]` entry: the email-relay endpoint magic links are
    /// `POST`ed to. Unset → [`WorkerMailer`] logs the link instead.
    const HUB_EMAIL_API_URL: &str = "HUB_EMAIL_API_URL";
    /// Optional secret: a `Bearer` token for the email relay above.
    const HUB_EMAIL_API_TOKEN: &str = "HUB_EMAIL_API_TOKEN";
    /// The Cloudflare Email Service binding name (`[[send_email]]`).
    ///
    /// Present only once the operator has onboarded a sender domain and deployed
    /// with the binding; when present (with [`HUB_EMAIL_FROM`]) the
    /// [`WorkerMailer`] sends through it, taking priority over the HTTP relay.
    const EMAIL_BINDING: &str = "EMAIL";
    /// Optional `[vars]` entry: the verified sender address the Email Service
    /// binding sends `from`. Required to use the [`EMAIL_BINDING`].
    const HUB_EMAIL_FROM: &str = "HUB_EMAIL_FROM";

    /// Build the shared `axum` router over the Worker's D1/R2 bindings.
    ///
    /// Constructs the runtime-neutral pieces once — a non-migrating [`Database`]
    /// over the D1 [`crate::d1backend`] (the schema is applied by the operator
    /// CLI, `aos-hub init --target d1:<name>`), the HS256 [`JwtKeys`],
    /// the external URL, and the D1-backed rate limiter
    /// ([`crate::workerlimit`]) — and wires them into **both** shared routers:
    ///
    /// - the RPC + facade + browse router built from the [`RpcService`]
    ///   ([`aos_hub_core::connect::router`]), over the R2 surface provider
    ///   ([`crate::surface`]);
    /// - the producer-console router ([`console_router`]) built from a
    ///   [`ConsoleDeps`], over the Worker's console ports
    ///   ([`crate::consoleports`]): the logging [`WorkerMailer`], the Fetch-API
    ///   [`WorkerHttpClient`], the inline [`WorkerReindexer`] (over which
    ///   a hosted-key channel advance runs the shared
    ///   [`advance_channel`](aos_hub_core::signing::advance_channel)), and
    ///   the shared AES-GCM sealer from `HUB_SEAL_KEY`.
    ///
    /// Both routers carry their own state, so they merge into one `Router<()>`
    /// exactly as the native hub composes them; the console's static paths win
    /// over the facade wildcard by static-over-dynamic precedence.
    ///
    /// # Errors
    ///
    /// `request_origin` (`scheme://host` of the incoming request) is the
    /// fallback canonical URL when `HUB_EXTERNAL_URL` is unset, so a deploy with
    /// no custom domain simply serves at — and emits links for — whatever domain
    /// the Worker is reached on (its `*.workers.dev` URL or a bound domain).
    ///
    /// # Errors
    ///
    /// Returns an error if a binding is missing, the `HUB_JWT_SECRET` or
    /// `HUB_SEAL_KEY` secret is absent or empty, or the rate-limiter table cannot
    /// be ensured.
    async fn router_from(
        env: &Env,
        request_origin: &str,
    ) -> Result<(Router, Arc<RpcService>, ConsoleDeps)> {
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

        // The canonical URL is `HUB_EXTERNAL_URL` when set, else the request's
        // own origin — so a no-custom-domain deploy "just works" at its
        // `*.workers.dev` URL with no configuration.
        let external_url = env
            .var(HUB_EXTERNAL_URL)
            .ok()
            .map(|v| v.to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| request_origin.to_string());

        let seal_secret = env.secret(HUB_SEAL_KEY)?.to_string();
        if seal_secret.is_empty() {
            return Err(worker::Error::RustError(format!(
                "{HUB_SEAL_KEY} secret is empty; set it with `wrangler secret put {HUB_SEAL_KEY}`"
            )));
        }
        let sealer = sealer_from_secret(&seal_secret)
            .map_err(|err| worker::Error::RustError(format!("seal key: {err:#}")))?;

        // Email delivery, in priority order (see `WorkerMailer`):
        //  1. the Cloudflare Email Service `EMAIL` binding + `HUB_EMAIL_FROM`,
        //  2. the `HUB_EMAIL_API_URL` HTTP relay (+ optional bearer),
        //  3. logging (dev/unconfigured).
        // The `EMAIL` binding has no workers-rs wrapper, so it is read as a raw
        // JS object via Reflect and handed to the mailer for the JS interop call.
        let email_binding = js_sys::Reflect::get(
            env.as_ref(),
            &wasm_bindgen::JsValue::from_str(EMAIL_BINDING),
        )
        .ok()
        .filter(|v| !v.is_undefined())
        .and_then(|v| v.dyn_into::<js_sys::Object>().ok());
        let email_from = env.var(HUB_EMAIL_FROM).ok().map(|v| v.to_string());
        let email_api_url = env.var(HUB_EMAIL_API_URL).ok().map(|v| v.to_string());
        let email_api_token = env.secret(HUB_EMAIL_API_TOKEN).ok().map(|s| s.to_string());

        // The limiter drives its own D1 counter table over a second D1 backend
        // handle (the binding is cheap to re-resolve and D1 handles are owned).
        let ratelimit: Arc<dyn RateLimiter> = Arc::new(
            crate::workerlimit::D1RateLimiter::create(crate::d1backend::D1Backend::new(
                env.d1(crate::handlers::bindings::D1)?,
            ))
            .await
            .map_err(|err| worker::Error::RustError(format!("rate limiter init: {err:#}")))?,
        );

        let surface: Arc<dyn aos_hub_core::fetch::SurfaceProvider> =
            Arc::new(crate::surface::R2SurfaceProvider::new(
                env.bucket(crate::handlers::bindings::R2)?,
                Arc::clone(&db),
                Arc::clone(&sealer),
            ));
        let surface_write: Arc<dyn aos_hub_core::surface_write::SurfaceWriteProvider> =
            Arc::new(crate::surface::R2SurfaceWriteProvider::new(
                env.bucket(crate::handlers::bindings::R2)?,
                Arc::clone(&db),
                Arc::clone(&sealer),
            ));

        // The cross-isolate publish lease and the inline reindexer back the
        // shared facade-write handler on the Worker. The lease lives in D1 (a
        // process-local lease cannot serialize across isolates); the reindexer
        // re-indexes the published registry inline (event-driven), so a publish
        // is browse-visible the instant its final pointer write returns. The
        // `*/15` Cron remains the backstop for non-publish surface changes.
        let lease: Arc<dyn aos_hub_core::lease::PublishLease> =
            Arc::new(crate::workerlease::D1PublishLease::new(
                crate::d1backend::D1Backend::new(env.d1(crate::handlers::bindings::D1)?),
            ));
        let reindexer: Arc<dyn aos_hub_core::reindex::Reindexer> = Arc::new(WorkerReindexer::new(
            env.bucket(crate::handlers::bindings::R2)?,
            Arc::clone(&db),
            Arc::clone(&sealer),
        ));

        let service = Arc::new(
            RpcService::new(
                Arc::clone(&db),
                jwt_keys.clone(),
                external_url.clone(),
                Arc::clone(&ratelimit),
                Arc::clone(&surface),
                Arc::clone(&surface_write),
                Arc::clone(&lease),
                Arc::clone(&reindexer),
                Some(Arc::clone(&sealer)),
            )
            .with_origin_fetch(Arc::new(crate::surface::WorkerOriginFetch)),
        );

        let console_deps = ConsoleDeps {
            db,
            jwt_keys,
            external_url,
            dev: false,
            ratelimit,
            mailer: Arc::new(WorkerMailer::new(
                email_binding,
                email_from,
                email_api_url,
                email_api_token,
            )),
            sealer,
            http: Arc::new(WorkerHttpClient),
            surface,
            surface_write,
            reindexer,
        };

        // The service is returned alongside the router so the bridge can run the
        // shared frontend domain-routing decision before dispatch (the Worker's
        // `!Send` services preclude the native `from_fn` middleware). The
        // `ConsoleDeps` are cloned out before being moved into `console_router`
        // so the bridge can also run the shared nested-canonical console
        // dispatcher (the console routes capture only a single-segment slug, so
        // a nested registry's `/-/` pages need the explicit dispatcher).
        let router = aos_hub_core::connect::router(Arc::clone(&service))
            .merge(console_router(console_deps.clone()));
        Ok((router, service, console_deps))
    }

    /// The HTTP entry point: bridge every request to the shared router.
    ///
    /// The shared router ([`aos_hub_core::connect::router`]) owns the
    /// entire request surface — the `aos.registry.v1` RPC methods, the
    /// machine-path facade (`GET`/`HEAD` `/{slug}/{*path}`), and the no-JS
    /// browse UI + JSON read API (the hub home `/` and the `/{slug}/-/…` pages),
    /// all single-sourced with the native hub. The [`crate::surface`]
    /// `SurfaceProvider` backs the facade and the `GitService` reads, and the
    /// shared [`aos_hub_core::web`] browse reads the same `RpcService` read
    /// methods. There is no schema-init endpoint: migrations and root bootstrap
    /// are applied by the authenticated operator's CLI over D1 (`aos-hub
    /// init --target d1:<name>`), never over HTTP. A handler error is logged and
    /// returned as a `500` so a binding/back-end failure never panics the isolate.
    #[worker::event(fetch, respond_with_errors)]
    async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
        // Route the shared core's `tracing` events to the console so handler
        // errors land in Workers Logs (idempotent; see `crate::tracinglog`).
        crate::tracinglog::init();
        // The request's own `scheme://host`, the fallback canonical URL when
        // `HUB_EXTERNAL_URL` is unset (a no-custom-domain deploy).
        let request_origin = req
            .url()
            .ok()
            .map(|u| {
                let scheme = u.scheme();
                match (u.host_str(), u.port()) {
                    (Some(host), Some(port)) => format!("{scheme}://{host}:{port}"),
                    (Some(host), None) => format!("{scheme}://{host}"),
                    (None, _) => String::new(),
                }
            })
            .unwrap_or_default();
        let (router, service, console_deps) = router_from(&env, &request_origin).await?;
        crate::bridge::dispatch(router, &service, console_deps, req).await
    }

    /// The Cron-triggered indexer: re-walk every public registry's R2 surface
    /// into D1, reusing the pure verifier.
    ///
    /// Bound to a Cron schedule in `wrangler.toml`; mirrors the native hub's
    /// scheduled re-index. Failures of an individual registry are logged and do
    /// not abort the run (see [`crate::indexer::index_all`]).
    #[worker::event(scheduled)]
    async fn scheduled(_event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
        crate::tracinglog::init();
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
        // The AES-GCM sealer (from `HUB_SEAL_KEY`) unseals an external S3/R2
        // storage binding's credentials, so the Cron indexer/GC can read and
        // write managed surfaces hosted off the hub R2 bucket — the same sealer
        // the request path builds.
        let sealer = match env
            .secret(HUB_SEAL_KEY)
            .map_err(|err| format!("{err}"))
            .and_then(|s| sealer_from_secret(&s.to_string()).map_err(|err| format!("{err:#}")))
        {
            Ok(sealer) => sealer,
            Err(err) => {
                worker::console_error!("scheduled: {HUB_SEAL_KEY} unavailable: {err}");
                return;
            }
        };
        // Drive the indexer's D1 access through the shared D1Backend (f64 binds,
        // NULL-tolerant reads), the same engine the read path uses; the surface
        // read goes through the R2-backed SurfaceProvider.
        let backend = crate::d1backend::D1Backend::new(db);
        if let Err(err) =
            crate::indexer::index_all(backend, bucket, Arc::clone(&sealer)).await
        {
            worker::console_error!("scheduled index failed: {err:#}");
        }

        // Then a cache re-scan over fresh handles: reconcile each cache's D1
        // index against its surface (the source of truth), healing drift from
        // direct presigned uploads that bypassed the facade write-through. Cheap
        // in steady state (one `list` per cache, no object reads).
        if let (Ok(rs_db), Ok(rs_bucket)) = (
            env.d1(crate::handlers::bindings::D1),
            env.bucket(crate::handlers::bindings::R2),
        ) {
            let rs_backend = crate::d1backend::D1Backend::new(rs_db);
            if let Err(err) =
                crate::indexer::rescan_all(rs_backend, rs_bucket, Arc::clone(&sealer)).await
            {
                worker::console_error!("scheduled cache rescan failed: {err:#}");
            }
        } else {
            worker::console_error!("scheduled rescan: D1/R2 binding missing");
        }

        // Then a cache-GC pass over the same D1+R2, the Cron counterpart to the
        // native `aos-hub cache gc`. Fresh binding handles (the D1/Bucket handles
        // above were moved into the indexer); `Date::now()` is the Cron tick time
        // in seconds (wasm has no ambient clock, so `sweep_cache` takes it).
        let (Ok(gc_db), Ok(gc_bucket)) = (
            env.d1(crate::handlers::bindings::D1),
            env.bucket(crate::handlers::bindings::R2),
        ) else {
            worker::console_error!("scheduled gc: D1/R2 binding missing");
            return;
        };
        let now = (worker::Date::now().as_millis() / 1000) as i64;
        let gc_backend = crate::d1backend::D1Backend::new(gc_db);
        if let Err(err) = crate::indexer::gc_all(gc_backend, gc_bucket, now, sealer).await {
            worker::console_error!("scheduled cache gc failed: {err:#}");
        }
    }
}
