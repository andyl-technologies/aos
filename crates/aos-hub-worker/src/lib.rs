//! The Cloudflare Workers read-path target for the AOS registry hub (RFC-0004).
//!
//! RFC-0004 specifies a Cloudflare Workers deployment of the registry hub —
//! `wasm32-unknown-unknown` via `workers-rs`, with a colocated-SQLite system of record, R2
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
//!   queries) the native hub runs, driven over the [`sqldobackend`] so the
//!   Worker's read path and indexer cannot drift from the hub's.
//! - The native hub's facade classification — [`keymap`] is a faithful copy of
//!   `compat::{is_machine_path, cache_control, content_type}`.
//!
//! # What is and isn't here (yet)
//!
//! The data layer is shared with the native hub
//! (`aos_hub_core::Database` over the [`sqldobackend`]), and the **entire
//! request surface is now served by the *same* shared `axum` router the native
//! hub's RPC path mounts** ([`aos_hub_core::connect::router`]) — bridged to
//! the Workers runtime by [`bridge`] over the Worker's
//! [`RpcService`](aos_hub_core::service) (SQLite-DO backend, R2 [`surface`]
//! provider, Durable-Object-backed rate limiter via [`coordinatorobj`]). One
//! router serves three surfaces:
//!
//! - the `aos.hub.v1` RPC surface (`POST
//!   /aos.hub.v1.{Service}/{Method}`) — the write/publish path,
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
//! the R2 [`surface::R2SurfaceWriteProvider`] write provider, so **every**
//! console route is mounted on the Worker. Registries whose canonical paths
//! contain slashes are offered to the shared nested dispatcher by the Worker
//! bridge before frontend and facade routing, matching the native hub's
//! catch-all ordering.
//!
//! Worker-local: only the Cron-trigger indexer ([`indexer`]). The `fetch`
//! handler bridges every request to the shared router; the schema is migrated
//! inside the `HubDb` Durable Object on first use (no external init step), and
//! the root admin is bootstrapped over a seal-gated `HubDb` endpoint. See
//! `README.md` and the RFC.
//!
//! # Module map
//!
//! Pure, native-testable (compile on every target):
//!
//! - [`keymap`] — R2 key mapping and the facade cache/content classification.
//!
//! The Cron indexer no longer carries a bespoke `Registry` row model or a
//! `indexlogic` rules module: it projects the core
//! [`RegistryRecord`](aos_hub_core::db::RegistryRecord) from the database and runs the
//! shared [`aos_hub_core::indexer`] (the partition target checks, the
//! channel anti-rollback floor, and the snapshot write all live there now), so
//! the Worker's Cron index is byte-identical to the native hub's (RFC-0004
//! Phase 5).
//!
//! Worker glue (wasm32-only, gated behind `#[cfg(target_arch = "wasm32")]`):
//!
//! - `sqldobackend` — the [`aos_hub_core::backend::Backend`] over the `HubDb`
//!   Durable Object's colocated SQLite (the system of record — there is no D1).
//! - `handlers` — the Wrangler binding names.
//! - `indexer` — the Cron-trigger indexer: lists public registries and runs the
//!   shared [`aos_hub_core::indexer`] over each registry's R2 [`surface`]
//!   fetcher (driven inside `HubDb` over `sqldobackend`).
//! - `bridge` — the hand-rolled `worker`⇄`axum` bridge that runs the shared
//!   Connect-JSON router for the RPC surface (no `axum-cloudflare-adapter`).
//! - `surface` — the R2-backed [`aos_hub_core::fetch::SurfaceProvider`]
//!   the shared git/facade read logic uses.
//! - `workerkv` — the Workers KV [`aos_hub_core::kv::KvStore`] for hot
//!   point-key state (sessions/tokens/config/routing), off the read path.
//! - `coordinatorobj` — the `CoordinatorObject` Durable Object and its
//!   `WorkerCoordinator` client: the strongly-consistent
//!   [`aos_hub_core::coordinator::Coordinator`] backing the rate limiter and the
//!   publish lease without a relational write (RFC-0004 ch.14).
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

// The method-agnostic nested-console bridge seam is compiled for the Worker
// and for native unit tests. Keeping the Workers request conversion outside
// this module makes the routing boundary testable without a JS runtime.
#[cfg(any(target_arch = "wasm32", test))]
mod bridge_dispatch;

#[cfg(target_arch = "wasm32")]
pub mod bridge;
#[cfg(target_arch = "wasm32")]
pub mod consoleports;
#[cfg(target_arch = "wasm32")]
pub mod coordinatorobj;
#[cfg(target_arch = "wasm32")]
pub mod edgeratelimit;
#[cfg(target_arch = "wasm32")]
pub mod handlers;
#[cfg(target_arch = "wasm32")]
pub mod indexer;
// Pure (no `worker`/wasm dependency) DO-SQLite placeholder translation, so it
// is unit-tested on the native target too — see [`placeholder`].
pub mod placeholder;
#[cfg(target_arch = "wasm32")]
pub mod sqldobackend;
#[cfg(target_arch = "wasm32")]
pub mod surface;
#[cfg(target_arch = "wasm32")]
pub mod tenantdb;
#[cfg(target_arch = "wasm32")]
pub mod tracinglog;
#[cfg(target_arch = "wasm32")]
pub mod workerkv;
#[cfg(target_arch = "wasm32")]
pub mod workerqueue;

#[cfg(target_arch = "wasm32")]
mod entry {
    //! The Workers runtime entry points: the `fetch` and `scheduled` handlers.
    //!
    //! The `fetch` handler bridges **every** request to the shared `axum` router
    //! ([`aos_hub_core::connect::router`]), built per request over the
    //! Worker's D1/R2 bindings ([`service_from`]) and bridged to the Workers
    //! runtime by [`crate::bridge`]. That one router serves the
    //! `aos.hub.v1.*` RPC surface, the machine-path facade, and the no-JS
    //! browse UI + JSON read API ([`aos_hub_core::web`]), all single-sourced
    //! with the native hub.
    //!
    //! Two layers sit in front of the router for read performance: an **edge
    //! cache read-through** (`caches.default`) serves a previously-stored public
    //! facade object — NAR/narinfo — straight from the colo with no D1, R2, or
    //! dispatch; and a per-request **D1 read-replication session** routes the
    //! reads that do reach the router to the nearest replica, threading a
    //! consistency bookmark through a cookie. Both are bypassed/excluded for
    //! authenticated, non-cacheable, and write requests.

    use std::sync::Arc;

    use wasm_bindgen::{JsCast, JsValue};
    use worker::{
        durable_object, Context, DurableObject, Env, Method, Request, RequestInit, Response,
        Result, ScheduleContext, ScheduledEvent, State,
    };

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
    /// Optional `[vars]` entry: the name of the deployment's default R2 bucket
    /// (the store unbound registries/caches push to). Baked by `worker deploy`
    /// so instance settings can show where the default storage lives; unset on
    /// older deploys, where the UI falls back to "configured at deploy time".
    const HUB_DEFAULT_BUCKET: &str = "HUB_DEFAULT_BUCKET";
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
    /// over the colocated-SQLite [`crate::sqldobackend`] (the schema is applied by the operator
    /// CLI, `aos-hub init --target d1:<name>`), the HS256 [`JwtKeys`],
    /// the external URL, and the Durable-Object-backed rate limiter
    /// ([`crate::coordinatorobj`]) — and wires them into **both** shared routers:
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
    /// Build the shared router/service/console over a **pre-built** `Database`,
    /// independent of the backend.
    ///
    /// The `db` is constructed by the caller — the D1 [`SqlDoBackend`](crate::sqldobackend)
    /// in the `fetch` handler, or the colocated [`SqlDoBackend`](crate::sqldobackend)
    /// inside the [`HubDb`](crate::hubdb) Durable Object (RFC-0004 ch.14 Phase E,
    /// "get off D1"). Everything else (JWT, rate-limit bindings, surface, lease,
    /// reindexer, KV) is built from `env`, so one router-builder serves both the
    /// D1 read path and the colocated SQLite-in-DO system of record.
    async fn router_from(
        env: &Env,
        request_origin: &str,
        db: Arc<Database>,
    ) -> Result<(Router, Arc<RpcService>, ConsoleDeps)> {
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
        // The `EMAIL` binding is the structured Email Sending API, which has no
        // matching workers-rs wrapper (0.8's typed `SendEmail` is the raw-MIME
        // Email Routing product — see `WorkerMailer`), so it is read as a raw JS
        // object via Reflect and handed to the mailer for the JS interop call.
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

        // RFC-0004 ch.14 (corrected): rate limiting uses the **edge-local** Rate
        // Limiting bindings — `limit({key})` increments a machine-local counter
        // with no network round-trip, so it adds nothing to the read path (the
        // earlier Durable Object limiter added a ~100 ms cross-region hop per
        // request). The publish lease keeps its DO backing (a write-path concern).
        let ratelimit: Arc<dyn RateLimiter> =
            Arc::new(crate::edgeratelimit::EdgeRateLimiter::from_env(env)?);
        // The DO coordinator now backs only the cross-isolate publish lease; its
        // hop is paid only on a publish, never on a read.
        let coordinator: Arc<dyn aos_hub_core::coordinator::Coordinator> =
            Arc::new(crate::coordinatorobj::WorkerCoordinator::from_env(env)?);

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
        // shared facade-write handler on the Worker. The lease lives in the
        // Durable Object coordinator (a single serialized instance replaces the
        // prior cross-isolate D1 lease — RFC-0004 ch.14); the reindexer
        // re-indexes the published registry inline (event-driven), so a publish
        // is browse-visible the instant its final pointer write returns. The
        // `*/15` Cron remains the backstop for non-publish surface changes.
        let lease: Arc<dyn aos_hub_core::lease::PublishLease> = Arc::new(
            aos_hub_core::lease::CoordinatorLease::new(Arc::clone(&coordinator)),
        );
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
            .with_origin_fetch(Arc::new(crate::surface::WorkerOriginFetch))
            // RFC-0004 ch.14 Phase C: read-through cache hot point-key state
            // (sessions/tokens/config/routing) off the D1 read path via Workers
            // KV (the `SESSIONS` namespace). When the binding is absent the
            // service falls back to the database (the pre-Phase-C path).
            .with_kv(Arc::new(crate::workerkv::WorkerKv::new(
                env.kv(crate::handlers::bindings::KV_SESSIONS)?,
            ))),
        );

        // Seed the editable site chrome (title/banner/footer) from D1 once per
        // isolate, so a fresh isolate reflects persisted branding. A branding
        // save updates the live chrome via `set_site_chrome`; other isolates
        // pick it up on recycle. Guarded so the hot path reads D1 at most once
        // per isolate.
        {
            use std::sync::atomic::{AtomicBool, Ordering};
            static SEEDED: AtomicBool = AtomicBool::new(false);
            if !SEEDED.swap(true, Ordering::Relaxed) {
                if let Ok(s) = db.instance_settings().await {
                    aos_hub_core::web::console_render::set_site_chrome(
                        s.site_title.as_deref(),
                        s.tagline.as_deref(),
                        s.announcement.as_deref(),
                        s.tos_url.as_deref(),
                        s.privacy_url.as_deref(),
                        s.support_url.as_deref(),
                    );
                    aos_hub_core::web::console_render::set_caches_public(s.caches_public);
                }
            }
        }

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
            // The default store is this Worker's R2 bucket; show its name (as
            // `r2://<bucket>`) on instance settings when the deploy baked it.
            default_storage_location: env
                .var(HUB_DEFAULT_BUCKET)
                .ok()
                .map(|v| format!("r2://{}", v.to_string()))
                .filter(|s| s != "r2://"),
            // RFC-0004 ch.14 Phase C: Workers KV for read-through caching +
            // token-revocation tombstones (the `SESSIONS` namespace).
            kv: Some(Arc::new(crate::workerkv::WorkerKv::new(
                env.kv(crate::handlers::bindings::KV_SESSIONS)?,
            ))),
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

    /// Whether `resp` may be stored by a shared (edge) cache — its
    /// `Cache-Control` contains `public`.
    ///
    /// Such responses (the machine facade's NAR/narinfo, the generated
    /// `robots.txt`/`llms.txt`) must not carry a `Set-Cookie`, which would make
    /// them uncacheable, so the bookmark cookie is set only on the rest.
    fn is_publicly_cacheable(resp: &Response) -> bool {
        resp.headers()
            .get("cache-control")
            .ok()
            .flatten()
            .is_some_and(|cc| cc.to_ascii_lowercase().contains("public"))
    }

    /// The edge-cache key for `req` when it is a cacheable facade read, else
    /// `None`.
    ///
    /// Only anonymous, whole-object `GET`s are eligible: a `GET` carrying no
    /// `Authorization` (a private-registry read must never land in a shared
    /// cache) and no `Range` (the Cloudflare Cache API serves a partial read
    /// from the cached *whole* object on lookup, and refuses to *store* a `206`).
    /// The key is the full request URL, which uniquely identifies a public
    /// machine-facade object (`*.narinfo`, `nar/**`, …). Non-facade `GET`s (the
    /// browse UI) may match here but are excluded at *store* time by
    /// [`is_publicly_cacheable`], so they are never actually cached.
    fn facade_cache_key(req: &Request) -> Option<String> {
        if req.method() != Method::Get {
            return None;
        }
        let headers = req.headers();
        if headers.get("authorization").ok().flatten().is_some()
            || headers.get("range").ok().flatten().is_some()
        {
            return None;
        }
        req.url().ok().map(|url| url.to_string())
    }

    /// The HTTP entry point: bridge every request to the shared router.
    ///
    /// The shared router ([`aos_hub_core::connect::router`]) owns the
    /// entire request surface — the `aos.hub.v1` RPC methods, the
    /// machine-path facade (`GET`/`HEAD` `/{slug}/{*path}`), and the no-JS
    /// browse UI + JSON read API (the hub home `/` and the `/{slug}/-/…` pages),
    /// all single-sourced with the native hub. The [`crate::surface`]
    /// `SurfaceProvider` backs the facade and the `GitService` reads, and the
    /// shared [`aos_hub_core::web`] browse reads the same `RpcService` read
    /// methods. The schema is migrated inside the `HubDb` Durable Object on first
    /// use; root bootstrap goes through the seal-gated `HubDb` endpoint — there is
    /// no unauthenticated init path. A handler error is logged and returned as a
    /// `500` so a binding/back-end failure never panics the isolate.
    #[worker::event(fetch, respond_with_errors)]
    async fn fetch(req: Request, env: Env, ctx: Context) -> Result<Response> {
        // Route the shared core's `tracing` events to the console so handler
        // errors land in Workers Logs (idempotent; see `crate::tracinglog`).
        crate::tracinglog::init();

        // Edge cache read-through: a previously-stored public facade object
        // (NAR/narinfo/...) is served straight from this colo's cache — no D1
        // session, no R2 read, no shared-router dispatch. Only anonymous
        // whole-object GETs are eligible (`facade_cache_key`); the Cache API
        // honors a `Range` on lookup against the cached whole object, so range
        // reads are served from it too once it is warm. Everything else falls
        // through to the router below.
        let cache_key = facade_cache_key(&req);
        if let Some(key) = &cache_key {
            if let Ok(Some(hit)) = worker::Cache::default().get(key.clone(), false).await {
                return Ok(hit);
            }
        }

        // The request's own `scheme://host`, the fallback canonical URL when
        // RFC-0004 ch.14 Phase E ("get off D1"): the **`HubDb` colocated-SQLite
        // Durable Object is the only system of record** — there is no D1. The
        // worker is a thin edge: it serves the edge cache, then forwards the whole
        // request to `HubDb`, whose SQLite runs in the DO's own thread (no
        // per-request session cost). The DO runs the shared router over
        // `SqlDoBackend`. Pinned to WNAM (the hub's home) via a location hint so a
        // fresh instance lands near the readership; the package data plane
        // (NAR/narinfo on R2/CDN) is globally replicated independently.
        let stub = env
            .durable_object(crate::handlers::bindings::HUB_DB)?
            .id_from_name("hub")
            .and_then(|id| id.get_stub_with_location_hint("wnam"))?;
        let mut resp = stub.fetch_with_request(req).await?;

        // Edge cache write-through: store a fresh public facade response so the
        // read-through above serves repeat reads from this colo without touching
        // D1 or R2. `wait_until` runs the store after the response is returned,
        // off its critical path, and `cloned` tees the (possibly streamed) body
        // so the client is served concurrently. Gated on a `200` *and*
        // [`is_publicly_cacheable`], so browse/RPC/private/error responses — and
        // anything carrying the bookmark `Set-Cookie` — are never stored.
        if let Some(key) = cache_key {
            if resp.status_code() == 200 && is_publicly_cacheable(&resp) {
                if let Ok(clone) = resp.cloned() {
                    ctx.wait_until(async move {
                        if let Err(err) = worker::Cache::default().put(key, clone).await {
                            worker::console_error!("edge cache put failed: {err}");
                        }
                    });
                }
            }
        }
        Ok(resp)
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
        // RFC-0004 ch.14 Phase E: the maintenance pass runs **inside `HubDb`**
        // over its colocated SQLite (the only system of record — no D1). The
        // worker forwards the Cron tick to the DO's seal-gated `/_internal/cron`.
        if let Err(err) = forward_internal(&env, "/_internal/cron", None).await {
            worker::console_error!("scheduled: forward to HubDb failed: {err:#}");
        }
    }

    /// The Queue-trigger consumer: drain deferred post-write jobs (RFC-0004
    /// ch.14 Phase D).
    ///
    /// Decodes each [`Job`](aos_hub_core::jobs::Job) in the batch and runs it.
    /// `RebuildDirectory` is executed inline (it rebuilds the KV directory
    /// projection from D1); the remaining job kinds (surface regeneration,
    /// reindex, read-model invalidation, webhook delivery) are logged pending
    /// their full consumer wiring, which is exercised under a live queue. A
    /// decode failure retries the whole batch; otherwise the batch is acked.
    #[worker::event(queue)]
    async fn queue(
        batch: worker::MessageBatch<aos_hub_core::jobs::Job>,
        env: Env,
        _ctx: Context,
    ) -> Result<()> {
        crate::tracinglog::init();
        // RFC-0004 ch.14 Phase E: jobs run **inside `HubDb`** over its colocated
        // SQLite (no D1). The worker forwards each decoded job to the DO's
        // seal-gated `/_internal/job`. A decode failure retries the batch.
        let messages = match batch.messages() {
            Ok(messages) => messages,
            Err(err) => {
                worker::console_error!("queue: failed to decode batch: {err}");
                batch.retry_all();
                return Ok(());
            }
        };
        for message in &messages {
            let body = match serde_json::to_string(message.body()) {
                Ok(body) => body,
                Err(err) => {
                    worker::console_error!("queue: re-encode job: {err}");
                    continue;
                }
            };
            if let Err(err) = forward_internal(&env, "/_internal/job", Some(body)).await {
                worker::console_error!("queue: forward job to HubDb failed: {err:#}");
            }
        }
        batch.ack_all();
        Ok(())
    }

    /// Forwards an internal control-plane request (Cron tick or a single queue
    /// job) to the `HubDb` Durable Object's seal-gated `/_internal/*` endpoint,
    /// so the work runs over the colocated SQLite system of record.
    ///
    /// # Errors
    ///
    /// Returns an error if the seal secret or `HUB_DB` binding is unavailable, the
    /// DO cannot be reached, or it responds non-200.
    async fn forward_internal(env: &Env, path: &str, body: Option<String>) -> Result<()> {
        let seal = env.secret(HUB_SEAL_KEY)?.to_string();
        let stub = env
            .durable_object(crate::handlers::bindings::HUB_DB)?
            .id_from_name("hub")
            .and_then(|id| id.get_stub_with_location_hint("wnam"))?;
        let headers = worker::Headers::new();
        headers.set("x-hub-seal", &seal)?;
        let mut init = RequestInit::new();
        init.with_method(Method::Post).with_headers(headers);
        if let Some(body) = body {
            init.with_body(Some(JsValue::from_str(&body)));
        }
        let req = Request::new_with_init(&format!("https://hub{path}"), &init)?;
        let mut resp = stub.fetch_with_request(req).await?;
        if resp.status_code() != 200 {
            let detail = resp.text().await.unwrap_or_default();
            return Err(worker::Error::RustError(format!(
                "HubDb {path}: {} {detail}",
                resp.status_code()
            )));
        }
        Ok(())
    }

    /// Runs the Cron maintenance pass inside `HubDb` over its colocated SQLite:
    /// re-index every registry's surface, rescan + GC caches, and rebuild the KV
    /// directory projection. Each step is best-effort and logged on failure.
    async fn run_cron(state: &State, env: &Env) {
        let make = || -> Box<dyn aos_hub_core::backend::Backend> {
            Box::new(crate::sqldobackend::SqlDoBackend::new(
                state.storage().sql(),
            ))
        };
        // The AES-GCM sealer (from `HUB_SEAL_KEY`) unseals an external storage
        // binding's credentials so the indexer/GC can read off-bucket surfaces.
        let sealer = match env
            .secret(HUB_SEAL_KEY)
            .map_err(|err| format!("{err}"))
            .and_then(|s| sealer_from_secret(&s.to_string()).map_err(|err| format!("{err:#}")))
        {
            Ok(sealer) => sealer,
            Err(err) => {
                worker::console_error!("cron: {HUB_SEAL_KEY} unavailable: {err}");
                return;
            }
        };
        if let Ok(bucket) = env.bucket(crate::handlers::bindings::R2) {
            if let Err(err) = crate::indexer::index_all(make(), bucket, Arc::clone(&sealer)).await {
                worker::console_error!("cron index failed: {err:#}");
            }
        }
        if let Ok(bucket) = env.bucket(crate::handlers::bindings::R2) {
            if let Err(err) = crate::indexer::rescan_all(make(), bucket, Arc::clone(&sealer)).await
            {
                worker::console_error!("cron rescan failed: {err:#}");
            }
        }
        if let Ok(bucket) = env.bucket(crate::handlers::bindings::R2) {
            let now = (worker::Date::now().as_millis() / 1000) as i64;
            if let Err(err) = crate::indexer::gc_all(make(), bucket, now, Arc::clone(&sealer)).await
            {
                worker::console_error!("cron gc failed: {err:#}");
            }
        }
        if let Ok(kv_ns) = env.kv(crate::handlers::bindings::KV_SESSIONS) {
            let db = aos_hub_core::db::Database::attach(make());
            let kv = crate::workerkv::WorkerKv::new(kv_ns);
            if let Err(err) = aos_hub_core::directory::rebuild(&db, &kv).await {
                worker::console_error!("cron directory rebuild failed: {err:#}");
            }
        }
    }

    /// Runs a single deferred [`Job`](aos_hub_core::jobs::Job) inside `HubDb` over
    /// its colocated SQLite (the queue consumer's per-job body, Phase E).
    async fn run_job(job: &aos_hub_core::jobs::Job, state: &State, env: &Env) {
        use aos_hub_core::jobs::Job;
        let make = || -> Box<dyn aos_hub_core::backend::Backend> {
            Box::new(crate::sqldobackend::SqlDoBackend::new(
                state.storage().sql(),
            ))
        };
        match job {
            Job::RebuildDirectory => {
                if let Ok(kv_ns) = env.kv(crate::handlers::bindings::KV_SESSIONS) {
                    let db = aos_hub_core::db::Database::attach(make());
                    let kv = crate::workerkv::WorkerKv::new(kv_ns);
                    if let Err(err) = aos_hub_core::directory::rebuild(&db, &kv).await {
                        worker::console_error!("job rebuild_directory: {err:#}");
                    }
                }
            }
            Job::Reindex { registry_id } => {
                let Ok(bucket) = env.bucket(crate::handlers::bindings::R2) else {
                    worker::console_error!("job reindex: R2 binding missing");
                    return;
                };
                let sealer = match env
                    .secret(HUB_SEAL_KEY)
                    .map_err(|err| format!("{err}"))
                    .and_then(|s| {
                        sealer_from_secret(&s.to_string()).map_err(|err| format!("{err:#}"))
                    }) {
                    Ok(sealer) => sealer,
                    Err(err) => {
                        worker::console_error!("job reindex: {HUB_SEAL_KEY}: {err}");
                        return;
                    }
                };
                let db = Arc::new(aos_hub_core::db::Database::attach(make()));
                match db.registry_by_id(*registry_id).await {
                    Ok(Some(registry)) => {
                        use aos_hub_core::reindex::Reindexer as _;
                        let reindexer = WorkerReindexer::new(bucket, Arc::clone(&db), sealer);
                        if let Err(err) = reindexer.reindex(&registry).await {
                            worker::console_error!("job reindex {registry_id}: {err:#}");
                        }
                    }
                    Ok(None) => worker::console_log!("job reindex {registry_id}: registry gone"),
                    Err(err) => worker::console_error!("job reindex load {registry_id}: {err:#}"),
                }
            }
            Job::InvalidateReadModel { keys } => {
                let cache = worker::Cache::default();
                for key in keys {
                    if let Err(err) = cache.delete(key.as_str(), false).await {
                        worker::console_error!("job cache delete {key}: {err}");
                    }
                }
            }
            other => {
                worker::console_log!("job pending consumer wiring: {other:?}");
            }
        }
    }

    /// The colocated-SQLite **system of record** Durable Object (RFC-0004 ch.14
    /// Phase E, "get off D1").
    ///
    /// When `HUB_SQLITE_DO` is enabled, the `fetch` handler forwards every request
    /// to this DO (a single global instance, `id_from_name("hub")`). The DO runs
    /// the **same shared router** ([`router_from`]) over a
    /// [`SqlDoBackend`](crate::sqldobackend) whose SQLite lives in the DO's own
    /// thread — so the request makes one hop to the DO's region and then every
    /// query is **local** (microseconds), eliminating the ~120 ms per-request D1
    /// session cost that was the real latency floor. The schema is the shared
    /// `MIGRATIONS`, applied to the DO's SQLite on first use (`ensure_migrated`).
    #[durable_object]
    pub struct HubDb {
        state: State,
        env: Env,
    }

    impl DurableObject for HubDb {
        fn new(state: State, env: Env) -> Self {
            HubDb { state, env }
        }

        async fn fetch(&self, mut req: Request) -> Result<Response> {
            let backend = crate::sqldobackend::SqlDoBackend::new(self.state.storage().sql());
            if let Err(err) = crate::tenantdb::ensure_migrated(&backend).await {
                return Response::error(format!("hubdb migrate: {err:#}"), 500);
            }
            // DO-SQLite e2e probe (`do-e2e` feature only — never in production):
            // run the managed-registry bootstrap directly over `SqlDoBackend` so
            // the workerd-driven `aos-hub-worker-do-e2e` check exercises the
            // create + read path against the *real* DO SQLite engine, with no
            // router/rate-limit/R2/KV bindings. This is the regression guard for
            // the bound-`NULL` corruption that 500'd `ListRegistries`/`GetRegistry`
            // after a binding-less managed registry was created
            // (see `crate::placeholder`).
            #[cfg(feature = "do-e2e")]
            {
                let path = req
                    .url()
                    .ok()
                    .map(|u| u.path().to_string())
                    .unwrap_or_default();
                if req.method() == Method::Post && path == "/_e2e/managed-registry-bootstrap" {
                    return self.e2e_managed_registry_bootstrap().await;
                }
            }
            // Seal-gated control-plane (RFC-0004 ch.14 Phase E): the worker's
            // `scheduled`/`queue` handlers forward the Cron tick and each job to
            // `/_internal/{cron,job}` so maintenance runs over the colocated
            // SQLite, and the operator's `worker install` creates the instance
            // root admin via `/_admin/bootstrap-root` (the D1-free replacement for
            // the old `init --target d1:` root step). All require the `x-hub-seal`
            // secret, so an external caller forwarded through the worker cannot
            // reach them.
            {
                let path = req
                    .url()
                    .ok()
                    .map(|u| u.path().to_string())
                    .unwrap_or_default();
                if req.method() == Method::Post
                    && (path == "/_internal/cron"
                        || path == "/_internal/job"
                        || path == "/_admin/bootstrap-root")
                {
                    let want = self
                        .env
                        .secret(HUB_SEAL_KEY)
                        .map(|s| s.to_string())
                        .unwrap_or_default();
                    let got = req
                        .headers()
                        .get("x-hub-seal")
                        .ok()
                        .flatten()
                        .unwrap_or_default();
                    if want.is_empty() || got != want {
                        return Response::error("forbidden", 403);
                    }
                    if path == "/_internal/cron" {
                        run_cron(&self.state, &self.env).await;
                        return Response::ok("ok");
                    }
                    if path == "/_admin/bootstrap-root" {
                        #[derive(serde::Deserialize)]
                        struct BootstrapRoot {
                            email: String,
                            password: String,
                        }
                        let body: BootstrapRoot = match req.json().await {
                            Ok(body) => body,
                            Err(err) => {
                                return Response::error(
                                    format!("bootstrap-root decode: {err}"),
                                    400,
                                )
                            }
                        };
                        let db = Database::attach(Box::new(
                            crate::sqldobackend::SqlDoBackend::new(self.state.storage().sql()),
                        ));
                        return match db.bootstrap_root(&body.email, &body.password).await {
                            Ok((email, user_id)) => Response::from_json(
                                &serde_json::json!({ "email": email, "user_id": user_id }),
                            ),
                            Err(err) => Response::error(format!("bootstrap-root: {err:#}"), 500),
                        };
                    }
                    let job: aos_hub_core::jobs::Job = match req.json().await {
                        Ok(job) => job,
                        Err(err) => return Response::error(format!("job decode: {err}"), 400),
                    };
                    run_job(&job, &self.state, &self.env).await;
                    return Response::ok("ok");
                }
            }
            // Cutover admin (`POST /_admin/sql`, seal-gated) — the one-time
            // D1→`HubDb` data-replay tool, gated behind the `cutover-admin`
            // feature so the production build has no raw-SQL surface. Build with
            // `--features cutover-admin` only to run a migration.
            #[cfg(feature = "cutover-admin")]
            {
                let path = req
                    .url()
                    .ok()
                    .map(|u| u.path().to_string())
                    .unwrap_or_default();
                if req.method() == Method::Post && path == "/_admin/sql" {
                    let want = self
                        .env
                        .secret(HUB_SEAL_KEY)
                        .map(|s| s.to_string())
                        .unwrap_or_default();
                    let got = req
                        .headers()
                        .get("x-hub-seal")
                        .ok()
                        .flatten()
                        .unwrap_or_default();
                    if want.is_empty() || got != want {
                        return Response::error("forbidden", 403);
                    }
                    // `x-hub-query: 1` → run the body as a SELECT and return rows
                    // as JSON (for verifying the migration); otherwise run it as a
                    // batch of statements.
                    let is_query = req.headers().get("x-hub-query").ok().flatten().is_some();
                    let sql = req.text().await?;
                    use aos_hub_core::backend::Backend as _;
                    if is_query {
                        return match backend.query(&sql, &[]).await {
                            Ok(rows) => {
                                let out: Vec<Vec<String>> = rows
                                    .iter()
                                    .map(|r| {
                                        (0..r.len())
                                            .filter_map(|i| r.value(i))
                                            .map(|v| format!("{v:?}"))
                                            .collect()
                                    })
                                    .collect();
                                Response::from_json(&out)
                            }
                            Err(err) => Response::error(format!("admin query: {err:#}"), 500),
                        };
                    }
                    return match backend.execute_batch(&sql).await {
                        Ok(()) => Response::ok("ok"),
                        Err(err) => Response::error(format!("admin sql: {err:#}"), 500),
                    };
                }
            }
            let db = Arc::new(Database::attach(Box::new(backend)));
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
            // The DO runs the same shared router as the D1 path — single-sourced.
            let (router, service, console_deps) =
                router_from(&self.env, &request_origin, db).await?;
            crate::bridge::dispatch(router, &service, console_deps, req).await
        }
    }

    #[cfg(feature = "do-e2e")]
    impl HubDb {
        /// Runs the managed-registry bootstrap over this DO's local SQLite and
        /// returns a plain-text transcript (one `OK`/`ERR` line per step).
        ///
        /// The `aos-hub-worker-do-e2e` check drives this under the real DO SQLite
        /// engine: create an org, create a binding-less (default-storage) managed
        /// registry, then read it back via `list_registries`, `registry_by_slug`,
        /// and the per-registry reads `registry_message` issues. It is the
        /// regression guard for the bound-`NULL` corruption (a binding-less
        /// registry's `storage_binding_id`) that 500'd those reads; the body ends
        /// with `ALL OK` only when every step succeeds and the registry reads back
        /// with a genuine `NULL` `storage_binding_id`.
        ///
        /// # Errors
        ///
        /// Returns a `worker` error only if the HTTP response cannot be built; a
        /// failing database step is reported in the `200` body (so the e2e driver
        /// sees the exact SQL error rather than a swallowed 500).
        async fn e2e_managed_registry_bootstrap(&self) -> Result<Response> {
            use aos_hub_core::db::Database;
            let db = Database::attach(Box::new(crate::sqldobackend::SqlDoBackend::new(
                self.state.storage().sql(),
            )));
            let mut out = String::new();
            macro_rules! step {
                ($label:expr, $e:expr) => {
                    match $e.await {
                        Ok(v) => out.push_str(&format!("OK  {}: {:?}\n", $label, v)),
                        Err(e) => {
                            out.push_str(&format!("ERR {}: {:#}\n", $label, e));
                            return Response::ok(out);
                        }
                    }
                };
            }
            step!("create_org", db.create_org("andyl", "Andyl"));
            let org_id = match db.org_by_slug("andyl").await {
                Ok(Some(org)) => org.id,
                _ => return Response::ok(format!("{out}ERR org_by_slug: no row\n")),
            };
            step!(
                "create_managed_registry",
                db.create_managed_registry(
                    org_id,
                    "",
                    "main",
                    "public",
                    None,
                    "andyl/main",
                    &[] as &[String],
                    false,
                )
            );
            step!("list_registries", db.list_registries());
            step!("registry_by_slug", db.registry_by_slug("andyl/main"));
            let record = match db.registry_by_slug("andyl/main").await {
                Ok(Some(record)) => record,
                _ => return Response::ok(format!("{out}ERR registry_by_slug: no row\n")),
            };
            // The reads `registry_message` issues per registry (the list/get path).
            step!("index_status", db.index_status(record.id));
            step!("list_roster", db.list_roster(record.id));
            step!(
                "list_advertised_caches",
                db.list_advertised_caches(record.id)
            );
            step!(
                "registry_by_scope",
                db.registry_by_scope("andyl", "", "main")
            );
            // The fix's invariant: the binding-less registry's storage_binding_id
            // round-trips as a genuine SQL NULL (not the `"[object Object]"` text
            // a bound NULL was corrupted into).
            if record.storage_binding_id.is_some() {
                out.push_str(&format!(
                    "ERR storage_binding_id not NULL: {:?}\n",
                    record.storage_binding_id
                ));
                return Response::ok(out);
            }
            out.push_str("ALL OK\n");
            Response::ok(out)
        }
    }
}
