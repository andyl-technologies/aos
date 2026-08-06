//! The Cloudflare Workers read-path target for the AOS registry hub (RFC-0004).
//!
//! RFC-0004 specifies a Cloudflare Workers deployment of the registry hub —
//! `wasm32-unknown-unknown` via `workers-rs`, with a colocated-SQLite system of record, R2
//! as zero-egress storage, KV for sessions, and Cron Triggers driving the
//! indexer ("Architecture and runtime targets"). The native hub is a sync
//! axum + tokio + rusqlite binary that cannot compile to wasm32, so this is a
//! **separate Worker crate** implementing the RFC's phase-1 Cloudflare
//! deployment: **read the index + serve typed delivery routes**. It deliberately reuses
//! the pure, shared crates rather than porting the native hub:
//!
//! - [`aos_registry_surface`] — the wasm-clean reader (objects, tags, refs,
//!   Ed25519 verification) the native hub indexer and `apm` already run, reused
//!   verbatim in the Cron indexer ([`indexer`]).
//! - [`aos_hub_core`] — the shared `Database` (schema `MIGRATIONS` + read
//!   queries) the native hub runs, driven over the [`sqldobackend`] so the
//!   Worker's read path and indexer cannot drift from the hub's.
//! - The shared machine-object classification in [`aos_hub_core::keymap`] — re-exported
//!   through [`keymap`] for Worker object-key mapping.
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
//! - exact domain/IP endpoints and delivery routes, resolved before delegating
//!   to the shared streaming
//!   [`registry_serve`](aos_hub_core::service::RpcService::registry_serve) and
//!   [`cache_serve`](aos_hub_core::service::RpcService::cache_serve) paths over
//!   the placement-aware R2 [`surface`] provider;
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
//! (`/{slug}/-/settings/configuration`, `/{slug}/-/settings/change-requests`):
//! its base-commit reads go
//! through the R2 [`surface`] read provider and its draft-object writes through
//! the R2 [`surface::R2SurfaceWriteProvider`] write provider, so **every**
//! console route is mounted on the Worker. Registries whose canonical paths
//! contain slashes are offered to the shared nested dispatcher by the Worker
//! bridge before delivery-route and facade routing, matching the native hub's
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
//!   Durable Object's colocated SQLite system of record.
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
//!   used after reviewed publication writes.
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
#[cfg(all(target_arch = "wasm32", feature = "do-e2e"))]
mod e2e_surface;
#[cfg(target_arch = "wasm32")]
pub mod edgeratelimit;
#[cfg(target_arch = "wasm32")]
pub mod handlers;
#[cfg(target_arch = "wasm32")]
pub mod indexer;
// Pure (no `worker`/wasm dependency) DO-SQLite placeholder translation, so it
// is unit-tested on the native target too — see [`placeholder`].
pub mod placeholder;
pub(crate) mod r2_adapter;
#[cfg(target_arch = "wasm32")]
pub mod secretversions;
#[cfg(target_arch = "wasm32")]
pub mod sqldobackend;
#[cfg(target_arch = "wasm32")]
pub mod surface;
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
    //! Worker's HubDb/R2 bindings and bridged to the Workers
    //! runtime by [`crate::bridge`]. That one router serves the
    //! `aos.hub.v1.*` RPC surface, the machine-path facade, and the no-JS
    //! browse UI + JSON read API ([`aos_hub_core::web`]), all single-sourced
    //! with the native hub.
    //!
    //! Two layers sit in front of the router for read performance: an **edge
    //! cache read-through** (`caches.default`) serves a previously-stored public
    //! facade object — NAR/narinfo — straight from the colo without a HubDb
    //! dispatch. Authenticated, non-cacheable, and write requests always reach
    //! the Durable Object router.

    use std::sync::Arc;

    use wasm_bindgen::{JsCast, JsValue};
    use worker::{
        durable_object, Context, DurableObject, Env, Method, Request, RequestInit, Response,
        Result, ScheduleContext, ScheduledEvent, State,
    };

    use aos_hub_core::auth::jwt::JwtKeys;
    use aos_hub_core::db::{Database, TokenAuth};
    use aos_hub_core::domain::{Permission, Principal, Role, Scope};
    use aos_hub_core::ratelimit::RateLimiter;
    use aos_hub_core::service::RpcService;
    use aos_hub_core::web::console::{console_router, ConsoleDeps};
    use axum::Router;

    use crate::consoleports::{
        sealer_from_secret, WorkerCloudflareControlPlaneClient, WorkerEgressClient,
        WorkerHttpClient, WorkerMailer, WorkerReindexer, WorkerStorageCredentialProbeProvider,
    };

    /// The Wrangler secret holding the HS256 JWT signing secret.
    const HUB_JWT_SECRET: &str = "HUB_JWT_SECRET";
    /// The Wrangler secret holding the at-rest secret-sealing key.
    ///
    /// Hashed to a 256-bit AES-GCM instance key (see
    /// [`sealer_from_secret`](crate::consoleports::sealer_from_secret)); the
    /// console's OIDC token exchange unseals a tenant's client secret with it.
    const HUB_SEAL_KEY: &str = "HUB_SEAL_KEY";
    /// Optional HMAC key shared with an authenticated upstream ingress adapter.
    const HUB_DELIVERY_ATTESTATION_KEY: &str = "HUB_DELIVERY_ATTESTATION_KEY";
    /// JSON secret containing Worker TLS-terminator probe signer material.
    const HUB_DOMAIN_PROBE_SIGNER_MANIFEST: &str = "HUB_DOMAIN_PROBE_SIGNER_MANIFEST";
    /// JSON secret containing active and retained route URL-reservation keys.
    const HUB_ROUTE_RESERVATION_KEYRING: &str = "HUB_ROUTE_RESERVATION_KEYRING";
    /// Signed controller-owned publication manifest for direct-route probes.
    const HUB_ROUTE_PUBLICATION_MANIFEST: &str = "HUB_ROUTE_PUBLICATION_MANIFEST";
    /// Pinned Ed25519 public key for the direct-route publication manifest.
    const HUB_ROUTE_PUBLICATION_PUBLIC_KEY: &str = "HUB_ROUTE_PUBLICATION_PUBLIC_KEY";
    /// The Wrangler `[vars]` entry holding the hub's externally-reachable URL.
    const HUB_EXTERNAL_URL: &str = "HUB_EXTERNAL_URL";
    /// Immutable source/build identity used to attest the active deployment.
    const HUB_DEPLOYMENT_ID: &str = "HUB_DEPLOYMENT_ID";
    /// Non-cacheable endpoint exposing [`HUB_DEPLOYMENT_ID`].
    const DEPLOYMENT_ID_PATH: &str = "/.well-known/aos-deployment";
    /// Required `[vars]` entry naming the deployment's default R2 bucket.
    const HUB_DEFAULT_BUCKET: &str = "HUB_DEFAULT_BUCKET";
    /// Optional `[vars]` entry: the email-relay endpoint magic links are
    /// `POST`ed to. Unset → [`WorkerMailer`] logs the link instead.
    const HUB_EMAIL_API_URL: &str = "HUB_EMAIL_API_URL";
    const HUB_DNS_JSON_ENDPOINT: &str = "HUB_DNS_JSON_ENDPOINT";
    /// Optional repository-owned native egress-router endpoint.
    const HUB_EGRESS_GATEWAY_URL: &str = "HUB_EGRESS_GATEWAY_URL";
    /// Optional shared authentication key for the egress router.
    const HUB_EGRESS_GATEWAY_KEY: &str = "HUB_EGRESS_GATEWAY_KEY";
    /// Scoped Cloudflare API token used by the control-plane observer.
    const HUB_CLOUDFLARE_API_TOKEN: &str = "HUB_CLOUDFLARE_API_TOKEN";
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

    fn worker_egress(env: &Env) -> worker::Result<Arc<WorkerEgressClient>> {
        match (
            env.var(HUB_EGRESS_GATEWAY_URL),
            env.secret(HUB_EGRESS_GATEWAY_KEY),
        ) {
            (Err(_), _) => Ok(Arc::new(WorkerEgressClient::direct())),
            (Ok(url), Ok(key)) => WorkerEgressClient::gateway(url.to_string(), &key.to_string())
                .map(Arc::new)
                .map_err(|error| worker::Error::RustError(format!("egress gateway: {error:#}"))),
            (Ok(_), Err(_)) => Err(worker::Error::RustError(format!(
                "{HUB_EGRESS_GATEWAY_KEY} is required when {HUB_EGRESS_GATEWAY_URL} is configured"
            ))),
        }
    }

    #[cfg(feature = "do-e2e")]
    struct DoE2eReindexer;

    #[cfg(feature = "do-e2e")]
    #[async_trait::async_trait(?Send)]
    impl aos_hub_core::reindex::Reindexer for DoE2eReindexer {
        async fn reindex(
            &self,
            _registry: &aos_hub_core::db::RegistryRecord,
        ) -> anyhow::Result<Option<String>> {
            Ok(None)
        }
    }

    /// Builds the shared API and machine router with the live-workerd storage adapter.
    #[cfg(feature = "do-e2e")]
    async fn router_from_do_e2e(
        state: &State,
        env: &Env,
        db: Arc<Database>,
    ) -> Result<(Router, Arc<RpcService>)> {
        let secret = env.secret(HUB_JWT_SECRET)?.to_string();
        let jwt_keys = JwtKeys::from_secret(secret.as_bytes());
        let external_url = env.var(HUB_EXTERNAL_URL)?.to_string();
        let coordinator: Arc<dyn aos_hub_core::coordinator::Coordinator> =
            Arc::new(crate::coordinatorobj::WorkerCoordinator::from_env(env)?);
        let rate_limiter: Arc<dyn RateLimiter> = Arc::new(
            aos_hub_core::ratelimit::CoordinatorRateLimiter::new(Arc::clone(&coordinator)),
        );
        let lease: Arc<dyn aos_hub_core::lease::PublishLease> = Arc::new(
            aos_hub_core::lease::CoordinatorLease::new(Arc::clone(&coordinator)),
        );
        let fetch: Arc<dyn aos_hub_core::fetch::SurfaceProvider> = Arc::new(
            crate::e2e_surface::DoE2eSurfaceProvider::new(state.storage().sql())
                .map_err(|error| worker::Error::RustError(format!("e2e storage: {error:#}")))?,
        );
        let write: Arc<dyn aos_hub_core::surface_write::SurfaceWriteProvider> = Arc::new(
            crate::e2e_surface::DoE2eSurfaceProvider::new(state.storage().sql())
                .map_err(|error| worker::Error::RustError(format!("e2e storage: {error:#}")))?,
        );
        let service = Arc::new(RpcService::new(
            Arc::clone(&db),
            jwt_keys,
            external_url,
            rate_limiter,
            fetch,
            write,
            lease,
            Arc::new(DoE2eReindexer),
            Arc::new(
                aos_hub_core::topology_probe::DatabaseTopologyProbeScheduler::new(Arc::clone(&db)),
            ),
            None,
        ));
        Ok((aos_hub_core::connect::router(Arc::clone(&service)), service))
    }

    /// Build the shared `axum` router over HubDb SQLite and R2 bindings.
    ///
    /// Constructs the runtime-neutral pieces once — a non-migrating [`Database`]
    /// over the colocated-SQLite [`crate::sqldobackend`] (the schema is applied by the operator
    /// `HubDb` schema bootstrap, the HS256 [`JwtKeys`],
    /// the external URL, and the Durable-Object-backed rate limiter
    /// ([`crate::coordinatorobj`]) — and wires them into **both** shared routers:
    ///
    /// - the RPC + facade + browse router built from the [`RpcService`]
    ///   ([`aos_hub_core::connect::router`]), over the R2 surface provider
    ///   ([`crate::surface`]);
    /// - the producer-console router ([`console_router`]) built from a
    ///   [`ConsoleDeps`], over the Worker's console ports
    ///   ([`crate::consoleports`]): the logging [`WorkerMailer`], the gateway-backed
    ///   [`WorkerHttpClient`], the inline [`WorkerReindexer`], and the shared
    ///   AES-GCM sealer from `HUB_SEAL_KEY`.
    ///
    /// Both routers carry their own state, so they merge into one `Router<()>`
    /// exactly as the native hub composes them; the console's static paths win
    /// over the facade wildcard by static-over-dynamic precedence.
    ///
    /// # Errors
    ///
    /// Returns an error if a binding is missing, the required external URL is
    /// invalid, the `HUB_JWT_SECRET` or
    /// `HUB_SEAL_KEY` secret is absent or empty, or the rate-limiter table cannot
    /// be ensured.
    ///
    /// The caller constructs `db` from the colocated
    /// [`SqlDoBackend`](crate::sqldobackend) inside the
    /// [`HubDb`](crate::hubdb) Durable Object. Everything else (JWT, rate-limit
    /// bindings, surface, lease, reindexer, and KV projections) is built from
    /// `env`.
    async fn router_from(
        env: &Env,
        _request_origin: &str,
        db: Arc<Database>,
    ) -> Result<(
        Router,
        Arc<RpcService>,
        ConsoleDeps,
        Option<Arc<aos_hub_core::delivery_attestation::DeliveryAttestationVerifier>>,
    )> {
        let default_bucket = env
            .var(HUB_DEFAULT_BUCKET)
            .map_err(|_| {
                worker::Error::RustError(format!(
                    "{HUB_DEFAULT_BUCKET} is required and must name the deployment R2 bucket"
                ))
            })?
            .to_string();
        if default_bucket.is_empty() {
            return Err(worker::Error::RustError(format!(
                "{HUB_DEFAULT_BUCKET} must not be empty"
            )));
        }
        db.ensure_instance_default_binding("deployment_r2", None, Some(&default_bucket))
            .await
            .map_err(|error| {
                worker::Error::RustError(format!(
                    "provisioning instance-default storage binding: {error:#}"
                ))
            })?;

        let secret = env.secret(HUB_JWT_SECRET)?.to_string();
        if secret.is_empty() {
            return Err(worker::Error::RustError(format!(
                "{HUB_JWT_SECRET} secret is empty; set it with `wrangler secret put {HUB_JWT_SECRET}`"
            )));
        }
        let jwt_keys = JwtKeys::from_secret(secret.as_bytes());

        // The canonical URL is also the exact trusted control-plane authority.
        // It must be deployment configuration: deriving it from the incoming
        // request origin would let an arbitrary `Host` gain access to the API,
        // console, or delivery routes.
        let external_url = env
            .var(HUB_EXTERNAL_URL)
            .map_err(|_| {
                worker::Error::RustError(format!(
                    "{HUB_EXTERNAL_URL} is required and must name the control-plane origin"
                ))
            })?
            .to_string();
        if external_url.is_empty() {
            return Err(worker::Error::RustError(format!(
                "{HUB_EXTERNAL_URL} must not be empty"
            )));
        }

        let seal_secret = env.secret(HUB_SEAL_KEY)?.to_string();
        if seal_secret.is_empty() {
            return Err(worker::Error::RustError(format!(
                "{HUB_SEAL_KEY} secret is empty; set it with `wrangler secret put {HUB_SEAL_KEY}`"
            )));
        }
        let sealer = sealer_from_secret(&seal_secret)
            .map_err(|err| worker::Error::RustError(format!("seal key: {err:#}")))?;
        let secret_versions = crate::secretversions::from_env(env)?;
        let route_reservation_secret = env
            .secret(HUB_ROUTE_RESERVATION_KEYRING)
            .map_err(|_| {
                worker::Error::RustError(format!(
                    "{HUB_ROUTE_RESERVATION_KEYRING} is required for route management"
                ))
            })?
            .to_string();
        let route_reservation_keyring = Arc::new(
            aos_hub_core::service::ConfiguredRouteReservationKeyring::from_json(
                &route_reservation_secret,
            )
            .map_err(|error| {
                worker::Error::RustError(format!(
                    "{HUB_ROUTE_RESERVATION_KEYRING} is invalid: {error:#}"
                ))
            })?,
        );
        route_reservation_keyring
            .validate_referenced_versions(&db)
            .await
            .map_err(|error| {
                worker::Error::RustError(format!(
                    "{HUB_ROUTE_RESERVATION_KEYRING} cannot open this database: {error:#}"
                ))
            })?;
        let delivery_attestation_verifier = env
            .secret(HUB_DELIVERY_ATTESTATION_KEY)
            .ok()
            .map(|secret| {
                aos_hub_core::delivery_attestation::DeliveryAttestationVerifier::new(
                    secret.to_string().as_bytes(),
                )
                .map(Arc::new)
                .map_err(|err| {
                    worker::Error::RustError(format!(
                        "{HUB_DELIVERY_ATTESTATION_KEY} is invalid: {err}"
                    ))
                })
            })
            .transpose()?;

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

        let egress = worker_egress(env)?;
        let cloudflare_api_token = env
            .secret(HUB_CLOUDFLARE_API_TOKEN)
            .map_err(|_| {
                worker::Error::RustError(format!("{HUB_CLOUDFLARE_API_TOKEN} is required"))
            })?
            .to_string();

        let dns_endpoint = env.var(HUB_DNS_JSON_ENDPOINT).map_err(|_| {
            worker::Error::RustError(format!(
                "{HUB_DNS_JSON_ENDPOINT} is required for domain verification"
            ))
        })?;
        let tls_probe_verifier = aos_hub_core::topology_probe::DomainTlsProbeVerifier::new();
        let signer_manifest = env
            .secret(HUB_DOMAIN_PROBE_SIGNER_MANIFEST)
            .map_err(|_| {
                worker::Error::RustError(format!(
                    "{HUB_DOMAIN_PROBE_SIGNER_MANIFEST} is required for domain verification"
                ))
            })?
            .to_string();
        let domain_probe_terminator = Arc::new(
            aos_hub_core::topology_probe::ManifestDomainProbeTerminatorProvider::from_json(
                &signer_manifest,
                "worker_secret",
            )
            .map_err(|error| {
                worker::Error::RustError(format!(
                    "{HUB_DOMAIN_PROBE_SIGNER_MANIFEST} is invalid: {error:#}"
                ))
            })?,
        );
        // Validate readiness while constructing the runtime, rather than
        // accepting verification work that a later queue consumer cannot run.
        let route_http: Arc<dyn aos_hub_core::web::console::ports::HttpClient> =
            Arc::new(WorkerHttpClient::new(Arc::clone(&egress)));
        let mut domain_probe_readiness = aos_hub_core::topology_probe::DomainProbeController::new(
            Arc::clone(&db),
            Arc::clone(&route_http),
            tls_probe_verifier,
            dns_endpoint.to_string(),
            "cloudflare-worker",
        )
        .map_err(|error| worker::Error::RustError(format!("domain probes: {error:#}")))?;
        let mut route_adapters =
            aos_hub_core::topology_probe::ControllerOwnedDeliveryRouteObservationProvider::new()
                .with_external(Arc::new(
                    aos_hub_core::topology_probe::CloudflareDeliveryRouteControlPlane::new(
                        Arc::new(WorkerCloudflareControlPlaneClient::new(
                            Arc::clone(&egress),
                            cloudflare_api_token,
                        )),
                        Arc::clone(&route_http),
                    ),
                ));
        domain_probe_readiness = domain_probe_readiness.with_storage_credential_probe(Arc::new(
            WorkerStorageCredentialProbeProvider::new(
                Arc::clone(&egress),
                Arc::clone(&secret_versions),
            ),
        ));
        match (
            env.secret(HUB_ROUTE_PUBLICATION_MANIFEST).ok(),
            env.var(HUB_ROUTE_PUBLICATION_PUBLIC_KEY).ok(),
        ) {
            (Some(manifest), Some(public_key)) => {
                let direct = aos_hub_core::topology_probe::SignedManifestDeliveryRouteObservationProvider::from_signed_json(
                    &manifest.to_string(),
                    &public_key.to_string(),
                    aos_hub_core::clock::now_unix_secs(),
                    route_http,
                )
                .map_err(|error| worker::Error::RustError(format!("route publication manifest: {error:#}")))?;
                route_adapters = route_adapters.with_direct(Arc::new(direct));
            }
            (None, None) => {}
            _ => {
                return Err(worker::Error::RustError(format!(
                    "{HUB_ROUTE_PUBLICATION_MANIFEST} and {HUB_ROUTE_PUBLICATION_PUBLIC_KEY} must be configured together"
                )))
            }
        }
        domain_probe_readiness =
            domain_probe_readiness.with_route_observer(Arc::new(route_adapters));
        drop(domain_probe_readiness);

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
                Arc::clone(&secret_versions),
                Arc::clone(&egress),
            ));
        let surface_write: Arc<dyn aos_hub_core::surface_write::SurfaceWriteProvider> =
            Arc::new(crate::surface::R2SurfaceWriteProvider::new(
                env.bucket(crate::handlers::bindings::R2)?,
                Arc::clone(&db),
                Arc::clone(&secret_versions),
                Arc::clone(&egress),
            ));

        // The cross-isolate publish lease and the inline reindexer back the
        // shared facade-write handler on the Worker. The lease lives in the
        // Durable Object coordinator (one serialized instance owns the lease);
        // the reindexer
        // re-indexes the published registry inline (event-driven), so a publish
        // is browse-visible the instant its final pointer write returns. The
        // `*/15` Cron remains the backstop for non-publish surface changes.
        let lease: Arc<dyn aos_hub_core::lease::PublishLease> = Arc::new(
            aos_hub_core::lease::CoordinatorLease::new(Arc::clone(&coordinator)),
        );
        let reindexer: Arc<dyn aos_hub_core::reindex::Reindexer> = Arc::new(WorkerReindexer::new(
            env.bucket(crate::handlers::bindings::R2)?,
            Arc::clone(&db),
            Arc::clone(&secret_versions),
            Arc::clone(&egress),
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
                Arc::new(
                    aos_hub_core::topology_probe::DatabaseTopologyProbeScheduler::new(Arc::clone(
                        &db,
                    ))
                    .with_wakeup(Arc::new(crate::workerqueue::WorkerQueue::from_env(env)?)),
                ),
                Some(Arc::clone(&sealer)),
            )
            .with_secret_versions(Arc::clone(&secret_versions))
            .with_origin_fetch(Arc::new(crate::surface::WorkerOriginFetch::new(
                Arc::clone(&egress),
            )))
            .with_domain_probe_terminator(domain_probe_terminator)
            .with_route_reservation_keyring(route_reservation_keyring)
            // RFC-0004 ch.14 Phase C: read-through cache hot point-key state
            // (sessions/tokens/config/routing) off the relational read path via Workers
            // KV (the `SESSIONS` namespace). When the binding is absent the
            // service falls back to the database (the pre-Phase-C path).
            .with_kv(Arc::new(crate::workerkv::WorkerKv::new(
                env.kv(crate::handlers::bindings::KV_SESSIONS)?,
            ))),
        );

        // Seed the editable site chrome (title/banner/footer) from HubDb once per
        // isolate, so a fresh isolate reflects persisted branding. A branding
        // save updates the live chrome via `set_site_chrome`; other isolates
        // pick it up on recycle. Guarded so the hot path reads HubDb at most once
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
                Arc::clone(&egress),
            )),
            sealer,
            http: Arc::new(WorkerHttpClient::new(Arc::clone(&egress))),
            surface,
            surface_write,
            reindexer,
            // The default store is this Worker's R2 bucket; show its name (as
            // `r2://<bucket>`) on instance settings when the deploy baked it.
            default_storage_location: Some(format!("r2://{default_bucket}")),
            // RFC-0004 ch.14 Phase C: Workers KV for read-through caching +
            // token-revocation tombstones (the `SESSIONS` namespace).
            kv: Some(Arc::new(crate::workerkv::WorkerKv::new(
                env.kv(crate::handlers::bindings::KV_SESSIONS)?,
            ))),
            topology: Arc::clone(&service) as Arc<dyn aos_hub_core::web::console::TopologyConsole>,
        };

        // The service is returned alongside the router so the bridge can run the
        // shared typed delivery-route decision before dispatch (the Worker's
        // `!Send` services preclude the native `from_fn` middleware). The
        // `ConsoleDeps` are cloned out before being moved into `console_router`
        // so the bridge can also run the shared nested-canonical console
        // dispatcher (the console routes capture only a single-segment slug, so
        // a nested registry's `/-/` pages need the explicit dispatcher).
        let router = aos_hub_core::connect::router(Arc::clone(&service))
            .merge(console_router(console_deps.clone()));
        Ok((router, service, console_deps, delivery_attestation_verifier))
    }

    /// The HTTP entry point: bridge every request to the shared router.
    ///
    /// The shared router ([`aos_hub_core::connect::router`]) owns the
    /// entire request surface — the `aos.hub.v1` RPC methods, the
    /// typed delivery-route dispatcher, and the no-JS
    /// browse UI + JSON read API (the hub home `/` and the `/{slug}/-/…` pages),
    /// all single-sourced with the native hub. The [`crate::surface`]
    /// `SurfaceProvider` backs delivery and the `GitService` reads, and the
    /// shared [`aos_hub_core::web`] browse reads the same `RpcService` read
    /// methods. The schema is migrated inside the `HubDb` Durable Object on first
    /// use; root bootstrap goes through the seal-gated `HubDb` endpoint — there is
    /// no unauthenticated init path. A handler error is logged and returned as a
    /// `500` so a binding/back-end failure never panics the isolate.
    #[worker::event(fetch, respond_with_errors)]
    async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
        // Route the shared core's `tracing` events to the console so handler
        // errors land in Workers Logs (idempotent; see `crate::tracinglog`).
        crate::tracinglog::init();

        if req.url()?.path() == DEPLOYMENT_ID_PATH {
            if !matches!(req.method(), Method::Get | Method::Head) {
                return Response::error("method not allowed", 405);
            }
            let deployment_id = env
                .var(HUB_DEPLOYMENT_ID)
                .map_err(|_| {
                    worker::Error::RustError(format!(
                        "{HUB_DEPLOYMENT_ID} is required for deployment verification"
                    ))
                })?
                .to_string();
            let headers = worker::Headers::new();
            headers.set("cache-control", "no-store, max-age=0")?;
            headers.set("content-type", "text/plain; charset=utf-8")?;
            headers.set("x-aos-deployment-id", &deployment_id)?;
            headers.set("x-content-type-options", "nosniff")?;
            let response = if req.method() == Method::Head {
                Response::empty()?
            } else {
                Response::ok(deployment_id)?
            };
            return Ok(response.with_headers(headers));
        }

        // The request's own `scheme://host`, the fallback canonical URL when
        // The **`HubDb` colocated-SQLite Durable Object is the only system of
        // record**. The
        // worker forwards the request to `HubDb`, whose SQLite runs in the DO's
        // own thread (no
        // per-request session cost). The DO runs the shared router over
        // `SqlDoBackend`. Pinned to WNAM (the hub's home) via a location hint so a
        // fresh instance lands near the readership; the package data plane
        // (NAR/narinfo on R2/CDN) is globally replicated independently.
        let stub = env
            .durable_object(crate::handlers::bindings::HUB_DB)?
            .id_from_name("hub")
            .and_then(|id| id.get_stub_with_location_hint("wnam"))?;
        let resp = stub.fetch_with_request(req).await?;

        Ok(resp)
    }

    /// The Cron-triggered indexer: re-walk every live registry placement into
    /// the HubDb derived index, reusing the pure verifier.
    ///
    /// Bound to a Cron schedule in `wrangler.toml`; mirrors the native hub's
    /// scheduled re-index. Failures of an individual registry are logged and do
    /// not abort the run (see [`crate::indexer::index_all`]).
    #[worker::event(scheduled)]
    async fn scheduled(_event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
        crate::tracinglog::init();
        // RFC-0004 ch.14 Phase E: the maintenance pass runs **inside `HubDb`**
        // over its colocated SQLite system of record. The
        // worker forwards the Cron tick to the DO's seal-gated `/_internal/cron`.
        if let Err(err) = forward_internal(&env, "/_internal/cron", None).await {
            worker::console_error!("scheduled: forward to HubDb failed: {err:#}");
        }
    }

    /// The Queue-trigger consumer: drain deferred post-write jobs (RFC-0004
    /// ch.14 Phase D).
    ///
    /// Decodes each [`Job`](aos_hub_core::jobs::Job) in the batch and runs it.
    /// Supported jobs execute inside HubDb and return success only after their
    /// durable outcome is recorded. Unsupported, decode, and execution failures
    /// make the internal endpoint non-2xx, so the entire batch is retried.
    #[worker::event(queue)]
    async fn queue(
        batch: worker::MessageBatch<aos_hub_core::jobs::Job>,
        env: Env,
        _ctx: Context,
    ) -> Result<()> {
        crate::tracinglog::init();
        // RFC-0004 ch.14 Phase E: jobs run **inside `HubDb`** over its colocated
        // SQLite. The worker forwards each decoded job to the DO's
        // seal-gated `/_internal/job`. A decode failure retries the batch.
        let messages = match batch.messages() {
            Ok(messages) => messages,
            Err(err) => {
                worker::console_error!("queue: failed to decode batch: {err}");
                batch.retry_all();
                return Ok(());
            }
        };
        let mut failed = false;
        for message in &messages {
            let body = match serde_json::to_string(message.body()) {
                Ok(body) => body,
                Err(err) => {
                    worker::console_error!("queue: re-encode job: {err}");
                    failed = true;
                    continue;
                }
            };
            if let Err(err) = forward_internal(&env, "/_internal/job", Some(body)).await {
                worker::console_error!("queue: forward job to HubDb failed: {err:#}");
                failed = true;
            }
        }
        if failed {
            batch.retry_all();
        } else {
            batch.ack_all();
        }
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
    /// re-index every registry's surface, rescan caches, and rebuild the KV
    /// directory projection. Indexing, scanning, GC, and directory failures are
    /// logged independently; webhook materialization or delivery failure fails
    /// the Cron request so the platform retries it.
    async fn run_cron(state: &State, env: &Env) -> Result<()> {
        let make = || -> Box<dyn aos_hub_core::backend::Backend> {
            Box::new(crate::sqldobackend::SqlDoBackend::new(state.storage()))
        };
        // Drain already-committed notifications before longer maintenance.
        // A second pass below catches events raised by indexing in this tick.
        run_webhook_batch(make(), env).await?;
        run_domain_probes(make(), env).await;
        let secret_versions = match crate::secretversions::from_env(env) {
            Ok(resolver) => resolver,
            Err(err) => {
                worker::console_error!("cron: secret-version resolver unavailable: {err}");
                return Err(err);
            }
        };
        let egress = match worker_egress(env) {
            Ok(client) => client,
            Err(error) => {
                worker::console_error!("cron: invalid egress configuration: {error}");
                return Err(error);
            }
        };
        if let Ok(bucket) = env.bucket(crate::handlers::bindings::R2) {
            if let Err(err) = crate::indexer::index_all(
                make(),
                bucket,
                Arc::clone(&secret_versions),
                Arc::clone(&egress),
            )
            .await
            {
                worker::console_error!("cron index failed: {err:#}");
            }
        }
        if let Ok(bucket) = env.bucket(crate::handlers::bindings::R2) {
            if let Err(err) = crate::indexer::rescan_all(
                make(),
                bucket,
                Arc::clone(&secret_versions),
                Arc::clone(&egress),
            )
            .await
            {
                worker::console_error!("cron rescan failed: {err:#}");
            }
        }
        if let Ok(bucket) = env.bucket(crate::handlers::bindings::R2) {
            let db = Arc::new(aos_hub_core::db::Database::attach(make()));
            let writers: Arc<dyn aos_hub_core::surface_write::SurfaceWriteProvider> =
                Arc::new(crate::surface::R2SurfaceWriteProvider::new(
                    bucket,
                    Arc::clone(&db),
                    Arc::clone(&secret_versions),
                    Arc::clone(&egress),
                ));
            let controller =
                aos_hub_core::gc_controller::CacheGcDeletionController::new(db, writers);
            let now = (worker::Date::now().as_millis() / 1000) as i64;
            if let Err(err) = controller.run_due(now, 100).await {
                worker::console_error!("physical cache deletion controller failed: {err:#}");
            }
        }
        if let Ok(kv_ns) = env.kv(crate::handlers::bindings::KV_SESSIONS) {
            let db = aos_hub_core::db::Database::attach(make());
            let kv = crate::workerkv::WorkerKv::new(kv_ns);
            if let Err(err) = aos_hub_core::directory::rebuild(&db, &kv).await {
                worker::console_error!("cron directory rebuild failed: {err:#}");
            }
        }
        run_webhook_batch(make(), env).await?;
        Ok(())
    }

    async fn run_webhook_batch(
        backend: Box<dyn aos_hub_core::backend::Backend>,
        env: &Env,
    ) -> Result<()> {
        let db = aos_hub_core::db::Database::attach(backend);
        let (_, delivery_ids) = db
            .materialize_topology_events_with_delivery_ids()
            .await
            .map_err(|error| {
                worker::Error::RustError(format!("materialize webhook deliveries: {error:#}"))
            })?;
        let queue_error = if delivery_ids.is_empty() {
            None
        } else {
            use aos_hub_core::jobs::Queue as _;
            let jobs = delivery_ids
                .into_iter()
                .map(|delivery_id| aos_hub_core::jobs::Job::DeliverWebhook { delivery_id })
                .collect::<Vec<_>>();
            crate::workerqueue::WorkerQueue::from_env(env)?
                .enqueue_all(&jobs)
                .await
                .err()
        };
        let now = aos_hub_core::clock::now_unix_secs();
        for delivery in db
            .claim_due_deliveries(now, 25, 60)
            .await
            .map_err(|error| {
                worker::Error::RustError(format!("claim webhook deliveries: {error:#}"))
            })?
        {
            deliver_webhook(&db, env, &delivery).await?;
        }
        if let Some(error) = queue_error {
            return Err(worker::Error::RustError(format!(
                "enqueue webhook deliveries: {error:#}"
            )));
        }
        Ok(())
    }

    async fn deliver_webhook(
        db: &aos_hub_core::db::Database,
        env: &Env,
        delivery: &aos_hub_core::db::DueDelivery,
    ) -> Result<()> {
        if aos_hub_core::url_guard::is_safe_remote_url(&delivery.url).is_err() {
            db.mark_delivery(
                delivery.id,
                &delivery.claim_token,
                "failed",
                None,
                delivery.attempts + 1,
                None,
            )
            .await
            .map_err(|error| {
                worker::Error::RustError(format!("commit rejected webhook URL: {error:#}"))
            })?;
            return Ok(());
        }
        let secrets = crate::secretversions::from_env(env)?;
        let secret = match secrets.resolve(&delivery.secret_version_ref).await {
            Ok(secret) => secret,
            Err(_) => {
                schedule_webhook_retry(db, delivery, None).await?;
                return Ok(());
            }
        };
        if aos_hub_core::secret_version::verify_secret_fingerprint(
            &secret,
            &delivery.credential_fingerprint,
        )
        .is_err()
        {
            drop(secret);
            db.mark_delivery(
                delivery.id,
                &delivery.claim_token,
                "failed",
                None,
                delivery.attempts + 1,
                None,
            )
            .await
            .map_err(|error| {
                worker::Error::RustError(format!("commit credential mismatch: {error:#}"))
            })?;
            return Ok(());
        }
        let signature = aos_hub_core::webhook::sign_body_bytes(
            secret.expose_bytes(),
            delivery.payload.as_bytes(),
        );
        drop(secret);
        let egress = match worker_egress(env) {
            Ok(egress) => egress,
            Err(_) => {
                schedule_webhook_retry(db, delivery, None).await?;
                return Ok(());
            }
        };
        let response = match egress
            .send_webhook(
                &delivery.url,
                delivery.payload.as_bytes().to_vec(),
                &delivery.event,
                &signature,
                &delivery.delivery_id,
            )
            .await
        {
            Ok(response) => response,
            Err(_) => {
                schedule_webhook_retry(db, delivery, None).await?;
                return Ok(());
            }
        };
        let attempts = delivery.attempts + 1;
        if (200..300).contains(&response.status_code()) {
            db.mark_delivery(
                delivery.id,
                &delivery.claim_token,
                "delivered",
                Some(i64::from(response.status_code())),
                attempts,
                None,
            )
            .await
            .map_err(|error| worker::Error::RustError(format!("commit webhook outcome: {error:#}")))
        } else {
            schedule_webhook_retry(db, delivery, Some(i64::from(response.status_code()))).await
        }
    }

    async fn schedule_webhook_retry(
        db: &aos_hub_core::db::Database,
        delivery: &aos_hub_core::db::DueDelivery,
        response_code: Option<i64>,
    ) -> Result<()> {
        let attempts = delivery.attempts + 1;
        let (status, next_attempt_at) = if attempts >= aos_hub_core::webhook::MAX_ATTEMPTS {
            ("failed", None)
        } else {
            (
                "pending",
                Some(
                    now_for_worker().saturating_add(aos_hub_core::webhook::backoff_secs(attempts)),
                ),
            )
        };
        db.mark_delivery(
            delivery.id,
            &delivery.claim_token,
            status,
            response_code,
            attempts,
            next_attempt_at,
        )
        .await
        .map_err(|error| worker::Error::RustError(format!("commit webhook retry: {error:#}")))
    }

    fn now_for_worker() -> i64 {
        aos_hub_core::clock::now_unix_secs()
    }

    /// Runs a single deferred [`Job`](aos_hub_core::jobs::Job) inside `HubDb` over
    /// its colocated SQLite (the queue consumer's per-job body, Phase E).
    async fn run_job(job: &aos_hub_core::jobs::Job, state: &State, env: &Env) -> Result<()> {
        use aos_hub_core::jobs::Job;
        let make = || -> Box<dyn aos_hub_core::backend::Backend> {
            Box::new(crate::sqldobackend::SqlDoBackend::new(state.storage()))
        };
        match job {
            Job::RunTopologyProbes => run_domain_probes(make(), env).await,
            Job::RebuildDirectory => {
                let kv_ns = env
                    .kv(crate::handlers::bindings::KV_SESSIONS)
                    .map_err(|error| {
                        worker::Error::RustError(format!("job rebuild_directory binding: {error}"))
                    })?;
                let db = aos_hub_core::db::Database::attach(make());
                let kv = crate::workerkv::WorkerKv::new(kv_ns);
                aos_hub_core::directory::rebuild(&db, &kv)
                    .await
                    .map_err(|error| {
                        worker::Error::RustError(format!("job rebuild_directory: {error:#}"))
                    })?;
            }
            Job::Reindex { registry_id } => {
                let Ok(bucket) = env.bucket(crate::handlers::bindings::R2) else {
                    worker::console_error!("job reindex: R2 binding missing");
                    return Err(worker::Error::RustError(
                        "job reindex: R2 binding missing".into(),
                    ));
                };
                let secret_versions = match crate::secretversions::from_env(env) {
                    Ok(resolver) => resolver,
                    Err(err) => {
                        worker::console_error!("job reindex: secret-version resolver: {err}");
                        return Err(err);
                    }
                };
                let db = Arc::new(aos_hub_core::db::Database::attach(make()));
                match db.registry_by_id(*registry_id).await {
                    Ok(Some(registry)) => {
                        use aos_hub_core::reindex::Reindexer as _;
                        let egress = match worker_egress(env) {
                            Ok(egress) => egress,
                            Err(error) => {
                                worker::console_error!("job reindex: {error}");
                                return Err(error);
                            }
                        };
                        let reindexer =
                            WorkerReindexer::new(bucket, Arc::clone(&db), secret_versions, egress);
                        if let Err(err) = reindexer.reindex(&registry).await {
                            return Err(worker::Error::RustError(format!(
                                "job reindex {registry_id}: {err:#}"
                            )));
                        }
                    }
                    Ok(None) => worker::console_log!("job reindex {registry_id}: registry gone"),
                    Err(err) => {
                        return Err(worker::Error::RustError(format!(
                            "job reindex load {registry_id}: {err:#}"
                        )))
                    }
                }
            }
            Job::DeliverWebhook { delivery_id } => {
                let db = aos_hub_core::db::Database::attach(make());
                if let Some(delivery) = db
                    .claim_delivery_by_stable_id(delivery_id, now_for_worker(), 60)
                    .await
                    .map_err(|error| {
                        worker::Error::RustError(format!("claim webhook: {error:#}"))
                    })?
                {
                    deliver_webhook(&db, env, &delivery).await?;
                }
            }
            Job::RegenerateSurface { .. } => {
                return Err(worker::Error::RustError(
                    "regenerate_surface is unsupported".into(),
                ))
            }
        }
        Ok(())
    }

    async fn run_domain_probes(backend: Box<dyn aos_hub_core::backend::Backend>, env: &Env) {
        let Ok(endpoint) = env.var(HUB_DNS_JSON_ENDPOINT) else {
            worker::console_error!("domain probes: {HUB_DNS_JSON_ENDPOINT} is not configured");
            return;
        };
        let db = Arc::new(aos_hub_core::db::Database::attach(backend));
        let tls_verifier = aos_hub_core::topology_probe::DomainTlsProbeVerifier::new();
        let egress = match worker_egress(env) {
            Ok(client) => client,
            Err(error) => {
                worker::console_error!("domain probes: invalid egress configuration: {error}");
                return;
            }
        };
        let route_http: Arc<dyn aos_hub_core::web::console::ports::HttpClient> =
            Arc::new(WorkerHttpClient::new(Arc::clone(&egress)));
        let mut controller = match aos_hub_core::topology_probe::DomainProbeController::new(
            db,
            Arc::clone(&route_http),
            tls_verifier,
            endpoint.to_string(),
            "cloudflare-worker",
        ) {
            Ok(controller) => controller,
            Err(error) => {
                worker::console_error!("domain probes: {error:#}");
                return;
            }
        };
        let mut route_adapters =
            aos_hub_core::topology_probe::ControllerOwnedDeliveryRouteObservationProvider::new()
                .with_external(Arc::new(
                    aos_hub_core::topology_probe::CloudflareDeliveryRouteControlPlane::new(
                        Arc::new(WorkerCloudflareControlPlaneClient::new(
                            Arc::clone(&egress),
                            match env.secret(HUB_CLOUDFLARE_API_TOKEN) {
                                Ok(token) => token.to_string(),
                                Err(_) => {
                                    worker::console_error!(
                                        "domain probes: Cloudflare API token is not configured"
                                    );
                                    return;
                                }
                            },
                        )),
                        Arc::clone(&route_http),
                    ),
                ));
        match (
            env.secret(HUB_ROUTE_PUBLICATION_MANIFEST).ok(),
            env.var(HUB_ROUTE_PUBLICATION_PUBLIC_KEY).ok(),
        ) {
            (Some(manifest), Some(public_key)) => {
                let direct = match aos_hub_core::topology_probe::SignedManifestDeliveryRouteObservationProvider::from_signed_json(
                    &manifest.to_string(),
                    &public_key.to_string(),
                    aos_hub_core::clock::now_unix_secs(),
                    route_http,
                ) {
                    Ok(direct) => direct,
                    Err(error) => {
                        worker::console_error!("route publication manifest: {error:#}");
                        return;
                    }
                };
                route_adapters = route_adapters.with_direct(Arc::new(direct));
            }
            (None, None) => {}
            _ => {
                worker::console_error!(
                    "{HUB_ROUTE_PUBLICATION_MANIFEST} and {HUB_ROUTE_PUBLICATION_PUBLIC_KEY} must be configured together"
                );
                return;
            }
        }
        controller = controller.with_route_observer(Arc::new(route_adapters));
        let secret_versions = match crate::secretversions::from_env(env) {
            Ok(resolver) => resolver,
            Err(error) => {
                worker::console_error!("storage credential probes: {error:#}");
                return;
            }
        };
        controller = controller.with_storage_credential_probe(Arc::new(
            WorkerStorageCredentialProbeProvider::new(Arc::clone(&egress), secret_versions),
        ));
        if let Err(error) = controller.run_due(25).await {
            worker::console_error!("domain probes: {error:#}");
        }
    }

    /// The colocated-SQLite system-of-record Durable Object.
    ///
    /// The `fetch` handler forwards every request to this DO (a single global
    /// instance, `id_from_name("hub")`). The DO runs
    /// the **same shared router** ([`router_from`]) over a
    /// [`SqlDoBackend`](crate::sqldobackend) whose SQLite lives in the DO's own
    /// thread — so the request makes one hop to the DO's region and every query
    /// is local to the object. The schema is the shared
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
            let backend = crate::sqldobackend::SqlDoBackend::new(self.state.storage());
            if let Err(err) = crate::sqldobackend::ensure_migrated(&backend).await {
                return Response::error(format!("hubdb migrate: {err:#}"), 500);
            }
            // Live-workerd bootstrap (`do-e2e` only, never production). This
            // endpoint installs disposable topology and authentication state;
            // subsequent multipart requests use the ordinary outer Worker,
            // HubDb, bridge, shared router/service, SqlDoBackend, and the
            // feature-gated disk-backed surface-provider boundary.
            #[cfg(feature = "do-e2e")]
            {
                let path = req
                    .url()
                    .ok()
                    .map(|u| u.path().to_string())
                    .unwrap_or_default();
                if req.method() == Method::Post && path == "/_e2e/r2-js-contract" {
                    return match crate::surface::e2e_assert_r2_js_shape().await {
                        Ok(()) => Response::ok("ok"),
                        Err(error) => Response::error(format!("R2 JS contract: {error:#}"), 500),
                    };
                }
                if req.method() == Method::Post && path == "/_e2e/managed-registry-bootstrap" {
                    let body = req.bytes().await.unwrap_or_default();
                    return self.e2e_managed_registry_bootstrap(&body).await;
                }
            }
            // Seal-gated control-plane (RFC-0004 ch.14 Phase E): the worker's
            // `scheduled`/`queue` handlers forward the Cron tick and each job to
            // `/_internal/{cron,job}` so maintenance runs over the colocated
            // SQLite, and the operator's `worker install` creates the instance
            // root admin via `/_admin/bootstrap-root`. All require the `x-hub-seal`
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
                        return match run_cron(&self.state, &self.env).await {
                            Ok(()) => Response::ok("ok"),
                            Err(error) => Response::error(format!("cron: {error}"), 500),
                        };
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
                            crate::sqldobackend::SqlDoBackend::new(self.state.storage()),
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
                    return match run_job(&job, &self.state, &self.env).await {
                        Ok(()) => Response::ok("ok"),
                        Err(error) => Response::error(format!("job: {error}"), 500),
                    };
                }
            }
            let db = Arc::new(Database::attach(Box::new(backend)));
            #[cfg(not(feature = "do-e2e"))]
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
            #[cfg(feature = "do-e2e")]
            {
                let (router, service) = router_from_do_e2e(&self.state, &self.env, db).await?;
                return crate::bridge::dispatch_do_e2e(router, &service, req).await;
            }
            // The DO runs the same shared router as the native shell.
            #[cfg(not(feature = "do-e2e"))]
            let (router, service, console_deps, delivery_attestation_verifier) =
                router_from(&self.env, &request_origin, db).await?;
            #[cfg(not(feature = "do-e2e"))]
            crate::bridge::dispatch(
                router,
                &service,
                console_deps,
                delivery_attestation_verifier.as_deref(),
                req,
            )
            .await
        }
    }

    #[cfg(feature = "do-e2e")]
    impl HubDb {
        /// Installs the disposable topology and returns an authenticated token.
        ///
        /// # Errors
        ///
        /// Returns a `worker` error when the live SQL transaction, topology
        /// fixture, principal grant, token mint, or response encoding fails.
        async fn e2e_managed_registry_bootstrap(
            &self,
            producer_surface: &[u8],
        ) -> Result<Response> {
            use aos_hub_core::db::Database;
            let backend = crate::sqldobackend::SqlDoBackend::new(self.state.storage());
            backend
                .e2e_assert_checked_batch_row_counts_and_rollback()
                .await
                .map_err(|error| worker::Error::RustError(format!("checked batch: {error:#}")))?;
            let db = Database::attach(Box::new(backend));
            db.install_do_e2e_topology_fixture()
                .await
                .map_err(|error| {
                    worker::Error::RustError(format!("topology fixture: {error:#}"))
                })?;
            for (surface, placement_id, slug) in [
                (
                    aos_hub_core::db::SurfaceTarget::BinaryCache(2),
                    3,
                    "flat-cache",
                ),
                (
                    aos_hub_core::db::SurfaceTarget::BinaryCache(1),
                    1,
                    "failure/cache",
                ),
                (
                    aos_hub_core::db::SurfaceTarget::Registry(2),
                    4,
                    "flat-registry",
                ),
                (
                    aos_hub_core::db::SurfaceTarget::Registry(1),
                    2,
                    "failure/registry",
                ),
            ] {
                crate::e2e_surface::configure_hub_delivery_route(&db, surface, placement_id, slug)
                    .await
                    .map_err(|error| {
                        worker::Error::RustError(format!("fixture delivery route: {error:#}"))
                    })?;
            }
            let image_fixture = crate::e2e_surface::decode_producer_surface_fixture(
                producer_surface,
            )
            .map_err(|error| worker::Error::RustError(format!("producer fixture: {error:#}")))?;
            let image_fixture =
                crate::e2e_surface::DoE2eSurfaceProvider::new(self.state.storage().sql())
                    .map_err(|error| worker::Error::RustError(format!("image surface: {error:#}")))?
                    .install_signed_image_fixtures(&db, image_fixture)
                    .await
                    .map_err(|error| {
                        worker::Error::RustError(format!("image fixture: {error:#}"))
                    })?;
            let public_registry = db
                .registry_by_slug("failure/images-public")
                .await
                .map_err(|error| worker::Error::RustError(format!("image registry: {error:#}")))?
                .ok_or_else(|| worker::Error::RustError("public image registry missing".into()))?;
            let gc_root_count = db
                .list_system_image_root_keys(public_registry.id)
                .await
                .map_err(|error| worker::Error::RustError(format!("image GC roots: {error:#}")))?
                .len();
            if gc_root_count != 4 {
                return Err(worker::Error::RustError(format!(
                    "apr image publication produced {gc_root_count} GC roots, expected 4"
                )));
            }
            // Materialize topology setup events before installing the webhook.
            // The lifecycle assertion below must observe only its two seeded
            // events, and a newly-created hook must not receive historical
            // placement or image-publication notifications.
            loop {
                let materialized = db.materialize_topology_events().await.map_err(|error| {
                    worker::Error::RustError(format!(
                        "fixture event pre-materialization: {error:#}"
                    ))
                })?;
                if materialized == 0 {
                    break;
                }
            }
            let webhook_id = db
                .seed_webhook_for_test(
                    1,
                    "https://hooks.example.test/aos",
                    "worker://e2e/webhook/v1",
                    "0000000000000000000000000000000000000000000000000000000000000000",
                    &[],
                )
                .await
                .map_err(|error| worker::Error::RustError(format!("webhook fixture: {error:#}")))?;
            for event_name in ["webhook.created", "webhook.deleted"] {
                db.seed_topology_event_for_test(
                    event_name,
                    "org:00000000000000000000000000000001",
                    "webhook",
                    &format!("webhook:{webhook_id}"),
                )
                .await
                .map_err(|error| worker::Error::RustError(format!("webhook outbox: {error:#}")))?;
            }
            let materialized = db.materialize_topology_events().await.map_err(|error| {
                worker::Error::RustError(format!("webhook materialization: {error:#}"))
            })?;
            if materialized != 2
                || db
                    .claim_due_deliveries(now_for_worker().saturating_add(60), 10, 30)
                    .await
                    .map_err(|error| {
                        worker::Error::RustError(format!("webhook claims: {error:#}"))
                    })?
                    .len()
                    != 2
                || !db
                    .seed_delete_webhook_for_test(webhook_id)
                    .await
                    .map_err(|error| {
                        worker::Error::RustError(format!("webhook delete: {error:#}"))
                    })?
            {
                return Err(worker::Error::RustError(
                    "Worker DO webhook lifecycle assertion failed".into(),
                ));
            }
            let user_id = db
                .create_user("workerd@example.test", None)
                .await
                .map_err(|error| worker::Error::RustError(format!("e2e user: {error:#}")))?;
            db.grant_membership("user", user_id, "instance", Role::Owner.as_str())
                .await
                .map_err(|error| worker::Error::RustError(format!("e2e grant: {error:#}")))?;
            let session = db
                .create_session(user_id, 3_600, 0)
                .await
                .map_err(|error| worker::Error::RustError(format!("e2e session: {error:#}")))?;
            let jwt = JwtKeys::from_secret(self.env.secret(HUB_JWT_SECRET)?.to_string().as_bytes());
            let token = jwt
                .mint(
                    &TokenAuth {
                        token_id: "workerd-e2e".into(),
                        owner: Principal::user(user_id),
                        scope: Scope::root(),
                        permissions: vec![
                            Permission::IamAdmin,
                            Permission::RegistryConfigure,
                            Permission::Publish,
                            Permission::Read,
                        ],
                    },
                    3_600,
                )
                .map_err(|error| worker::Error::RustError(format!("e2e token: {error:#}")))?;
            Response::from_json(&serde_json::json!({
                "token": token,
                "session": session,
                "raw_key": image_fixture.raw_key,
                "qcow2_key": image_fixture.qcow2_key,
                "gc_root_count": gc_root_count,
            }))
        }
    }
}
