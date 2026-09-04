//! The Cloudflare Workers runtime for the AOS registry hub (RFC-0004).
//!
//! RFC-0004 specifies a Cloudflare Workers deployment of the registry hub —
//! `wasm32-unknown-unknown` via `workers-rs`, with a colocated-SQLite system of record, R2
//! as zero-egress storage, KV for sessions, and Cron Triggers driving the
//! indexer ("Architecture and runtime targets"). The native hub is a sync
//! axum + tokio + rusqlite binary that cannot compile to wasm32, so this is a
//! **separate Worker crate** implementing the RFC's Cloudflare deployment. It
//! deliberately reuses the pure, shared crates rather than porting the native
//! hub:
//!
//! - [`aos_registry_surface`] — the wasm-clean reader (objects, tags, refs,
//!   Ed25519 verification) the native hub indexer and `apm` already run, reused
//!   verbatim in the Cron indexer ([`indexer`]).
//! - [`aos_hub_core`] — the shared `Database` (schema `MIGRATIONS` + read
//!   queries) the native hub runs. Application requests execute in
//!   resource-affine Durable Objects over [`remotebackend`], while the
//!   authoritative `HubDb` owns checked transactions through
//!   [`sqldobackend`].
//! - The shared machine-object classification in [`aos_hub_core::keymap`] — re-exported
//!   through [`keymap`] for Worker object-key mapping.
//!
//! # Request and storage architecture
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
//! - exact domain/IP endpoints and routes, resolved before delegating
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
//! Browser authentication and the management application shell are served by
//! the same shared router too: the Worker builds a
//! [`ConsoleDeps`](aos_hub_core::web::console::ConsoleDeps) over its console
//! ports ([`consoleports`]) and merges
//! [`console_router`](aos_hub_core::web::console::console_router) onto the
//! RPC/facade/browse router. The identical hermetic Leptos bundle performs all
//! resource reads and reviewed mutations through `aos.hub.v1` on both
//! runtimes. Registries whose canonical paths contain slashes are offered to
//! the shared nested dispatcher before delivery-route and facade routing.
//!
//! The outer `fetch` handler assigns public requests to deterministic control,
//! tenant, registry, or cache execution objects. Those objects bridge to the
//! shared router and make only short, seal-gated SQL calls to `HubDb`; they do
//! not copy relational state. Internal and administrative endpoints remain
//! pinned to `HubDb`. The schema is migrated there on first use (no external
//! init step), and the root admin is bootstrapped over a seal-gated endpoint.
//! Cron and queue handlers run outside the database object and likewise keep
//! provider or network I/O outside its serialized request turn. See `README.md`
//! and the RFC.
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
//! - `indexer` — the queued reconciler: runs the shared
//!   [`aos_hub_core::indexer`] over each registry's R2 [`surface`] fetcher in
//!   the queue isolate while short SQL operations cross through `remotebackend`.
//! - `remotebackend` — the seal-gated SQL transport used by background jobs;
//!   checked batches remain atomic inside `HubDb`, while provider I/O does not
//!   occupy the database object's request turn.
//! - `requestshard` — deterministic public-request affinity and staged
//!   `off`/`read`/`on` cutover classification.
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
#[cfg(any(target_arch = "wasm32", test))]
mod frozen_surface_access;
#[cfg(target_arch = "wasm32")]
pub mod handlers;
#[cfg(target_arch = "wasm32")]
pub mod indexer;
// Pure (no `worker`/wasm dependency) DO-SQLite placeholder translation, so it
// is unit-tested on the native target too — see [`placeholder`].
pub mod placeholder;
pub(crate) mod r2_adapter;
#[cfg(target_arch = "wasm32")]
mod remotebackend;
mod remoteprotocol;
mod requestshard;
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

/// Derives the stable identity of one registry's current index input.
///
/// Queue envelopes deliberately have unique operation IDs, but several publish
/// or maintenance events may request the same derived index. Fencing builds by
/// the configuration version, publication identity, and selected placement
/// coalesces those duplicates while still admitting a new build whenever an
/// input changes. The placement identity matters during topology cutover: the
/// same publication may become readable from a newly reconciled placement
/// after an earlier source returned an unchanged or stale surface.
fn registry_index_build_id(
    registry_id: i64,
    registry_resource_version: i64,
    publication_id: Option<&str>,
    placement_id: i64,
) -> String {
    use sha2::{Digest as _, Sha256};

    let mut digest = Sha256::new();
    digest.update(b"aos-registry-index-build-v2\0");
    digest.update(registry_id.to_be_bytes());
    digest.update(registry_resource_version.to_be_bytes());
    digest.update(placement_id.to_be_bytes());
    match publication_id {
        Some(publication_id) => {
            digest.update([1]);
            digest.update(publication_id.as_bytes());
        }
        None => digest.update([0]),
    }
    hex::encode(digest.finalize())
}

#[cfg(any(test, target_arch = "wasm32"))]
fn oci_inventory_follow_up(
    envelope: &aos_hub_core::jobs::JobEnvelope,
    cursor: Option<String>,
) -> anyhow::Result<Option<aos_hub_core::jobs::JobEnvelope>> {
    cursor
        .map(|cursor| envelope.continued(aos_hub_core::jobs::Job::InventoryOciProviders, cursor))
        .transpose()
}

#[cfg(any(test, target_arch = "wasm32"))]
fn scheduled_maintenance_jobs(
    rollout: aos_hub_core::container_rollout::ContainerRollout,
) -> Vec<aos_hub_core::jobs::Job> {
    let mut jobs = vec![
        aos_hub_core::jobs::Job::RunTopologyProbes,
        aos_hub_core::jobs::Job::RecoverCacheWrites,
        aos_hub_core::jobs::Job::RecoverOciUploads,
        aos_hub_core::jobs::Job::RunCacheGc,
        aos_hub_core::jobs::Job::RebuildDirectory,
    ];
    if rollout.garbage_collection {
        jobs.extend([
            aos_hub_core::jobs::Job::InventoryOciProviders,
            aos_hub_core::jobs::Job::ProbeOciConditionalDeletes,
            aos_hub_core::jobs::Job::RunOciGc,
        ]);
    }
    jobs
}

/// Controls which requests the outer Worker may move onto execution shards.
#[cfg(any(test, target_arch = "wasm32"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestShardingMode {
    Off,
    ReadOnly,
    On,
}

#[cfg(any(test, target_arch = "wasm32"))]
impl RequestShardingMode {
    /// Returns whether a route with the given mutability may use a shard.
    fn allows(self, read_only: bool) -> bool {
        match self {
            Self::Off => false,
            Self::ReadOnly => read_only,
            Self::On => true,
        }
    }
}

#[cfg(test)]
mod index_build_identity_tests {
    use super::{
        oci_inventory_follow_up, registry_index_build_id, scheduled_maintenance_jobs,
        RequestShardingMode,
    };

    #[test]
    fn identity_coalesces_duplicates_and_tracks_every_input_version() {
        let original = registry_index_build_id(7, 3, Some("publication-a"), 11);
        assert_eq!(
            original,
            registry_index_build_id(7, 3, Some("publication-a"), 11)
        );
        assert_ne!(
            original,
            registry_index_build_id(7, 4, Some("publication-a"), 11)
        );
        assert_ne!(
            original,
            registry_index_build_id(7, 3, Some("publication-b"), 11)
        );
        assert_ne!(original, registry_index_build_id(7, 3, None, 11));
        assert_ne!(
            original,
            registry_index_build_id(7, 3, Some("publication-a"), 12)
        );
    }

    #[test]
    fn sharding_modes_preserve_the_read_only_cutover_for_oci_methods() {
        for method in ["GET", "HEAD"] {
            let route = crate::requestshard::classify_oci_repository(
                method,
                "registry-00000000000000000000000000000001",
                &aos_oci_types::RepositoryName::parse("team/aos").unwrap(),
            );
            assert!(!RequestShardingMode::Off.allows(route.read_only));
            assert!(RequestShardingMode::ReadOnly.allows(route.read_only));
            assert!(RequestShardingMode::On.allows(route.read_only));
        }

        for method in ["POST", "PATCH", "PUT", "DELETE"] {
            let route = crate::requestshard::classify_oci_repository(
                method,
                "registry-00000000000000000000000000000001",
                &aos_oci_types::RepositoryName::parse("team/aos").unwrap(),
            );
            assert!(!RequestShardingMode::Off.allows(route.read_only));
            assert!(!RequestShardingMode::ReadOnly.allows(route.read_only));
            assert!(RequestShardingMode::On.allows(route.read_only));
        }
    }

    #[test]
    fn worker_maintenance_never_schedules_provider_gc_while_rollout_is_disabled() {
        use aos_hub_core::jobs::Job;

        let disabled = aos_hub_core::container_rollout::ContainerRollout::default();
        let disabled_jobs = scheduled_maintenance_jobs(disabled);
        assert!(!disabled_jobs.iter().any(|job| matches!(
            job,
            Job::InventoryOciProviders | Job::ProbeOciConditionalDeletes | Job::RunOciGc
        )));

        let enabled_jobs =
            scheduled_maintenance_jobs(aos_hub_core::container_rollout::ContainerRollout {
                garbage_collection: true,
                ..disabled
            });
        assert!(enabled_jobs
            .iter()
            .any(|job| matches!(job, Job::InventoryOciProviders)));
        assert!(enabled_jobs
            .iter()
            .any(|job| matches!(job, Job::ProbeOciConditionalDeletes)));
        assert!(enabled_jobs.iter().any(|job| matches!(job, Job::RunOciGc)));
    }

    #[test]
    fn inventory_continuations_are_deterministic_bounded_queue_children() {
        use aos_hub_core::jobs::{Job, JobEnvelope};

        let root = JobEnvelope::new(Job::InventoryOciProviders);
        let cursor = "oci-provider-inventory-v1:generation:claim".to_string();
        let first = oci_inventory_follow_up(&root, Some(cursor.clone()))
            .unwrap()
            .unwrap();
        let replay = oci_inventory_follow_up(&root, Some(cursor))
            .unwrap()
            .unwrap();
        assert_eq!(first, replay);
        assert_eq!(first.job, Job::InventoryOciProviders);
        assert_eq!(first.continuation.as_ref().unwrap().sequence, 1);
        assert!(oci_inventory_follow_up(&first, None).unwrap().is_none());

        let maximum = "x".repeat(2_048);
        assert!(oci_inventory_follow_up(&root, Some(maximum)).is_ok());
        let oversized = "x".repeat(2_049);
        assert!(oci_inventory_follow_up(&root, Some(oversized)).is_err());
    }
}

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

    use futures_util::{lock::Mutex, stream, StreamExt};
    use wasm_bindgen::JsCast;
    use worker::{
        durable_object, Cache, Context, DurableObject, Env, MessageExt, Method, Request, Response,
        Result, ScheduleContext, ScheduledEvent, State,
    };

    use aos_hub_core::auth::jwt::JwtKeys;
    use aos_hub_core::db::Database;
    #[cfg(feature = "do-e2e")]
    use aos_hub_core::db::TokenAuth;
    #[cfg(feature = "do-e2e")]
    use aos_hub_core::domain::{Permission, Principal, Role, Scope};
    use aos_hub_core::fetch::SurfaceProvider as _;
    use aos_hub_core::kv::KvStore as _;
    use aos_hub_core::ratelimit::RateLimiter;
    use aos_hub_core::service::RpcService;
    use aos_hub_core::web::console::{console_router, ConsoleDeps};
    use axum::Router;

    use crate::consoleports::{
        sealer_from_secret, WorkerCloudflareControlPlaneClient, WorkerEgressClient,
        WorkerHttpClient, WorkerMailer, WorkerReindexer, WorkerStorageCredentialProbeProvider,
    };
    use crate::{scheduled_maintenance_jobs, RequestShardingMode};

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
    /// Staged request-execution cutover: `off`, `read`, or `on`.
    const HUB_REQUEST_SHARDING: &str = "HUB_REQUEST_SHARDING";
    /// Optional fail-closed OCI Distribution pull rollout flag.
    const HUB_OCI_PULL_ENABLED: &str = "HUB_OCI_PULL_ENABLED";
    /// Optional fail-closed OCI Distribution push rollout flag.
    const HUB_OCI_PUSH_ENABLED: &str = "HUB_OCI_PUSH_ENABLED";
    /// Optional fail-closed verified container-publication rollout flag.
    const HUB_OCI_VERIFIED_PUBLICATION_ENABLED: &str = "HUB_OCI_VERIFIED_PUBLICATION_ENABLED";
    /// Optional fail-closed container-administration rollout flag.
    const HUB_OCI_ADMINISTRATION_ENABLED: &str = "HUB_OCI_ADMINISTRATION_ENABLED";
    /// Optional fail-closed container garbage-collection rollout flag.
    const HUB_OCI_GC_ENABLED: &str = "HUB_OCI_GC_ENABLED";
    /// Non-cacheable endpoint exposing [`HUB_DEPLOYMENT_ID`].
    const DEPLOYMENT_ID_PATH: &str = "/.well-known/aos-deployment";
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

    fn request_sharding_mode(env: &Env) -> Result<RequestShardingMode> {
        match env
            .var(HUB_REQUEST_SHARDING)
            .map(|value| value.to_string())
            .unwrap_or_else(|_| "off".to_string())
            .as_str()
        {
            "off" => Ok(RequestShardingMode::Off),
            "read" => Ok(RequestShardingMode::ReadOnly),
            "on" => Ok(RequestShardingMode::On),
            value => Err(worker::Error::RustError(format!(
                "{HUB_REQUEST_SHARDING} must be off, read, or on; got {value:?}"
            ))),
        }
    }

    fn container_rollout(env: &Env) -> Result<aos_hub_core::container_rollout::ContainerRollout> {
        Ok(aos_hub_core::container_rollout::ContainerRollout {
            pull: rollout_flag(env, HUB_OCI_PULL_ENABLED)?,
            push: rollout_flag(env, HUB_OCI_PUSH_ENABLED)?,
            verified_publication: rollout_flag(env, HUB_OCI_VERIFIED_PUBLICATION_ENABLED)?,
            administration: rollout_flag(env, HUB_OCI_ADMINISTRATION_ENABLED)?,
            garbage_collection: rollout_flag(env, HUB_OCI_GC_ENABLED)?,
        })
    }

    fn rollout_flag(env: &Env, name: &str) -> Result<bool> {
        match env
            .var(name)
            .map(|value| value.to_string())
            .unwrap_or_else(|_| "false".to_string())
            .as_str()
        {
            "true" => Ok(true),
            "false" => Ok(false),
            value => Err(worker::Error::RustError(format!(
                "{name} must be true or false; got {value:?}"
            ))),
        }
    }

    fn request_shard_binding(kind: crate::requestshard::RequestShardKind) -> &'static str {
        use crate::requestshard::RequestShardKind;

        match kind {
            RequestShardKind::Control => crate::handlers::bindings::HUB_CONTROL_SHARDS,
            RequestShardKind::Tenant => crate::handlers::bindings::HUB_TENANT_SHARDS,
            RequestShardKind::Registry => crate::handlers::bindings::HUB_REGISTRY_SHARDS,
            RequestShardKind::Cache => crate::handlers::bindings::HUB_CACHE_SHARDS,
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum AnonymousBrowseTarget {
        Instance,
        Registry(String),
    }

    fn anonymous_browse_target(req: &Request) -> Result<Option<AnonymousBrowseTarget>> {
        let url = req.url()?;
        let headers = req.headers();
        let accept = headers.get("accept")?;
        let authorization_present = headers.has("authorization")?;
        let session_cookie_present = headers
            .get("cookie")?
            .is_some_and(|cookie| cookie.contains("__Host-aos_session="));
        let route = crate::requestshard::anonymous_browse_route(
            req.method().as_ref(),
            url.path(),
            accept.as_deref(),
            authorization_present,
            session_cookie_present,
        );
        Ok(route.map(|route| match route {
            crate::requestshard::AnonymousBrowseRoute::Instance => AnonymousBrowseTarget::Instance,
            crate::requestshard::AnonymousBrowseRoute::Registry(slug) => {
                AnonymousBrowseTarget::Registry(slug.to_string())
            }
        }))
    }

    fn anonymous_browse_cache_key(req: &Request, env: &Env) -> Result<Option<String>> {
        if req.method() != Method::Get {
            return Ok(None);
        }
        if req.url()?.query().is_some() {
            return Ok(None);
        }
        browse_cache_key_url(req.url()?, env).map(Some)
    }

    fn browse_cache_key_url(mut url: url::Url, env: &Env) -> Result<String> {
        let deployment = env
            .var(HUB_DEPLOYMENT_ID)
            .map(|value| value.to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        url.query_pairs_mut()
            .append_pair("__aos_browse_deployment", &deployment);
        Ok(url.to_string())
    }

    async fn purge_registry_browse_cache(env: &Env, slug: &str) -> Result<()> {
        let origin = env
            .var(HUB_EXTERNAL_URL)
            .map_err(|_| worker::Error::RustError(format!("{HUB_EXTERNAL_URL} is required")))?;
        let mut url = url::Url::parse(&origin.to_string())
            .map_err(|error| worker::Error::RustError(format!("browse cache origin: {error}")))?;
        let cache = Cache::default();
        for path in [
            "/".to_string(),
            format!("/{slug}/"),
            format!("/{slug}/-/packages"),
            format!("/{slug}/-/images"),
            format!("/{slug}/-/containers"),
            // Query-bearing container detail pages are deliberately not
            // cached; purging the canonical index prevents stale discovery.
            format!("/{slug}/-/channels"),
            format!("/{slug}/-/releases"),
            format!("/{slug}/-/health"),
        ] {
            url.set_path(&path);
            url.set_query(None);
            let key = browse_cache_key_url(url.clone(), env)?;
            let _ = cache.delete(key, false).await?;
        }
        Ok(())
    }

    async fn request_execution_route(
        req: &Request,
        env: &Env,
    ) -> Result<Option<crate::requestshard::RequestShardRoute>> {
        if anonymous_browse_target(req)?.is_some() {
            return Ok(None);
        }
        let mode = request_sharding_mode(env)?;
        if !mode.allows(true) {
            return Ok(None);
        }
        let url = req.url()?;
        let path = url.path();
        let request_method = req.method();
        let method = request_method.as_ref();
        if path.starts_with("/_internal/") || path.starts_with("/_admin/") {
            return Ok(None);
        }
        if let Some(repository) = crate::requestshard::oci_repository_from_path(path) {
            let Some(authority) = crate::requestshard::canonical_oci_authority(&url) else {
                return Ok(None);
            };
            let projection_key = aos_hub_core::oci::oci_route_projection_key(&authority);
            let kv =
                crate::workerkv::WorkerKv::new(env.kv(crate::handlers::bindings::KV_SESSIONS)?);
            let Some(registry_stable_id) = kv
                .get_str(&projection_key)
                .await
                .map_err(|error| {
                    worker::Error::RustError(format!(
                        "read OCI route projection {projection_key}: {error:#}"
                    ))
                })?
                .filter(|stable_id| crate::requestshard::canonical_registry_stable_id(stable_id))
            else {
                // A cold/stale projection must not invent an authority-based
                // shard. HubDb resolves the route and writes through the exact
                // current stable registry incarnation for the next request.
                return Ok(None);
            };
            let route = crate::requestshard::classify_oci_repository(
                method,
                &registry_stable_id,
                &repository,
            );
            return Ok(mode.allows(route.read_only).then_some(route));
        }
        let authority = url.host_str().unwrap_or_default();
        let initial = crate::requestshard::classify_request(method, path, authority, None);
        let content_length = req
            .headers()
            .get("content-length")?
            .and_then(|value| value.parse::<usize>().ok());
        let json_content = req
            .headers()
            .get("content-type")?
            .is_some_and(|value| value.starts_with("application/json"));
        let body = if !initial.resource_specific
            && method == "POST"
            && json_content
            && content_length.is_some_and(|length| length <= 512 * 1024)
        {
            let mut cloned = req.clone()?;
            cloned.bytes().await.ok()
        } else {
            None
        };
        let route = crate::requestshard::classify_request(method, path, authority, body.as_deref());
        Ok(mode.allows(route.read_only).then_some(route))
    }

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

    /// Builds the complete shared router with the live-workerd storage adapter.
    #[cfg(feature = "do-e2e")]
    async fn router_from_do_e2e(
        state: &State,
        env: &Env,
        db: Arc<Database>,
    ) -> Result<(Router, Arc<RpcService>, ConsoleDeps)> {
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
        let mut service = RpcService::new(
            Arc::clone(&db),
            jwt_keys.clone(),
            external_url.clone(),
            Arc::clone(&rate_limiter),
            fetch,
            write,
            lease,
            Arc::new(DoE2eReindexer),
            Arc::new(
                aos_hub_core::topology_probe::DatabaseTopologyProbeScheduler::new(Arc::clone(&db)),
            ),
            None,
        )
        .with_container_rollout(container_rollout(env)?);
        if let Some(delivery_url) = default_public_delivery_url(env)? {
            service = service.with_default_public_delivery_url(delivery_url);
        }
        let service = Arc::new(service);
        let egress = worker_egress(env)?;
        let sealer = sealer_from_secret(&env.secret(HUB_SEAL_KEY)?.to_string())
            .map_err(|error| worker::Error::RustError(format!("e2e sealer: {error:#}")))?;
        let console_deps = ConsoleDeps {
            db,
            jwt_keys,
            external_url,
            dev: false,
            ratelimit: rate_limiter,
            mailer: Arc::new(WorkerMailer::new(
                None,
                None,
                None,
                None,
                Arc::clone(&egress),
            )),
            sealer,
            http: Arc::new(WorkerHttpClient::new(egress)),
            control: Some(Arc::clone(&service)),
        };
        let router = aos_hub_core::connect::router(Arc::clone(&service))
            .merge(console_router(console_deps.clone()));
        Ok((router, service, console_deps))
    }

    /// Builds the shared `axum` router over a database backend and R2 bindings.
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
    /// - the browser identity and application-shell router ([`console_router`])
    ///   built from [`ConsoleDeps`], the Worker's [`WorkerMailer`] and
    ///   [`WorkerHttpClient`], and the shared AES-GCM sealer from
    ///   `HUB_SEAL_KEY`.
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
    /// The authoritative `HubDb` caller supplies a colocated
    /// [`SqlDoBackend`](crate::sqldobackend). Resource-affine execution objects
    /// supply the seal-gated [`RemoteHubBackend`](crate::remotebackend), which
    /// keeps transaction ownership in `HubDb`. Everything else (JWT,
    /// rate-limit bindings, surface, lease, reindexer, and KV projections) is
    /// built from `env`.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum RouterRuntimeKind {
        Colocated,
        ExecutionShard,
    }

    async fn router_from(
        env: &Env,
        db: Arc<Database>,
        runtime_kind: RouterRuntimeKind,
    ) -> Result<(
        Router,
        Arc<RpcService>,
        ConsoleDeps,
        Option<Arc<aos_hub_core::delivery_attestation::DeliveryAttestationVerifier>>,
    )> {
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
        // console, or routes.
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
        if runtime_kind == RouterRuntimeKind::Colocated {
            route_reservation_keyring
                .validate_referenced_versions(&db)
                .await
                .map_err(|error| {
                    worker::Error::RustError(format!(
                        "{HUB_ROUTE_RESERVATION_KEYRING} cannot open this database: {error:#}"
                    ))
                })?;
        }
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
            aos_hub_core::topology_probe::ControllerOwnedRouteObservationProvider::new()
                .with_external(Arc::new(
                    aos_hub_core::topology_probe::CloudflareRouteControlPlane::new(
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
                let direct = aos_hub_core::topology_probe::SignedManifestRouteObservationProvider::from_signed_json(
                    &manifest.to_string(),
                    &public_key.to_string(),
                    aos_hub_core::clock::now_unix_secs(),
                    Arc::clone(&route_http),
                )
                .map_err(|error| worker::Error::RustError(format!("route publication manifest: {error:#}")))?;
                route_adapters = route_adapters.with_direct(Arc::new(direct));
            }
            (None, None) => {}
            _ => {
                return Err(worker::Error::RustError(format!(
                    "{HUB_ROUTE_PUBLICATION_MANIFEST} and {HUB_ROUTE_PUBLICATION_PUBLIC_KEY} must be configured together"
                )));
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

        // The cross-isolate publish lease and queued reindexer back the
        // shared facade-write handler on the Worker. The lease lives in the
        // Durable Object coordinator (one serialized instance owns the lease);
        // indexing runs through the durable job consumer so a large registry
        // cannot extend an already-committed request beyond its client timeout.
        // The periodic Cron remains the backstop if queue admission fails.
        let lease: Arc<dyn aos_hub_core::lease::PublishLease> = Arc::new(
            aos_hub_core::lease::CoordinatorLease::new(Arc::clone(&coordinator)),
        );
        let reindexer: Arc<dyn aos_hub_core::reindex::Reindexer> =
            Arc::new(aos_hub_core::reindex::QueuedReindexer::new(Arc::new(
                crate::workerqueue::WorkerQueue::from_env(env)?,
            )));

        let mut service = RpcService::new(
            Arc::clone(&db),
            jwt_keys.clone(),
            external_url.clone(),
            Arc::clone(&ratelimit),
            Arc::clone(&surface),
            Arc::clone(&surface_write),
            Arc::clone(&lease),
            Arc::clone(&reindexer),
            Arc::new(
                aos_hub_core::topology_probe::DatabaseTopologyProbeScheduler::new(Arc::clone(&db))
                    .with_wakeup(Arc::new(crate::workerqueue::WorkerQueue::from_env(env)?)),
            ),
            Some(Arc::clone(&sealer)),
        )
        .with_container_rollout(container_rollout(env)?)
        .with_secret_versions(Arc::clone(&secret_versions))
        .with_origin_fetch(Arc::new(crate::surface::WorkerOriginFetch::new(
            Arc::clone(&egress),
        )))
        .with_domain_probe_terminator(domain_probe_terminator)
        .with_identity_domain_verifier(Arc::new(
            aos_hub_core::topology_probe::DnsJsonIdentityDomainVerifier::new(
                Arc::clone(&route_http),
                dns_endpoint.to_string(),
            ),
        ))
        .with_route_reservation_keyring(route_reservation_keyring)
        // RFC-0004 ch.14 Phase C: read-through cache hot point-key state
        // (sessions/tokens/config/routing) off the relational read path via Workers
        // KV (the `SESSIONS` namespace). When the binding is absent the
        // service falls back to the database (the pre-Phase-C path).
        .with_kv(Arc::new(crate::workerkv::WorkerKv::new(
            env.kv(crate::handlers::bindings::KV_SESSIONS)?,
        )));
        let service = Arc::new(service);

        // Seed the editable site chrome (title/banner/footer) from HubDb once per
        // isolate, so a fresh isolate reflects persisted branding. A branding
        // save updates the live chrome via `set_site_chrome`; other isolates
        // pick it up on recycle. Guarded so the hot path reads HubDb at most once
        // per isolate.
        if runtime_kind == RouterRuntimeKind::Colocated {
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
            control: Some(Arc::clone(&service)),
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
    async fn fetch(req: Request, env: Env, ctx: Context) -> Result<Response> {
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

        #[cfg(feature = "do-e2e")]
        if req.method() == Method::Post && req.url()?.path() == "/_e2e/direct-egress" {
            return match crate::consoleports::e2e_assert_direct_egress().await {
                Ok(()) => Response::ok("ok"),
                Err(error) => Response::error(format!("direct egress contract: {error:#}"), 500),
            };
        }

        let browse_target = anonymous_browse_target(&req)?;
        let browse_cache_key = match browse_target.as_ref() {
            Some(_) => anonymous_browse_cache_key(&req, &env)?,
            None => None,
        };
        if let Some(cache_key) = browse_cache_key.as_ref() {
            if let Some(response) = Cache::default().get(cache_key, false).await? {
                let headers = response.headers().clone();
                headers.set("cache-control", "private, no-store")?;
                headers.set("server-timing", "hubedgecache;dur=0;desc=\"hit\"")?;
                headers.set("x-aos-browse-cache", "hit")?;
                return Ok(response.with_headers(headers));
            }
        }

        // `HubDb` remains the only relational system of record. During the
        // staged execution-shard cutover, the outer Worker routes application
        // work to a control singleton or a resource-affine tenant, registry, or
        // cache object. Those objects run the shared router and use short,
        // seal-gated SQL calls into HubDb. `off` (and internal/admin requests)
        // retains the legacy direct HubDb path; `read` moves only read methods;
        // `on` moves the complete public request surface.
        let database_instance = env
            .var("HUB_DATABASE_INSTANCE")
            .map(|value| value.to_string())
            .unwrap_or_else(|_| "hub".to_string());
        let route = request_execution_route(&req, &env).await?;
        let (binding, instance_name, timing_name, shard_kind) = match route.as_ref() {
            Some(route) => (
                request_shard_binding(route.kind),
                route.instance_name(&database_instance),
                "hubshard",
                route.kind.as_str(),
            ),
            None => (
                crate::handlers::bindings::HUB_DB,
                database_instance,
                "hubdb",
                "database",
            ),
        };
        let invalidates_browse = req.url().ok().is_some_and(|url| {
            crate::requestshard::invalidates_browse_directory(req.method().as_ref(), url.path())
        });
        let stub = env
            .durable_object(binding)?
            .id_from_name(&instance_name)
            .and_then(|id| id.get_stub_with_location_hint("wnam"))?;
        let started_at = worker::Date::now().as_millis();
        let resp = stub.fetch_with_request(req).await?;
        let duration_ms = worker::Date::now().as_millis().saturating_sub(started_at);
        let prior_timing = resp
            .headers()
            .get("server-timing")?
            .filter(|value| !value.is_empty());
        let timing = prior_timing
            .map(|prior| format!("{prior}, {timing_name};dur={duration_ms}"))
            .unwrap_or_else(|| format!("{timing_name};dur={duration_ms}"));
        // Responses returned by Durable Object fetches carry the Fetch API's
        // immutable header guard. Replace that view with an owned header copy
        // before adding edge timing and routing evidence, while preserving the
        // original response body, status, and encoding configuration.
        let headers = resp.headers().clone();
        headers.set("server-timing", &timing)?;
        headers.set("x-aos-hub-shard", shard_kind)?;
        let mut resp = resp.with_headers(headers);
        if let Some(cache_key) = browse_cache_key {
            let content_is_html = resp
                .headers()
                .get("content-type")?
                .is_some_and(|value| value.starts_with("text/html"));
            if resp.status_code() == 200 && content_is_html && !resp.headers().has("set-cookie")? {
                let cached = resp.cloned()?;
                let cached_headers = cached.headers().clone();
                cached_headers.set("cache-control", "public, max-age=10")?;
                cached_headers.set("x-aos-browse-cache", "stored")?;
                let cached = cached.with_headers(cached_headers);
                ctx.wait_until(async move {
                    if let Err(error) = Cache::default().put(cache_key, cached).await {
                        worker::console_error!("browse cache put: {error}");
                    }
                });
                let response_headers = resp.headers().clone();
                response_headers.set("cache-control", "private, no-store")?;
                response_headers.set("x-aos-browse-cache", "miss")?;
                resp = resp.with_headers(response_headers);
            }
        }
        if invalidates_browse && (200..300).contains(&resp.status_code()) {
            let kv =
                crate::workerkv::WorkerKv::new(env.kv(crate::handlers::bindings::KV_SESSIONS)?);
            let root_cache_key = env
                .var(HUB_EXTERNAL_URL)
                .ok()
                .and_then(|origin| url::Url::parse(&origin.to_string()).ok())
                .and_then(|mut url| {
                    url.set_path("/");
                    url.set_query(None);
                    browse_cache_key_url(url, &env).ok()
                });
            ctx.wait_until(async move {
                if let Err(error) = kv.delete(aos_hub_core::directory::DIRECTORY_KEY).await {
                    worker::console_error!("browse directory invalidation: {error:#}");
                }
                if let Some(cache_key) = root_cache_key {
                    if let Err(error) = Cache::default().delete(cache_key, false).await {
                        worker::console_error!("browse root cache invalidation: {error}");
                    }
                }
            });
        }
        worker::console_log!(
            "hub_edge_request status={} route={shard_kind} dispatch_ms={duration_ms}",
            resp.status_code()
        );

        Ok(resp)
    }

    /// Enqueues one short maintenance dispatcher for each Cron tick.
    ///
    /// Bound to a Cron schedule in `wrangler.toml`; mirrors the native hub's
    /// scheduled maintenance. The dispatcher reads topology only long enough
    /// to fan out bounded per-resource queue jobs; provider I/O never runs in
    /// the scheduled event.
    #[worker::event(scheduled)]
    async fn scheduled(_event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
        crate::tracinglog::init();
        use aos_hub_core::jobs::Queue as _;
        let result = match crate::workerqueue::WorkerQueue::from_env(&env) {
            Ok(queue) => {
                queue
                    .enqueue(&aos_hub_core::jobs::Job::DispatchMaintenance)
                    .await
            }
            Err(error) => Err(anyhow::anyhow!("maintenance queue binding: {error}")),
        };
        if let Err(error) = result {
            worker::console_error!("scheduled: enqueue maintenance: {error:#}");
        }
    }

    /// The Queue-trigger consumer: drain deferred post-write jobs (RFC-0004
    /// ch.14 Phase D).
    ///
    /// Decodes each [`Job`](aos_hub_core::jobs::Job) in the batch and runs it.
    /// Supported jobs execute network/provider work in the queue isolate and
    /// send short SQL operations to HubDb. Messages are acknowledged independently so
    /// one transient or malformed job cannot replay successful neighbors.
    #[worker::event(queue)]
    async fn queue(
        batch: worker::MessageBatch<aos_hub_core::jobs::JobEnvelope>,
        env: Env,
        _ctx: Context,
    ) -> Result<()> {
        crate::tracinglog::init();
        #[derive(serde::Deserialize)]
        #[serde(untagged)]
        enum QueuedJobBody {
            Versioned(aos_hub_core::jobs::JobEnvelope),
            Legacy(aos_hub_core::jobs::Job),
        }

        // Raw iteration keeps decode failures scoped to their own message. The
        // queue's configured retry limit moves a persistent poison message to
        // the dead-letter queue without replaying successfully acknowledged
        // jobs from the same delivery batch.
        stream::iter(batch.raw_iter())
            .for_each_concurrent(4, |message| {
                let env = &env;
                async move {
                    let message_id = message.id();
                    let queued_at = message.timestamp().as_millis();
                    let queue_age_ms = worker::Date::now().as_millis().saturating_sub(queued_at);
                    let envelope =
                        match serde_wasm_bindgen::from_value(message.body()) {
                            Ok(QueuedJobBody::Versioned(envelope)) => envelope,
                            Ok(QueuedJobBody::Legacy(job)) => {
                                aos_hub_core::jobs::JobEnvelope::from_legacy(job, &message_id)
                            }
                            Err(error) => {
                                worker::console_error!(
                                    "queue: message={message_id} age_ms={queue_age_ms} decode failed: {error}"
                                );
                                message.retry();
                                return;
                            }
                        };
                    let operation_id = envelope.operation_id.clone();
                    match run_job_envelope(&envelope, None, env).await {
                        Ok(()) => {
                            worker::console_log!(
                                "queue: message={message_id} operation={operation_id} age_ms={queue_age_ms} acknowledged"
                            );
                            message.ack();
                        }
                        Err(error) => {
                            worker::console_error!(
                                "queue: message={message_id} operation={operation_id} age_ms={queue_age_ms} failed: {error:#}"
                            );
                            message.retry();
                        }
                    }
                }
            })
            .await;
        Ok(())
    }

    fn job_backend(state: Option<&State>, env: &Env) -> Box<dyn aos_hub_core::backend::Backend> {
        match state {
            Some(state) => Box::new(crate::sqldobackend::SqlDoBackend::new(state.storage())),
            None => Box::new(crate::remotebackend::RemoteHubBackend::new(env)),
        }
    }

    async fn rebuild_worker_directory(db: &Database, env: &Env) -> Result<()> {
        let namespace = env.kv(crate::handlers::bindings::KV_SESSIONS)?;
        let kv = crate::workerkv::WorkerKv::new(namespace);
        aos_hub_core::directory::rebuild(db, &kv)
            .await
            .map(|_| ())
            .map_err(|error| {
                worker::Error::RustError(format!("rebuild registry directory: {error:#}"))
            })
    }

    /// Fans a maintenance tick out into independent bounded queue jobs.
    ///
    /// This database-only pass intentionally performs no provider, webhook,
    /// DNS, or KV I/O. A slow registry or cache therefore cannot hold the
    /// global database object for the duration of every other maintenance job.
    async fn run_cron(
        state: Option<&State>,
        env: &Env,
        parent: &aos_hub_core::jobs::JobEnvelope,
    ) -> Result<()> {
        let now = now_for_worker();
        let db = aos_hub_core::db::Database::attach(job_backend(state, env));
        db.prune_expired_invitation_secrets(now, 1_000)
            .await
            .map_err(|error| {
                worker::Error::RustError(format!("prune expired invitation credentials: {error:#}"))
            })?;
        let (_, newly_materialized_delivery_ids) = db
            .materialize_topology_events_with_delivery_ids()
            .await
            .map_err(|error| {
                worker::Error::RustError(format!("materialize webhook deliveries: {error:#}"))
            })?;
        let due_delivery_ids = db.list_due_delivery_ids(now, 100).await.map_err(|error| {
            worker::Error::RustError(format!("list due webhook deliveries: {error:#}"))
        })?;
        let registries = db
            .list_registries()
            .await
            .map_err(|error| worker::Error::RustError(format!("list registries: {error:#}")))?;
        let caches = db
            .list_binary_caches()
            .await
            .map_err(|error| worker::Error::RustError(format!("list caches: {error:#}")))?;

        let mut jobs = scheduled_maintenance_jobs(container_rollout(env)?);
        jobs.extend(
            registries
                .into_iter()
                .map(|registry| aos_hub_core::jobs::Job::Reindex {
                    registry_id: registry.id,
                }),
        );
        jobs.extend(
            caches
                .into_iter()
                .filter(|cache| cache.deleted_at.is_none())
                .map(|cache| aos_hub_core::jobs::Job::RescanCache { cache_id: cache.id }),
        );
        let delivery_ids = newly_materialized_delivery_ids
            .into_iter()
            .chain(due_delivery_ids)
            .collect::<std::collections::BTreeSet<_>>();
        jobs.extend(
            delivery_ids
                .into_iter()
                .map(|delivery_id| aos_hub_core::jobs::Job::DeliverWebhook { delivery_id }),
        );

        let envelopes = jobs
            .into_iter()
            .map(|job| {
                let cursor = match &job {
                    aos_hub_core::jobs::Job::RunTopologyProbes => "topology".to_string(),
                    aos_hub_core::jobs::Job::RecoverCacheWrites => "cache-recovery".to_string(),
                    aos_hub_core::jobs::Job::RecoverOciUploads => "oci-recovery".to_string(),
                    aos_hub_core::jobs::Job::RunCacheGc => "cache-gc".to_string(),
                    aos_hub_core::jobs::Job::RunOciGc => "oci-gc".to_string(),
                    aos_hub_core::jobs::Job::ProbeOciConditionalDeletes => {
                        "oci-conditional-delete-probes".to_string()
                    }
                    aos_hub_core::jobs::Job::InventoryOciProviders => {
                        "oci-provider-inventory".to_string()
                    }
                    aos_hub_core::jobs::Job::RebuildDirectory => "directory".to_string(),
                    aos_hub_core::jobs::Job::Reindex { registry_id } => {
                        format!("registry:{registry_id}")
                    }
                    aos_hub_core::jobs::Job::RescanCache { cache_id } => {
                        format!("cache:{cache_id}")
                    }
                    aos_hub_core::jobs::Job::DeliverWebhook { delivery_id } => {
                        format!("webhook:{delivery_id}")
                    }
                    _ => "maintenance".to_string(),
                };
                parent.continued(job, cursor)
            })
            .collect::<anyhow::Result<Vec<_>>>()
            .map_err(|error| {
                worker::Error::RustError(format!("build maintenance jobs: {error:#}"))
            })?;
        crate::workerqueue::WorkerQueue::from_env(env)?
            .enqueue_envelopes(&envelopes)
            .await
            .map_err(|error| {
                worker::Error::RustError(format!("enqueue maintenance jobs: {error:#}"))
            })?;
        worker::console_log!(
            "maintenance dispatch enqueued {} bounded jobs",
            envelopes.len()
        );
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

    /// Claims, executes, and durably completes one versioned queue operation.
    async fn run_job_envelope(
        envelope: &aos_hub_core::jobs::JobEnvelope,
        state: Option<&State>,
        env: &Env,
    ) -> Result<()> {
        use aos_hub_core::db::WorkerJobClaim;

        envelope
            .validate()
            .map_err(|error| worker::Error::RustError(format!("invalid envelope: {error:#}")))?;
        let payload_digest = envelope
            .payload_digest()
            .map_err(|error| worker::Error::RustError(format!("job payload digest: {error:#}")))?;
        let now = now_for_worker();
        let db = aos_hub_core::db::Database::attach(job_backend(state, env));
        let claim = db
            .claim_worker_job(
                &envelope.operation_id,
                envelope.kind(),
                &payload_digest,
                now,
                900,
            )
            .await
            .map_err(|error| worker::Error::RustError(format!("claim job: {error:#}")))?;
        let (claim_token, attempt) = match claim {
            WorkerJobClaim::Acquired {
                claim_token,
                attempt,
            } => (claim_token, attempt),
            WorkerJobClaim::Completed => {
                worker::console_log!(
                    "job operation={} kind={} duplicate completed",
                    envelope.operation_id,
                    envelope.kind()
                );
                return Ok(());
            }
            WorkerJobClaim::Busy => {
                return Err(worker::Error::RustError(format!(
                    "job operation {} is already running",
                    envelope.operation_id
                )));
            }
        };
        worker::console_log!(
            "job operation={} kind={} attempt={} started",
            envelope.operation_id,
            envelope.kind(),
            attempt
        );

        match run_job(envelope, state, env).await {
            Ok(()) => db
                .complete_worker_job(&envelope.operation_id, &claim_token, now_for_worker())
                .await
                .map_err(|error| worker::Error::RustError(format!("complete job: {error:#}"))),
            Err(error) => {
                let detail = aos_hub_core::jobs::redacted_job_failure(&format!("{error:#}"));
                if let Err(release_error) = db
                    .release_worker_job(
                        &envelope.operation_id,
                        &claim_token,
                        &detail,
                        now_for_worker(),
                    )
                    .await
                {
                    return Err(worker::Error::RustError(format!(
                        "{error:#}; releasing job claim failed: {release_error:#}"
                    )));
                }
                Err(error)
            }
        }
    }

    /// Runs one deferred [`Job`](aos_hub_core::jobs::Job) in its caller's isolate.
    ///
    /// Queue callers use the remote SQL backend; the retained internal endpoint
    /// uses colocated SQL for compatibility and runtime tests.
    async fn run_job(
        envelope: &aos_hub_core::jobs::JobEnvelope,
        state: Option<&State>,
        env: &Env,
    ) -> Result<()> {
        use aos_hub_core::jobs::Job;
        if !envelope.job.enabled_for(container_rollout(env)?) {
            worker::console_log!(
                "job operation={} kind={} skipped by rollout",
                envelope.operation_id,
                envelope.kind()
            );
            return Ok(());
        }
        let make = || job_backend(state, env);
        match &envelope.job {
            Job::DispatchMaintenance => run_cron(state, env, envelope).await?,
            Job::RunTopologyProbes => run_domain_probes(make(), env).await?,
            Job::RecoverCacheWrites => {
                let bucket = env.bucket(crate::handlers::bindings::R2).map_err(|error| {
                    worker::Error::RustError(format!(
                        "job recover cache writes R2 binding: {error}"
                    ))
                })?;
                let secret_versions = crate::secretversions::from_env(env).map_err(|error| {
                    worker::Error::RustError(format!(
                        "job recover cache writes secret versions: {error}"
                    ))
                })?;
                let egress = worker_egress(env)?;
                let db = Arc::new(aos_hub_core::db::Database::attach(make()));
                let provider = crate::surface::R2SurfaceProvider::new(
                    bucket.clone(),
                    Arc::clone(&db),
                    Arc::clone(&secret_versions),
                    Arc::clone(&egress),
                );
                let writers = crate::surface::R2SurfaceWriteProvider::new(
                    bucket,
                    Arc::clone(&db),
                    secret_versions,
                    egress,
                );
                let now = now_for_worker();
                aos_hub_core::cache_scan::reap_due_cache_tombstones(&db, now)
                    .await
                    .map_err(|error| {
                        worker::Error::RustError(format!("job recover cache tombstones: {error:#}"))
                    })?;
                aos_hub_core::cache_scan::recover_expired_cache_writes(
                    &db,
                    &provider,
                    &writers,
                    now,
                    aos_hub_core::cache_scan::MAX_CLEANUP_ITEMS_PER_PASS,
                )
                .await
                .map_err(|error| {
                    worker::Error::RustError(format!("job recover expired cache writes: {error:#}"))
                })?;
            }
            Job::RecoverOciUploads => {
                let bucket = env.bucket(crate::handlers::bindings::R2).map_err(|error| {
                    worker::Error::RustError(format!("job recover OCI uploads R2 binding: {error}"))
                })?;
                let secret_versions = crate::secretversions::from_env(env).map_err(|error| {
                    worker::Error::RustError(format!(
                        "job recover OCI uploads secret versions: {error}"
                    ))
                })?;
                let egress = worker_egress(env)?;
                let db = Arc::new(aos_hub_core::db::Database::attach(make()));
                let writers = crate::surface::R2SurfaceWriteProvider::new(
                    bucket,
                    Arc::clone(&db),
                    secret_versions,
                    egress,
                );
                aos_hub_core::oci::recover_expired_oci_work(&db, &writers, now_for_worker(), 100)
                    .await
                    .map_err(|error| {
                        worker::Error::RustError(format!("job recover OCI uploads: {error:#}"))
                    })?;
            }
            Job::RunCacheGc => {
                let bucket = env.bucket(crate::handlers::bindings::R2).map_err(|error| {
                    worker::Error::RustError(format!("job cache GC R2 binding: {error}"))
                })?;
                let secret_versions = crate::secretversions::from_env(env).map_err(|error| {
                    worker::Error::RustError(format!("job cache GC secret versions: {error}"))
                })?;
                let egress = worker_egress(env)?;
                let db = Arc::new(aos_hub_core::db::Database::attach(make()));
                let writers: Arc<dyn aos_hub_core::surface_write::SurfaceWriteProvider> =
                    Arc::new(crate::surface::R2SurfaceWriteProvider::new(
                        bucket,
                        Arc::clone(&db),
                        secret_versions,
                        egress,
                    ));
                aos_hub_core::gc_controller::CacheGcDeletionController::new(db, writers)
                    .run_due(now_for_worker(), 25)
                    .await
                    .map_err(|error| {
                        worker::Error::RustError(format!("job cache GC: {error:#}"))
                    })?;
            }
            Job::RunOciGc => {
                let bucket = env.bucket(crate::handlers::bindings::R2).map_err(|error| {
                    worker::Error::RustError(format!("job OCI GC R2 binding: {error}"))
                })?;
                let secret_versions = crate::secretversions::from_env(env).map_err(|error| {
                    worker::Error::RustError(format!("job OCI GC secret versions: {error}"))
                })?;
                let egress = worker_egress(env)?;
                let db = Arc::new(aos_hub_core::db::Database::attach(make()));
                let surfaces: Arc<dyn aos_hub_core::fetch::SurfaceProvider> =
                    Arc::new(crate::surface::R2SurfaceProvider::new(
                        bucket.clone(),
                        Arc::clone(&db),
                        Arc::clone(&secret_versions),
                        Arc::clone(&egress),
                    ));
                let writes: Arc<dyn aos_hub_core::surface_write::SurfaceWriteProvider> =
                    Arc::new(crate::surface::R2SurfaceWriteProvider::new(
                        bucket,
                        Arc::clone(&db),
                        secret_versions,
                        egress,
                    ));
                aos_hub_core::oci_gc_controller::OciGcDeletionController::new(db, surfaces, writes)
                    .run_due(
                        &format!("worker:{}", envelope.operation_id),
                        now_for_worker(),
                        25,
                    )
                    .await
                    .map_err(|error| worker::Error::RustError(format!("job OCI GC: {error:#}")))?;
            }
            Job::InventoryOciProviders => {
                let bucket = env.bucket(crate::handlers::bindings::R2).map_err(|error| {
                    worker::Error::RustError(format!(
                        "job OCI provider inventory R2 binding: {error}"
                    ))
                })?;
                let secret_versions = crate::secretversions::from_env(env).map_err(|error| {
                    worker::Error::RustError(format!(
                        "job OCI provider inventory secret versions: {error}"
                    ))
                })?;
                let egress = worker_egress(env)?;
                let db = Arc::new(aos_hub_core::db::Database::attach(make()));
                let surfaces: Arc<dyn aos_hub_core::fetch::SurfaceProvider> =
                    Arc::new(crate::surface::R2SurfaceProvider::new(
                        bucket,
                        Arc::clone(&db),
                        secret_versions,
                        egress,
                    ));
                let stats = aos_hub_core::oci_inventory_controller::OciProviderInventoryController::new(
                    db, surfaces,
                )
                .run_due_bounded(
                    "worker-oci-inventory",
                    &envelope.operation_id,
                    now_for_worker(),
                    25,
                    envelope
                        .continuation
                        .as_ref()
                        .map(|continuation| continuation.cursor.as_str()),
                    aos_hub_core::oci_inventory_controller::WORKER_OCI_INVENTORY_DISPATCH_BUDGET,
                )
                .await
                .map_err(|error| {
                    worker::Error::RustError(format!("job OCI provider inventory: {error:#}"))
                })?;
                if let Some(next) = crate::oci_inventory_follow_up(envelope, stats.continuation)
                    .map_err(|error| {
                        worker::Error::RustError(format!(
                            "build OCI provider inventory continuation: {error:#}"
                        ))
                    })?
                {
                    crate::workerqueue::WorkerQueue::from_env(env)?
                        .enqueue_envelopes(&[next])
                        .await
                        .map_err(|error| {
                            worker::Error::RustError(format!(
                                "enqueue OCI provider inventory continuation: {error:#}"
                            ))
                        })?;
                }
            }
            Job::ProbeOciConditionalDeletes => {
                let bucket = env.bucket(crate::handlers::bindings::R2).map_err(|error| {
                    worker::Error::RustError(format!("job OCI delete probes R2 binding: {error}"))
                })?;
                let secret_versions = crate::secretversions::from_env(env).map_err(|error| {
                    worker::Error::RustError(format!(
                        "job OCI delete probes secret versions: {error}"
                    ))
                })?;
                let egress = worker_egress(env)?;
                let db = Arc::new(aos_hub_core::db::Database::attach(make()));
                let surfaces: Arc<dyn aos_hub_core::fetch::SurfaceProvider> =
                    Arc::new(crate::surface::R2SurfaceProvider::new(
                        bucket.clone(),
                        Arc::clone(&db),
                        Arc::clone(&secret_versions),
                        Arc::clone(&egress),
                    ));
                let writes: Arc<dyn aos_hub_core::surface_write::SurfaceWriteProvider> =
                    Arc::new(crate::surface::R2SurfaceWriteProvider::new(
                        bucket,
                        Arc::clone(&db),
                        secret_versions,
                        egress,
                    ));
                aos_hub_core::conditional_delete_probe::ConditionalDeleteProbeController::new(
                    db, surfaces, writes,
                )
                .run_due(now_for_worker(), 10)
                .await
                .map_err(|error| {
                    worker::Error::RustError(format!("job OCI delete probes: {error:#}"))
                })?;
            }
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
                        let publication_state = db
                            .registry_publication_state(*registry_id)
                            .await
                            .map_err(|error| {
                            worker::Error::RustError(format!(
                                "job reindex {registry_id} publication state: {error:#}"
                            ))
                        })?;
                        let placement = db
                            .reconciled_surface_reader(aos_hub_core::db::SurfaceTarget::Registry(
                                *registry_id,
                            ))
                            .await
                            .map_err(|error| {
                                worker::Error::RustError(format!(
                                    "job reindex {registry_id} placement: {error:#}"
                                ))
                            })?;
                        let build_id = crate::registry_index_build_id(
                            *registry_id,
                            registry.resource_version,
                            publication_state
                                .as_ref()
                                .and_then(|state| state.current_publication_id.as_deref()),
                            placement.id,
                        );
                        let reindexer = WorkerReindexer::new(
                            bucket,
                            Arc::clone(&db),
                            secret_versions,
                            egress,
                            placement,
                        );
                        let claim = db
                            .claim_registry_index_build(
                                *registry_id,
                                &build_id,
                                now_for_worker(),
                                900,
                            )
                            .await
                            .map_err(|error| {
                                worker::Error::RustError(format!(
                                    "job reindex {registry_id} generation claim: {error:#}"
                                ))
                            })?;
                        let (owner_token, base_generation, target_generation) = match claim {
                            aos_hub_core::db::RegistryIndexBuildClaim::Acquired {
                                owner_token,
                                base_generation,
                                target_generation,
                            } => (owner_token, base_generation, target_generation),
                            aos_hub_core::db::RegistryIndexBuildClaim::Busy => {
                                worker::console_log!(
                                    "job reindex {registry_id}: another generation is building"
                                );
                                return Ok(());
                            }
                            aos_hub_core::db::RegistryIndexBuildClaim::AlreadyFinished => {
                                worker::console_log!(
                                    "job reindex {registry_id}: generation already finished"
                                );
                                rebuild_worker_directory(db.as_ref(), env).await?;
                                purge_registry_browse_cache(env, &registry.slug).await?;
                                return Ok(());
                            }
                        };
                        if let Err(error) = reindexer.reindex(&registry).await {
                            let detail =
                                aos_hub_core::jobs::redacted_job_failure(&format!("{error:#}"));
                            if let Err(failure_error) = db
                                .fail_registry_index_build(
                                    *registry_id,
                                    &build_id,
                                    &owner_token,
                                    &detail,
                                    now_for_worker(),
                                )
                                .await
                            {
                                return Err(worker::Error::RustError(format!(
                                    "job reindex {registry_id}: {error:#}; recording generation failure: {failure_error:#}"
                                )));
                            }
                            return Err(worker::Error::RustError(format!(
                                "job reindex {registry_id}: {error:#}"
                            )));
                        }
                        let status = db
                            .index_status(*registry_id)
                            .await
                            .map_err(|error| {
                                worker::Error::RustError(format!(
                                    "job reindex {registry_id} generation status: {error:#}"
                                ))
                            })?
                            .ok_or_else(|| {
                                worker::Error::RustError(format!(
                                    "job reindex {registry_id} generation status disappeared"
                                ))
                            })?;
                        db.complete_registry_index_build(
                            *registry_id,
                            &build_id,
                            &owner_token,
                            base_generation,
                            target_generation,
                            status.generation,
                            status.content_digest.as_deref(),
                            now_for_worker(),
                        )
                        .await
                        .map_err(|error| {
                            worker::Error::RustError(format!(
                                "job reindex {registry_id} generation completion: {error:#}"
                            ))
                        })?;
                        rebuild_worker_directory(db.as_ref(), env).await?;
                        purge_registry_browse_cache(env, &registry.slug).await?;
                    }
                    Ok(None) => worker::console_log!("job reindex {registry_id}: registry gone"),
                    Err(err) => {
                        return Err(worker::Error::RustError(format!(
                            "job reindex load {registry_id}: {err:#}"
                        )));
                    }
                }
            }
            Job::RescanCache { cache_id } => {
                let bucket = env.bucket(crate::handlers::bindings::R2).map_err(|error| {
                    worker::Error::RustError(format!("job rescan cache R2 binding: {error}"))
                })?;
                let secret_versions = crate::secretversions::from_env(env).map_err(|error| {
                    worker::Error::RustError(format!("job rescan cache secret versions: {error}"))
                })?;
                let egress = worker_egress(env)?;
                let db = Arc::new(aos_hub_core::db::Database::attach(make()));
                let Some(cache) = db.binary_cache_by_id(*cache_id).await.map_err(|error| {
                    worker::Error::RustError(format!("job rescan cache load {cache_id}: {error:#}"))
                })?
                else {
                    worker::console_log!("job rescan cache {cache_id}: cache gone");
                    return Ok(());
                };
                if cache.deleted_at.is_some() {
                    worker::console_log!("job rescan cache {cache_id}: cache deleted");
                    return Ok(());
                }
                let provider = crate::surface::R2SurfaceProvider::new(
                    bucket,
                    Arc::clone(&db),
                    secret_versions,
                    egress,
                );
                let stats = aos_hub_core::cache_scan::rescan_cache(&db, &provider, &cache)
                    .await
                    .map_err(|error| {
                        worker::Error::RustError(format!("job rescan cache {cache_id}: {error:#}"))
                    })?;
                worker::console_log!(
                    "job rescan cache {}: +{} -{} ={}",
                    cache_id,
                    stats.added,
                    stats.removed,
                    stats.unchanged
                );
            }
            Job::ResetIndex { registry_id } => {
                let db = aos_hub_core::db::Database::attach(make());
                let Some(registry) = db.registry_by_id(*registry_id).await.map_err(|error| {
                    worker::Error::RustError(format!(
                        "job reset index load {registry_id}: {error:#}"
                    ))
                })?
                else {
                    worker::console_log!("job reset index {registry_id}: registry gone");
                    return Ok(());
                };
                let placement = db
                    .reconciled_surface_reader(aos_hub_core::db::SurfaceTarget::Registry(
                        registry.id,
                    ))
                    .await
                    .map_err(|error| {
                        worker::Error::RustError(format!(
                            "job reset index placement {registry_id}: {error:#}"
                        ))
                    })?;
                db.mark_index_empty_from_placement(registry.id, placement.id)
                    .await
                    .map_err(|error| {
                        worker::Error::RustError(format!(
                            "job reset index {registry_id}: {error:#}"
                        ))
                    })?;
            }
            Job::RefreshPublicationObject {
                registry_id,
                object_key,
            } => {
                let Ok(bucket) = env.bucket(crate::handlers::bindings::R2) else {
                    return Err(worker::Error::RustError(
                        "job refresh publication object: R2 binding missing".into(),
                    ));
                };
                let secret_versions = crate::secretversions::from_env(env).map_err(|error| {
                    worker::Error::RustError(format!(
                        "job refresh publication object secret versions: {error}"
                    ))
                })?;
                let egress = worker_egress(env)?;
                let db = Arc::new(aos_hub_core::db::Database::attach(make()));
                let state = db
                    .registry_publication_state(*registry_id)
                    .await
                    .map_err(|error| {
                        worker::Error::RustError(format!(
                            "job refresh publication object state: {error:#}"
                        ))
                    })?
                    .ok_or_else(|| {
                        worker::Error::RustError(
                            "job refresh publication object: publication state missing".into(),
                        )
                    })?;
                let publication_id = state.current_publication_id.ok_or_else(|| {
                    worker::Error::RustError(
                        "job refresh publication object: current publication missing".into(),
                    )
                })?;
                let object = db
                    .registry_publication_upload_objects(&publication_id)
                    .await
                    .map_err(|error| {
                        worker::Error::RustError(format!(
                            "job refresh publication object manifest: {error:#}"
                        ))
                    })?
                    .into_iter()
                    .find(|object| object.object_key == *object_key)
                    .ok_or_else(|| {
                        worker::Error::RustError(
                            "job refresh publication object: object is not declared".into(),
                        )
                    })?;
                let placement = db
                    .reconciled_surface_reader(aos_hub_core::db::SurfaceTarget::Registry(
                        *registry_id,
                    ))
                    .await
                    .map_err(|error| {
                        worker::Error::RustError(format!(
                            "job refresh publication object placement: {error:#}"
                        ))
                    })?;
                let provider = crate::surface::R2SurfaceProvider::new(
                    bucket,
                    Arc::clone(&db),
                    secret_versions,
                    egress,
                );
                let fetch = provider
                    .placement_fetcher(&placement)
                    .await
                    .map_err(|error| {
                        worker::Error::RustError(format!(
                            "job refresh publication object fetcher: {error:#}"
                        ))
                    })?;
                let evidence = fetch
                    .inventory_evidence(object_key)
                    .await
                    .map_err(|error| {
                        worker::Error::RustError(format!(
                            "job refresh publication object read: {error:#}"
                        ))
                    })?
                    .ok_or_else(|| {
                        worker::Error::RustError(
                            "job refresh publication object: object is absent".into(),
                        )
                    })?;
                let observed_hash = hex::encode(evidence.sha256);
                if observed_hash != object.expected_hash || evidence.size != object.expected_size {
                    return Err(worker::Error::RustError(
                        "job refresh publication object: physical identity mismatch".into(),
                    ));
                }
                let etag = evidence.strong_etag.ok_or_else(|| {
                    worker::Error::RustError(
                        "job refresh publication object: strong version missing".into(),
                    )
                })?;
                let etag = aos_hub_core::surface_write::strong_if_match_etag(&etag)
                    .map_err(|error| worker::Error::RustError(format!("{error:#}")))?;
                db.refresh_ready_registry_publication_object_presence(
                    &publication_id,
                    object.surface_object_id,
                    placement.id,
                    &observed_hash,
                    evidence.size,
                    &etag,
                    now_for_worker(),
                )
                .await
                .map_err(|error| {
                    worker::Error::RustError(format!(
                        "job refresh publication object record: {error:#}"
                    ))
                })?;
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
                ));
            }
        }
        Ok(())
    }

    async fn run_domain_probes(
        backend: Box<dyn aos_hub_core::backend::Backend>,
        env: &Env,
    ) -> Result<()> {
        let endpoint = env.var(HUB_DNS_JSON_ENDPOINT).map_err(|error| {
            worker::Error::RustError(format!(
                "domain probes: {HUB_DNS_JSON_ENDPOINT} is not configured: {error}"
            ))
        })?;
        let db = Arc::new(aos_hub_core::db::Database::attach(backend));
        let tls_verifier = aos_hub_core::topology_probe::DomainTlsProbeVerifier::new();
        let egress = worker_egress(env)?;
        let route_http: Arc<dyn aos_hub_core::web::console::ports::HttpClient> =
            Arc::new(WorkerHttpClient::new(Arc::clone(&egress)));
        let mut controller = aos_hub_core::topology_probe::DomainProbeController::new(
            Arc::clone(&db),
            Arc::clone(&route_http),
            tls_verifier,
            endpoint.to_string(),
            "cloudflare-worker",
        )
        .map_err(|error| worker::Error::RustError(format!("domain probes: {error:#}")))?;
        let mut route_adapters =
            aos_hub_core::topology_probe::ControllerOwnedRouteObservationProvider::new()
                .with_external(Arc::new(
                    aos_hub_core::topology_probe::CloudflareRouteControlPlane::new(
                        Arc::new(WorkerCloudflareControlPlaneClient::new(
                            Arc::clone(&egress),
                            env.secret(HUB_CLOUDFLARE_API_TOKEN)
                                .map_err(|error| {
                                    worker::Error::RustError(format!(
                                    "domain probes: Cloudflare API token is not configured: {error}"
                                ))
                                })?
                                .to_string(),
                        )),
                        Arc::clone(&route_http),
                    ),
                ));
        match (
            env.secret(HUB_ROUTE_PUBLICATION_MANIFEST).ok(),
            env.var(HUB_ROUTE_PUBLICATION_PUBLIC_KEY).ok(),
        ) {
            (Some(manifest), Some(public_key)) => {
                let direct = match aos_hub_core::topology_probe::SignedManifestRouteObservationProvider::from_signed_json(
                    &manifest.to_string(),
                    &public_key.to_string(),
                    aos_hub_core::clock::now_unix_secs(),
                    route_http,
                ) {
                    Ok(direct) => direct,
                    Err(error) => {
                        return Err(worker::Error::RustError(format!(
                            "route publication manifest: {error:#}"
                        )));
                    }
                };
                route_adapters = route_adapters.with_direct(Arc::new(direct));
            }
            (None, None) => {}
            _ => {
                return Err(worker::Error::RustError(format!(
                    "{HUB_ROUTE_PUBLICATION_MANIFEST} and {HUB_ROUTE_PUBLICATION_PUBLIC_KEY} must be configured together"
                )));
            }
        }
        controller = controller.with_route_observer(Arc::new(route_adapters));
        let secret_versions = crate::secretversions::from_env(env).map_err(|error| {
            worker::Error::RustError(format!("storage credential probes: {error:#}"))
        })?;
        controller = controller.with_storage_credential_probe(Arc::new(
            WorkerStorageCredentialProbeProvider::new(
                Arc::clone(&egress),
                Arc::clone(&secret_versions),
            ),
        ));
        if let Err(error) = controller.run_due(25).await {
            worker::console_error!("domain probes: {error:#}");
        }
        match env.bucket(crate::handlers::bindings::R2) {
            Ok(bucket) => {
                let placement_scans = aos_hub_core::placement_scan::PlacementScanController::new(
                    Arc::clone(&db),
                    Arc::new(crate::surface::R2SurfaceProvider::new(
                        bucket.clone(),
                        Arc::clone(&db),
                        Arc::clone(&secret_versions),
                        Arc::clone(&egress),
                    )),
                )
                .with_writes(Arc::new(
                    crate::surface::R2SurfaceWriteProvider::new(
                        bucket,
                        Arc::clone(&db),
                        secret_versions,
                        Arc::clone(&egress),
                    ),
                ));
                if let Err(error) = placement_scans.run_due(5).await {
                    worker::console_error!("placement scans: {error:#}");
                }
            }
            Err(error) => {
                worker::console_error!("placement scans: R2 binding missing: {error}");
            }
        }
        Ok(())
    }

    /// Cached shared-router dependencies for one request-execution shard.
    #[derive(Clone)]
    struct HubShardRuntime {
        router: Router,
        service: Arc<RpcService>,
        console_deps: ConsoleDeps,
        remote_sql_metrics: crate::remotebackend::RemoteSqlMetrics,
        delivery_attestation_verifier:
            Option<Arc<aos_hub_core::delivery_attestation::DeliveryAttestationVerifier>>,
    }

    async fn shard_request_runtime(
        env: &Env,
        runtime: &Mutex<Option<HubShardRuntime>>,
    ) -> Result<HubShardRuntime> {
        let mut runtime = runtime.lock().await;
        if let Some(runtime) = runtime.as_ref() {
            return Ok(runtime.clone());
        }

        let remote_sql_metrics = crate::remotebackend::RemoteSqlMetrics::default();
        let db = Arc::new(Database::attach(Box::new(
            crate::remotebackend::RemoteHubBackend::with_metrics(env, remote_sql_metrics.clone()),
        )));
        let (router, service, console_deps, delivery_attestation_verifier) =
            router_from(env, db, RouterRuntimeKind::ExecutionShard).await?;
        let initialized = HubShardRuntime {
            router,
            service,
            console_deps,
            remote_sql_metrics,
            delivery_attestation_verifier,
        };
        *runtime = Some(initialized.clone());
        Ok(initialized)
    }

    async fn execute_sharded_request(
        shard: &'static str,
        env: &Env,
        runtime: &Mutex<Option<HubShardRuntime>>,
        req: Request,
    ) -> Result<Response> {
        crate::tracinglog::init();
        let path = req
            .url()
            .ok()
            .map(|url| url.path().to_string())
            .unwrap_or_else(|| "<invalid>".to_string());
        if path.starts_with("/_internal/") || path.starts_with("/_admin/") {
            return Response::error("not found", 404);
        }
        let method = format!("{:?}", req.method());
        let runtime = shard_request_runtime(env, runtime).await?;
        let started_at = worker::Date::now().as_millis();
        let sql_before = runtime.remote_sql_metrics.snapshot();
        let response = crate::bridge::dispatch(
            runtime.router,
            runtime.service.as_ref(),
            runtime.console_deps,
            runtime.delivery_attestation_verifier.as_deref(),
            req,
        )
        .await?;
        let duration_ms = worker::Date::now().as_millis().saturating_sub(started_at);
        let sql = runtime.remote_sql_metrics.snapshot().since(sql_before);
        let existing_timing = response
            .headers()
            .get("server-timing")?
            .filter(|value| !value.is_empty());
        let shard_timing = format!(
            "hubexec;dur={duration_ms}, hubsql;dur={};desc=\"{} calls\"",
            sql.duration_ms, sql.calls
        );
        let timing = existing_timing
            .map(|existing| format!("{existing}, {shard_timing}"))
            .unwrap_or(shard_timing);
        // A nested dispatcher may return a Fetch-backed response with immutable
        // headers. Always install a mutable copy before appending diagnostics.
        let headers = response.headers().clone();
        headers.set("server-timing", &timing)?;
        let response = response.with_headers(headers);
        worker::console_log!(
            "hub_shard_request shard={shard} method={method} path={path} status={} duration_ms={duration_ms} sql_calls={} sql_ms={} sql_rows_read={}",
            response.status_code(),
            sql.calls,
            sql.duration_ms,
            sql.rows_read,
        );
        Ok(response)
    }

    /// Instance-wide request-execution shard.
    #[durable_object]
    pub struct HubControlShard {
        env: Env,
        runtime: Mutex<Option<HubShardRuntime>>,
    }

    impl DurableObject for HubControlShard {
        fn new(_state: State, env: Env) -> Self {
            Self {
                env,
                runtime: Mutex::new(None),
            }
        }

        async fn fetch(&self, req: Request) -> Result<Response> {
            execute_sharded_request("control", &self.env, &self.runtime, req).await
        }
    }

    /// Resource-affine tenant request-execution shard.
    #[durable_object]
    pub struct HubTenantShard {
        env: Env,
        runtime: Mutex<Option<HubShardRuntime>>,
    }

    impl DurableObject for HubTenantShard {
        fn new(_state: State, env: Env) -> Self {
            Self {
                env,
                runtime: Mutex::new(None),
            }
        }

        async fn fetch(&self, req: Request) -> Result<Response> {
            execute_sharded_request("tenant", &self.env, &self.runtime, req).await
        }
    }

    /// Resource-affine registry request-execution shard.
    #[durable_object]
    pub struct HubRegistryShard {
        env: Env,
        runtime: Mutex<Option<HubShardRuntime>>,
    }

    impl DurableObject for HubRegistryShard {
        fn new(_state: State, env: Env) -> Self {
            Self {
                env,
                runtime: Mutex::new(None),
            }
        }

        async fn fetch(&self, req: Request) -> Result<Response> {
            execute_sharded_request("registry", &self.env, &self.runtime, req).await
        }
    }

    /// Resource-affine binary-cache request-execution shard.
    #[durable_object]
    pub struct HubCacheShard {
        env: Env,
        runtime: Mutex<Option<HubShardRuntime>>,
    }

    impl DurableObject for HubCacheShard {
        fn new(_state: State, env: Env) -> Self {
            Self {
                env,
                runtime: Mutex::new(None),
            }
        }

        async fn fetch(&self, req: Request) -> Result<Response> {
            execute_sharded_request("cache", &self.env, &self.runtime, req).await
        }
    }

    /// The colocated-SQLite system-of-record Durable Object.
    ///
    /// Internal and administrative requests are forwarded directly to this
    /// DO. Public requests may also run here when execution sharding is off or
    /// in read-only cutover mode. The DO runs the **same shared router**
    /// ([`router_from`]) over a
    /// [`SqlDoBackend`](crate::sqldobackend) whose SQLite lives in the DO's own
    /// thread — so the request makes one hop to the DO's region and every query
    /// is local to the object. The schema is the shared
    /// `MIGRATIONS`, applied to the DO's SQLite on first use (`ensure_migrated`).
    #[cfg(not(feature = "do-e2e"))]
    #[derive(Clone)]
    struct HubRequestRuntime {
        router: Router,
        service: Arc<RpcService>,
        console_deps: ConsoleDeps,
        sql_metrics: crate::sqldobackend::SqlDoMetrics,
        delivery_attestation_verifier:
            Option<Arc<aos_hub_core::delivery_attestation::DeliveryAttestationVerifier>>,
    }

    #[durable_object]
    pub struct HubDb {
        state: State,
        env: Env,
        migrated: Mutex<bool>,
        #[cfg(not(feature = "do-e2e"))]
        request_runtime: Mutex<Option<HubRequestRuntime>>,
    }

    impl DurableObject for HubDb {
        fn new(state: State, env: Env) -> Self {
            HubDb {
                state,
                env,
                migrated: Mutex::new(false),
                #[cfg(not(feature = "do-e2e"))]
                request_runtime: Mutex::new(None),
            }
        }

        async fn fetch(&self, mut req: Request) -> Result<Response> {
            // Durable Objects execute in an isolate distinct from the outer
            // Worker, so they must install their own tracing subscriber.
            crate::tracinglog::init();

            if let Err(err) = self.ensure_migrated().await {
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
                if req.method() == Method::Post && path == "/_e2e/rescan-image-cache" {
                    return self.e2e_rescan_image_cache().await;
                }
            }
            // Seal-gated control-plane (RFC-0004 ch.14 Phase E). Background
            // queue isolates use `/_internal/sql` for short database operations;
            // the cron/job endpoints remain compatible administrative entry
            // points. Root bootstrap uses `/_admin/bootstrap-root`. All require
            // `x-hub-seal`, so forwarded external callers cannot reach them.
            {
                let path = req
                    .url()
                    .ok()
                    .map(|u| u.path().to_string())
                    .unwrap_or_default();
                if req.method() == Method::Post
                    && (path == "/_internal/cron"
                        || path == "/_internal/job"
                        || path == crate::remotebackend::REMOTE_SQL_PATH
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
                    if path == crate::remotebackend::REMOTE_SQL_PATH {
                        let body = match req.bytes().await {
                            Ok(body) => body,
                            Err(error) => {
                                return Response::error(format!("remote SQL body: {error}"), 400);
                            }
                        };
                        let operation = match crate::remoteprotocol::decode_request(&body) {
                            Ok(operation) => operation,
                            Err(error) => {
                                return Response::error(format!("remote SQL decode: {error}"), 400);
                            }
                        };
                        let backend = crate::sqldobackend::SqlDoBackend::new(self.state.storage());
                        return match crate::remotebackend::execute_remote_sql(&backend, operation)
                            .await
                        {
                            Ok(response) => Response::from_json(&response),
                            Err(error) => Response::error(format!("remote SQL: {error:#}"), 500),
                        };
                    }
                    if path == "/_internal/cron" {
                        let envelope = aos_hub_core::jobs::JobEnvelope::new(
                            aos_hub_core::jobs::Job::DispatchMaintenance,
                        );
                        return match run_cron(Some(&self.state), &self.env, &envelope).await {
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
                                );
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
                    let envelope: aos_hub_core::jobs::JobEnvelope = match req.json().await {
                        Ok(envelope) => envelope,
                        Err(err) => return Response::error(format!("job decode: {err}"), 400),
                    };
                    return match run_job_envelope(&envelope, Some(&self.state), &self.env).await {
                        Ok(()) => Response::ok("ok"),
                        Err(error) => Response::error(format!("job: {error}"), 500),
                    };
                }
            }
            #[cfg(feature = "do-e2e")]
            {
                let db = Arc::new(Database::attach(Box::new(
                    crate::sqldobackend::SqlDoBackend::new(self.state.storage()),
                )));
                let (router, service, console_deps) =
                    router_from_do_e2e(&self.state, &self.env, db).await?;
                return crate::bridge::dispatch(router, &service, console_deps, None, req).await;
            }
            // The DO runs the same shared router as the native shell.
            #[cfg(not(feature = "do-e2e"))]
            {
                let runtime = self.request_runtime().await?;
                let method = format!("{:?}", req.method());
                let path = req
                    .url()
                    .ok()
                    .map(|url| url.path().to_string())
                    .unwrap_or_else(|| "<invalid>".to_string());
                let started_at = worker::Date::now().as_millis();
                let sql_before = runtime.sql_metrics.snapshot();
                let result = crate::bridge::dispatch(
                    runtime.router,
                    runtime.service.as_ref(),
                    runtime.console_deps,
                    runtime.delivery_attestation_verifier.as_deref(),
                    req,
                )
                .await;
                let duration_ms = worker::Date::now().as_millis().saturating_sub(started_at);
                let sql = runtime.sql_metrics.snapshot().since(sql_before);
                let status = result
                    .as_ref()
                    .map(worker::Response::status_code)
                    .unwrap_or(500);
                worker::console_log!(
                    "hub_do_request method={method} path={path} status={status} duration_ms={duration_ms} sql_statements={} sql_queries={} sql_mutations={} sql_transactions={} sql_changes_queries={} sql_rows_read={} sql_rows_written={}",
                    sql.statements,
                    sql.queries,
                    sql.mutations,
                    sql.transactions,
                    sql.affected_count_queries,
                    sql.rows_read,
                    sql.rows_written,
                );
                result
            }
        }
    }

    impl HubDb {
        /// Applies and validates the colocated schema once per object activation.
        async fn ensure_migrated(&self) -> anyhow::Result<()> {
            let mut migrated = self.migrated.lock().await;
            if *migrated {
                return Ok(());
            }

            let backend = crate::sqldobackend::SqlDoBackend::new(self.state.storage());
            crate::sqldobackend::ensure_migrated(&backend).await?;
            *migrated = true;
            Ok(())
        }

        /// Builds immutable request dependencies once per object activation.
        #[cfg(not(feature = "do-e2e"))]
        async fn request_runtime(&self) -> Result<HubRequestRuntime> {
            let mut runtime = self.request_runtime.lock().await;
            if let Some(runtime) = runtime.as_ref() {
                return Ok(runtime.clone());
            }

            let sql_metrics = crate::sqldobackend::SqlDoMetrics::default();
            let db = Arc::new(Database::attach(Box::new(
                crate::sqldobackend::SqlDoBackend::with_metrics(
                    self.state.storage(),
                    sql_metrics.clone(),
                ),
            )));
            let (router, service, console_deps, delivery_attestation_verifier) =
                router_from(&self.env, db, RouterRuntimeKind::Colocated).await?;
            let initialized = HubRequestRuntime {
                router,
                service,
                console_deps,
                sql_metrics,
                delivery_attestation_verifier,
            };
            *runtime = Some(initialized.clone());
            Ok(initialized)
        }
    }

    #[cfg(feature = "do-e2e")]
    impl HubDb {
        /// Publishes a complete inventory for the cache populated by the live driver.
        async fn e2e_rescan_image_cache(&self) -> Result<Response> {
            let db = aos_hub_core::db::Database::attach(Box::new(
                crate::sqldobackend::SqlDoBackend::new(self.state.storage()),
            ));
            let cache = db
                .binary_cache_by_slug("flat-cache")
                .await
                .map_err(|error| {
                    worker::Error::RustError(format!("image cache inventory: {error:#}"))
                })?
                .ok_or_else(|| {
                    worker::Error::RustError("image cache fixture is missing".to_string())
                })?;
            let provider =
                crate::e2e_surface::DoE2eSurfaceProvider::new(self.state.storage().sql()).map_err(
                    |error| worker::Error::RustError(format!("image cache provider: {error:#}")),
                )?;
            let stats = aos_hub_core::cache_scan::rescan_cache(&db, &provider, &cache)
                .await
                .map_err(|error| {
                    worker::Error::RustError(format!("image cache rescan: {error:#}"))
                })?;
            Response::ok(format!(
                "added={} removed={} unchanged={}",
                stats.added, stats.removed, stats.unchanged
            ))
        }

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
            // The signed system-image fixture advertises this cache to
            // anonymous clients. Keep the topology fixture's write authority,
            // but qualify the public read policy before its route snapshot is
            // created below.
            let image_cache = db
                .binary_cache_by_slug("flat-cache")
                .await
                .map_err(|error| {
                    worker::Error::RustError(format!("image cache fixture: {error:#}"))
                })?
                .ok_or_else(|| {
                    worker::Error::RustError("image cache fixture is missing".to_string())
                })?;
            db.update_binary_cache(
                image_cache.id,
                &image_cache.name,
                "public",
                image_cache.priority,
                &image_cache.compression,
                image_cache.want_mass_query,
            )
            .await
            .map_err(|error| {
                worker::Error::RustError(format!("public image cache fixture: {error:#}"))
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
                crate::e2e_surface::configure_hub_route(&db, surface, placement_id, slug)
                    .await
                    .map_err(|error| {
                        worker::Error::RustError(format!("fixture route: {error:#}"))
                    })?;
            }
            for (registry_id, placement_id, port, access_policy_kind) in
                [(2, 4, 8799, "public"), (1, 2, 8800, "hub_auth")]
            {
                crate::e2e_surface::configure_oci_route(
                    &db,
                    registry_id,
                    placement_id,
                    port,
                    access_policy_kind,
                )
                .await
                .map_err(|error| {
                    worker::Error::RustError(format!("fixture OCI route: {error:#}"))
                })?;
            }
            let image_fixture = crate::e2e_surface::decode_producer_surface_fixture(
                producer_surface,
            )
            .map_err(|error| worker::Error::RustError(format!("producer fixture: {error:#}")))?;
            let _image_fixture =
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
            if gc_root_count != 0 {
                return Err(worker::Error::RustError(format!(
                    "store-backed apr image publication produced {gc_root_count} direct-object GC roots"
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
            let (docker_username, docker_password) = db
                .create_token(
                    Principal::user(user_id),
                    "instance",
                    &[Permission::Read, Permission::Publish],
                    Some("workerd OCI parity Docker credential"),
                    None,
                )
                .await
                .map_err(|error| {
                    worker::Error::RustError(format!("e2e Docker credential: {error:#}"))
                })?;
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
                "gc_root_count": gc_root_count,
                "docker_username": docker_username,
                "docker_password": docker_password,
                "oci_public_base": "http://127.0.0.1:8799",
                "oci_public_registry": "flat-registry",
                "oci_private_base": "http://127.0.0.1:8800",
                "oci_private_registry": "failure/registry",
            }))
        }
    }
}
