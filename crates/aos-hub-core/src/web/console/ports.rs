//! The dependency bundle and platform ports the shared console handlers run on.
//!
//! The producer-console handlers ([`super`]) are transport- and runtime-neutral
//! HTTP handlers: they speak [`axum`] *types* (never an HTTP server), read and
//! write the shared [`Database`](crate::db::Database), and reach every
//! platform-specific capability through a *port* — a trait each deployment
//! satisfies with its own concrete type. That keeps the handlers
//! `wasm32-unknown-unknown`-clean (RFC-0004 Phase 5, console-dedup stage B) so
//! the native hub and the Cloudflare Worker mount the same console.
//!
//! [`ConsoleDeps`] is the bundle a handler's `axum` `State` carries. It holds:
//!
//! - the shared [`Database`](crate::db::Database) and the HS256
//!   [`JwtKeys`](crate::auth::jwt::JwtKeys);
//! - the externally reachable base URL and the `--dev` flag (which surfaces the
//!   magic-link URL on the "check your email" page);
//! - the three abstractions core already owns — the
//!   [`RateLimiter`](crate::ratelimit::RateLimiter) abuse bound, the
//!   [`Mailer`](crate::auth::magic::Mailer) magic-link sender, and the
//!   [`SecretSealer`](crate::auth::seal::SecretSealer) that unseals an OIDC
//!   client secret;
//! - and the [`HttpClient`] port defined here for the OIDC flow's outbound HTTP.
//!
//! A hosted-key channel advance is *not* a port: it runs the shared
//! [`advance_channel`](crate::signing::advance_channel) directly over the
//! deps it already carries (db, sealer, [`surface`](ConsoleDeps::surface),
//! [`surface_write`](ConsoleDeps::surface_write), and
//! [`reindexer`](ConsoleDeps::reindexer)), so the *same* signing-and-publishing
//! code path runs on both shells.
//!
//! The native hub satisfies [`HttpClient`] with its hardened [`reqwest`] client;
//! the Worker satisfies it with the Fetch API.

use std::sync::Arc;

use crate::auth::jwt::JwtKeys;
use crate::auth::magic::Mailer;
use crate::auth::seal::SecretSealer;
use crate::backend::BackendBounds;
use crate::db::Database;
use crate::fetch::SurfaceProvider;
use crate::ratelimit::RateLimiter;
use crate::reindex::Reindexer;
use crate::surface_write::SurfaceWriteProvider;

/// The dependency bundle the shared console handlers carry as `axum` `State`.
///
/// A clone is cheap: every field is an [`Arc`], a small `Copy` flag, or a
/// `String`/[`JwtKeys`] that clones shallowly. The native hub builds one from
/// its `AppState`; the Worker (stage C) builds one from its request-scoped
/// environment.
#[derive(Clone)]
pub struct ConsoleDeps {
    /// The shared hub database (one implementation over the async backend).
    pub db: Arc<Database>,
    /// HS256 keys minting and verifying the bearer JWTs the console issues for
    /// device-grant approval and token operations.
    pub jwt_keys: JwtKeys,
    /// The externally reachable base URL, used to build magic-link and OIDC
    /// redirect URLs and the WebAuthn relying-party id.
    pub external_url: String,
    /// Whether the hub runs in `--dev` mode; when set, the "check your email"
    /// page surfaces the magic-link URL directly (no real mail is sent).
    pub dev: bool,
    /// The abuse-bound rate limiter (the [`RateLimiter`] port), metering the
    /// pre-auth login paths and the device-approval surface.
    pub ratelimit: Arc<dyn RateLimiter>,
    /// The magic-link email sender (the [`Mailer`] port).
    pub mailer: Arc<dyn Mailer>,
    /// The at-rest secret sealer (the [`SecretSealer`] port), used to unseal an
    /// org's OIDC client secret at the token exchange.
    pub sealer: Arc<dyn SecretSealer>,
    /// Outbound HTTP for the OIDC flow (the [`HttpClient`] port).
    pub http: Arc<dyn HttpClient>,
    /// Per-registry surface **read** access (the [`SurfaceProvider`] port),
    /// used by the git-backed config/change-request flow to read the base
    /// commit's `registry.toml` and the committed history.
    pub surface: Arc<dyn SurfaceProvider>,
    /// Per-registry surface **write** access (the [`SurfaceWriteProvider`]
    /// port), used by the git-backed config-change-request flow to write the
    /// draft commit's loose objects and ref, and by a hosted-key channel
    /// advance to write the signed partitions.
    pub surface_write: Arc<dyn SurfaceWriteProvider>,
    /// Per-registry re-index (the [`Reindexer`] port), run by a hosted-key
    /// channel advance after its signed partitions land: the native hub
    /// re-indexes inline; the Worker defers to its Cron indexer.
    pub reindexer: Arc<dyn Reindexer>,
    /// Human-readable location of the deployment's **default** storage — what a
    /// registry/cache with no explicit binding pushes to (the Worker's R2 bucket
    /// name, or the native hub's storage root). Surfaced read-only on the
    /// instance-settings page; `None` when the deployment did not advertise it
    /// (e.g. an older Worker deploy without `HUB_DEFAULT_BUCKET`), so the UI
    /// falls back to "configured at deploy time".
    pub default_storage_location: Option<String>,
    /// The hot-state key-value store ([`KvStore`](crate::kv::KvStore)) for
    /// read-through caching (RFC-0004 ch.14 Phase C). `None` disables caching
    /// (the database is authoritative). The console uses it to **invalidate** the
    /// token cache on revoke/rotate (a `tokrev:` tombstone) so a revoked token is
    /// rejected immediately rather than after the cache TTL.
    pub kv: Option<Arc<dyn crate::kv::KvStore>>,
}

impl ConsoleDeps {
    /// Tombstones a token id in KV so any cached resolution for it is rejected
    /// (call on revoke/rotate). A no-op when no [`KvStore`](crate::kv::KvStore)
    /// is attached. Mirrors
    /// [`RpcService::invalidate_token_cache`](crate::service::RpcService::invalidate_token_cache).
    pub async fn invalidate_token_cache(&self, token_id: &str) {
        if let Some(kv) = &self.kv {
            let ttl = crate::cache::HOT_TTL_SECS * 10;
            let _ = kv.put(&format!("tokrev:{token_id}"), b"1", Some(ttl)).await;
        }
    }
}

/// A minimal outbound HTTP client for the OIDC authorization-code flow.
///
/// The OIDC callback exchanges an authorization code at the IdP's
/// `token_endpoint` (an HTTP `POST` of a `application/x-www-form-urlencoded`
/// body) and fetches the IdP's JWKS document from its `jwks_uri` (an HTTP
/// `GET`). Both endpoints come from *tenant-admin-controlled* IdP configuration,
/// so an implementation MUST treat them as untrusted:
///
/// - **SSRF.** A native implementation routes the request through a resolver
///   that refuses private, loopback, and link-local addresses, so a hostile
///   IdP config cannot turn the multi-tenant hub into an SSRF proxy against its
///   own metadata service or internal network.
/// - **Body cap.** A response body MUST be read with a hard size cap (a token
///   response and a JWKS document are KB-scale by nature) so a hostile endpoint
///   cannot stream an unbounded body and OOM the hub. Implementations should cap
///   at roughly 1 MiB.
/// - **Timeout.** Both calls MUST carry a bounded request timeout so a slow or
///   hung endpoint cannot pin a request future indefinitely.
///
/// Returning the decoded body bytes (rather than a streaming response) lets the
/// handler share one cap-and-decode path across both targets. The native hub
/// implements this over its hardened [`reqwest`] client; the Worker (stage C)
/// implements it over the Fetch API.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait HttpClient: BackendBounds {
    /// `POST url` with a form-urlencoded body, returning the response body
    /// bytes.
    ///
    /// `form` is the unencoded `(key, value)` pairs; the implementation
    /// percent-encodes them into an `application/x-www-form-urlencoded` body.
    /// The returned bytes are the response body, already read under the
    /// implementation's size cap.
    ///
    /// # Errors
    ///
    /// Returns an error when the request cannot be sent, the endpoint resolves
    /// to a blocked address, the endpoint returns a non-success status, the
    /// response exceeds the body cap, or the request times out.
    async fn post_form(&self, url: &str, form: &[(String, String)]) -> anyhow::Result<Vec<u8>>;

    /// `GET url`, returning the response body bytes.
    ///
    /// The returned bytes are the response body, already read under the
    /// implementation's size cap.
    ///
    /// # Errors
    ///
    /// Returns an error when the request cannot be sent, the endpoint resolves
    /// to a blocked address, the endpoint returns a non-success status, the
    /// response exceeds the body cap, or the request times out.
    async fn get(&self, url: &str) -> anyhow::Result<Vec<u8>>;
}
