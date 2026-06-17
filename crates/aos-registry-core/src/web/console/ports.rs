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
//! - and the two ports defined here: [`HttpClient`] for the OIDC flow's
//!   outbound HTTP, and [`ChannelAdvancer`] for a hosted-key channel advance.
//!
//! The native hub satisfies [`HttpClient`] with its hardened [`reqwest`] client
//! and [`ChannelAdvancer`] with its `signing` module; the Worker (stage C) will
//! satisfy them with the Fetch API and an R2-backed signer.

use std::sync::Arc;

use crate::auth::jwt::JwtKeys;
use crate::auth::magic::Mailer;
use crate::auth::seal::SecretSealer;
use crate::backend::BackendBounds;
use crate::db::{Database, RegistryRecord};
use crate::fetch::SurfaceProvider;
use crate::ratelimit::RateLimiter;
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
    /// Hosted-key channel advance (the [`ChannelAdvancer`] port).
    pub advancer: Arc<dyn ChannelAdvancer>,
    /// Per-registry surface **read** access (the [`SurfaceProvider`] port),
    /// used by the git-backed config/change-request flow to read the base
    /// commit's `registry.toml` and the committed history.
    pub surface: Arc<dyn SurfaceProvider>,
    /// Per-registry surface **write** access (the [`SurfaceWriteProvider`]
    /// port), used by the git-backed config-change-request flow to write the
    /// draft commit's loose objects and ref.
    pub surface_write: Arc<dyn SurfaceWriteProvider>,
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

/// The outcome of a hosted-key channel advance.
///
/// Mirrors the native signer's result so the console's advance handler renders
/// the same confirmation regardless of which shell signed the partitions.
#[derive(Debug, Clone)]
pub struct AdvanceOutcome {
    /// The channel that was advanced.
    pub channel: String,
    /// The release the advanced partitions now point at.
    pub release: String,
    /// How many partitions this advance newly moved to `release`.
    pub moved: usize,
    /// How many of the 256 partitions point at `release` after the advance.
    pub at_target: usize,
    /// The rollout percentage (`at_target` / 256), rounded to a whole number.
    pub rollout_percent: u32,
}

/// A hosted-key channel advance, server-side.
///
/// When a registry has a bound hosted signing key, the console can advance a
/// channel directly: sign the next partitions with the hub-held key, write them
/// to the surface, re-index, and audit. *How* that happens differs by
/// deployment — the native hub holds the key sealed in its database and writes
/// to a filesystem or HTTP-backed surface; the Worker signs against an R2
/// surface — so it is a port.
///
/// The implementation owns the entire signing-and-publishing closure (key load,
/// anti-rollback floor check, partition signing, atomic write, re-index, audit,
/// and webhook dispatch); the handler supplies only the registry, channel,
/// target release, partition count, and timestamp, and renders the returned
/// [`AdvanceOutcome`].
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait ChannelAdvancer: BackendBounds {
    /// Advance `registry`'s `channel_name` to `target_semver`, moving up to
    /// `count` partitions, stamping the advance at `when` (Unix seconds).
    ///
    /// The release must already be published on the surface; advancing to an
    /// unindexed release, or below the channel's recorded anti-rollback floor,
    /// is refused. Returns how many partitions moved and the resulting rollout.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry has no hosted key, has no writable
    /// surface root, when `target_semver` has no indexed release, when
    /// `target_semver` is below the channel's floor, or when signing, writing,
    /// or re-indexing fails.
    async fn advance(
        &self,
        registry: &RegistryRecord,
        channel_name: &str,
        target_semver: &str,
        count: usize,
        when: i64,
    ) -> anyhow::Result<AdvanceOutcome>;
}
