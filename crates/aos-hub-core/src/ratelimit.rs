//! The rate-limiter port: abuse bounds the shared service depends on.
//!
//! The registry-hub service ([`crate::service::RpcService`]) meters a few
//! abuse-prone operations (currently `CreateOrg`). *How* the count is kept
//! differs by deployment — the native hub uses an in-process token bucket,
//! while the Cloudflare Worker must keep it across stateless isolate
//! invocations (D1/KV or a Durable Object) — so the mechanism is a port:
//! [`RateLimiter`]. The shared service calls [`RateLimiter::check`] and acts on
//! the [`RateDecision`]; each shell supplies the concrete limiter.
//!
//! [`RateClass`] and [`RateDecision`] are the wire-free data the port speaks;
//! they mirror the native limiter's classes so the native implementation can
//! adopt this trait without changing call sites.

use crate::backend::BackendBounds;

/// The maximum number of orgs a single user principal may own at once.
///
/// A steady-state complement to the per-principal [`RateClass::CreateOrg`]
/// burst limit: even a slow creation loop cannot accumulate namespace pollution
/// past this cap (RFC-0004 sec L-3).
pub const MAX_ORGS_PER_OWNER: i64 = 50;

/// The metered operation classes, each with its own keying and budget.
///
/// The variants mirror the native hub's limiter so a single concrete limiter
/// can serve both the HTTP handlers and the shared service. The shared service
/// currently uses only [`RateClass::CreateOrg`]; the rest are listed so the
/// native limiter implements one trait over all its classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateClass {
    /// `POST /oauth2/device_authorization` — keyed per source IP.
    DeviceAuthorization,
    /// Magic-link issuance, keyed per **target email** (the email-bomb victim).
    MagicLinkEmail,
    /// Magic-link issuance, keyed per **source IP** (the email-bomb sender).
    MagicLinkIp,
    /// `POST /login/password` attempt, keyed per **target email**.
    PasswordEmail,
    /// `POST /login/password` attempt, keyed per **source IP**.
    PasswordIp,
    /// `POST /oauth2/token` exchange — keyed per token id or source IP.
    TokenExchange,
    /// Anonymous browse/search — keyed per source IP (loose).
    BrowseSearch,
    /// `CreateOrg` RPC — keyed per authenticated **principal** (the JWT owner).
    CreateOrg,
    /// `/activate` device-approval page — keyed per **session user + source IP**.
    DeviceActivate,
}

/// The limiter's verdict for one [`RateLimiter::check`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateDecision {
    /// The request is within budget and may proceed.
    Allowed,
    /// The request exceeds the budget; retry after `retry_after` seconds.
    Limited {
        /// Seconds until the current window resets (for `Retry-After`).
        retry_after: i64,
    },
}

/// A per-key request-rate limiter (the abuse-bound port).
///
/// Implemented by each shell: an in-process token bucket on the native hub, a
/// D1/KV- or Durable-Object-backed counter on the Cloudflare Worker. The method
/// is `async` so the Worker's durable backing can be awaited; the in-process
/// native limiter satisfies it trivially. The [`BackendBounds`] supertrait
/// applies the same target-conditional `Send + Sync` (native) / unbounded
/// (wasm32) bound the rest of the core ports use.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait RateLimiter: BackendBounds {
    /// Record an attempt for `(class, key)` at time `now` and decide its fate.
    ///
    /// A call that stays within the class budget is [`RateDecision::Allowed`]
    /// and counted; one that would exceed it is [`RateDecision::Limited`] and is
    /// *not* counted (so validation failures never consume budget — the caller
    /// gates cheap checks first).
    async fn check(&self, class: RateClass, key: &str, now: i64) -> RateDecision;
}
