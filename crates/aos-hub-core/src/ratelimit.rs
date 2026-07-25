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

use std::sync::Arc;

use crate::backend::BackendBounds;
use crate::coordinator::Coordinator;

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

/// The fixed-window length, in seconds, for the [`CoordinatorRateLimiter`].
///
/// One minute matches the burst horizon the service's budgets are expressed
/// against (the same window the Worker's prior D1 limiter used).
const WINDOW_SECS: i64 = 60;

/// A [`RateLimiter`] backed by the strongly-consistent [`Coordinator`] port.
///
/// RFC-0004 chapter 14 routes rate limiting off D1 — whose per-window upsert was
/// a *write on every browse request* (the read-path-poisoning anti-pattern) — and
/// onto the [`Coordinator`]'s atomic [`admit`](Coordinator::admit). On the Worker
/// the coordinator is a Durable Object (`WorkerCoordinator`); natively it is the
/// in-process [`InMemoryCoordinator`](crate::coordinator::InMemoryCoordinator).
/// One limiter type serves both shells, so the class budgets are single-sourced.
///
/// This is a **fixed window**, not a sliding window: the [`admit`] increment and
/// budget test are one serialized operation, so two concurrent callers racing a
/// key cannot both admit at the boundary, and a denied attempt never consumes
/// budget (the `WHERE count < budget` guard lives in `admit`).
///
/// [`admit`]: Coordinator::admit
pub struct CoordinatorRateLimiter {
    coordinator: Arc<dyn Coordinator>,
}

impl CoordinatorRateLimiter {
    /// Builds a limiter over a shared [`Coordinator`].
    #[must_use]
    pub fn new(coordinator: Arc<dyn Coordinator>) -> CoordinatorRateLimiter {
        CoordinatorRateLimiter { coordinator }
    }

    /// The per-window attempt budget for a metered class.
    ///
    /// Mirrors the burst budgets the Worker's prior D1 limiter enforced; classes
    /// the shared service does not yet meter keep a conservative default so a
    /// future call site is bounded rather than unlimited.
    #[must_use]
    pub fn budget(class: RateClass) -> i64 {
        match class {
            RateClass::CreateOrg => 5,
            RateClass::DeviceAuthorization
            | RateClass::MagicLinkEmail
            | RateClass::MagicLinkIp
            | RateClass::PasswordEmail
            | RateClass::PasswordIp
            | RateClass::TokenExchange
            | RateClass::DeviceActivate => 10,
            RateClass::BrowseSearch => 120,
        }
    }

    /// The stable string discriminant a class is counted under in the coordinator.
    #[must_use]
    pub fn class_name(class: RateClass) -> &'static str {
        match class {
            RateClass::DeviceAuthorization => "device_authorization",
            RateClass::MagicLinkEmail => "magic_link_email",
            RateClass::MagicLinkIp => "magic_link_ip",
            RateClass::PasswordEmail => "password_email",
            RateClass::PasswordIp => "password_ip",
            RateClass::TokenExchange => "token_exchange",
            RateClass::BrowseSearch => "browse_search",
            RateClass::CreateOrg => "create_org",
            RateClass::DeviceActivate => "device_activate",
        }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl RateLimiter for CoordinatorRateLimiter {
    async fn check(&self, class: RateClass, key: &str, now: i64) -> RateDecision {
        let name = CoordinatorRateLimiter::class_name(class);
        let budget = CoordinatorRateLimiter::budget(class);
        let window = now.div_euclid(WINDOW_SECS);
        match self.coordinator.admit(name, key, window, budget).await {
            Ok(true) => RateDecision::Allowed,
            Ok(false) => {
                // Seconds until this fixed window resets, for `Retry-After`.
                let window_end = (window + 1) * WINDOW_SECS;
                RateDecision::Limited {
                    retry_after: (window_end - now).max(1),
                }
            }
            // Fail open: a coordinator error must not wedge the hub. The metered
            // operations carry their own DB-enforced backstops (e.g.
            // [`MAX_ORGS_PER_OWNER`] for `CreateOrg`).
            Err(err) => {
                tracing::warn!(class = name, key, error = %format!("{err:#}"), "rate-limit admit failed; failing open");
                RateDecision::Allowed
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CoordinatorRateLimiter, RateClass, RateDecision, RateLimiter, WINDOW_SECS};
    use crate::coordinator::InMemoryCoordinator;
    use std::sync::Arc;

    #[tokio::test]
    async fn admits_up_to_budget_then_limits_within_a_window() {
        let limiter = CoordinatorRateLimiter::new(Arc::new(InMemoryCoordinator::new()));
        let budget = CoordinatorRateLimiter::budget(RateClass::CreateOrg); // 5
        let now = 1_000_000;
        for _ in 0..budget {
            assert_eq!(
                limiter.check(RateClass::CreateOrg, "owner", now).await,
                RateDecision::Allowed
            );
        }
        // Next attempt in the same window is limited, with a positive retry_after.
        match limiter.check(RateClass::CreateOrg, "owner", now).await {
            RateDecision::Limited { retry_after } => assert!(retry_after >= 1),
            other => panic!("expected Limited, got {other:?}"),
        }
        // A fresh window (one minute later) admits again.
        assert_eq!(
            limiter
                .check(RateClass::CreateOrg, "owner", now + WINDOW_SECS)
                .await,
            RateDecision::Allowed
        );
    }

    #[tokio::test]
    async fn keys_and_classes_are_independent() {
        let limiter = CoordinatorRateLimiter::new(Arc::new(InMemoryCoordinator::new()));
        let now = 2_000_000;
        // Exhaust CreateOrg for owner-a.
        for _ in 0..CoordinatorRateLimiter::budget(RateClass::CreateOrg) {
            limiter.check(RateClass::CreateOrg, "owner-a", now).await;
        }
        assert!(matches!(
            limiter.check(RateClass::CreateOrg, "owner-a", now).await,
            RateDecision::Limited { .. }
        ));
        // A different key is unaffected.
        assert_eq!(
            limiter.check(RateClass::CreateOrg, "owner-b", now).await,
            RateDecision::Allowed
        );
        // A different class for the same key has its own budget.
        assert_eq!(
            limiter.check(RateClass::BrowseSearch, "owner-a", now).await,
            RateDecision::Allowed
        );
    }
}
