//! In-memory per-endpoint rate limiting (RFC-0004 "Quotas and limits").
//!
//! A multi-tenant hub must bound the abuse surface of its unauthenticated and
//! pre-authentication endpoints. This module is a small, dependency-free
//! **fixed-window** limiter keyed by `(class, key)`, held in a
//! `Mutex<HashMap>` on [`AppState`](crate::server::AppState). It is
//! deliberately process-local and approximate — a multi-process deployment
//! wanting a shared limiter is a later phase — but it is exact enough to stop
//! the email-bombing and credential-spray surfaces the RFC calls out.
//!
//! # Classes and the trust model
//!
//! Each [`RateClass`] carries a sane default budget (requests per window),
//! exposed as configurable consts:
//!
//! ```text
//! class                   keyed by                  default budget
//! device_authorization    client IP                 DEVICE_AUTH_PER_IP / window
//! magic_link (per email)  target email              MAGIC_LINK_PER_EMAIL / window
//! magic_link (per IP)     client IP                 MAGIC_LINK_PER_IP / window
//! token_exchange          token id or client IP     TOKEN_EXCHANGE / window
//! browse_search           client IP                 BROWSE_SEARCH / window (loose)
//! ```
//!
//! The magic-link issuance surface is rate-limited on **both** the target
//! email *and* the source IP — the email-bomb surface is "many requests for
//! one victim from one attacker", and either key alone misses a variant.
//!
//! **Client-IP trust model.** Behind a trusted reverse proxy the real client
//! is the last hop of `X-Forwarded-For`; directly exposed, it is the TCP peer
//! address. [`client_ip`] reads `X-Forwarded-For`'s last entry when present,
//! else falls back to the supplied peer string. An operator who does *not*
//! front the hub with a proxy that strips inbound `X-Forwarded-For` should not
//! trust the header — but the limiter failing open per-IP is a
//! denial-of-abuse-protection, never a security bypass (the credential checks
//! downstream are unchanged), so the conservative default of honoring the
//! header keeps the email/IP buckets meaningful behind the common proxy
//! deployment.
//!
//! # Testability
//!
//! Every decision takes an explicit `now` (Unix seconds), so tests drive the
//! window with a fixed clock rather than sleeping. [`RateLimiter::check`]
//! returns [`RateDecision::Allowed`] or [`RateDecision::Limited`] with the
//! `retry_after` seconds to surface in a `429` `Retry-After` header.

use std::collections::HashMap;
use std::sync::Mutex;

/// Default fixed-window length, in seconds, shared by every class.
pub const WINDOW_SECS: i64 = 60;

/// Default device-authorization starts allowed per IP per window.
pub const DEVICE_AUTH_PER_IP: u32 = 10;

/// Default magic-link issuances allowed per target email per window.
pub const MAGIC_LINK_PER_EMAIL: u32 = 3;

/// Default magic-link issuances allowed per source IP per window.
pub const MAGIC_LINK_PER_IP: u32 = 10;

/// Default OAuth2 token exchanges allowed per key (token id or IP) per window.
pub const TOKEN_EXCHANGE: u32 = 60;

/// Default anonymous browse/search requests allowed per IP per window (loose).
pub const BROWSE_SEARCH: u32 = 300;

/// A rate-limited endpoint class.
///
/// Each class carries its own per-window budget via [`RateClass::budget`]; the
/// limiter keys buckets on `(class, key)`, so the same source IP is metered
/// independently across classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RateClass {
    /// `POST /oauth2/device_authorization` — keyed per source IP.
    DeviceAuthorization,
    /// Magic-link issuance, keyed per **target email** (the email-bomb victim).
    MagicLinkEmail,
    /// Magic-link issuance, keyed per **source IP** (the email-bomb sender).
    MagicLinkIp,
    /// `POST /oauth2/token` exchange — keyed per token id or source IP.
    TokenExchange,
    /// Anonymous browse/search — keyed per source IP (loose).
    BrowseSearch,
}

impl RateClass {
    /// The per-window request budget for this class.
    #[must_use]
    pub fn budget(self) -> u32 {
        match self {
            RateClass::DeviceAuthorization => DEVICE_AUTH_PER_IP,
            RateClass::MagicLinkEmail => MAGIC_LINK_PER_EMAIL,
            RateClass::MagicLinkIp => MAGIC_LINK_PER_IP,
            RateClass::TokenExchange => TOKEN_EXCHANGE,
            RateClass::BrowseSearch => BROWSE_SEARCH,
        }
    }
}

/// The outcome of a [`RateLimiter::check`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateDecision {
    /// The request is within budget and may proceed.
    Allowed,
    /// The request exceeds the budget; retry after `retry_after` seconds.
    Limited {
        /// Seconds until the current window resets (for the `Retry-After`
        /// header).
        retry_after: i64,
    },
}

impl RateDecision {
    /// Whether the request may proceed.
    #[must_use]
    pub fn is_allowed(self) -> bool {
        matches!(self, RateDecision::Allowed)
    }
}

/// One fixed-window counter: the window's start and the count so far in it.
#[derive(Debug, Clone, Copy)]
struct Window {
    /// Unix-second start of the current window.
    started_at: i64,
    /// Requests counted within the current window.
    count: u32,
}

/// A process-local fixed-window rate limiter keyed by `(class, key)`.
///
/// Cheap to share behind an `Arc`; the single `Mutex` is held only for the
/// brief counter read-modify-write. See the [module docs](self) for the trust
/// model and class budgets.
#[derive(Debug, Default)]
pub struct RateLimiter {
    windows: Mutex<HashMap<(RateClass, String), Window>>,
}

impl RateLimiter {
    /// Builds an empty limiter.
    #[must_use]
    pub fn new() -> RateLimiter {
        RateLimiter::default()
    }

    /// Account one request in `class` for `key` at time `now`, deciding whether
    /// it is within budget.
    ///
    /// Uses a fixed window of [`WINDOW_SECS`]: the first request opens a window
    /// at `now`; subsequent requests in the same window increment the counter;
    /// once `now` passes the window end the counter resets. A request that
    /// would push the count past [`RateClass::budget`] is
    /// [`RateDecision::Limited`] (and is *not* counted), carrying the seconds
    /// until the window resets.
    pub fn check(&self, class: RateClass, key: &str, now: i64) -> RateDecision {
        let budget = class.budget();
        let mut windows = self.windows.lock().unwrap_or_else(|p| p.into_inner());
        let entry = windows.entry((class, key.to_string())).or_insert(Window {
            started_at: now,
            count: 0,
        });
        // Reset the window if the prior one has elapsed.
        if now.saturating_sub(entry.started_at) >= WINDOW_SECS {
            entry.started_at = now;
            entry.count = 0;
        }
        if entry.count >= budget {
            let retry_after = (entry.started_at + WINDOW_SECS - now).max(1);
            return RateDecision::Limited { retry_after };
        }
        entry.count += 1;
        RateDecision::Allowed
    }
}

/// Resolve the client IP from a forwarded header or the peer address.
///
/// Honors `X-Forwarded-For`'s **last** hop when the header is present (the hop
/// a trusted reverse proxy appends), falling back to `peer` (the TCP peer
/// address string) otherwise. See the [module docs](self) for the trust model.
#[must_use]
pub fn client_ip(forwarded_for: Option<&str>, peer: &str) -> String {
    if let Some(xff) = forwarded_for {
        // The last non-empty comma-separated hop (the one a trusted proxy
        // appends), scanning from the right.
        if let Some(last) = xff.rsplit(',').map(str::trim).find(|s| !s.is_empty()) {
            return last.to_string();
        }
    }
    peer.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_budget_then_limits() {
        let limiter = RateLimiter::new();
        // MagicLinkEmail budget is 3 per window.
        for _ in 0..MAGIC_LINK_PER_EMAIL {
            assert_eq!(
                limiter.check(RateClass::MagicLinkEmail, "victim@acme.com", 1000),
                RateDecision::Allowed
            );
        }
        // The (N+1)th in the same window is limited with a positive retry.
        match limiter.check(RateClass::MagicLinkEmail, "victim@acme.com", 1000) {
            RateDecision::Limited { retry_after } => assert!(retry_after > 0),
            other => panic!("expected limited, got {other:?}"),
        }
    }

    #[test]
    fn window_resets_after_window_secs() {
        let limiter = RateLimiter::new();
        for _ in 0..DEVICE_AUTH_PER_IP {
            assert!(limiter
                .check(RateClass::DeviceAuthorization, "1.2.3.4", 0)
                .is_allowed());
        }
        assert!(!limiter
            .check(RateClass::DeviceAuthorization, "1.2.3.4", 0)
            .is_allowed());
        // After the window elapses, the budget is fresh.
        assert!(limiter
            .check(RateClass::DeviceAuthorization, "1.2.3.4", WINDOW_SECS)
            .is_allowed());
    }

    #[test]
    fn keys_and_classes_are_independent() {
        let limiter = RateLimiter::new();
        for _ in 0..MAGIC_LINK_PER_EMAIL {
            assert!(limiter
                .check(RateClass::MagicLinkEmail, "a@acme.com", 0)
                .is_allowed());
        }
        // A different email has its own budget.
        assert!(limiter
            .check(RateClass::MagicLinkEmail, "b@acme.com", 0)
            .is_allowed());
        // The same string under a different class is independent too.
        assert!(limiter
            .check(RateClass::BrowseSearch, "a@acme.com", 0)
            .is_allowed());
    }

    #[test]
    fn client_ip_prefers_forwarded_last_hop() {
        assert_eq!(
            client_ip(Some("203.0.113.1, 10.0.0.2"), "10.0.0.2:443"),
            "10.0.0.2"
        );
        assert_eq!(
            client_ip(Some("203.0.113.1"), "10.0.0.2:443"),
            "203.0.113.1"
        );
        assert_eq!(client_ip(None, "10.0.0.2:443"), "10.0.0.2:443");
        assert_eq!(client_ip(Some("  "), "peer"), "peer");
    }
}
