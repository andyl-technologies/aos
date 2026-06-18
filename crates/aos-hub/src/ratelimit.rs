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
//! password (per email)    target email              PASSWORD_PER_EMAIL / window
//! password (per IP)       client IP                 PASSWORD_PER_IP / window
//! token_exchange          token id or client IP     TOKEN_EXCHANGE / window
//! browse_search           client IP                 BROWSE_SEARCH / window (loose)
//! create_org              JWT principal id          CREATE_ORG_PER_OWNER / window
//! device_activate         session user + client IP  DEVICE_ACTIVATE / window
//! ```
//!
//! The magic-link issuance surface is rate-limited on **both** the target
//! email *and* the source IP — the email-bomb surface is "many requests for
//! one victim from one attacker", and either key alone misses a variant.
//!
//! **Client-IP trust model.** Behind a trusted reverse proxy the real client
//! is the last hop of `X-Forwarded-For`; directly exposed, it is the TCP peer
//! address. [`client_ip`] only honors `X-Forwarded-For` when the deployment is
//! configured to trust its proxy (`trusted_proxy = true`); otherwise it keys
//! on the real TCP peer address, ignoring the header entirely. This is the
//! safe default: an attacker who can send arbitrary `X-Forwarded-For` values
//! to a directly-exposed hub could otherwise mint a fresh per-IP bucket per
//! request and evade every per-IP limit (and, with unique forged values,
//! balloon the limiter's tracking map). With `trusted_proxy = false` the
//! forged header is discarded and the peer address is the limiter key.
//!
//! **Bounded tracking.** The window map is hard-capped at [`MAX_TRACKED`]
//! entries, so a flood of distinct keys — forged or genuine — cannot grow it
//! without bound. Eviction is sub-linear under such a flood: an auxiliary
//! ordered index (keyed by window start) makes "evict the oldest window" an
//! `O(log n)` operation instead of an `O(n)` min-scan, and expired entries are
//! pruned lazily (every [`PRUNE_INTERVAL`] new keys) rather than with a full
//! `O(n)` sweep on every call. A high-cardinality flood therefore no longer
//! turns each check into `O(n)` work under the global lock.
//!
//! # Testability
//!
//! Every decision takes an explicit `now` (Unix seconds), so tests drive the
//! window with a fixed clock rather than sleeping. [`RateLimiter::check`]
//! returns [`RateDecision::Allowed`] or [`RateDecision::Limited`] with the
//! `retry_after` seconds to surface in a `429` `Retry-After` header.

use std::collections::{BTreeSet, HashMap};
use std::sync::Mutex;

/// Default fixed-window length, in seconds, shared by every class.
pub const WINDOW_SECS: i64 = 60;

/// Default device-authorization starts allowed per IP per window.
pub const DEVICE_AUTH_PER_IP: u32 = 10;

/// Default magic-link issuances allowed per target email per window.
pub const MAGIC_LINK_PER_EMAIL: u32 = 3;

/// Default magic-link issuances allowed per source IP per window.
pub const MAGIC_LINK_PER_IP: u32 = 10;

/// Default password login attempts allowed per target email per window.
///
/// Tight, to blunt online password guessing against one account.
pub const PASSWORD_PER_EMAIL: u32 = 5;

/// Default password login attempts allowed per source IP per window.
///
/// Tighter than magic-link issuance, to blunt credential-stuffing sprays that
/// rotate the email but share a source IP.
pub const PASSWORD_PER_IP: u32 = 20;

/// Default OAuth2 token exchanges allowed per key (token id or IP) per window.
pub const TOKEN_EXCHANGE: u32 = 60;

/// Default org creations allowed per authenticated principal per window.
///
/// Tight: org creation mints a namespace, a membership scope, and an `Owner`
/// grant, and bloats every `list_orgs`/instance-home scan. A handful per
/// window is ample for a human (or a CI principal) and blunts a loop that mints
/// orgs to pollute the namespace. The per-owner *total* is additionally capped
/// by [`MAX_ORGS_PER_OWNER`].
pub const CREATE_ORG_PER_OWNER: u32 = 5;

/// Default device-activation (approve) views/submits allowed per session user
/// (combined with the source IP) per window.
///
/// The `/activate` approve page keys a pending grant solely on its `user_code`
/// with no ownership predicate, so without a throttle an authenticated user
/// could enumerate the code space at full speed to discover and hijack other
/// users' in-flight device grants. This bounds the guess rate per signed-in
/// user; the 15-minute grant TTL and the code entropy remain the other
/// barriers.
pub const DEVICE_ACTIVATE: u32 = 30;

/// Default anonymous browse/search requests allowed per IP per window (loose).
pub const BROWSE_SEARCH: u32 = 300;

/// Hard cap on the number of orgs a single user may *own* (hold an `Owner`
/// membership on) at once.
///
/// A complement to the [`RateClass::CreateOrg`] rate limit: the rate limit
/// bounds the *burst* of creations, while this bounds the steady-state total a
/// principal can accumulate, so a slow loop cannot pollute the namespace over
/// time. Enforced in the `CreateOrg` RPC handler against the caller's current
/// owned-org count (via
/// [`Database::count_user_owned_orgs`](crate::db::Database::count_user_owned_orgs))
/// before the org row is written. Sized
/// generously for a legitimate user running several orgs; instance admins are
/// the path for anyone who genuinely needs more.
pub const MAX_ORGS_PER_OWNER: i64 = 50;

/// Maximum number of `(class, key)` windows the limiter tracks at once.
///
/// A bound on the limiter's memory footprint: once the map reaches this size a
/// fresh key evicts the entry whose window started earliest (least recently
/// opened). Sized generously enough that legitimate traffic is never evicted
/// mid-window in practice, while a flood of distinct (e.g. forged) keys cannot
/// OOM the process. Expired windows are also swept on insert, so the cap is
/// rarely the binding constraint.
pub const MAX_TRACKED: usize = 100_000;

/// Number of new-key inserts between lazy expired-entry sweeps.
///
/// Pruning every elapsed window on *every* `check` would cost `O(n)` per call
/// under a distinct-key flood. Instead the limiter amortizes the sweep, running
/// it once per this many new keys; between sweeps the [`MAX_TRACKED`] cap and
/// the per-key window reset keep the map correct and bounded. Eviction of the
/// single oldest window (when at the cap) remains `O(log n)` and runs whenever
/// needed regardless of this interval.
pub const PRUNE_INTERVAL: u64 = 1024;

/// A rate-limited endpoint class.
///
/// Each class carries its own per-window budget via [`RateClass::budget`]; the
/// limiter keys buckets on `(class, key)`, so the same source IP is metered
/// independently across classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RateClass {
    /// `POST /oauth2/device_authorization` — keyed per source IP.
    DeviceAuthorization,
    /// Magic-link issuance, keyed per **target email** (the email-bomb victim).
    MagicLinkEmail,
    /// Magic-link issuance, keyed per **source IP** (the email-bomb sender).
    MagicLinkIp,
    /// `POST /login/password` attempt, keyed per **target email** (the account
    /// under online-guessing attack).
    PasswordEmail,
    /// `POST /login/password` attempt, keyed per **source IP** (the
    /// credential-stuffing sprayer).
    PasswordIp,
    /// `POST /oauth2/token` exchange — keyed per token id or source IP.
    TokenExchange,
    /// Anonymous browse/search — keyed per source IP (loose).
    BrowseSearch,
    /// `CreateOrg` RPC — keyed per authenticated **principal** (the JWT owner),
    /// bounding the rate at which one caller can mint orgs.
    CreateOrg,
    /// `/activate` device-approval page (GET form + POST submit) — keyed per
    /// **session user combined with source IP**, bounding `user_code`
    /// enumeration of other users' in-flight device grants.
    DeviceActivate,
}

impl RateClass {
    /// The per-window request budget for this class.
    #[must_use]
    pub fn budget(self) -> u32 {
        match self {
            RateClass::DeviceAuthorization => DEVICE_AUTH_PER_IP,
            RateClass::MagicLinkEmail => MAGIC_LINK_PER_EMAIL,
            RateClass::MagicLinkIp => MAGIC_LINK_PER_IP,
            RateClass::PasswordEmail => PASSWORD_PER_EMAIL,
            RateClass::PasswordIp => PASSWORD_PER_IP,
            RateClass::TokenExchange => TOKEN_EXCHANGE,
            RateClass::BrowseSearch => BROWSE_SEARCH,
            RateClass::CreateOrg => CREATE_ORG_PER_OWNER,
            RateClass::DeviceActivate => DEVICE_ACTIVATE,
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

/// The mutable state behind the limiter's single lock.
///
/// Two structures kept in lock-step: `windows` is the authoritative
/// `(class, key) → counter` map, and `by_start` is an ordered index of
/// `(window_start, class, key)` over the *same* keys, so the oldest-started
/// window is `by_start.first()` — an `O(log n)` lookup instead of an `O(n)`
/// min-scan. `inserts` counts new keys to drive the lazy prune.
#[derive(Debug, Default)]
struct State {
    /// Authoritative per-`(class, key)` window counters.
    windows: HashMap<(RateClass, String), Window>,
    /// Window-start index over the same keys, for `O(log n)` oldest eviction.
    by_start: BTreeSet<(i64, RateClass, String)>,
    /// New-key inserts since the last lazy expired-entry sweep.
    inserts: u64,
}

/// A process-local fixed-window rate limiter keyed by `(class, key)`.
///
/// Cheap to share behind an `Arc`; the single `Mutex` is held only for the
/// brief counter read-modify-write. See the [module docs](self) for the trust
/// model and class budgets.
#[derive(Debug, Default)]
pub struct RateLimiter {
    state: Mutex<State>,
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
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let map_key = (class, key.to_string());

        // Refresh-in-place for an already-tracked key: reset the window if it
        // elapsed (re-indexing its start), then meter. No growth bookkeeping is
        // paid on the hot path of a returning key.
        if let Some(window) = state.windows.get(&map_key).copied() {
            if now.saturating_sub(window.started_at) >= WINDOW_SECS {
                // Window elapsed: re-key its index entry to the new start.
                state
                    .by_start
                    .remove(&(window.started_at, class, key.to_string()));
                state.by_start.insert((now, class, key.to_string()));
                let entry = state.windows.entry(map_key).or_insert(window);
                entry.started_at = now;
                entry.count = 1;
                return RateDecision::Allowed;
            }
            if window.count >= budget {
                let retry_after = (window.started_at + WINDOW_SECS - now).max(1);
                return RateDecision::Limited { retry_after };
            }
            if let Some(entry) = state.windows.get_mut(&map_key) {
                entry.count += 1;
            }
            return RateDecision::Allowed;
        }

        // A new key: bound the map first. Prune expired entries lazily (every
        // PRUNE_INTERVAL inserts, amortizing the O(n) sweep), then — if still
        // at the cap — evict the single oldest-started window in O(log n) via
        // the ordered index.
        state.inserts = state.inserts.wrapping_add(1);
        if state.inserts.is_multiple_of(PRUNE_INTERVAL) {
            Self::prune_expired(&mut state, now);
        }
        if state.windows.len() >= MAX_TRACKED {
            Self::evict_oldest(&mut state);
        }
        state.windows.insert(
            map_key,
            Window {
                started_at: now,
                count: 1,
            },
        );
        state.by_start.insert((now, class, key.to_string()));
        RateDecision::Allowed
    }

    /// Drop every window whose fixed window has fully elapsed by `now`.
    ///
    /// An elapsed window would reset to a fresh budget on its next touch
    /// anyway, so removing it is free of behavioral effect and bounds the map
    /// against keys that are never seen again (e.g. one-shot forged values).
    /// Both the authoritative map and the ordered index are pruned together.
    fn prune_expired(state: &mut State, now: i64) {
        let expired: Vec<(i64, RateClass, String)> = state
            .by_start
            .iter()
            .take_while(|(started, _, _)| now.saturating_sub(*started) >= WINDOW_SECS)
            .cloned()
            .collect();
        for (started, class, key) in expired {
            state.windows.remove(&(class, key.clone()));
            state.by_start.remove(&(started, class, key));
        }
    }

    /// Evict the entry whose window started earliest (least recently opened).
    ///
    /// The hard backstop when the map is at [`MAX_TRACKED`] and every tracked
    /// window is still live: evicting the oldest only resets that one key's
    /// budget early, which is acceptable under a key flood and keeps the map
    /// from growing past the cap. `O(log n)` via the window-start index, not an
    /// `O(n)` min-scan.
    fn evict_oldest(state: &mut State) {
        if let Some(oldest) = state.by_start.iter().next().cloned() {
            let (started, class, key) = oldest;
            state.windows.remove(&(class, key.clone()));
            state.by_start.remove(&(started, class, key));
        }
    }
}

/// Resolve the client IP for rate-limiting, honoring `X-Forwarded-For` only
/// when the deployment trusts its proxy.
///
/// When `trusted_proxy` is `true`, returns `X-Forwarded-For`'s **last** hop
/// (the one a trusted reverse proxy appends) if present, falling back to
/// `peer`. When `trusted_proxy` is `false`, the header is ignored entirely and
/// the real TCP `peer` address is always the key — so a directly-exposed hub
/// cannot be tricked into a fresh bucket per forged header value. See the
/// [module docs](self) for the trust model.
#[must_use]
pub fn client_ip(forwarded_for: Option<&str>, peer: &str, trusted_proxy: bool) -> String {
    if trusted_proxy {
        if let Some(xff) = forwarded_for {
            // The last non-empty comma-separated hop (the one a trusted proxy
            // appends), scanning from the right.
            if let Some(last) = xff.rsplit(',').map(str::trim).find(|s| !s.is_empty()) {
                return last.to_string();
            }
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
    fn client_ip_honors_forwarded_only_when_trusted() {
        // Trusted proxy: the last forwarded hop wins.
        assert_eq!(
            client_ip(Some("203.0.113.1, 10.0.0.2"), "10.0.0.2:443", true),
            "10.0.0.2"
        );
        assert_eq!(
            client_ip(Some("203.0.113.1"), "10.0.0.2:443", true),
            "203.0.113.1"
        );
        assert_eq!(client_ip(None, "10.0.0.2:443", true), "10.0.0.2:443");
        assert_eq!(client_ip(Some("  "), "peer", true), "peer");

        // Untrusted (the default): the forwarded header is ignored entirely;
        // the real peer is always the key, however the attacker forges XFF.
        assert_eq!(
            client_ip(Some("1.1.1.1"), "10.0.0.2:443", false),
            "10.0.0.2:443"
        );
        assert_eq!(
            client_ip(Some("2.2.2.2"), "10.0.0.2:443", false),
            "10.0.0.2:443"
        );
        assert_eq!(client_ip(None, "10.0.0.2:443", false), "10.0.0.2:443");
    }

    #[test]
    fn forged_forwarded_for_does_not_evade_limit_when_untrusted() {
        let limiter = RateLimiter::new();
        // The attacker is one peer but rotates a unique forged XFF per request.
        // With trusted_proxy = false the limiter keys on the peer, so the
        // budget is enforced regardless of the forged header.
        let peer = "198.51.100.7:5000";
        let mut allowed = 0;
        for i in 0..(DEVICE_AUTH_PER_IP + 5) {
            let forged = format!("{i}.{i}.{i}.{i}");
            let key = client_ip(Some(&forged), peer, false);
            if limiter
                .check(RateClass::DeviceAuthorization, &key, 0)
                .is_allowed()
            {
                allowed += 1;
            }
        }
        assert_eq!(
            allowed, DEVICE_AUTH_PER_IP,
            "forged XFF must not mint fresh per-IP buckets"
        );
    }

    #[test]
    fn expired_windows_are_pruned_lazily() {
        let limiter = RateLimiter::new();
        // Open windows for many distinct keys at t=0 — enough to cross the
        // lazy prune interval so the sweep runs.
        let seed = PRUNE_INTERVAL as usize;
        for i in 0..seed {
            limiter.check(RateClass::BrowseSearch, &format!("k{i}"), 0);
        }
        assert_eq!(limiter.state.lock().unwrap().windows.len(), seed);
        // New keys well past the window sweep every elapsed entry; after the
        // prune interval is crossed only the recent (un-elapsed) keys remain.
        for i in 0..PRUNE_INTERVAL {
            limiter.check(
                RateClass::BrowseSearch,
                &format!("fresh{i}"),
                WINDOW_SECS + 1,
            );
        }
        let state = limiter.state.lock().unwrap();
        assert!(
            state.windows.len() <= PRUNE_INTERVAL as usize,
            "expired entries must be swept; got {} live",
            state.windows.len()
        );
        // The two index structures stay in lock-step.
        assert_eq!(state.windows.len(), state.by_start.len());
    }

    #[test]
    fn distinct_key_flood_stays_bounded_and_enforces_limits() {
        let limiter = RateLimiter::new();
        // Flood a single class with many distinct keys; the map must stay
        // bounded and each key must still get its own budget.
        for i in 0..(PRUNE_INTERVAL as usize * 4) {
            assert!(limiter
                .check(RateClass::PasswordEmail, &format!("user{i}@acme.com"), 0)
                .is_allowed());
        }
        // One flooded key is still independently limited at its budget.
        let key = "user0@acme.com";
        let mut allowed = 1; // already spent one above
        while limiter.check(RateClass::PasswordEmail, key, 0).is_allowed() {
            allowed += 1;
            assert!(allowed <= PASSWORD_PER_EMAIL, "limit must eventually bite");
        }
        assert_eq!(allowed, PASSWORD_PER_EMAIL);
        let state = limiter.state.lock().unwrap();
        assert!(state.windows.len() <= MAX_TRACKED, "map must stay bounded");
        assert_eq!(
            state.windows.len(),
            state.by_start.len(),
            "the window map and its ordered index must stay in lock-step"
        );
    }
}
