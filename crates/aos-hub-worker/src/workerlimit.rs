//! The D1-backed [`RateLimiter`] for the shared service (wasm32-only).
//!
//! The shared [`RpcService`](aos_hub_core::service::RpcService) meters a
//! few abuse-prone operations through the [`RateLimiter`] port
//! ([`aos_hub_core::ratelimit`]); the native hub keeps the count in an
//! in-process token bucket, but a Cloudflare Worker isolate is stateless across
//! invocations, so the count must live in durable storage. This module keeps it
//! in D1, the same sqlite database the rest of the Worker drives, as a
//! **fixed-window counter**.
//!
//! # Schema
//!
//! The counter table is created lazily (the shared `MIGRATIONS` do not own it,
//! since rate limiting is a per-deployment concern) the first time a limiter is
//! built:
//!
//! ```sql
//! CREATE TABLE IF NOT EXISTS rate_limits (
//!     class  TEXT    NOT NULL,   -- the RateClass discriminant name
//!     key    TEXT    NOT NULL,   -- the per-class key (principal, IP, email, …)
//!     window INTEGER NOT NULL,   -- the fixed-window index: now / WINDOW_SECS
//!     count  INTEGER NOT NULL,   -- attempts recorded in this window
//!     PRIMARY KEY (class, key, window)
//! );
//! ```
//!
//! Each [`check`](RateLimiter::check) computes the current window from `now` and
//! runs a single atomic conditional upsert
//! (`INSERT … ON CONFLICT DO UPDATE SET count = count + 1 WHERE count < budget
//! RETURNING count`): it inserts the first attempt or increments an existing
//! count only while the window stays under the class budget, and otherwise
//! denies without counting (so a denied attempt never consumes budget). Because
//! the increment and the budget test live in one statement that SQLite
//! serializes, two *concurrent* isolates racing the same key cannot both admit
//! at the budget boundary — there is no read-then-write window to over-admit
//! through. Stale rows for past windows are left in place; a periodic sweep (or
//! the Cron indexer) can prune `window < current` rows. This is intentionally a
//! **fixed window**, not a sliding window or a leaky bucket: it is simple,
//! correct under the Worker's single-threaded-per-isolate execution, and
//! adequate for the burst budgets the service enforces.

use async_trait::async_trait;

use aos_hub_core::backend::Backend;
use aos_hub_core::ratelimit::{RateClass, RateDecision, RateLimiter};
use aos_hub_core::value::Value;

use crate::d1backend::D1Backend;

/// The fixed-window length, in seconds.
///
/// One minute matches the burst horizon the service's `CreateOrg` budget is
/// expressed against.
const WINDOW_SECS: i64 = 60;

/// A D1-backed fixed-window [`RateLimiter`].
///
/// Built once per request from the bound D1 database; the lazily-created
/// `rate_limits` table persists the per-window counts across isolate
/// invocations.
pub struct D1RateLimiter {
    backend: D1Backend,
}

impl D1RateLimiter {
    /// Build a limiter over a D1 backend, creating the counter table if absent.
    ///
    /// # Errors
    ///
    /// Returns an error if the `CREATE TABLE IF NOT EXISTS` fails (a D1 access
    /// error); a table that already exists is not an error.
    pub async fn create(backend: D1Backend) -> anyhow::Result<D1RateLimiter> {
        backend
            .execute(
                "CREATE TABLE IF NOT EXISTS rate_limits (\
                   class TEXT NOT NULL, \
                   key TEXT NOT NULL, \
                   window INTEGER NOT NULL, \
                   count INTEGER NOT NULL, \
                   PRIMARY KEY (class, key, window))",
                &[],
            )
            .await?;
        Ok(D1RateLimiter { backend })
    }

    /// The per-window attempt budget for a metered class.
    ///
    /// Mirrors the native hub's burst budgets. Classes the shared service does
    /// not yet meter keep a conservative default so a future call site is bounded
    /// rather than unlimited.
    fn budget(class: RateClass) -> i64 {
        match class {
            // Org creation: a handful per minute per principal; the DB-enforced
            // MAX_ORGS_PER_OWNER is the steady-state backstop.
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

    /// The stable string discriminant a class is stored under.
    fn class_name(class: RateClass) -> &'static str {
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

    /// Atomically admit one attempt against the window budget.
    ///
    /// Runs a single conditional upsert: the first attempt in a window inserts
    /// the row at `count = 1`; a later attempt increments an existing row only
    /// while `count < budget`. SQLite serializes the statement, so two
    /// concurrent isolates racing the same key cannot both increment past the
    /// boundary, and the `WHERE count < ?` guard makes a window already at
    /// budget a no-op — a denied attempt never consumes further budget.
    ///
    /// Returns `true` when the attempt was recorded (admitted) and `false`
    /// when the window was already at budget (denied). `RETURNING count` emits
    /// the post-increment count on the insert/update paths and no row when the
    /// conditional update is skipped.
    ///
    /// # Errors
    ///
    /// Returns an error if the upsert fails (a D1 access error).
    async fn admit(&self, class: &str, key: &str, window: i64, budget: i64) -> anyhow::Result<bool> {
        let rows = self
            .backend
            .query(
                "INSERT INTO rate_limits (class, key, window, count) VALUES (?, ?, ?, 1) \
                 ON CONFLICT(class, key, window) DO UPDATE SET count = count + 1 \
                   WHERE count < ? \
                 RETURNING count",
                &[
                    Value::Text(class.to_string()),
                    Value::Text(key.to_string()),
                    Value::Int(window),
                    Value::Int(budget),
                ],
            )
            .await?;
        Ok(!rows.is_empty())
    }
}

#[async_trait(?Send)]
impl RateLimiter for D1RateLimiter {
    async fn check(&self, class: RateClass, key: &str, now: i64) -> RateDecision {
        let name = D1RateLimiter::class_name(class);
        let budget = D1RateLimiter::budget(class);
        let window = now.div_euclid(WINDOW_SECS);

        match self.admit(name, key, window, budget).await {
            Ok(true) => RateDecision::Allowed,
            Ok(false) => {
                // Seconds until this fixed window resets, for `Retry-After`.
                let window_end = (window + 1) * WINDOW_SECS;
                let retry_after = (window_end - now).max(1);
                RateDecision::Limited { retry_after }
            }
            Err(err) => {
                // Fail open: a counter-store error must not wedge the hub. The
                // metered operations carry their own DB-enforced backstops
                // (e.g. MAX_ORGS_PER_OWNER for CreateOrg).
                worker::console_error!("rate_limits upsert failed ({name}/{key}): {err:#}");
                RateDecision::Allowed
            }
        }
    }
}
