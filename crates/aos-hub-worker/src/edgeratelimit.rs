//! The edge-local Workers Rate Limiting binding impl of the shared
//! [`RateLimiter`] port (wasm32-only).
//!
//! RFC-0004 ch.14 (corrected): rate limiting must stay **off the request's
//! network path**. Cloudflare's [Rate Limiting binding] is **edge-local** —
//! `env.X.limit({key})` increments a counter cached on the executing machine
//! with async background reconciliation, so "you are not waiting on a network
//! request." This replaces the earlier Durable Object limiter, whose single
//! global instance added a ~100 ms cross-region hop to every read.
//!
//! The binding carries **one `limit`/`period` per binding**, but the service
//! meters classes with three different burst budgets (5, 10, 120 per minute), so
//! three bindings are declared — one per tier, all `period = 60` — and a class
//! is routed to the binding matching its budget. Keys are namespaced
//! `{class}:{key}` so classes sharing a tier do not collide.
//!
//! The publish lease keeps its Durable Object backing (a write-path concern, not
//! latency-critical); only the read-path limiter moves to the edge binding. The
//! native hub keeps its in-process token-bucket [`RateLimiter`] — same trait,
//! feature parity.
//!
//! [Rate Limiting binding]: https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/

use async_trait::async_trait;

use aos_hub_core::ratelimit::{CoordinatorRateLimiter, RateClass, RateDecision, RateLimiter};

/// The fixed window length the bindings are configured with, in seconds.
///
/// The Rate Limiting binding accepts only a `period` of 10 or 60; the service's
/// budgets are per-minute, so 60.
const WINDOW_SECS: i64 = 60;

/// A [`RateLimiter`] backed by the edge-local Workers Rate Limiting bindings.
///
/// Holds one binding handle per budget tier; [`check`](RateLimiter::check) routes
/// a class to the matching tier and calls its `limit({key})`. Construction is
/// cheap (it wraps the JS binding handles); the actual metering is edge-local.
pub struct EdgeRateLimiter {
    /// Tier for the 5/min classes (`CreateOrg`).
    burst5: worker::RateLimiter,
    /// Tier for the 10/min classes (login/device/magic/token).
    burst10: worker::RateLimiter,
    /// Tier for the 120/min class (`BrowseSearch`).
    browse120: worker::RateLimiter,
}

impl EdgeRateLimiter {
    /// Builds the limiter from the Worker environment's three rate-limit
    /// bindings.
    ///
    /// # Errors
    ///
    /// Returns an error if any of the `RL_BURST5` / `RL_BURST10` / `RL_BROWSE120`
    /// rate-limit bindings is missing.
    pub fn from_env(env: &worker::Env) -> worker::Result<EdgeRateLimiter> {
        Ok(EdgeRateLimiter {
            burst5: env.rate_limiter(crate::handlers::bindings::RL_BURST5)?,
            burst10: env.rate_limiter(crate::handlers::bindings::RL_BURST10)?,
            browse120: env.rate_limiter(crate::handlers::bindings::RL_BROWSE120)?,
        })
    }

    /// The binding for a class, chosen by its per-window budget tier.
    fn binding_for(&self, class: RateClass) -> &worker::RateLimiter {
        match CoordinatorRateLimiter::budget(class) {
            5 => &self.burst5,
            120 => &self.browse120,
            _ => &self.burst10,
        }
    }
}

#[async_trait(?Send)]
impl RateLimiter for EdgeRateLimiter {
    async fn check(&self, class: RateClass, key: &str, now: i64) -> RateDecision {
        let binding = self.binding_for(class);
        // Namespace the key by class so classes sharing a tier's binding keep
        // independent counters.
        let composite = format!("{}:{}", CoordinatorRateLimiter::class_name(class), key);
        match binding.limit(composite).await {
            Ok(outcome) if outcome.success => RateDecision::Allowed,
            Ok(_) => {
                // The binding does not return a reset time; approximate it as the
                // current fixed window's end (the budgets are per-minute).
                let window_end = (now.div_euclid(WINDOW_SECS) + 1) * WINDOW_SECS;
                RateDecision::Limited {
                    retry_after: (window_end - now).max(1),
                }
            }
            // Fail open: a limiter error must not wedge the hub (the metered
            // operations carry their own DB-enforced backstops).
            Err(err) => {
                worker::console_error!(
                    "edge rate-limit failed ({}): {err}",
                    CoordinatorRateLimiter::class_name(class)
                );
                RateDecision::Allowed
            }
        }
    }
}
