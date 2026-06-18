//! The wall clock, abstracted across deployment targets.
//!
//! The hub's `Database` writes (and JWT issuance/expiry) stamp Unix-second
//! timestamps. On a native build that is `std::time::SystemTime`; on the
//! Cloudflare Worker (`wasm32-unknown-unknown`) `SystemTime::now()` is
//! unavailable and panics, so this module reads the host JS clock through
//! `js_sys::Date::now()` instead (RFC-0004 Phase 5). Callers use the single
//! [`now_unix_secs`] entry point and never branch on the target themselves.

/// The current Unix time in whole seconds.
///
/// On native targets this reads `std::time::SystemTime`; on
/// `wasm32-unknown-unknown` (the Worker) it reads the JS `Date.now()` clock.
/// A clock before the Unix epoch (impossible in practice) yields `0` rather
/// than panicking, matching the hub's prior `unix_now` behavior.
#[must_use]
pub fn now_unix_secs() -> i64 {
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }
    #[cfg(target_arch = "wasm32")]
    {
        // `Date.now()` is milliseconds since the Unix epoch as an f64; the
        // Workers runtime provides it. Truncate to whole seconds.
        (js_sys::Date::now() / 1000.0) as i64
    }
}

/// A stopwatch for render timing, abstracted across deployment targets.
///
/// On native this is `std::time::Instant`. On `wasm32-unknown-unknown`
/// `Instant::now()` **panics** (the bare wasm target has no monotonic clock),
/// which inside an `async` request handler aborts the future and surfaces on the
/// Workers runtime as "a hanging Promise was canceled" — so the Worker uses a
/// `Date.now()`-backed stopwatch instead. It backs only the cosmetic
/// "rendered Nms" page footer (the sole [`elapsed`](Instant::elapsed) consumer),
/// so wall-clock resolution is fine; a backwards step clamps to zero.
#[cfg(not(target_arch = "wasm32"))]
pub use std::time::Instant;

/// A `Date.now()`-backed stopwatch (the Worker's [`Instant`] replacement).
#[cfg(target_arch = "wasm32")]
#[derive(Clone, Copy, Debug)]
pub struct Instant {
    /// `Date.now()` (ms since the Unix epoch) captured at construction.
    start_ms: f64,
}

#[cfg(target_arch = "wasm32")]
impl Instant {
    /// Start the stopwatch at the current `Date.now()`.
    #[must_use]
    pub fn now() -> Instant {
        Instant {
            start_ms: js_sys::Date::now(),
        }
    }

    /// Time elapsed since [`now`](Instant::now), clamped to non-negative.
    #[must_use]
    pub fn elapsed(&self) -> std::time::Duration {
        let ms = (js_sys::Date::now() - self.start_ms).max(0.0);
        std::time::Duration::from_millis(ms as u64)
    }
}
